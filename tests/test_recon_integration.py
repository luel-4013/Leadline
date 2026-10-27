"""
Leadline - Integration Tests for Recon Phases
Tests that verify actual reconnaissance functionality against a controlled target.
"""
import pytest
import threading
import time
from http.server import HTTPServer

# Import controlled target server
from tests.controlled_target import ControlledTargetHandler

from app.recon.dns_discovery import DNSDiscoveryPhase
from app.recon.http_fingerprinting import HTTPFingerprintingPhase
from app.recon.tech_detection import TechDetectionPhase
from app.recon.js_analysis import JSAnalysisPhase
from app.recon.param_discovery import ParamDiscoveryPhase
from app.recon.security_headers import SecurityHeadersPhase
from app.recon.api_discovery import APIDiscoveryPhase
from app.recon.vuln_classification import VulnClassificationPhase
from app.recon.graph_builder import GraphBuilderPhase


# Global server reference for teardown
_server_instance = None
_server_thread = None


@pytest.fixture(scope="module")
def controlled_target_server():
    """Start a controlled test target server for integration tests."""
    global _server_instance, _server_thread

    # Create and start server in background thread
    port = 8765
    _server_instance = HTTPServer(('127.0.0.1', port), ControlledTargetHandler)

    def run():
        _server_instance.serve_forever()

    _server_thread = threading.Thread(target=run, daemon=True)
    _server_thread.start()

    # Give server time to start
    time.sleep(0.5)

    yield f"http://127.0.0.1:{port}"

    # Teardown
    if _server_instance:
        _server_instance.shutdown()
        _server_instance.server_close()


class TestDNSDiscovery:
    """Test DNS Discovery phase."""

    @pytest.mark.asyncio
    async def test_dns_localhost_resolution(self, controlled_target_server):
        """Test DNS resolution for localhost."""
        phase = DNSDiscoveryPhase(controlled_target_server, {})
        result = await phase.execute()

        assert result["status"] == "completed"
        assert result["hostname"] == "127.0.0.1"
        assert isinstance(result["addresses"], list)
        # Should handle IP addresses directly
        assert len(result["addresses"]) >= 1

    @pytest.mark.asyncio
    async def test_dns_ip_target_handling(self, controlled_target_server):
        """Test that IP targets are handled without DNS lookup."""
        phase = DNSDiscoveryPhase(controlled_target_server, {})
        result = await phase.execute()

        assert result["status"] != "stub"
        assert result.get("resolved_from_dns") in [True, False]


class TestHTTPFingerprinting:
    """Test HTTP Fingerprinting phase."""

    @pytest.mark.asyncio
    async def test_http_fingerprinting_basic(self, controlled_target_server):
        """Test basic HTTP fingerprinting."""
        phase = HTTPFingerprintingPhase(controlled_target_server, {})
        result = await phase.execute()

        assert result["status"] == "completed"
        assert "GET" in result.get("methods", [])
        assert result.get("status_codes", {}).get("GET") == 200

    @pytest.mark.asyncio
    async def test_server_header_detection(self, controlled_target_server):
        """Test server header detection."""
        phase = HTTPFingerprintingPhase(controlled_target_server, {})
        result = await phase.execute()

        server_info = result.get("server_info", {})
        # Our controlled target has TestServer/1.0
        assert "server_header" in server_info or "powered_by" in server_info


class TestTechDetection:
    """Test Technology Detection phase."""

    @pytest.mark.asyncio
    async def test_tech_detection_with_context(self, controlled_target_server):
        """Test technology detection using HTTP results."""
        # Simulate having HTTP results from previous phase
        context = {
            "http_fingerprinting": {
                "server_info": {
                    "server_header": "TestServer/1.0",
                    "powered_by": "ExampleFramework/2.0"
                },
                "detailed_results": {
                    "GET": {
                        "headers": {
                            "Server": "TestServer/1.0",
                            "X-Powered-By": "ExampleFramework/2.0"
                        }
                    }
                }
            }
        }

        phase = TechDetectionPhase(controlled_target_server, context)
        result = await phase.execute()

        assert result["status"] == "completed"
        assert "technologies" in result
        assert "technology_count" in result


class TestJSAnalysis:
    """Test JavaScript Analysis phase."""

    @pytest.mark.asyncio
    async def test_js_file_discovery(self, controlled_target_server):
        """Test JavaScript file discovery."""
        # First get HTML content
        http_phase = HTTPFingerprintingPhase(controlled_target_server, {})
        http_result = await http_phase.execute()

        # Get HTML from response
        context = {"http_fingerprinting": http_result}

        js_phase = JSAnalysisPhase(controlled_target_server, context)
        result = await js_phase.execute()

        assert result["status"] == "completed"
        # Should find at least one JS file reference
        assert "js_files" in result
        assert "extracted_endpoints" in result


class TestParamDiscovery:
    """Test Parameter Discovery phase."""

    @pytest.mark.asyncio
    async def test_parameter_extraction(self, controlled_target_server):
        """Test parameter extraction from HTML."""
        phase = ParamDiscoveryPhase(controlled_target_server, {})
        result = await phase.execute()

        assert result["status"] == "completed"
        # The controlled target has parameters: q, page, id, action
        assert "url_parameters" in result
        assert "form_fields" in result

        # Should find some parameters
        param_count = result.get("parameter_count", 0)
        form_count = result.get("form_field_count", 0)
        assert param_count > 0 or form_count > 0


class TestSecurityHeaders:
    """Test Security Headers Analysis phase."""

    @pytest.mark.asyncio
    async def test_security_headers_analysis(self, controlled_target_server):
        """Test security headers analysis."""
        phase = SecurityHeadersPhase(controlled_target_server, {})
        result = await phase.execute()

        assert result["status"] == "completed"
        assert "present_headers" in result
        assert "missing_headers" in result
        assert "issues" in result

        # Our controlled target has X-Frame-Options but missing others
        present_count = result.get("present_count", 0)
        missing_count = result.get("missing_count", 0)
        assert present_count > 0 or missing_count > 0


class TestAPIDiscovery:
    """Test API Discovery phase."""

    @pytest.mark.asyncio
    async def test_api_endpoint_discovery(self, controlled_target_server):
        """Test API endpoint discovery."""
        phase = APIDiscoveryPhase(controlled_target_server, {})
        result = await phase.execute()

        assert result["status"] == "completed"
        assert "api_endpoints" in result
        assert "endpoint_count" in result

        # Should find /api endpoints
        endpoints = result.get("api_endpoints", [])
        api_paths = [e.get("url", "") for e in endpoints if "/api/" in e.get("url", "")]
        assert len(api_paths) > 0


class TestVulnClassification:
    """Test Vulnerability Classification phase."""

    @pytest.mark.asyncio
    async def test_vulnerability_classification(self, controlled_target_server):
        """Test vulnerability classification."""
        # Simulate context with findings from previous phases
        context = {
            "security_headers": {
                "missing_headers": [
                    {"name": "Content-Security-Policy", "severity": "high"},
                    {"name": "Strict-Transport-Security", "severity": "medium"}
                ]
            },
            "param_discovery": {
                "url_parameters": [
                    {"name": "id", "location": "/users"},
                    {"name": "user_id", "location": "/api/data"}
                ]
            },
            "api_discovery": {
                "api_endpoints": [
                    {"url": f"{controlled_target_server}/api/users", "source": "path_probe"},
                    {"url": f"{controlled_target_server}/admin", "source": "path_probe"}
                ]
            }
        }

        phase = VulnClassificationPhase(controlled_target_server, context)
        result = await phase.execute()

        assert result["status"] == "completed"
        assert "potential_vulns" in result
        assert "idor_candidates" in result
        assert "exposed_interfaces" in result


class TestGraphBuilder:
    """Test Graph Builder phase."""

    @pytest.mark.asyncio
    async def test_graph_construction(self, controlled_target_server):
        """Test graph construction from discovered paths."""
        context = {
            "api_discovery": {
                "api_endpoints": [
                    {"url": f"{controlled_target_server}/api/users"},
                    {"url": f"{controlled_target_server}/api/orders"},
                    {"url": f"{controlled_target_server}/admin"}
                ]
            },
            "js_analysis": {
                "extracted_endpoints": [
                    "/api/products",
                    "/debug/trace"
                ]
            }
        }

        phase = GraphBuilderPhase(controlled_target_server, context)
        result = await phase.execute()

        assert result["status"] == "completed"
        assert "nodes" in result
        assert "edges" in result
        assert "tree_structure" in result

        # Should have nodes and edges
        node_count = result.get("node_count", 0)
        edge_count = result.get("edge_count", 0)
        assert node_count > 0
        assert edge_count > 0


class TestEndToEndScan:
    """Test end-to-end scan simulation."""

    @pytest.mark.asyncio
    async def test_full_recon_pipeline(self, controlled_target_server):
        """Test complete reconnaissance pipeline."""
        context = {}

        # Run phases in order
        phases = [
            ("dns_discovery", DNSDiscoveryPhase),
            ("http_fingerprinting", HTTPFingerprintingPhase),
            ("tech_detection", TechDetectionPhase),
            ("js_analysis", JSAnalysisPhase),
            ("param_discovery", ParamDiscoveryPhase),
            ("security_headers", SecurityHeadersPhase),
            ("api_discovery", APIDiscoveryPhase),
            ("vuln_classification", VulnClassificationPhase),
            ("graph_builder", GraphBuilderPhase),
        ]

        all_results = {}
        findings_count = 0

        for phase_name, phase_class in phases:
            phase = phase_class(controlled_target_server, context)
            result = await phase.execute()

            # Store result for next phases
            all_results[phase_name] = result
            context[phase_name] = result

            # Count findings
            if hasattr(phase, 'findings'):
                findings_count += len(phase.findings)

            # Verify phase completed (not stub)
            assert result.get("status") == "completed", f"{phase_name} returned status: {result.get('status')}"

        # Verify we got actual findings
        assert findings_count > 0, "No findings were generated during the scan"

        # Verify graph has nodes
        graph_result = all_results.get("graph_builder", {})
        assert graph_result.get("node_count", 0) > 0, "Graph should have nodes"

        # Verify report-worthy data exists
        api_result = all_results.get("api_discovery", {})
        assert api_result.get("endpoint_count", 0) > 0, "Should discover API endpoints"

        print("\n=== End-to-End Scan Results ===")
        print(f"Total findings: {findings_count}")
        print(f"Graph nodes: {graph_result.get('node_count', 0)}")
        print(f"API endpoints: {api_result.get('endpoint_count', 0)}")
        print("All phases completed successfully!")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
