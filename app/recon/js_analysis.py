"""
Leadline - JavaScript Analysis Phase
Phase 4: JavaScript file analysis, endpoint extraction, parameter discovery
"""
import re
import aiohttp
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
from app.recon.base import BaseReconPhase
from app.config import settings


class JSAnalysisPhase(BaseReconPhase):
    """JavaScript Analysis reconnaissance phase."""

    name = "js_analysis"
    order = 6
    description = "JavaScript file analysis and endpoint extraction"

    # Patterns for extracting useful information from JavaScript
    PATTERNS = {
        'urls': r'(?:https?://[^\s"\'>]+|/[a-zA-Z0-9/_\-\.]+)',
        'api_endpoints': r'(?:/api/[a-zA-Z0-9/_\-]+)',
        'fetch_calls': r'fetch\s*\(\s*[`\'"]([^`\'"]+)[`\'"]',
        'axios_calls': r'axios\.(?:get|post|put|delete)\s*\(\s*[`\'"]([^`\'"]+)[`\'"]',
        'variables': r'(?:const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*[`\'"]([^`\'"]+)[`\'"]',
        'comments': r'//\s*(.+)$',
        'parameters': r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=',
    }

    async def execute(self) -> Dict[str, Any]:
        """Execute JavaScript analysis."""
        try:
            js_files: List[Dict[str, Any]] = []
            extracted_endpoints: List[str] = []
            api_calls: List[Dict[str, str]] = []
            parameters: List[Dict[str, str]] = []
            found_urls: Set[str] = set()

            # Get base URL for resolving relative paths
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # First, try to get JS files from HTTP fingerprinting results
            http_results = self.context.get('http_fingerprinting', {}) if hasattr(self, 'context') else {}

            # If we have HTML content, extract JS file references
            html_content = http_results.get('html_content', '')
            if html_content:
                js_refs = self._extract_js_references(html_content)
                for js_ref in js_refs:
                    js_url = urljoin(base_url, js_ref)
                    if js_url not in found_urls:
                        found_urls.add(js_url)

            # Also scan common JS paths
            common_js_paths = ['/static/app.js', '/static/utils.js', '/js/main.js', '/assets/app.js']
            for path in common_js_paths:
                js_url = urljoin(base_url, path)
                if js_url not in found_urls:
                    found_urls.add(js_url)

            # Fetch and analyze each JS file
            headers = self._get_headers()
            timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)

            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                for i, js_url in enumerate(list(found_urls)[:10]):  # Limit to 10 files
                    if i > 0:
                        await self._delay()  # jitter between requests, not just between phases
                    try:
                        async with session.get(js_url) as response:
                            if response.status == 200 and 'javascript' in response.content_type:
                                content, _truncated = await self._read_text_limited(response)

                                js_info = {
                                    "url": js_url,
                                    "size": len(content),
                                    "status": "analyzed"
                                }
                                js_files.append(js_info)

                                # Extract endpoints
                                endpoints = self._extract_endpoints(content)
                                for ep in endpoints:
                                    full_url = urljoin(base_url, ep) if ep.startswith('/') else ep
                                    if full_url not in extracted_endpoints:
                                        extracted_endpoints.append(full_url)
                                        self.add_finding(
                                            finding_type="endpoint_discovered",
                                            title="Endpoint Found in JavaScript",
                                            severity="info",
                                            description="Discovered endpoint referenced in JavaScript",
                                            location=full_url,
                                            evidence=f"Found in: {js_url}",
                                            metadata={"source": "javascript", "js_file": js_url}
                                        )

                                # Extract API calls
                                api_matches = self._extract_api_calls(content)
                                for api_call in api_matches:
                                    api_info = {"endpoint": api_call, "source": js_url}
                                    if api_info not in api_calls:
                                        api_calls.append(api_info)

                                # Extract parameters
                                params = self._extract_parameters(content)
                                for param in params:
                                    param_info = {"name": param, "source": js_url}
                                    if param_info not in parameters:
                                        parameters.append(param_info)
                                        self.add_finding(
                                            finding_type="parameter_discovered",
                                            title="Parameter Found in JavaScript",
                                            severity="info",
                                            description=f"Parameter '{param}' referenced in JavaScript",
                                            evidence=f"Found in: {js_url}",
                                            metadata={"parameter": param, "source": "javascript"}
                                        )

                    except Exception:
                        pass  # Skip failed fetches

            return {
                "js_files": js_files,
                "js_file_count": len(js_files),
                "extracted_endpoints": extracted_endpoints,
                "endpoint_count": len(extracted_endpoints),
                "api_calls": api_calls,
                "api_call_count": len(api_calls),
                "parameters": [p["name"] for p in parameters],
                "parameter_count": len(parameters),
                "status": "completed"
            }

        except Exception as e:
            return {
                "js_files": [],
                "extracted_endpoints": [],
                "api_calls": [],
                "status": "failed",
                "error": str(e)
            }

    def _extract_js_references(self, html_content: str) -> List[str]:
        """Extract JavaScript file references from HTML."""
        js_refs = []

        # Match <script src="..."> tags
        script_pattern = r'<script[^>]+src=[\'"]([^\'"]+\.js)[\'"]'
        matches = re.findall(script_pattern, html_content, re.IGNORECASE)
        js_refs.extend(matches)

        return js_refs

    def _extract_endpoints(self, content: str) -> List[str]:
        """Extract potential endpoints from JavaScript content."""
        endpoints = []

        # Look for API-like patterns
        api_pattern = r'/api/[a-zA-Z0-9/_\-]+'
        matches = re.findall(api_pattern, content)
        endpoints.extend(matches)

        # Look for fetch/axios calls with paths
        fetch_pattern = r'fetch\s*\(\s*[`\'"](/[^`\'"]+)[`\'"]'
        matches = re.findall(fetch_pattern, content)
        endpoints.extend(matches)

        # Look for route definitions
        route_pattern = r'(?:path|route|url)\s*[:=]\s*[`\'"](/[^`\'"]+)[`\'"]'
        matches = re.findall(route_pattern, content, re.IGNORECASE)
        endpoints.extend(matches)

        return list(set(endpoints))

    def _extract_api_calls(self, content: str) -> List[str]:
        """Extract API call patterns from JavaScript."""
        api_calls = []

        # fetch() calls
        fetch_pattern = r'fetch\s*\(\s*[`\'"]([^`\'"]+)[`\'"]'
        matches = re.findall(fetch_pattern, content)
        api_calls.extend(matches)

        # axios calls
        axios_pattern = r'axios\.(?:get|post|put|delete)\s*\(\s*[`\'"]([^`\'"]+)[`\'"]'
        matches = re.findall(axios_pattern, content)
        api_calls.extend(matches)

        return list(set(api_calls))

    def _extract_parameters(self, content: str) -> List[str]:
        """Extract parameter names from JavaScript."""
        params = []

        # Query string parameters
        param_pattern = r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)='
        matches = re.findall(param_pattern, content)
        params.extend(matches)

        # Variable assignments that look like parameters
        var_pattern = r'(?:const|let|var)\s+(query|filter|sort|limit|offset|page|id|userId|orderId)\s*='
        matches = re.findall(var_pattern, content, re.IGNORECASE)
        params.extend(matches)

        return list(set(params))
