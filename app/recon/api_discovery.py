"""
Leadline - API Discovery Phase
Phase 7: REST/GraphQL API endpoint detection from HTML, JS, and common paths
"""
import re
import aiohttp
from typing import Dict, Any, List, Set
from urllib.parse import urljoin, urlparse
from app.recon.base import BaseReconPhase
from app.config import settings


class APIDiscoveryPhase(BaseReconPhase):
    """API Discovery reconnaissance phase."""

    name = "api_discovery"
    order = 9
    description = "REST/GraphQL API endpoint detection"

    # Common API paths to probe
    COMMON_API_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/graphql",
        "/graphql", "/graphiql", "/playground",
        "/swagger", "/swagger.json", "/swagger-ui",
        "/openapi.json", "/docs", "/redoc",
        "/api/docs", "/api/swagger",
    ]

    # API indicators in content
    API_INDICATORS = {
        "rest": [r'/api/', r'rest', r'resource', r'endpoint'],
        "graphql": [r'graphql', r'query\s*\{', r'mutation\s*\{', r'__schema'],
        "swagger": [r'swagger', r'openapi', r'swagger-ui'],
        "json_api": [r'application/vnd\.api\+json', r'json:api'],
    }

    async def execute(self) -> Dict[str, Any]:
        """Execute API discovery."""
        try:
            api_endpoints: List[Dict[str, Any]] = []
            swagger_docs: List[str] = []
            graphql_endpoints: List[str] = []
            found_paths: Set[str] = set()

            # Get base URL
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            headers = self._get_headers()
            timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)

            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                # Check common API paths
                for i, path in enumerate(self.COMMON_API_PATHS):
                    api_url = urljoin(base_url, path)
                    if api_url in found_paths:
                        continue
                    if i > 0:
                        await self._delay()  # jitter between probes, not just between phases

                    try:
                        async with session.get(api_url, allow_redirects=False) as response:
                            if response.status in [200, 201, 301, 302]:
                                content_type = response.content_type or ""

                                endpoint_info = {
                                    "url": api_url,
                                    "status_code": response.status,
                                    "content_type": content_type,
                                    "method": "GET",
                                    "source": "path_probe",
                                    "discovery_type": "observed",
                                    "confidence": "high"
                                }

                                # Detect API type
                                if 'json' in content_type.lower():
                                    endpoint_info["api_type"] = "json_api"
                                    api_endpoints.append(endpoint_info)
                                    found_paths.add(api_url)

                                    # Check for Swagger/OpenAPI
                                    if 'swagger' in path.lower() or 'openapi' in path.lower():
                                        swagger_docs.append(api_url)

                                elif 'graphql' in path.lower() or response.status == 200:
                                    endpoint_info["api_type"] = "unknown"
                                    api_endpoints.append(endpoint_info)
                                    found_paths.add(api_url)

                                    if 'graphql' in path.lower():
                                        graphql_endpoints.append(api_url)

                                else:
                                    # Still might be an API even without JSON content type
                                    endpoint_info["api_type"] = "possible_api"
                                    api_endpoints.append(endpoint_info)
                                    found_paths.add(api_url)

                    except Exception:
                        pass  # Skip failed requests

                # Also check JavaScript results for API references
                js_results = self.context.get('js_analysis', {}) if hasattr(self, 'context') else {}
                js_endpoints = js_results.get('extracted_endpoints', [])
                js_api_calls = js_results.get('api_calls', [])

                for endpoint in js_endpoints:
                    if '/api/' in endpoint or 'graphql' in endpoint.lower():
                        full_url = endpoint if endpoint.startswith('http') else urljoin(base_url, endpoint)
                        if full_url not in found_paths:
                            api_endpoints.append({
                                "url": full_url,
                                "status_code": None,
                                "content_type": None,
                                "method": "GET",
                                "api_type": "referenced_in_js",
                                "source": "javascript",
                                "discovery_type": "inferred",
                                "confidence": "medium"
                            })
                            found_paths.add(full_url)

                            if 'graphql' in full_url.lower():
                                graphql_endpoints.append(full_url)

                for api_call in js_api_calls:
                    # Handle both string and dict formats
                    endpoint_str = api_call.get('endpoint', '') if isinstance(api_call, dict) else api_call
                    if not endpoint_str:
                        continue
                    full_url = endpoint_str if endpoint_str.startswith('http') else urljoin(base_url, endpoint_str)
                    if full_url not in found_paths and ('/api/' in full_url or 'graphql' in full_url.lower()):
                        api_endpoints.append({
                            "url": full_url,
                            "status_code": None,
                            "content_type": None,
                            "method": "GET",
                            "api_type": "referenced_in_js",
                            "source": "javascript",
                            "discovery_type": "inferred",
                            "confidence": "medium"
                        })
                        found_paths.add(full_url)

                # Check HTML for API references
                try:
                    async with session.get(self.target_url) as response:
                        if response.status == 200:
                            html_content, _truncated = await self._read_text_limited(response)

                            # Look for API links in HTML
                            api_link_pattern = r'href=[\'"]([^\'"]*\/api\/[^\'"]*)[\'"]'
                            matches = re.findall(api_link_pattern, html_content, re.IGNORECASE)
                            for match in matches:
                                full_url = urljoin(base_url, match)
                                if full_url not in found_paths:
                                    api_endpoints.append({
                                        "url": full_url,
                                        "status_code": None,
                                        "content_type": None,
                                        "method": "GET",
                                        "api_type": "html_reference",
                                        "source": "html",
                                        "discovery_type": "observed",
                                        "confidence": "high"
                                    })
                                    found_paths.add(full_url)
                except Exception:
                    pass

            # Add findings for discovered APIs
            for endpoint in api_endpoints:
                self.add_finding(
                    finding_type="api_endpoint",
                    title="API Endpoint Discovered",
                    severity="info",
                    description=f"Discovered API endpoint at {endpoint['url']}",
                    location=endpoint['url'],
                    evidence=f"Source: {endpoint.get('source', 'unknown')}, Type: {endpoint.get('api_type', 'unknown')}",
                    metadata={
                        "api_type": endpoint.get('api_type'),
                        "source": endpoint.get('source'),
                        # path_probe = we actively hit this path and got a
                        # response ourselves ("observed"); javascript/html =
                        # we only saw a reference to it in scanned content,
                        # never confirmed it responds ("inferred"). The
                        # report summary's observed/inferred API counts read
                        # this field.
                        "discovery_type": "observed" if endpoint.get('source') == "path_probe" else "inferred",
                    }
                )

            return {
                "api_endpoints": api_endpoints,
                "endpoint_count": len(api_endpoints),
                "swagger_docs": swagger_docs,
                "swagger_count": len(swagger_docs),
                "graphql_endpoints": graphql_endpoints,
                "graphql_count": len(graphql_endpoints),
                "status": "completed"
            }

        except Exception as e:
            return {
                "api_endpoints": [],
                "swagger_docs": [],
                "graphql_endpoints": [],
                "status": "failed",
                "error": str(e)
            }
