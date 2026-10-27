"""
Leadline - HTTP Fingerprinting Phase
Phase 2: HTTP method detection, status codes, redirects, server identification
"""
import aiohttp
from typing import Dict, Any
from app.recon.base import BaseReconPhase
from app.config import settings


class HTTPFingerprintingPhase(BaseReconPhase):
    """HTTP Fingerprinting reconnaissance phase."""

    name = "http_fingerprinting"
    order = 4
    description = "HTTP method detection, status codes, redirects, server identification"

    async def execute(self) -> Dict[str, Any]:
        """Execute HTTP fingerprinting."""
        try:
            # Ensure URL has scheme
            url = self._normalize_url(self.target_url)

            headers = self._get_headers()
            timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)

            methods_tested = ["GET", "HEAD", "OPTIONS"]
            results = {}
            redirects = []
            html_content = ""

            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                for method in methods_tested:
                    try:
                        allow_redirects = True
                        async with session.request(
                            method,
                            url,
                            allow_redirects=allow_redirects
                        ) as response:
                            # Track redirects
                            if response.history:
                                for redirect in response.history:
                                    if str(redirect.url) not in [r.get('from') for r in redirects]:
                                        redirects.append({
                                            "from": str(redirect.url),
                                            "to": str(response.url),
                                            "status": redirect.status
                                        })

                            # Only the GET response is needed downstream. Do
                            # not store every method's body in the event row:
                            # that is how a single hostile response turns into
                            # a multi-megabyte SQLite row.
                            body = ""
                            truncated = False
                            if method == "GET":
                                body, truncated = await self._read_text_limited(response)

                            results[method] = {
                                "status_code": response.status,
                                "headers": dict(response.headers),
                                "content_type": response.content_type,
                                "content_length": response.content_length,
                                "server": response.headers.get('Server', 'Unknown'),
                                "final_url": str(response.url),
                            }

                            # Store capped HTML content for downstream phases.
                            if method == "GET" and response.content_type and 'text/html' in response.content_type:
                                html_content = body

                            # Extract key findings
                            if method == "GET":
                                self._analyze_response(response, url)

                    except aiohttp.ClientError as e:
                        results[method] = {"error": str(e)}
                    except Exception as e:
                        results[method] = {"error": str(e)}

            return {
                "methods": list(results.keys()),
                "status_codes": {m: r.get("status_code") for m, r in results.items() if "status_code" in r},
                "redirects": redirects,
                "server_info": self._extract_server_info(results),
                "detailed_results": results,
                "html_content": html_content,
                "html_truncated": truncated,
                "status": "completed"
            }

        except Exception as e:
            return {
                "methods": [],
                "status_codes": {},
                "redirects": [],
                "server_info": {},
                "status": "failed",
                "error": str(e)
            }

    def _normalize_url(self, url: str) -> str:
        """Ensure URL has a proper scheme."""
        if not url.startswith(('http://', 'https://')):
            return f"http://{url}"
        return url

    def _extract_server_info(self, results: Dict) -> Dict[str, Any]:
        """Extract server technology information from responses."""
        server_info = {}

        for method, result in results.items():
            if isinstance(result, dict) and "headers" in result:
                headers = result["headers"]

                if "Server" in headers:
                    server_info["server_header"] = headers["Server"]

                if "X-Powered-By" in headers:
                    server_info["powered_by"] = headers["X-Powered-By"]

                if "Via" in headers:
                    server_info["via"] = headers["Via"]

        return server_info

    def _analyze_response(self, response: aiohttp.ClientResponse, url: str):
        """Analyze HTTP response for findings."""
        headers = dict(response.headers)

        # Server identification
        if "Server" in headers:
            self.add_finding(
                finding_type="server_identification",
                title="Web Server Identified",
                severity="info",
                description=f"Server header reveals: {headers['Server']}",
                evidence=headers['Server'],
                metadata={"header": "Server", "value": headers['Server']}
            )

        # Technology disclosure
        if "X-Powered-By" in headers:
            self.add_finding(
                finding_type="technology_disclosure",
                title="Technology Disclosure via X-Powered-By",
                severity="low",
                description=f"X-Powered-By header reveals: {headers['X-Powered-By']}",
                evidence=headers['X-Powered-By'],
                remediation="Consider removing X-Powered-By header to reduce information disclosure"
            )

        # Interesting status codes
        status = response.status
        if status == 403:
            self.add_finding(
                finding_type="access_control",
                title="Forbidden Response Detected",
                severity="info",
                description="Resource requires authentication or is access-controlled",
                location=url,
                evidence=f"Status code: {status}"
            )
        elif status == 500:
            self.add_finding(
                finding_type="server_error",
                title="Internal Server Error",
                severity="medium",
                description="Server returned 500 error, may indicate misconfiguration or vulnerability",
                location=url,
                evidence=f"Status code: {status}"
            )
