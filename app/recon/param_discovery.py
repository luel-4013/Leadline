"""
Leadline - Parameter Discovery Phase
Phase 5: URL parameter and form field discovery from HTML and JS
"""
import re
import aiohttp
from typing import Dict, Any, List, Set
from urllib.parse import urlparse, parse_qs, urljoin
from app.recon.base import BaseReconPhase
from app.config import settings


class ParamDiscoveryPhase(BaseReconPhase):
    """Parameter Discovery reconnaissance phase."""

    name = "param_discovery"
    order = 7
    description = "URL parameter and form field discovery"

    # Suspicious parameter names that may indicate security-relevant functionality
    SUSPICIOUS_PARAM_PATTERNS = [
        r'id$', r'uid$', r'user_id$', r'userid$',
        r'file$', r'path$', r'dir$',
        r'url$', r'redirect$', r'next$',
        r'cmd$', r'exec$', r'command$',
        r'query$', r'sql$',
        r'page$', r'p$',
        r'sort$', r'order$',
        r'filter$', r'search$', r'q$',
    ]

    async def execute(self) -> Dict[str, Any]:
        """Execute parameter discovery."""
        try:
            url_parameters: List[Dict[str, Any]] = []
            form_fields: List[Dict[str, Any]] = []
            suspicious_params: List[Dict[str, Any]] = []
            found_params: Set[str] = set()

            # Get base URL
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Fetch the main page to analyze
            headers = self._get_headers()
            timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)

            async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
                try:
                    async with session.get(self.target_url) as response:
                        if response.status == 200:
                            html_content, _truncated = await self._read_text_limited(response)

                            # Extract parameters from URLs in HTML
                            url_params = self._extract_url_parameters(html_content, base_url)
                            for param in url_params:
                                key = f"{param['location']}:{param['name']}"
                                if key not in found_params:
                                    found_params.add(key)
                                    url_parameters.append(param)

                                    # Check if suspicious
                                    if self._is_suspicious_param(param['name']):
                                        suspicious_params.append({
                                            **param,
                                            "reason": "Potentially sensitive parameter name"
                                        })
                                        self.add_finding(
                                            finding_type="suspicious_parameter",
                                            title="Suspicious Parameter Discovered",
                                            severity="medium",
                                            description=f"Parameter '{param['name']}' may be security-sensitive",
                                            location=param['location'],
                                            evidence=f"Parameter: {param['name']}={param.get('example_value', '')}",
                                            metadata={"parameter": param['name'], "type": "url_parameter"}
                                        )

                            # Extract form fields
                            forms = self._extract_form_fields(html_content)
                            for form in forms:
                                form_fields.append(form)
                                self.add_finding(
                                    finding_type="form_field",
                                    title="Form Field Discovered",
                                    severity="info",
                                    description=f"Form input field '{form['name']}' found",
                                    location=form.get('action', '/'),
                                    evidence=f"Field: {form['name']} (type: {form['type']})",
                                    metadata={"field_name": form['name'], "field_type": form['type']}
                                )

                                # Check for suspicious form fields
                                if self._is_suspicious_param(form['name']):
                                    suspicious_params.append({
                                        "name": form['name'],
                                        "location": form.get('action', '/'),
                                        "type": "form_field",
                                        "reason": "Potentially sensitive form field"
                                    })

                except Exception:
                    pass

            # Also check previous phase results for parameters
            js_results = self.context.get('js_analysis', {}) if hasattr(self, 'context') else {}
            js_params = js_results.get('parameters', [])
            for param_name in js_params:
                if param_name not in [p['name'] for p in url_parameters]:
                    url_parameters.append({
                        "name": param_name,
                        "location": "javascript",
                        "type": "js_reference",
                        "evidence": "Referenced in JavaScript code"
                    })

                    if self._is_suspicious_param(param_name):
                        suspicious_params.append({
                            "name": param_name,
                            "location": "javascript",
                            "type": "js_reference",
                            "reason": "Suspicious parameter referenced in JavaScript"
                        })

            return {
                "url_parameters": url_parameters,
                "parameter_count": len(url_parameters),
                "form_fields": form_fields,
                "form_field_count": len(form_fields),
                "suspicious_params": suspicious_params,
                "suspicious_count": len(suspicious_params),
                "status": "completed"
            }

        except Exception as e:
            return {
                "url_parameters": [],
                "form_fields": [],
                "suspicious_params": [],
                "status": "failed",
                "error": str(e)
            }

    def _extract_url_parameters(self, html_content: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract parameters from URLs in HTML content."""
        params = []

        # Find all href attributes with query strings
        href_pattern = r'href=[\'"]([^\'"]*\?[^\'"]*)[\'"]'
        matches = re.findall(href_pattern, html_content, re.IGNORECASE)

        for href in matches:
            url = href if href.startswith('http') else urljoin(base_url, href)
            parsed = urlparse(url)

            # Extract query parameters
            query_params = parse_qs(parsed.query)
            for param_name, values in query_params.items():
                params.append({
                    "name": param_name,
                    "location": parsed.path or '/',
                    "type": "query_parameter",
                    "example_value": values[0] if values else '',
                    "full_url": url
                })

        # Also find action attributes in forms
        action_pattern = r'action=[\'"]([^\'"]*\?[^\'"]*)[\'"]'
        matches = re.findall(action_pattern, html_content, re.IGNORECASE)

        for action in matches:
            parsed = urlparse(action if action.startswith('http') else urljoin(base_url, action))
            query_params = parse_qs(parsed.query)
            for param_name, values in query_params.items():
                params.append({
                    "name": param_name,
                    "location": parsed.path or '/',
                    "type": "form_action_parameter",
                    "example_value": values[0] if values else ''
                })

        return params

    def _extract_form_fields(self, html_content: str) -> List[Dict[str, Any]]:
        """Extract form input fields from HTML content."""
        fields = []

        # Find all form tags
        form_pattern = r'<form[^>]*>(.*?)</form>'
        forms = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)

        for form_content in forms:
            # Extract action
            action_match = re.search(r'<form[^>]*action=[\'"]([^\'"]+)[\'"]', form_content, re.IGNORECASE)
            action = action_match.group(1) if action_match else '/'

            # Find all input fields
            input_pattern = r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*/?>'
            inputs = re.findall(input_pattern, form_content, re.IGNORECASE)

            for input_name in inputs:
                # Try to get type
                type_match = re.search(rf'<input[^>]*name=[\'"]{re.escape(input_name)}[\'"][^>]*type=[\'"]([^\'"]+)[\'"]', form_content, re.IGNORECASE)
                field_type = type_match.group(1) if type_match else 'text'

                fields.append({
                    "name": input_name,
                    "type": field_type,
                    "action": action
                })

        # Also find standalone inputs not in forms
        standalone_pattern = r'<input[^>]*name=[\'"]([^\'"]+)[\'"][^>]*type=[\'"]([^\'"]+)[\'"][^>]*>'
        matches = re.findall(standalone_pattern, html_content, re.IGNORECASE)
        for name, field_type in matches:
            if not any(f['name'] == name for f in fields):
                fields.append({
                    "name": name,
                    "type": field_type,
                    "action": '/'
                })

        return fields

    def _is_suspicious_param(self, param_name: str) -> bool:
        """Check if a parameter name is potentially suspicious."""
        param_lower = param_name.lower()
        for pattern in self.SUSPICIOUS_PARAM_PATTERNS:
            if re.search(pattern, param_lower, re.IGNORECASE):
                return True
        return False
