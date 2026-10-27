"""
Leadline - Security Headers Analysis Phase
Phase 6: Analyze HTTP security headers and identify missing controls

A missing security header is a hardening gap, not a vulnerability. This
phase deliberately reports low/info severities and labels its score as
indicative so a report does not imply that an absent header is exploitable
on its own.
"""
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import aiohttp

from app.recon.base import BaseReconPhase
from app.config import settings


class SecurityHeadersPhase(BaseReconPhase):
    """Security Headers Analysis reconnaissance phase."""

    name = "security_headers"
    order = 8
    description = "Security header analysis and missing control detection"

    # Defense-in-depth headers worth recording. X-XSS-Protection is
    # intentionally absent: it is obsolete, ignored by modern browsers, and
    # can introduce issues of its own. Cache-Control/Pragma are caching
    # directives, not security headers, so they do not belong here either.
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "recommended": "default-src 'self'",
            "severity": "low",
            "description": "Restricts which sources can load scripts, styles, frames, and other resources",
        },
        "Strict-Transport-Security": {
            "recommended": "max-age=31536000; includeSubDomains",
            "severity": "low",
            "description": "Tells browsers to use HTTPS for future requests (HTTPS targets only)",
        },
        "X-Content-Type-Options": {
            "recommended": "nosniff",
            "severity": "low",
            "description": "Prevents MIME type sniffing",
        },
        "X-Frame-Options": {
            "recommended": "DENY or SAMEORIGIN",
            "severity": "low",
            "description": "Prevents clickjacking (or use CSP frame-ancestors)",
        },
        "Referrer-Policy": {
            "recommended": "strict-origin-when-cross-origin",
            "severity": "info",
            "description": "Controls referrer information leakage",
        },
        "Permissions-Policy": {
            "recommended": "geolocation=(), microphone=(), camera=()",
            "severity": "info",
            "description": "Controls access to browser features",
        },
    }

    # Relative weights for the indicative score only.
    WEIGHTS = {
        "Content-Security-Policy": 3,
        "Strict-Transport-Security": 2,
        "X-Content-Type-Options": 1,
        "X-Frame-Options": 2,
        "Referrer-Policy": 1,
        "Permissions-Policy": 1,
    }

    async def execute(self) -> Dict[str, Any]:
        """Execute security headers analysis."""
        url = self.target_url if "://" in self.target_url else f"http://{self.target_url}"

        present_headers: List[Dict[str, Any]] = []
        missing_headers: List[Dict[str, Any]] = []
        issues: List[Dict[str, Any]] = []
        not_applicable: List[Dict[str, Any]] = []

        headers = self._get_headers()
        timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)

        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            try:
                async with session.get(url) as response:
                    # aiohttp follows redirects by default; judge HSTS against
                    # the final scheme, not the one we typed in.
                    final_scheme = urlparse(str(response.url)).scheme
                    response_headers = {
                        name.lower(): value for name, value in response.headers.items()
                    }
                    csp_value = response_headers.get("content-security-policy", "")

                    for header_name, header_info in self.SECURITY_HEADERS.items():
                        header_key = header_name.lower()
                        found_value = response_headers.get(header_key)

                        # HSTS is only meaningful once the response is HTTPS.
                        if header_key == "strict-transport-security" and final_scheme != "https":
                            not_applicable.append({
                                "name": header_name,
                                "reason": "Target is served over HTTP; HSTS has no effect until HTTPS is enabled.",
                            })
                            continue

                        # CSP frame-ancestors supersedes X-Frame-Options.
                        if (
                            header_key == "x-frame-options"
                            and not found_value
                            and "frame-ancestors" in csp_value.lower()
                        ):
                            present_headers.append({
                                "name": header_name,
                                "value": "covered by Content-Security-Policy frame-ancestors",
                                "recommended": header_info["recommended"],
                                "properly_configured": True,
                            })
                            continue

                        if found_value:
                            properly_configured = self._check_header_value(header_name, found_value)
                            present_headers.append({
                                "name": header_name,
                                "value": found_value,
                                "recommended": header_info["recommended"],
                                "properly_configured": properly_configured,
                            })
                            if not properly_configured:
                                issues.append({
                                    "header": header_name,
                                    "issue": "Improperly configured",
                                    "current_value": found_value,
                                    "recommended": header_info["recommended"],
                                    "severity": header_info["severity"],
                                })
                                self.add_finding(
                                    finding_type="misconfigured_header",
                                    title=f"Misconfigured Security Header: {header_name}",
                                    severity=header_info["severity"],
                                    description=(
                                        f"{header_name} is present but its value may not provide "
                                        "the intended protection."
                                    ),
                                    evidence=(
                                        f"Current: {found_value}; "
                                        f"Recommended: {header_info['recommended']}"
                                    ),
                                    remediation=f"Set {header_name} to: {header_info['recommended']}",
                                )
                        else:
                            missing_headers.append({
                                "name": header_name,
                                "severity": header_info["severity"],
                                "description": header_info["description"],
                                "recommended": header_info["recommended"],
                            })
                            issues.append({
                                "header": header_name,
                                "issue": "Missing",
                                "severity": header_info["severity"],
                                "recommended": header_info["recommended"],
                            })
                            self.add_finding(
                                finding_type="missing_security_header",
                                title=f"Missing Security Header: {header_name}",
                                severity=header_info["severity"],
                                description=header_info["description"],
                                evidence=f"Header {header_name} was not present in the response",
                                remediation=(
                                    f"Consider adding {header_name} with a value appropriate "
                                    f"for the application (example: {header_info['recommended']})."
                                ),
                            )
            except Exception as e:
                return {
                    "present_headers": [],
                    "missing_headers": [],
                    "issues": [{"error": str(e)}],
                    "status": "failed",
                }

        low_missing = len([h for h in missing_headers if h["severity"] == "low"])
        info_missing = len([h for h in missing_headers if h["severity"] == "info"])

        return {
            "present_headers": present_headers,
            "present_count": len(present_headers),
            "missing_headers": missing_headers,
            "missing_count": len(missing_headers),
            "issues": issues,
            "issue_count": len(issues),
            "not_applicable": not_applicable,
            "low_severity_issues": low_missing,
            "info_severity_issues": info_missing,
            "security_score": self._calculate_security_score(present_headers, not_applicable),
            "score_note": (
                "Indicative hardening score only. A missing header is not a "
                "vulnerability, and a present header is not proof of correct "
                "configuration."
            ),
            "status": "completed",
        }

    def _check_header_value(self, header_name: str, value: str) -> bool:
        """Check whether a header value plausibly enforces the control.

        This is a heuristic, not a browser-grade policy parser. It is
        intentionally conservative about calling a header "improper".
        """
        value_lower = value.lower()

        if header_name == "Strict-Transport-Security":
            match = re.search(r"max-age\s*=\s*(\d+)", value_lower)
            return bool(match) and int(match.group(1)) > 0

        if header_name == "Content-Security-Policy":
            return bool(value.strip())

        if header_name == "X-Content-Type-Options":
            return "nosniff" in value_lower

        if header_name == "X-Frame-Options":
            return "deny" in value_lower or "sameorigin" in value_lower

        if header_name == "Referrer-Policy":
            valid_policies = (
                "no-referrer",
                "no-referrer-when-downgrade",
                "origin",
                "origin-when-cross-origin",
                "same-origin",
                "strict-origin",
                "strict-origin-when-cross-origin",
                "unsafe-url",
            )
            return any(policy in value_lower for policy in valid_policies)

        if header_name == "Permissions-Policy":
            return bool(value.strip())

        return True

    def _calculate_security_score(self, present: List, not_applicable: Optional[List] = None) -> int:
        """Indicative 0-100 hardening score for the headers we can judge.

        Headers marked not-applicable (for example HSTS on a plain-HTTP
        target) are removed from the denominator instead of counting as
        failures.
        """
        excluded = {item.get("name") for item in (not_applicable or [])}
        applicable_weight = sum(
            weight for name, weight in self.WEIGHTS.items() if name not in excluded
        )
        earned = 0
        for header in present:
            weight = self.WEIGHTS.get(header.get("name"), 0)
            earned += weight if header.get("properly_configured") else weight / 2
        if applicable_weight == 0:
            return 0
        return min(100, int((earned / applicable_weight) * 100))
