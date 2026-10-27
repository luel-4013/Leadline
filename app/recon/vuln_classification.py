"""
Leadline - Vulnerability Classification Phase
Phase 8: Pattern-based potential vulnerability detection and classification
"""
from typing import Dict, Any, List
from app.recon.base import BaseReconPhase


class VulnClassificationPhase(BaseReconPhase):
    """Vulnerability Classification reconnaissance phase."""

    name = "vuln_classification"
    order = 10
    description = "Pattern-based potential vulnerability identification"

    # Patterns that may indicate security-relevant functionality
    # These are NOT confirmed vulnerabilities, but require manual review
    SUSPICIOUS_PATTERNS = {
        "debug_interface": {
            "patterns": [r'/debug', r'/trace', r'/console', r'/admin.*debug'],
            "severity": "medium",
            "description": "Debug or administrative interface may be publicly accessible"
        },
        "backup_file": {
            "patterns": [r'\.bak$', r'\.old$', r'\.backup$', r'~$'],
            "severity": "low",
            "description": "Potential backup file exposed"
        },
        "config_exposure": {
            "patterns": [r'\.env', r'\.config', r'config\.json', r'settings\.json'],
            "severity": "high",
            "description": "Potential configuration file exposure"
        },
        "version_control": {
            "patterns": [r'/.git', r'/.svn', r'/.hg'],
            "severity": "high",
            "description": "Version control directory may be accessible"
        },
        "test_environment": {
            "patterns": [r'/test', r'/staging', r'/dev', r'/beta'],
            "severity": "low",
            "description": "Test or development environment may be publicly accessible"
        },
        "api_without_auth": {
            "patterns": [r'/api/internal', r'/api/admin', r'/api/debug'],
            "severity": "medium",
            "description": "API endpoint may lack proper authentication"
        },
        "error_page": {
            "patterns": [r'error', r'exception', r'stack trace'],
            "severity": "low",
            "description": "Error page may reveal sensitive information"
        }
    }

    async def execute(self) -> Dict[str, Any]:
        """Execute vulnerability classification based on findings from previous phases."""
        try:
            potential_vulns: List[Dict[str, Any]] = []
            idor_candidates: List[Dict[str, Any]] = []
            exposed_interfaces: List[Dict[str, Any]] = []

            # Collect all findings from previous phases. The pipeline stores
            # every finding produced so far under context['_all_findings'] as
            # each phase completes (this phase's own self.findings is always
            # empty at this point, since it hasn't added any yet).
            all_findings = list(self.context.get('_all_findings', []))

            # Analyze findings for potential vulnerabilities
            for finding in all_findings:
                location = finding.get('location', '')
                evidence = finding.get('evidence', '')

                # Check against suspicious patterns
                for vuln_type, vuln_info in self.SUSPICIOUS_PATTERNS.items():
                    for pattern in vuln_info['patterns']:
                        import re
                        if re.search(pattern, location, re.IGNORECASE) or re.search(pattern, evidence, re.IGNORECASE):
                            vuln_entry = {
                                "type": vuln_type,
                                "severity": vuln_info['severity'],
                                "description": vuln_info['description'],
                                "location": location,
                                "evidence": evidence,
                                "confidence": "low",
                                "requires_manual_review": True
                            }

                            if vuln_entry not in potential_vulns:
                                potential_vulns.append(vuln_entry)
                                self.add_finding(
                                    finding_type="potential_vulnerability",
                                    title=f"Potential Security Issue: {vuln_type.replace('_', ' ').title()}",
                                    severity=vuln_info['severity'],
                                    description=vuln_info['description'],
                                    location=location,
                                    evidence=evidence,
                                    remediation="Manual verification required to confirm this is a security issue",
                                    metadata={"pattern_matched": pattern, "auto_classified": True}
                                )

            # Look for IDOR candidates (parameters with IDs)
            param_results = self.context.get('param_discovery', {})
            url_parameters = param_results.get('url_parameters', [])

            for param in url_parameters:
                param_name = param.get('name', '').lower()
                if any(id_pattern in param_name for id_pattern in ['id', 'uid', 'user_id', 'order_id', 'file_id']):
                    idor_candidates.append({
                        "parameter": param.get('name'),
                        "location": param.get('location', ''),
                        "type": "idor_candidate",
                        "description": f"Parameter '{param.get('name')}' may be susceptible to IDOR attacks",
                        "confidence": "low",
                        "requires_manual_review": True
                    })
                    self.add_finding(
                        finding_type="idor_candidate",
                        title="Potential IDOR Vector",
                        severity="medium",
                        description=f"Parameter '{param.get('name')}' accepts object identifiers",
                        location=param.get('location', ''),
                        evidence=f"Parameter: {param.get('name')}",
                        remediation="Verify proper authorization checks are in place for object access",
                        metadata={"parameter": param.get('name')}
                    )

            # Check for exposed interfaces from API discovery
            api_results = self.context.get('api_discovery', {})
            api_endpoints = api_results.get('api_endpoints', [])

            for endpoint in api_endpoints:
                url = endpoint.get('url', '')
                source = endpoint.get('source', '')

                # Flag admin/internal APIs
                if any(admin_pattern in url.lower() for admin_pattern in ['/admin', '/internal', '/management']):
                    exposed_interfaces.append({
                        "url": url,
                        "type": "administrative_interface",
                        "source": source,
                        "severity": "medium",
                        "requires_manual_review": True
                    })

            # Check security headers results
            security_results = self.context.get('security_headers', {})
            missing_headers = security_results.get('missing_headers', [])

            for header in missing_headers:
                if header.get('severity') in ['high', 'medium']:
                    potential_vulns.append({
                        "type": "missing_security_header",
                        "severity": header.get('severity', 'low'),
                        "description": f"Missing security header: {header.get('name')}",
                        "location": self.target_url,
                        "confidence": "high",
                        "requires_manual_review": False
                    })

            return {
                "potential_vulns": potential_vulns,
                "vuln_count": len(potential_vulns),
                "idor_candidates": idor_candidates,
                "idor_count": len(idor_candidates),
                "exposed_interfaces": exposed_interfaces,
                "interface_count": len(exposed_interfaces),
                "high_severity_count": len([v for v in potential_vulns if v.get('severity') == 'high']),
                "medium_severity_count": len([v for v in potential_vulns if v.get('severity') == 'medium']),
                "status": "completed",
                "note": "All classifications are preliminary and require manual verification"
            }

        except Exception as e:
            return {
                "potential_vulns": [],
                "idor_candidates": [],
                "exposed_interfaces": [],
                "status": "failed",
                "error": str(e)
            }
