"""
Leadline - Technology Detection Phase
Phase 3: Identify web technologies, frameworks, servers from response patterns
"""
import re
from typing import Dict, Any, List
from app.recon.base import BaseReconPhase


class TechDetectionPhase(BaseReconPhase):
    """Technology Detection reconnaissance phase."""

    name = "tech_detection"
    order = 5
    description = "Identify web technologies, frameworks, and servers"

    # Technology signatures: (pattern, technology_name, confidence)
    TECH_SIGNATURES = [
        # Server headers
        (r'nginx', 'Nginx', 'high'),
        (r'apache', 'Apache', 'high'),
        (r'iis', 'Microsoft IIS', 'high'),
        (r'openresty', 'OpenResty', 'high'),

        # Frameworks
        (r'django', 'Django', 'high'),
        (r'rails', 'Ruby on Rails', 'high'),
        (r'laravel', 'Laravel', 'high'),
        (r'express', 'Express.js', 'medium'),
        (r'flask', 'Flask', 'medium'),
        (r'react', 'React', 'medium'),
        (r'vue\.js', 'Vue.js', 'medium'),
        (r'angular', 'Angular', 'medium'),
        (r'next\.js', 'Next.js', 'medium'),
        (r'nuxt', 'Nuxt.js', 'medium'),

        # CMS
        (r'wordpress', 'WordPress', 'high'),
        (r'drupal', 'Drupal', 'high'),
        (r'joomla', 'Joomla', 'high'),

        # Programming languages
        (r'php', 'PHP', 'medium'),
        (r'python', 'Python', 'low'),
        (r'ruby', 'Ruby', 'low'),

        # Web servers
        (r'tomcat', 'Apache Tomcat', 'high'),
        (r'jetty', 'Jetty', 'high'),
        (r'gunicorn', 'Gunicorn', 'high'),
        (r'uwsgi', 'uWSGI', 'high'),

        # CDN/Cloud
        (r'cloudflare', 'Cloudflare', 'high'),
        (r'awselb', 'AWS ELB', 'high'),
        (r'google cloud', 'Google Cloud', 'medium'),
        (r'azure', 'Microsoft Azure', 'medium'),

        # Path patterns
        (r'/wp-content/', 'WordPress', 'high'),
        (r'/wp-includes/', 'WordPress', 'high'),
        (r'/sites/default/files/', 'Drupal', 'high'),
        (r'/media/jui/', 'Joomla', 'high'),
        (r'/static/admin/', 'Django Admin', 'high'),
        (r'/_next/static/', 'Next.js', 'high'),
        (r'/nuxt/', 'Nuxt.js', 'medium'),
    ]

    # CDN/WAF fingerprinting by *header name* (not value) -- these headers
    # are added by the edge/proxy layer itself and are a much more reliable
    # signal than spotting a provider's name inside some other header's
    # value. Matters beyond "what tech is used": if a CDN/WAF sits in
    # front of the target, whatever IP port_scan.py scanned is very likely
    # the edge node, not the origin server.
    CDN_WAF_HEADER_SIGNATURES = {
        "cf-ray": "Cloudflare", "cf-cache-status": "Cloudflare", "cf-request-id": "Cloudflare",
        "x-amz-cf-id": "Amazon CloudFront", "x-amz-cf-pop": "Amazon CloudFront",
        "x-akamai-transformed": "Akamai", "akamai-x-cache": "Akamai",
        "x-cdn": "Generic CDN (x-cdn header)",
        "x-sucuri-id": "Sucuri (WAF)", "x-sucuri-cache": "Sucuri (WAF)",
        "x-fastly-request-id": "Fastly", "fastly-debug-digest": "Fastly",
        "x-azure-ref": "Azure Front Door/CDN", "x-msedge-ref": "Azure Front Door",
        "x-vercel-id": "Vercel", "x-vercel-cache": "Vercel",
        "x-cache": "Generic caching proxy/CDN (x-cache header)",
        "x-datadome": "DataDome (WAF)", "x-akamai-waf-status": "Akamai (WAF)",
        "x-incapsula-caused-issue": "Imperva Incapsula (WAF)", "x-iinfo": "Imperva Incapsula (WAF)",
    }

    async def execute(self) -> Dict[str, Any]:
        """Execute technology detection."""
        try:
            technologies: List[Dict[str, str]] = []
            detected_names = set()

            # Analyze HTTP fingerprinting results if available from previous phase
            http_results = self.context.get('http_fingerprinting', {}) if hasattr(self, 'context') else {}
            server_info = http_results.get('server_info', {})
            detailed_results = http_results.get('detailed_results', {})

            # Check server header
            if 'server_header' in server_info:
                server = server_info['server_header'].lower()
                for pattern, tech, confidence in self.TECH_SIGNATURES:
                    if re.search(pattern, server, re.IGNORECASE):
                        if tech not in detected_names:
                            technologies.append({
                                "technology": tech,
                                "confidence": confidence,
                                "evidence": f"Server header: {server_info['server_header']}",
                                "source": "server_header"
                            })
                            detected_names.add(tech)

            # Check X-Powered-By
            if 'powered_by' in server_info:
                powered_by = server_info['powered_by'].lower()
                for pattern, tech, confidence in self.TECH_SIGNATURES:
                    if re.search(pattern, powered_by, re.IGNORECASE):
                        if tech not in detected_names:
                            technologies.append({
                                "technology": tech,
                                "confidence": confidence,
                                "evidence": f"X-Powered-By: {server_info['powered_by']}",
                                "source": "x_powered_by"
                            })
                            detected_names.add(tech)

            # Check detailed response bodies if available
            for method, result in detailed_results.items():
                if isinstance(result, dict) and 'headers' in result:
                    headers = result.get('headers', {})

                    # Check various headers
                    for header_name, header_value in headers.items():
                        for pattern, tech, confidence in self.TECH_SIGNATURES:
                            if re.search(pattern, str(header_value), re.IGNORECASE):
                                if tech not in detected_names:
                                    technologies.append({
                                        "technology": tech,
                                        "confidence": confidence,
                                        "evidence": f"{header_name}: {header_value}",
                                        "source": f"http_header_{header_name.lower()}"
                                    })
                                    detected_names.add(tech)

            # CDN/WAF detection by header *name* -- check every header seen
            # across every HTTP method http_fingerprinting probed.
            cdn_waf_detected: Dict[str, List[str]] = {}  # provider -> matching header names
            all_headers_seen: Dict[str, str] = dict(server_info) if isinstance(server_info, dict) else {}
            for method, result in detailed_results.items():
                if isinstance(result, dict) and 'headers' in result:
                    all_headers_seen.update({k.lower(): v for k, v in (result.get('headers') or {}).items()})
            for header_name, value in all_headers_seen.items():
                provider = self.CDN_WAF_HEADER_SIGNATURES.get(header_name.lower())
                if provider:
                    cdn_waf_detected.setdefault(provider, []).append(header_name)

            for provider, matched_headers in cdn_waf_detected.items():
                self.add_finding(
                    finding_type="cdn_waf_detected",
                    title=f"CDN/WAF detected: {provider}",
                    severity="info",
                    description=(
                        f"Response headers indicate traffic passes through {provider}. "
                        "The IP/ports scanned elsewhere in this report are likely the edge "
                        "node, not necessarily the origin server."
                    ),
                    evidence=f"Headers: {', '.join(matched_headers)}",
                    metadata={"provider": provider, "matched_headers": matched_headers},
                )

            # Add findings for detected technologies
            for tech in technologies:
                self.add_finding(
                    finding_type="technology_detected",
                    title=f"Technology Detected: {tech['technology']}",
                    severity="info",
                    description=f"Detected {tech['technology']} with {tech['confidence']} confidence",
                    evidence=tech['evidence'],
                    metadata={"technology": tech['technology'], "confidence": tech['confidence'], "source": tech['source']}
                )

            return {
                "technologies": technologies,
                "technology_count": len(technologies),
                "cdn_waf": cdn_waf_detected,
                "status": "completed"
            }

        except Exception as e:
            return {
                "technologies": [],
                "technology_count": 0,
                "cdn_waf": {},
                "status": "failed",
                "error": str(e)
            }
