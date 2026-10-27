"""
Leadline - DNS Discovery Phase
Phase 1: DNS enumeration and subdomain discovery
"""
import socket
from typing import Dict, Any, List
from urllib.parse import urlparse
from app.recon.base import BaseReconPhase


class DNSDiscoveryPhase(BaseReconPhase):
    """DNS Discovery reconnaissance phase."""

    name = "dns_discovery"
    order = 1
    description = "DNS enumeration and subdomain discovery"

    async def execute(self) -> Dict[str, Any]:
        """Execute DNS discovery."""
        try:
            parsed = urlparse(self.target_url)
            hostname = parsed.hostname or self.target_url

            # Handle IP addresses directly
            if self._is_ip_address(hostname):
                return {
                    "hostname": hostname,
                    "addresses": [hostname],
                    "resolved_from_dns": False,
                    "status": "completed",
                    "message": "Target is an IP address, no DNS resolution needed"
                }

            # Resolve DNS
            addresses = await self._resolve_hostname(hostname)

            result = {
                "hostname": hostname,
                "addresses": addresses,
                "resolved_from_dns": len(addresses) > 0,
                "status": "completed"
            }

            if addresses:
                self.add_finding(
                    finding_type="dns_resolution",
                    title="DNS Resolution Successful",
                    severity="info",
                    description=f"Hostname {hostname} resolved to {len(addresses)} address(es)",
                    evidence=f"Addresses: {', '.join(addresses)}",
                    metadata={"hostname": hostname, "addresses": addresses}
                )
            else:
                self.add_finding(
                    finding_type="dns_resolution",
                    title="DNS Resolution Failed",
                    severity="low",
                    description=f"Could not resolve hostname {hostname}",
                    evidence="No DNS records found"
                )

            return result

        except Exception as e:
            return {
                "hostname": self.target_url,
                "addresses": [],
                "resolved_from_dns": False,
                "status": "failed",
                "error": str(e)
            }

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        return bool(re.match(ip_pattern, hostname)) or bool(re.match(ipv6_pattern, hostname))

    async def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses using asyncio-compatible method."""
        addresses = []
        try:
            # Use asyncio-compatible DNS resolution
            loop = __import__('asyncio').get_event_loop()
            result = await loop.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)

            # Extract unique addresses
            for res in result:
                addr = res[4][0]
                if addr not in addresses:
                    addresses.append(addr)

        except socket.gaierror:
            pass  # DNS resolution failed, return empty list
        except Exception:
            pass  # Other errors, return empty list

        return addresses
