"""
Leadline - Host Intelligence Phase
DNS records (A/AAAA/MX/NS/TXT/CNAME/SOA), reverse DNS, IP<->hostname
resolution in either direction, domain WHOIS, and IP geolocation/ASN/org.

Runs early (order 2) so later phases have a resolved IP available via
context['host_intel']['resolved_ips'].
"""
import asyncio
import ipaddress
import socket
from typing import Dict, Any, List, Optional

from app.recon.base import BaseReconPhase
from app.config import settings


# Hardcoded fallback for the most common TLDs so a normal .com/.net/.org/etc
# lookup doesn't depend on the IANA referral succeeding. Anything not listed
# here goes through _whois_lookup's IANA-referral path instead.
KNOWN_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com",
    "org": "whois.pir.org", "io": "whois.nic.io", "co": "whois.nic.co",
    "dev": "whois.nic.google", "app": "whois.nic.google", "info": "whois.afilias.net",
    "biz": "whois.nic.biz", "us": "whois.nic.us", "me": "whois.nic.me",
    "xyz": "whois.nic.xyz", "ai": "whois.nic.ai",
}

WHOIS_FIELD_PREFIXES = {
    "registrar": ["registrar:"],
    "creation_date": ["creation date:", "created:", "registered:", "domain registration date:"],
    "expiration_date": ["registry expiry date:", "expiration date:", "expires:", "registrar registration expiration date:"],
    "updated_date": ["updated date:", "last updated:", "last modified:"],
    "status": ["domain status:", "status:"],
    "org": ["registrant organization:", "org:"],
    "country": ["registrant country:", "country:"],
}


class HostIntelPhase(BaseReconPhase):
    """Host/network intelligence: DNS, reverse DNS, WHOIS, geolocation/ASN."""

    name = "host_intel"
    order = 2
    description = "DNS records, reverse DNS, WHOIS, and IP geolocation/ASN/org"

    async def execute(self) -> Dict[str, Any]:
        host = self._extract_host(self.target_url)
        result: Dict[str, Any] = {"host": host}

        is_ip = self._is_ip_literal(host)
        result["is_ip_input"] = is_ip

        if is_ip:
            result["resolved_ips"] = [host]
            result["dns_records"] = {}
            result["hostnames"] = await self._reverse_dns(host)
            result["whois"] = {"skipped_reason": "input was an IP address, not a domain -- domain WHOIS doesn't apply"}
            result["subdomains"] = {"skipped_reason": "input was an IP address, not a domain"}
            result["dnssec"] = {"skipped_reason": "input was an IP address, not a domain"}
        else:
            dns_records = await self._dns_lookup(host)
            result["dns_records"] = dns_records
            resolved_ips = list(dns_records.get("A", [])) + list(dns_records.get("AAAA", []))
            result["resolved_ips"] = resolved_ips

            hostnames: List[str] = []
            for ip in resolved_ips[:3]:  # cap reverse lookups; a domain can have many A records
                for name in await self._reverse_dns(ip):
                    if name not in hostnames:
                        hostnames.append(name)
            result["hostnames"] = hostnames

            result["whois"] = await self._whois_lookup(host)
            result["subdomains"] = await self._enumerate_subdomains(host)
            result["dnssec"] = await self._check_dnssec(host)

        primary_ip = result["resolved_ips"][0] if result.get("resolved_ips") else None
        result["geolocation"] = (
            await self._geolocate(primary_ip) if primary_ip else {"skipped_reason": "no resolved IP available"}
        )
        result["ip_reputation"] = (
            await self._check_ip_reputation(primary_ip) if primary_ip else {"skipped_reason": "no resolved IP available"}
        )

        self._generate_findings(host, result)
        result["status"] = "completed"
        return result

    # ---------------------------------------------------------------- #

    def _is_ip_literal(self, host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    # ---- DNS ---------------------------------------------------------- #

    async def _dns_lookup(self, domain: str) -> Dict[str, Any]:
        """A/AAAA/MX/NS/TXT/CNAME/SOA lookup via dnspython's async resolver.

        NoAnswer (domain exists, no records of that type -- e.g. no MX on a
        domain that doesn't do email) is expected and not an error; NXDOMAIN
        stops further record-type queries since the domain doesn't exist at
        all. Each record type is isolated in its own try/except so one
        failing type (e.g. a timeout) doesn't take down the others.
        """
        import dns.asyncresolver
        import dns.resolver
        import dns.exception

        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = settings.DNS_TIMEOUT
        resolver.lifetime = settings.DNS_TIMEOUT

        records: Dict[str, Any] = {}
        warnings: List[str] = []

        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                answer = await resolver.resolve(domain, rtype)
                records[rtype] = self._format_records(rtype, answer)
            except dns.resolver.NXDOMAIN:
                records["_error"] = f"NXDOMAIN: '{domain}' does not exist"
                break
            except dns.resolver.NoAnswer:
                records[rtype] = []
            except dns.resolver.NoNameservers as e:
                records[rtype] = []
                warnings.append(f"{rtype}: no nameservers answered ({e})")
            except dns.exception.Timeout:
                records[rtype] = []
                warnings.append(f"{rtype}: lookup timed out")
            except Exception as e:
                records[rtype] = []
                warnings.append(f"{rtype}: {e}")

        if warnings:
            records["_warnings"] = warnings
        return records

    def _format_records(self, rtype: str, answer) -> List[str]:
        out = []
        for item in answer:
            if rtype == "MX":
                out.append(f"{item.preference} {str(item.exchange).rstrip('.')}")
            elif rtype == "TXT":
                out.append(b"".join(item.strings).decode("utf-8", errors="replace"))
            elif rtype == "SOA":
                out.append(
                    f"mname={str(item.mname).rstrip('.')} rname={str(item.rname).rstrip('.')} serial={item.serial}"
                )
            else:
                out.append(str(item).rstrip("."))
        return out

    async def _reverse_dns(self, ip: str) -> List[str]:
        """PTR lookup. Uses stdlib socket.gethostbyaddr (blocking) off the
        event loop rather than dnspython, since it's a single simple lookup
        and avoids an extra dnspython PTR-query code path."""
        try:
            loop = asyncio.get_event_loop()
            hostname, _aliases, _ips = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=settings.DNS_TIMEOUT,
            )
            return [hostname]
        except (socket.herror, socket.gaierror, asyncio.TimeoutError, OSError):
            return []

    # ---- WHOIS ---------------------------------------------------------- #

    async def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        tld = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
        server = KNOWN_WHOIS_SERVERS.get(tld, "whois.iana.org")
        hops = [server]
        try:
            raw = await self._whois_query(domain, server)
            referral = self._extract_referral(raw)
            if referral and referral.lower() != server.lower():
                try:
                    raw = await self._whois_query(domain, referral)
                    hops.append(referral)
                except Exception as e:
                    # Referral hop failed -- still return what the first hop gave us
                    return {
                        "queried_servers": hops,
                        "raw": raw[:4000],
                        "parsed": self._parse_whois(raw),
                        "warning": f"referral to {referral} failed: {e}",
                    }
            return {"queried_servers": hops, "raw": raw[:4000], "parsed": self._parse_whois(raw)}
        except Exception as e:
            return {"error": str(e), "queried_servers": hops}

    async def _whois_query(self, domain: str, server: str) -> str:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=settings.WHOIS_TIMEOUT
        )
        try:
            writer.write(f"{domain}\r\n".encode())
            await writer.drain()
            chunks = []
            total = 0
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=settings.WHOIS_TIMEOUT)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 65536:  # some servers stream more than needed; cap it
                    break
            return b"".join(chunks).decode("utf-8", errors="replace")
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _extract_referral(self, raw: str) -> Optional[str]:
        for line in raw.splitlines():
            lower = line.strip().lower()
            for prefix in ("refer:", "whois server:", "registrar whois server:"):
                if lower.startswith(prefix):
                    value = line.split(":", 1)[1].strip()
                    if value:
                        return value
        return None

    def _parse_whois(self, raw: str) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        name_servers: List[str] = []
        for line in raw.splitlines():
            stripped = line.strip()
            lower = stripped.lower()
            if lower.startswith("name server:") or lower.startswith("nserver:"):
                value = stripped.split(":", 1)[1].strip()
                if value and value not in name_servers:
                    name_servers.append(value)
                continue
            for field, prefixes in WHOIS_FIELD_PREFIXES.items():
                for prefix in prefixes:
                    if lower.startswith(prefix) and field not in fields:
                        value = stripped.split(":", 1)[1].strip()
                        if value:
                            fields[field] = value
        if name_servers:
            fields["name_servers"] = name_servers
        return fields

    # ---- Geolocation / ASN / org ---------------------------------------- #

    async def _geolocate(self, ip: str) -> Dict[str, Any]:
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return {"skipped_reason": f"'{ip}' is not a valid IP address"}

        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return {"skipped_reason": "private/reserved IP -- not publicly routable, geolocation doesn't apply"}

        config = self._scan_config()
        if config.get("enable_external_lookups") is False:
            return {"skipped_reason": "external lookups disabled for this scan (enable_external_lookups=False)"}

        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=settings.GEOIP_TIMEOUT)
            url = (
                f"http://ip-api.com/json/{ip}"
                "?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
            )
            # Deliberately not using self._get_headers(): that would inject
            # the *target's* custom headers (e.g. an Authorization token
            # meant for the target) into a request to a third-party service,
            # which is both useless there and an unwanted leak of that value.
            headers = {"User-Agent": settings.DEFAULT_USER_AGENT}
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        return {"error": f"geolocation API returned HTTP {response.status}", "source": "ip-api.com"}
                    data = await response.json(content_type=None)
                    if data.get("status") != "success":
                        return {"error": data.get("message", "lookup failed"), "source": "ip-api.com"}
                    return {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "source": "ip-api.com",
                    }
        except Exception as e:
            return {"error": f"geolocation lookup failed: {e}", "source": "ip-api.com"}

    # ---- Subdomain enumeration (certificate transparency) ---------------- #

    async def _enumerate_subdomains(self, domain: str) -> Dict[str, Any]:
        """Passive subdomain enumeration via crt.sh (certificate transparency
        log search). No wordlist brute-forcing -- this only surfaces
        subdomains that have ever had a public TLS certificate issued for
        them, which is a real coverage gap but has zero risk of hammering
        the target itself (it only ever talks to crt.sh)."""
        config = self._scan_config()
        if config.get("enable_external_lookups") is False:
            return {"skipped_reason": "external lookups disabled for this scan (enable_external_lookups=False)"}

        try:
            import aiohttp
            timeout = aiohttp.ClientTimeout(total=settings.GEOIP_TIMEOUT)
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            headers = {"User-Agent": settings.DEFAULT_USER_AGENT}
            async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
                async with session.get(url) as response:
                    if response.status != 200:
                        return {"error": f"crt.sh returned HTTP {response.status}", "source": "crt.sh"}
                    try:
                        entries = await response.json(content_type=None)
                    except Exception:
                        # crt.sh occasionally returns malformed/truncated JSON
                        # under load rather than a clean error status.
                        return {"error": "crt.sh returned unparseable data", "source": "crt.sh"}
                    subdomains = set()
                    for entry in entries or []:
                        name_value = entry.get("name_value", "") if isinstance(entry, dict) else ""
                        for name in name_value.split("\n"):
                            name = name.strip().lower().lstrip("*.")
                            if name and name.endswith(domain.lower()) and name != domain.lower():
                                subdomains.add(name)
                    sorted_subs = sorted(subdomains)
                    return {
                        "count": len(sorted_subs),
                        "subdomains": sorted_subs[:200],  # cap response size
                        "truncated": len(sorted_subs) > 200,
                        "source": "crt.sh",
                    }
        except Exception as e:
            return {"error": f"subdomain enumeration failed: {e}", "source": "crt.sh"}

    # ---- DNSSEC ---------------------------------------------------------- #

    async def _check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Best-effort DNSSEC check: looks for DNSKEY/RRSIG records at the
        domain. This confirms DNSSEC *appears configured* -- it is NOT a
        full cryptographic chain-of-trust validation up to the root, which
        would need to walk and verify signatures at every level. Good
        enough to flag "this domain doesn't seem to use DNSSEC at all",
        not to certify a domain as fully DNSSEC-valid."""
        try:
            import dns.asyncresolver
            import dns.resolver
            import dns.exception

            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT

            has_dnskey = False
            try:
                await resolver.resolve(domain, "DNSKEY")
                has_dnskey = True
            except dns.resolver.NoAnswer:
                pass
            except dns.resolver.NXDOMAIN:
                return {"enabled": False, "note": "domain does not exist"}
            except dns.exception.Timeout:
                return {"enabled": None, "note": "DNSKEY lookup timed out"}

            has_rrsig = False
            try:
                await resolver.resolve(domain, "RRSIG")
                has_rrsig = True
            except (dns.resolver.NoAnswer, dns.exception.Timeout):
                pass
            except Exception:
                pass

            return {
                "enabled": has_dnskey,
                "rrsig_present": has_rrsig,
                "note": "DNSKEY presence checked only -- not a full chain-of-trust validation",
            }
        except Exception as e:
            return {"enabled": None, "error": str(e)}

    # ---- IP reputation ---------------------------------------------------- #

    async def _check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Checks the IP against Spamhaus ZEN, a free, no-API-key DNS-based
        blocklist (DNSBL) that aggregates several Spamhaus lists. A DNSBL
        lookup is just a reversed-octet A-record query -- e.g. 1.2.3.4 is
        checked by querying 4.3.2.1.zen.spamhaus.org -- so it needs no HTTP
        client or API key, only a normal DNS query."""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return {"skipped_reason": f"'{ip}' is not a valid IP address"}

        if ip_obj.version != 4:
            return {"skipped_reason": "Spamhaus ZEN only supports IPv4 lookups"}
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
            return {"skipped_reason": "private/reserved IP -- not publicly routable, reputation doesn't apply"}

        config = self._scan_config()
        if config.get("enable_external_lookups") is False:
            return {"skipped_reason": "external lookups disabled for this scan (enable_external_lookups=False)"}

        # Spamhaus ZEN return codes (127.0.0.x) and what they mean
        RETURN_CODES = {
            "127.0.0.2": "Spamhaus SBL (spam source)", "127.0.0.3": "Spamhaus SBL (spam source)",
            "127.0.0.4": "Spamhaus XBL (compromised host/exploit)", "127.0.0.9": "Spamhaus SBL (malicious)",
            "127.0.0.10": "Spamhaus PBL (should not send mail directly)", "127.0.0.11": "Spamhaus PBL (should not send mail directly)",
        }
        try:
            import dns.asyncresolver
            import dns.resolver
            import dns.exception

            reversed_octets = ".".join(reversed(str(ip_obj).split(".")))
            query_name = f"{reversed_octets}.zen.spamhaus.org"

            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = settings.DNS_TIMEOUT
            resolver.lifetime = settings.DNS_TIMEOUT

            try:
                answer = await resolver.resolve(query_name, "A")
                codes = [str(r) for r in answer]
                reasons = [RETURN_CODES.get(c, f"listed ({c})") for c in codes]
                return {"listed": True, "codes": codes, "reasons": reasons, "source": "Spamhaus ZEN"}
            except dns.resolver.NXDOMAIN:
                return {"listed": False, "source": "Spamhaus ZEN"}
            except dns.exception.Timeout:
                return {"listed": None, "error": "reputation lookup timed out", "source": "Spamhaus ZEN"}
        except Exception as e:
            return {"listed": None, "error": str(e), "source": "Spamhaus ZEN"}

    # ---- Findings ---------------------------------------------------- #

    def _generate_findings(self, host: str, result: Dict[str, Any]):
        geo = result.get("geolocation") or {}
        if geo.get("country"):
            self.add_finding(
                finding_type="host_geolocation", severity="info",
                title=f"Host geolocated to {geo['country']}",
                description=(
                    f"IP geolocation (via {geo.get('source', 'unknown')}) places the resolved IP in "
                    f"{geo.get('city') or 'an unknown city'}, {geo['country']}. "
                    f"ISP/org: {geo.get('isp') or geo.get('org') or 'unknown'}."
                ),
                location=host, evidence=str(geo),
                metadata={"geolocation": geo},
            )

        whois = result.get("whois") or {}
        parsed = whois.get("parsed") if isinstance(whois, dict) else None
        if parsed:
            self.add_finding(
                finding_type="domain_registration", severity="info",
                title="Domain registration (WHOIS) information found",
                description=(
                    f"Registrar: {parsed.get('registrar', 'unknown')}. "
                    f"Created: {parsed.get('creation_date', 'unknown')}. "
                    f"Expires: {parsed.get('expiration_date', 'unknown')}."
                ),
                location=host, evidence=str(parsed)[:1500],
                metadata={"whois": parsed},
            )

        txt_records = (result.get("dns_records") or {}).get("TXT") or []
        if result.get("dns_records") and not result["dns_records"].get("_error"):
            has_spf = any("v=spf1" in t.lower() for t in txt_records)
            has_dmarc = any("v=dmarc1" in t.lower() for t in txt_records)
            if not has_spf or not has_dmarc:
                missing = [n for n, present in (("SPF", has_spf), ("DMARC", has_dmarc)) if not present]
                self.add_finding(
                    finding_type="missing_email_security", severity="low",
                    title=f"Missing {' and '.join(missing)} record(s)",
                    description=(
                        f"No {' or '.join(missing)} TXT record was found for this domain, which can make it "
                        "easier to spoof in phishing emails claiming to be from this domain."
                    ),
                    location=host,
                    remediation="Add SPF and DMARC TXT records to reduce email-spoofing risk.",
                )

        if result.get("is_ip_input") and result.get("hostnames"):
            self.add_finding(
                finding_type="reverse_dns", severity="info",
                title="Reverse DNS resolved for IP input",
                description=f"PTR lookup for {host} resolved to: {', '.join(result['hostnames'])}",
                location=host, evidence=", ".join(result["hostnames"]),
            )

        subdomains = result.get("subdomains") or {}
        if subdomains.get("count"):
            self.add_finding(
                finding_type="subdomains_discovered", severity="info",
                title=f"{subdomains['count']} subdomain(s) found via certificate transparency logs",
                description=(
                    f"crt.sh shows {subdomains['count']} distinct subdomain(s) with a public TLS "
                    "certificate ever issued for them. This only reflects domains that have had a "
                    "cert issued -- it's not a complete enumeration."
                ),
                location=host, evidence=", ".join(subdomains["subdomains"][:30]),
                metadata={"subdomains": subdomains["subdomains"]},
            )

        dnssec = result.get("dnssec") or {}
        if dnssec.get("enabled") is False and not dnssec.get("skipped_reason"):
            self.add_finding(
                finding_type="dnssec_not_enabled", severity="low",
                title="DNSSEC does not appear to be enabled",
                description=(
                    "No DNSKEY record was found for this domain. Without DNSSEC, DNS responses for "
                    "this domain cannot be cryptographically verified, making cache-poisoning/spoofing "
                    "attacks against its resolution easier."
                ),
                location=host,
                remediation="Enable DNSSEC signing at the domain's registrar/DNS provider.",
            )

        reputation = result.get("ip_reputation") or {}
        if reputation.get("listed") is True:
            self.add_finding(
                finding_type="ip_reputation_listed", severity="medium",
                title="Resolved IP is listed on a DNS blocklist (Spamhaus ZEN)",
                description=(
                    f"The IP this domain resolves to is listed: {', '.join(reputation.get('reasons', []))}. "
                    "This may indicate shared/compromised hosting infrastructure, or reflect the "
                    "history of a previous tenant on this IP if it's cloud/shared hosting."
                ),
                location=host, evidence=str(reputation),
                remediation="If this is your own infrastructure, investigate why it's listed and request delisting once resolved.",
            )
