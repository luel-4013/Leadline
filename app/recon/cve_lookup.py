"""
Leadline - CVE Lookup Phase
Correlates detected technologies and service versions (from tech_detection
and port_scan) against the National Vulnerability Database (NVD).

Two matching modes are used:

1. **CPE + version range (preferred).** Leadline resolves the detected
   product to a CPE 2.3 name, asks NVD for CVEs associated with that product,
   then checks each CVE's `cpeMatch` version ranges against the observed
   version. Matches are marked `applicability_verified: true` and include the
   matched CPE and range.
2. **NVD keyword fallback.** If no CPE can be resolved, the old keyword
   search is used and every result is marked `applicability_verified: false`
   so it is never presented as confirmed.

This phase does not fetch, generate, or embed exploit code. ExploitDB is a
plain search link for the analyst to follow.
"""
import asyncio
import re
import time
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlencode

import aiohttp

from app.recon.base import BaseReconPhase
from app.config import settings


NVD_CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Matches "name/version", "name_version", or "name version" patterns
# commonly seen in banners and Server headers, e.g. "nginx/1.24.0",
# "OpenSSH_8.9p1", "220 ProFTPD 1.3.5 Server". Deliberately requires the
# version to start with a digit so plain "Server: cloudflare" (no version)
# correctly doesn't match anything.
VERSION_PATTERN = re.compile(
    r'([A-Za-z][A-Za-z0-9._-]{1,40}?)[/_ ](\d+(?:\.\d+){1,3}[A-Za-z0-9]*)'
)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

# SSH banners follow a fixed "SSH-<protoversion>-<softwareversion>" format
# (RFC 4253). Without stripping this prefix first, the general pattern
# above swallows it into the product-name group -- there's no real
# separator (/, _, space) between "SSH-2.0-" and the actual product name,
# since hyphens/digits/dots are all valid product-name characters -- so
# "SSH-2.0-OpenSSH_7.4" would extract product="SSH-2.0-OpenSSH" instead of
# the much more NVD-search-friendly "OpenSSH".
SSH_BANNER_PREFIX = re.compile(r'^SSH-\d+\.\d+-')

# Known product -> CPE 2.3 prefix mappings for products that appear often in
# Server/X-Powered-By banners. A wrong alias is worse than no alias, so this
# list stays deliberately small; unknown products fall back to the NVD CPE
# keyword search. Keys are normalized (lowercase, punctuation -> spaces).
CPE_ALIASES: Dict[str, str] = {
    "nginx": "cpe:2.3:a:nginx:nginx",
    "openresty": "cpe:2.3:a:openresty:openresty",
    "apache": "cpe:2.3:a:apache:http_server",
    "apache httpd": "cpe:2.3:a:apache:http_server",
    "apache http server": "cpe:2.3:a:apache:http_server",
    "httpd": "cpe:2.3:a:apache:http_server",
    "apache tomcat": "cpe:2.3:a:apache:tomcat",
    "apache coyote": "cpe:2.3:a:apache:tomcat",
    "tomcat": "cpe:2.3:a:apache:tomcat",
    "microsoft iis": "cpe:2.3:a:microsoft:internet_information_services",
    "iis": "cpe:2.3:a:microsoft:internet_information_services",
    "openssh": "cpe:2.3:a:openbsd:openssh",
    "openssl": "cpe:2.3:a:openssl:openssl",
    "php": "cpe:2.3:a:php:php",
    "django": "cpe:2.3:a:djangoproject:django",
    "flask": "cpe:2.3:a:palletsprojects:flask",
    "express": "cpe:2.3:a:expressjs:express",
    "express.js": "cpe:2.3:a:expressjs:express",
    "next.js": "cpe:2.3:a:vercel:next.js",
    "react": "cpe:2.3:a:facebook:react",
    "vue.js": "cpe:2.3:a:vuejs:vue.js",
    "angular": "cpe:2.3:a:angular:angular",
    "jquery": "cpe:2.3:a:jquery:jquery",
    "wordpress": "cpe:2.3:a:wordpress:wordpress",
    "drupal": "cpe:2.3:a:drupal:drupal",
    "joomla": "cpe:2.3:a:joomla:joomla",
    "laravel": "cpe:2.3:a:laravel:laravel",
    "ruby on rails": "cpe:2.3:a:rubyonrails:rails",
    "rails": "cpe:2.3:a:rubyonrails:rails",
    "jetty": "cpe:2.3:a:eclipse:jetty",
    "gunicorn": "cpe:2.3:a:gunicorn:gunicorn",
    "uwsgi": "cpe:2.3:a:unbit:uwsgi",
    "mysql": "cpe:2.3:a:oracle:mysql",
    "mariadb": "cpe:2.3:a:mariadb:mariadb",
    "postgresql": "cpe:2.3:a:postgresql:postgresql",
    "postgres": "cpe:2.3:a:postgresql:postgresql",
    "redis": "cpe:2.3:a:redis:redis",
    "mongodb": "cpe:2.3:a:mongodb:mongodb",
    "elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
    "grafana": "cpe:2.3:a:grafana:grafana",
    "jenkins": "cpe:2.3:a:jenkins:jenkins",
    "gitlab": "cpe:2.3:a:gitlab:gitlab",
    "kubernetes": "cpe:2.3:a:kubernetes:kubernetes",
    "vsftpd": "cpe:2.3:a:vsftpd:vsftpd",
    "proftpd": "cpe:2.3:a:proftpd:proftpd",
    "pure-ftpd": "cpe:2.3:a:pureftpd:pure-ftpd",
    "postfix": "cpe:2.3:a:postfix:postfix",
    "exim": "cpe:2.3:a:exim:exim",
    "dovecot": "cpe:2.3:a:dovecot:dovecot",
    "samba": "cpe:2.3:a:samba:samba",
    "bind": "cpe:2.3:a:isc:bind",
    "ntp": "cpe:2.3:a:ntp:ntp",
}

# Tokens that indicate a pre-release, used only for version ordering.
_PRERELEASE_TOKENS = {
    "dev": -7,
    "snapshot": -6,
    "alpha": -5,
    "a": -5,
    "beta": -4,
    "b": -4,
    "pre": -3,
    "preview": -3,
    "rc": -2,
}


class NvdRequestError(RuntimeError):
    """Raised when an NVD API request cannot be completed."""


def _clean_for_matching(text: str) -> str:
    return SSH_BANNER_PREFIX.sub('', text)


def _normalize_product(name: str) -> str:
    """Normalize a product name for alias/CPE comparisons."""
    value = (name or "").lower().strip()
    value = value.replace("_", " ").replace("-", " ")
    value = re.sub(r"[^a-z0-9. ]+", " ", value)
    return re.sub(r"\s+", " ", value).strip()


def _word_tokens(value: str) -> List[str]:
    return [t for t in re.split(r"[^a-z0-9]+", (value or "").lower()) if t]


def _split_cpe(cpe_name: str) -> List[str]:
    """Split a CPE 2.3 string without breaking escaped colons."""
    parts = re.split(r"(?<!\\):", cpe_name or "")
    return [p.replace("\\:", ":").replace("\\\\", "\\") for p in parts]


def _cpe_prefix(cpe_name: str) -> Optional[str]:
    parts = _split_cpe(cpe_name)
    if len(parts) < 5 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return ":".join(parts[:5])


def _version_tokens(value: str) -> List[Any]:
    tokens: List[Any] = []
    for token in re.findall(r"\d+|[a-z]+", (value or "").lower().lstrip("v")):
        tokens.append(int(token) if token.isdigit() else token)
    return tokens


def _compare_versions(left: str, right: str) -> int:
    """Compare two loose software versions.

    Handles dotted numeric versions, letter suffixes (`8.9p1`), and common
    pre-release markers (`1.0rc1` < `1.0`). It is not a full distro version
    comparator, but it is deliberately dependency-free and predictable.
    """
    a = _version_tokens(left)
    b = _version_tokens(right)
    for i in range(max(len(a), len(b))):
        ta = a[i] if i < len(a) else None
        tb = b[i] if i < len(b) else None

        # Trailing zero components are insignificant: 1.24 == 1.24.0 and
        # 2.0 == 2.0.0. Without this, a banner "1.24" would not match a CPE
        # range boundary written as "1.24.0" (or vice versa).
        if ta is None:
            if all(isinstance(token, int) and token == 0 for token in b[i:]):
                return 0
            if isinstance(tb, str) and tb in _PRERELEASE_TOKENS:
                return 1
            return -1
        if tb is None:
            if all(isinstance(token, int) and token == 0 for token in a[i:]):
                return 0
            if isinstance(ta, str) and ta in _PRERELEASE_TOKENS:
                return -1
            return 1
        if ta == tb:
            continue

        ta_num, tb_num = isinstance(ta, int), isinstance(tb, int)
        if ta_num and tb_num:
            return -1 if ta < tb else 1
        if ta_num and not tb_num:
            return 1 if tb in _PRERELEASE_TOKENS else -1
        if not ta_num and tb_num:
            return -1 if ta in _PRERELEASE_TOKENS else 1

        ta_rank = _PRERELEASE_TOKENS.get(ta, 0)
        tb_rank = _PRERELEASE_TOKENS.get(tb, 0)
        if ta_rank == tb_rank:
            return -1 if ta < tb else 1
        return -1 if ta_rank < tb_rank else 1
    return 0


class CVELookupPhase(BaseReconPhase):
    """Correlates detected technology/service versions against the NVD."""

    name = "cve_lookup"
    order = 11
    description = (
        "Resolves detected products to CPEs and checks NVD version ranges; "
        "unresolved products fall back to labeled keyword candidates"
    )

    async def execute(self) -> Dict[str, Any]:
        config = self._scan_config()
        if config.get("enable_external_lookups") is False:
            return {
                "status": "completed",
                "skipped_reason": "external lookups disabled for this scan",
                "matches": [],
            }

        self._last_request = 0.0
        candidates = self._gather_candidates()
        max_lookups = settings.CVE_LOOKUP_MAX_CANDIDATES
        matches: List[Dict[str, Any]] = []
        errors: List[str] = []
        cpe_resolved = 0
        keyword_fallback = 0
        seen_cves = set()

        timeout = aiohttp.ClientTimeout(total=settings.CVE_LOOKUP_TIMEOUT)
        headers = {"User-Agent": settings.DEFAULT_USER_AGENT}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            for product, version, source in candidates[:max_lookups]:
                cpe_prefix, resolution, confidence = await self._resolve_cpe(session, product)
                if cpe_prefix:
                    cpe_resolved += 1
                    found, lookup_errors = await self._lookup_by_cpe(
                        session, cpe_prefix, product, version, confidence
                    )
                    errors.extend(lookup_errors)
                    mode = "cpe_version_range"
                else:
                    keyword_fallback += 1
                    found, lookup_errors = await self._lookup_by_keyword(
                        session, product, version
                    )
                    errors.extend(lookup_errors)
                    mode = "nvd_keyword_search"

                for cve in found[: settings.CVE_MAX_MATCHES_PER_PRODUCT]:
                    if cve["cve_id"] in seen_cves:
                        continue
                    seen_cves.add(cve["cve_id"])
                    matches.append({
                        **cve,
                        "product": product,
                        "version": version,
                        "source": source,
                        "match_method": mode,
                        "cpe_resolution": resolution,
                    })

        matches.sort(key=lambda m: -(m.get("cvss_score") or 0))
        self._generate_findings(matches)

        result: Dict[str, Any] = {
            "status": "completed",
            "candidates_found": len(candidates),
            "candidates_checked": min(len(candidates), max_lookups),
            "cpe_resolved": cpe_resolved,
            "keyword_fallback": keyword_fallback,
            "matches": matches,
        }
        if len(candidates) > max_lookups:
            result["note"] = (
                f"{len(candidates)} version-identifiable technologies were found, but only "
                f"{max_lookups} were checked against NVD to respect its public rate limit. "
                "Set NVD_API_KEY to raise the request limit."
            )
        if errors:
            result["errors"] = errors[:5]
        return result

    # ------------------------------------------------------------------ #
    # Candidate extraction
    # ------------------------------------------------------------------ #

    def _gather_candidates(self) -> List[Tuple[str, str, str]]:
        """Extract (product, version, source) tuples from tech_detection and
        port_scan's results, deduplicated by (product.lower(), version)."""
        seen = set()
        candidates: List[Tuple[str, str, str]] = []

        tech_data = self.context.get("tech_detection", {})
        for tech in tech_data.get("technologies", []) or []:
            evidence = _clean_for_matching(tech.get("evidence") or tech.get("technology") or "")
            match = VERSION_PATTERN.search(evidence)
            if match:
                product, version = match.group(1), match.group(2)
                key = (product.lower(), version)
                if key not in seen:
                    seen.add(key)
                    candidates.append((product, version, "tech_detection"))

        port_data = self.context.get("port_scan", {})
        for port, info in (port_data.get("open_ports") or {}).items():
            banner = _clean_for_matching(info.get("banner") or info.get("version_guess") or "")
            match = VERSION_PATTERN.search(banner)
            if match:
                product, version = match.group(1), match.group(2)
                key = (product.lower(), version)
                if key not in seen:
                    seen.add(key)
                    candidates.append((product, version, f"port_scan:{port}"))

        return candidates

    # ------------------------------------------------------------------ #
    # NVD transport
    # ------------------------------------------------------------------ #

    async def _pace(self):
        """Stay within NVD's public/keyed rate limits."""
        spacing = (
            settings.NVD_API_KEY_SPACING
            if settings.NVD_API_KEY
            else settings.CVE_LOOKUP_SPACING
        )
        elapsed = time.monotonic() - self._last_request
        if self._last_request and elapsed < spacing:
            await asyncio.sleep(spacing - elapsed)
        self._last_request = time.monotonic()

    async def _nvd_get(self, session: aiohttp.ClientSession, url: str) -> Dict[str, Any]:
        await self._pace()
        headers = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY
        try:
            async with session.get(url, headers=headers) as response:
                if response.status in (403, 429):
                    raise NvdRequestError(
                        f"NVD rate-limited or blocked this request (HTTP {response.status})"
                    )
                if response.status != 200:
                    raise NvdRequestError(f"NVD returned HTTP {response.status}")
                try:
                    return await response.json(content_type=None)
                except Exception as exc:
                    raise NvdRequestError(f"NVD returned unparseable data: {exc}") from exc
        except asyncio.TimeoutError as exc:
            raise NvdRequestError("NVD request timed out") from exc
        except aiohttp.ClientError as exc:
            raise NvdRequestError(f"NVD request failed: {exc}") from exc

    # ------------------------------------------------------------------ #
    # CPE resolution and matching
    # ------------------------------------------------------------------ #

    def _alias_cpe(self, product: str) -> Optional[Tuple[str, str, str]]:
        key = _normalize_product(product)
        if not key:
            return None

        if key in CPE_ALIASES:
            return CPE_ALIASES[key], "alias", "high"

        # Conservative fallback: only accept an alias when the detected
        # product is a whole-word prefix of the alias ("nginx upstream"
        # -> nginx) or vice versa, never a short substring.
        for alias, cpe in CPE_ALIASES.items():
            if len(key) < 3 or len(alias) < 3:
                continue
            if key.startswith(alias + " ") or alias.startswith(key + " "):
                return cpe, "alias_prefix", "medium"
        return None

    async def _resolve_cpe(
        self, session: aiohttp.ClientSession, product: str
    ) -> Tuple[Optional[str], str, str]:
        alias = self._alias_cpe(product)
        if alias:
            return alias

        params = urlencode({"keywordSearch": product, "resultsPerPage": 50})
        try:
            data = await self._nvd_get(session, f"{NVD_CPE_API}?{params}")
        except NvdRequestError:
            return None, "none", "none"

        best_prefix = None
        best_score = 0
        for item in data.get("products") or []:
            cpe = item.get("cpe") or {}
            if cpe.get("deprecated"):
                continue
            cpe_name = cpe.get("cpeName") or ""
            score = self._score_cpe(product, cpe_name)
            if score > best_score:
                best_score = score
                best_prefix = _cpe_prefix(cpe_name)

        if best_prefix and best_score >= 40:
            return best_prefix, "nvd_cpe_search", "medium"
        return None, "none", "none"

    def _score_cpe(self, product: str, cpe_name: str) -> int:
        fields = _split_cpe(cpe_name)
        if len(fields) < 5:
            return 0
        part, cpe_product = fields[2], fields[4]
        if part not in ("a", "o"):
            return 0

        product_tokens = set(_word_tokens(product))
        cpe_tokens = set(_word_tokens(cpe_product))
        if not product_tokens or not cpe_tokens:
            return 0
        overlap = len(product_tokens & cpe_tokens)
        if overlap == 0:
            return 0

        score = overlap * 10
        if product_tokens == cpe_tokens:
            score += 60
        elif product_tokens <= cpe_tokens:
            score += 30
        if part == "a":
            score += 10
        score -= max(0, len(cpe_tokens) - len(product_tokens)) * 2
        return score

    async def _lookup_by_cpe(
        self,
        session: aiohttp.ClientSession,
        cpe_prefix: str,
        product: str,
        version: str,
        cpe_confidence: str,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Return CVEs whose CPE ranges include the observed version."""
        results: List[Dict[str, Any]] = []
        errors: List[str] = []
        start_index = 0
        page_size = 2000
        total_results = None

        while start_index < settings.CVE_CPE_MAX_RESULTS:
            params = {
                "virtualMatchString": cpe_prefix,
                "resultsPerPage": page_size,
                "startIndex": start_index,
            }
            url = f"{NVD_CVE_API}?{urlencode(params)}"
            try:
                data = await self._nvd_get(session, url)
            except NvdRequestError as exc:
                errors.append(f"{product} {version}: {exc}")
                break

            vulnerabilities = data.get("vulnerabilities") or []
            if total_results is None:
                total_results = int(data.get("totalResults") or 0)

            for item in vulnerabilities:
                cve = item.get("cve") or {}
                if cve.get("vulnStatus") == "Rejected":
                    continue
                match = self._match_version(cve, cpe_prefix, version)
                if not match:
                    continue
                results.append(self._build_match(cve, match, cpe_prefix, cpe_confidence, True))

            start_index += len(vulnerabilities)
            if not vulnerabilities or start_index >= (total_results or 0):
                break

        if total_results and total_results > settings.CVE_CPE_MAX_RESULTS:
            errors.append(
                f"{product} {version}: checked the first {settings.CVE_CPE_MAX_RESULTS} "
                f"of {total_results} NVD records for {cpe_prefix}"
            )
        return results, errors

    async def _lookup_by_keyword(
        self,
        session: aiohttp.ClientSession,
        product: str,
        version: str,
    ) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Unverified fallback used only when no CPE can be resolved."""
        query = f"{product} {version}"
        params = urlencode({"keywordSearch": query, "resultsPerPage": 5})
        url = f"{NVD_CVE_API}?{params}"
        try:
            data = await self._nvd_get(session, url)
        except NvdRequestError as exc:
            return [], [f"{product} {version}: {exc}"]

        results = []
        for item in data.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            if cve.get("vulnStatus") == "Rejected":
                continue
            results.append(self._build_match(cve, None, None, "none", False))
        return results, []

    def _match_version(
        self, cve: Dict[str, Any], cpe_prefix: str, version: str
    ) -> Optional[Dict[str, Any]]:
        for configuration in cve.get("configurations") or []:
            for node in configuration.get("nodes") or []:
                if node.get("negate"):
                    continue
                for match in node.get("cpeMatch") or []:
                    if not match.get("vulnerable"):
                        continue
                    criteria = match.get("criteria") or ""
                    # Require a field boundary: cpe:2.3:a:nginx:nginx must not
                    # match a different product such as nginx_plus.
                    if criteria != cpe_prefix and not criteria.startswith(cpe_prefix + ":"):
                        continue
                    if self._version_in_cpe_range(version, criteria, match):
                        return match
        return None

    def _version_in_cpe_range(
        self, version: str, criteria: str, match: Dict[str, Any]
    ) -> bool:
        fields = _split_cpe(criteria)
        if len(fields) < 7:
            return False

        cpe_version = fields[5]
        cpe_update = fields[6]

        if cpe_version == "-":
            return False

        if cpe_version not in ("*", ""):
            candidate = cpe_version
            if cpe_update not in ("*", "-", ""):
                candidate = f"{cpe_version}{cpe_update}"
            if _compare_versions(version, candidate) == 0:
                return True

            # Distro builds append a package revision to the upstream
            # version (e.g. nginx 1.24.0-1ubuntu2). A CPE exact version of
            # "1.24.0" should still match that build. Only accept a
            # dash/plus/tilde suffix so 1.24.0 does not swallow 1.24.1.
            lowered = (version or "").lower()
            prefix = candidate.lower()
            if lowered.startswith(prefix) and len(lowered) > len(prefix):
                next_char = lowered[len(prefix)]
                if next_char in ("-", "+", "~"):
                    return True
            return False

        # Wildcard version: use NVD's explicit range fields.
        lower = match.get("versionStartIncluding")
        if lower and _compare_versions(version, lower) < 0:
            return False
        lower = match.get("versionStartExcluding")
        if lower and _compare_versions(version, lower) <= 0:
            return False
        upper = match.get("versionEndIncluding")
        if upper and _compare_versions(version, upper) > 0:
            return False
        upper = match.get("versionEndExcluding")
        if upper and _compare_versions(version, upper) >= 0:
            return False

        # A wildcard with no range means NVD considers every version
        # affected (or did not record a range). Keep it as a match but do
        # not claim a range in the report.
        return True

    def _build_match(
        self,
        cve: Dict[str, Any],
        cpe_match: Optional[Dict[str, Any]],
        cpe_prefix: Optional[str],
        cpe_confidence: str,
        verified: bool,
    ) -> Dict[str, Any]:
        cve_id = cve.get("id") or ""
        description = next(
            (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        cvss_score, cvss_severity = self._extract_cvss(cve.get("metrics") or {})
        return {
            "cve_id": cve_id,
            "description": description[:600],
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "published": cve.get("published"),
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "exploitdb_search_url": f"https://www.exploit-db.com/search?cve={cve_id}",
            "matched_cpe": (cpe_match or {}).get("criteria"),
            "version_range": self._describe_range(cpe_match) if cpe_match else None,
            "cpe_name": cpe_prefix,
            "cpe_confidence": cpe_confidence,
            "applicability_verified": verified,
        }

    def _describe_range(self, match: Optional[Dict[str, Any]]) -> Optional[str]:
        if not match:
            return None
        pieces = []
        if match.get("versionStartIncluding"):
            pieces.append(f">={match['versionStartIncluding']}")
        if match.get("versionStartExcluding"):
            pieces.append(f">{match['versionStartExcluding']}")
        if match.get("versionEndIncluding"):
            pieces.append(f"<={match['versionEndIncluding']}")
        if match.get("versionEndExcluding"):
            pieces.append(f"<{match['versionEndExcluding']}")
        return ", ".join(pieces) if pieces else "all versions"

    def _extract_cvss(self, metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        """NVD returns CVSS under different keys depending on which version
        scored the CVE (newer CVEs have v3.1, older ones may only have v2).
        Prefer the newest available."""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                entry = entries[0]
                data = entry.get("cvssData", {})
                score = data.get("baseScore")
                severity = (entry.get("baseSeverity") or data.get("baseSeverity") or "").lower()
                if not severity and score is not None:
                    severity = self._score_to_severity(score)
                return score, severity or None
        return None, None

    def _score_to_severity(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    def _generate_findings(self, matches: List[Dict[str, Any]]):
        for m in matches:
            severity = m.get("cvss_severity")
            if severity not in VALID_SEVERITIES:
                severity = "medium"  # unscored CVE -- don't silently downgrade to "info"
            score_str = f" (CVSS {m['cvss_score']})" if m.get("cvss_score") is not None else ""
            verified = bool(m.get("applicability_verified"))

            if verified:
                title = (
                    f"CVE applies to detected version: {m['product']} {m['version']} "
                    f"-- {m['cve_id']}{score_str}"
                )
                description = (
                    f"Matched via CPE {m.get('cpe_name')} with version range "
                    f"{m.get('version_range') or 'all versions'}.\n\n"
                    f"{m.get('description', '') or 'No description available from NVD.'}"
                )
                evidence = (
                    f"{m['product']}/{m['version']} falls within {m.get('version_range') or 'all versions'} "
                    f"for {m.get('matched_cpe')}"
                )
            else:
                title = (
                    f"CVE candidate (unverified): {m['product']} {m['version']} "
                    f"-- {m['cve_id']}{score_str}"
                )
                description = (
                    "NVD keyword correlation only. Confirm that this CVE affects "
                    f"the observed version before treating it as a finding.\n\n"
                    f"{m.get('description', '') or 'No description available from NVD.'}"
                )
                evidence = (
                    f"{m['product']}/{m['version']} matched via NVD keyword search; "
                    "version applicability has not been verified with CPE data."
                )

            self.add_finding(
                finding_type="cve_match",
                severity=severity,
                title=title,
                description=description,
                location=m.get("source", ""),
                evidence=evidence,
                remediation=(
                    f"Check {m['nvd_url']} and the vendor advisory; upgrade only if "
                    "the installed version is affected."
                ),
                metadata={
                    "cve_id": m["cve_id"],
                    "cvss_score": m.get("cvss_score"),
                    "cvss_severity": m.get("cvss_severity"),
                    "nvd_url": m["nvd_url"],
                    "exploitdb_search_url": m["exploitdb_search_url"],
                    "product": m["product"],
                    "version": m["version"],
                    "matched_cpe": m.get("matched_cpe"),
                    "version_range": m.get("version_range"),
                    "cpe_name": m.get("cpe_name"),
                    "cpe_confidence": m.get("cpe_confidence"),
                    "match_method": m.get("match_method"),
                    "applicability_verified": verified,
                },
            )
