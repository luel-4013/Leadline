"""
Leadline - Base Reconnaissance Phase
Phase 3: Reconnaissance Engine - Abstract base class for all phases
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
from urllib.parse import urlparse
import asyncio
import random

from app.config import settings


class BaseReconPhase(ABC):
    """
    Abstract base class for all reconnaissance phases.
    Each phase should inherit from this and implement execute().
    """

    # Phase metadata - override in subclasses
    name: str = "base_phase"
    order: int = 0
    description: str = "Base reconnaissance phase"

    def __init__(self, target_url: str, context: Optional[Dict] = None):
        self.target_url = target_url
        self.context = context or {}
        self.results: Dict[str, Any] = {}
        self.findings: List[Dict[str, Any]] = []
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None

    def _extract_host(self, target: str) -> str:
        """Pull just the hostname/IP out of a bare host, host:port, or full
        URL. Shared by any phase that needs the bare host (host_intel,
        port_scan) rather than each keeping its own copy -- a previous
        version of this duplicated across two files, and the two copies
        silently drifted (one stripped a trailing dot, the other didn't)."""
        candidate = target.strip()
        if "://" in candidate:
            host = urlparse(candidate).hostname
            if host:
                return host.rstrip(".")
            candidate = candidate.split("://", 1)[1]
        # IPv6 literal in brackets, e.g. "[::1]:8080"
        if candidate.startswith("["):
            return candidate[1:].split("]")[0]
        candidate = candidate.split("/", 1)[0]
        # host:port -- but don't truncate a bare IPv6 address that has no brackets
        if candidate.count(":") == 1:
            candidate = candidate.split(":", 1)[0]
        return candidate.rstrip(".")

    def _scan_config(self) -> Dict[str, Any]:
        """Per-scan pacing/header config, threaded in via the pipeline's
        shared context (see app/recon/pipeline.py). Empty if a phase is ever
        run standalone/in tests, which just falls back to global defaults."""
        return self.context.get('_scan_config') or {}

    async def _delay(self):
        """Apply configurable delay with optional randomization for request pacing."""
        config = self._scan_config()
        if config.get('evasion_enabled') is False:
            return

        base_delay = config.get('request_delay')
        if base_delay is None:
            base_delay = settings.REQUEST_DELAY
        delay = base_delay
        if settings.RANDOM_DELAY_MAX > settings.RANDOM_DELAY_MIN:
            delay += random.uniform(settings.RANDOM_DELAY_MIN, settings.RANDOM_DELAY_MAX)
        await asyncio.sleep(delay)

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with optional User-Agent rotation for detection
        evasion, then layer on any custom headers configured for the target
        (e.g. an Authorization/Cookie for auth-gated targets)."""
        config = self._scan_config()
        evasion_enabled = config.get('evasion_enabled', True)

        if evasion_enabled:
            # Real browser UAs conventionally all start with "Mozilla/" --
            # this keeps a deliberately self-identifying entry like
            # "Leadline/0.2 (Security Scanner)" out of the rotation
            # pool used to blend in, without hardcoding which entries are
            # "bad" by name.
            browser_like = [ua for ua in settings.USER_AGENTS if ua.startswith("Mozilla/")]
            selected_ua = random.choice(browser_like) if browser_like else settings.DEFAULT_USER_AGENT
        else:
            selected_ua = settings.DEFAULT_USER_AGENT

        headers = {
            "User-Agent": selected_ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }

        # Custom headers win on conflicts, so a target can override the
        # User-Agent too if a specific value is required.
        headers.update(config.get('custom_headers') or {})
        return headers

    async def _read_text_limited(self, response, limit: Optional[int] = None) -> tuple[str, bool]:
        """Read at most MAX_RESPONSE_BYTES from a response.

        A scanner talks to hostile or broken servers. Reading an unbounded
        body into memory (and then into SQLite) is a trivial DoS and a database
        bloat vector. Returns (text, truncated).
        """
        limit = limit if limit is not None else settings.MAX_RESPONSE_BYTES
        raw = await response.content.read(limit + 1)
        truncated = len(raw) > limit
        raw = raw[:limit]
        encoding = getattr(response, "charset", None) or "utf-8"
        try:
            return raw.decode(encoding, errors="replace"), truncated
        except LookupError:
            return raw.decode("utf-8", errors="replace"), truncated

    async def _make_request(self, url: str, method: str = "GET", **kwargs) -> Optional[Any]:
        """Make an HTTP request with configured settings."""
        import aiohttp

        headers = kwargs.pop('headers', self._get_headers())
        timeout = aiohttp.ClientTimeout(total=settings.TIMEOUT)

        proxy = settings.PROXY_URL
        if proxy:
            kwargs['proxy'] = proxy

        async with aiohttp.ClientSession(headers=headers, timeout=timeout) as session:
            try:
                async with session.request(method, url, **kwargs) as response:
                    body, truncated = await self._read_text_limited(response)
                    return {
                        "status": response.status,
                        "headers": dict(response.headers),
                        "body": body,
                        "body_truncated": truncated,
                        "url": str(response.url)
                    }
            except Exception as e:
                return {"error": str(e)}

    @abstractmethod
    async def execute(self) -> Dict[str, Any]:
        """
        Execute the reconnaissance phase.
        Must be implemented by subclasses.

        Returns:
            Dict containing phase results
        """
        pass

    async def run(self) -> Dict[str, Any]:
        """
        Run the phase with timing and error handling.
        This is the main entry point called by the pipeline.
        """
        self.started_at = datetime.now()
        try:
            await self._delay()
            result = await self.execute()
            self.results = result
            return {
                "phase_name": self.name,
                "phase_order": self.order,
                "status": "completed",
                "started_at": self.started_at.isoformat(),
                "completed_at": datetime.now().isoformat(),
                "result_data": result,
                "findings": self.findings
            }
        except Exception as e:
            return {
                "phase_name": self.name,
                "phase_order": self.order,
                "status": "failed",
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "completed_at": datetime.now().isoformat(),
                "error_message": str(e),
                "result_data": {},
                "findings": []
            }

    def add_finding(self, finding_type: str, title: str, severity: str = "info",
                    description: str = "", location: str = "", evidence: str = "",
                    remediation: str = "", metadata: Optional[Dict] = None):
        """Add a security finding."""
        self.findings.append({
            "finding_type": finding_type,
            "title": title,
            "severity": severity,
            "description": description,
            "location": location,
            "evidence": evidence,
            "remediation": remediation,
            "metadata": metadata or {}
        })
