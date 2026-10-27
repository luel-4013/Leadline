"""
Leadline - Reconnaissance Pipeline
Phase 3: Reconnaissance Engine - Orchestrates all recon phases
"""
from typing import List, Dict, Any, Type
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from app.recon.base import BaseReconPhase
from app.recon.dns_discovery import DNSDiscoveryPhase
from app.recon.host_intel import HostIntelPhase
from app.recon.port_scan import PortScanPhase
from app.recon.http_fingerprinting import HTTPFingerprintingPhase
from app.recon.tech_detection import TechDetectionPhase
from app.recon.js_analysis import JSAnalysisPhase
from app.recon.param_discovery import ParamDiscoveryPhase
from app.recon.security_headers import SecurityHeadersPhase
from app.recon.api_discovery import APIDiscoveryPhase
from app.recon.vuln_classification import VulnClassificationPhase
from app.recon.cve_lookup import CVELookupPhase
from app.recon.graph_builder import GraphBuilderPhase

from app.models import Scan, ScanEvent, Finding


class ReconPipeline:
    """
    Orchestrates the reconnaissance pipeline.
    Executes phases in order and stores results in the database.
    """

    # Phase classes in execution order. Instantiated lazily inside run() so
    # each phase can be handed the context accumulated from phases that
    # already completed (host_intel's resolved_ips feeds port_scan;
    # tech_detection, js_analysis, param_discovery, api_discovery,
    # vuln_classification and graph_builder all read prior phases' results
    # out of `context`).
    PHASE_CLASSES: List[Type[BaseReconPhase]] = [
        DNSDiscoveryPhase,
        HostIntelPhase,
        PortScanPhase,
        HTTPFingerprintingPhase,
        TechDetectionPhase,
        JSAnalysisPhase,
        ParamDiscoveryPhase,
        SecurityHeadersPhase,
        APIDiscoveryPhase,
        VulnClassificationPhase,
        CVELookupPhase,
        GraphBuilderPhase,
    ]

    def __init__(self, target_url: str, scan_id: int, db_session: AsyncSession,
                 scan_config: Dict[str, Any] = None):
        self.target_url = self._normalize_target_url(target_url)
        self.scan_id = scan_id
        self.db = db_session
        self.stop_requested = False
        self.scan_config = scan_config or {}

        # Shared context passed to each phase as it's constructed. Each
        # phase's own result_data is stored under context[phase.name] after
        # it runs, and all findings collected so far live under
        # context['_all_findings'], so later phases can build on earlier ones.
        # context['_scan_config'] carries per-scan request-pacing settings
        # and per-target custom headers -- see app/recon/base.py's _delay()
        # and _get_headers(), which read it from there.
        self.context: Dict[str, Any] = {"_scan_config": self.scan_config}

    def request_stop(self):
        """Request graceful stop of the pipeline (for in-process use)."""
        self.stop_requested = True

    @staticmethod
    def _normalize_target_url(target_url: str) -> str:
        """Accept a bare hostname/IP as well as a full URL.

        Users reasonably enter `example.com`, `192.168.1.10`, or
        `https://example.com`. Every phase parses the target with urlparse,
        so normalizing once here keeps DNS, port, HTTP, and report code
        consistent instead of making each phase guess.
        """
        import ipaddress

        raw = (target_url or "").strip()
        if not raw or "://" in raw:
            return raw

        host, slash, path = raw.partition("/")
        try:
            is_ipv6 = ipaddress.ip_address(host).version == 6
        except ValueError:
            is_ipv6 = False

        if is_ipv6:
            return f"http://[{host}]" + (f"/{path}" if slash else "")
        return f"http://{raw}"

    async def _is_stop_requested(self) -> bool:
        """Check whether a stop has been requested for this scan.

        POST /api/scans/{id}/stop runs in a separate HTTP request and has no
        reference to this in-memory pipeline instance -- it can only
        communicate a stop request by writing status="stopping" to the
        database. Poll for that here between phases (in addition to the
        in-memory flag, for callers that do hold a reference).
        """
        if self.stop_requested:
            return True
        from sqlalchemy import select
        result = await self.db.execute(select(Scan.status).where(Scan.id == self.scan_id))
        return result.scalar_one_or_none() == "stopping"

    async def _update_scan_status(self, status: str, progress: float = None,
                                   current_phase: str = None, error_message: str = None):
        """Update the scan record in the database."""
        from sqlalchemy import update

        update_data = {"status": status}
        if progress is not None:
            update_data["progress"] = progress
        if current_phase is not None:
            update_data["current_phase"] = current_phase
        if error_message is not None:
            update_data["error_message"] = error_message
        if status == "running" and not error_message:
            update_data["started_at"] = datetime.now()
        if status in ["completed", "failed", "stopped"]:
            update_data["completed_at"] = datetime.now()

        await self.db.execute(
            update(Scan).where(Scan.id == self.scan_id).values(**update_data)
        )
        await self.db.commit()

    async def _store_event(self, event_data: Dict[str, Any]):
        """Store a phase event in the database."""
        event = ScanEvent(
            scan_id=self.scan_id,
            phase_name=event_data["phase_name"],
            phase_order=event_data["phase_order"],
            status=event_data["status"],
            started_at=datetime.fromisoformat(event_data["started_at"]) if event_data.get("started_at") else None,
            completed_at=datetime.fromisoformat(event_data["completed_at"]) if event_data.get("completed_at") else None,
            result_data=event_data.get("result_data", {}),
            findings_count=len(event_data.get("findings") or []),
            error_message=event_data.get("error_message"),
        )
        self.db.add(event)
        await self.db.commit()
        return event.id

    async def _store_findings(self, findings: List[Dict[str, Any]]):
        """Store findings in the database."""
        for finding_data in findings:
            finding = Finding(
                scan_id=self.scan_id,
                finding_type=finding_data.get("finding_type", "unknown"),
                severity=finding_data.get("severity", "info"),
                title=finding_data.get("title", ""),
                description=finding_data.get("description", ""),
                location=finding_data.get("location", ""),
                evidence=finding_data.get("evidence", ""),
                remediation=finding_data.get("remediation", ""),
                # The ORM column is `extra_data`, not `metadata` -- `metadata`
                # is reserved on SQLAlchemy declarative models (it's the
                # schema MetaData object), so passing it as a constructor
                # kwarg raises "Attribute name 'metadata' is reserved".
                extra_data=finding_data.get("metadata", {}),
            )
            self.db.add(finding)
        await self.db.commit()

    async def run(self) -> Dict[str, Any]:
        """
        Execute the full reconnaissance pipeline.
        Returns summary of results.
        """
        total_phases = len(self.PHASE_CLASSES)
        completed_phases = 0
        all_results = []
        all_findings: List[Dict[str, Any]] = []
        self.context['_all_findings'] = all_findings

        await self._update_scan_status("running", progress=0)

        for phase_cls in self.PHASE_CLASSES:
            if await self._is_stop_requested():
                await self._update_scan_status("stopped", progress=(completed_phases / total_phases) * 100)
                break

            # Instantiate with the context accumulated from prior phases.
            phase = phase_cls(self.target_url, context=self.context)

            # Update current phase status
            await self._update_scan_status(
                "running",
                progress=(completed_phases / total_phases) * 100,
                current_phase=phase.name
            )

            # Execute phase
            result = await phase.run()
            all_results.append(result)

            # Make this phase's results available to phases that run after it
            self.context[phase.name] = result.get("result_data", {})

            # Store event
            await self._store_event(result)

            # Store any findings (also mutates all_findings / context['_all_findings'])
            if result.get("findings"):
                await self._store_findings(result["findings"])
                all_findings.extend(result["findings"])

            completed_phases += 1

        # Determine final status
        final_status = "completed" if completed_phases == total_phases else "stopped"
        await self._update_scan_status(
            final_status,
            progress=100.0,
            current_phase=None
        )

        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": final_status,
            "phases_completed": completed_phases,
            "total_phases": total_phases,
            "total_findings": len(all_findings),
            "results": all_results
        }
