"""
Leadline - Reports API Router
Phase 9: Reporting - Report generation and export
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, Optional
import json
import re
from html import escape as html_escape
from urllib.parse import urlsplit

from app.db import get_db
from app.models import Scan, Target, ScanEvent, Finding, GraphNode
from app.schemas import ReportSummary, ReportHighlights, FullReport, ReportPhaseResult
from app.pdf_export import generate_report_pdf
from app.risk import compute_risk

router = APIRouter(prefix="/reports", tags=["reports"])

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


async def _load_findings(scan_id: int, db: AsyncSession) -> list:
    """Load all findings for an export, most severe first."""
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id.asc())
    )
    findings = list(result.scalars().all())
    findings.sort(
        key=lambda f: _SEVERITY_ORDER.index(f.severity)
        if f.severity in _SEVERITY_ORDER else len(_SEVERITY_ORDER)
    )
    return findings


def _export_filename(target_url: str, scan_id: int, extension: str) -> str:
    """Name exports after the target so downloaded files are self-describing.

    ``example.com:8443`` becomes ``example.com_8443-scan-7.pdf``. The scan id
    keeps repeat scans from overwriting each other, and every character is
    reduced to a filesystem-safe set so a hostile target string cannot inject
    a path or header value.
    """
    raw = (target_url or "").strip()
    if raw and "://" not in raw:
        raw = f"//{raw}"

    try:
        parsed = urlsplit(raw)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError:
        host, port = raw, None

    label = host or raw or "target"
    # IPv6 colons are legal in a hostname but awkward in a filename. Mark the
    # address so ``[::1]`` does not collapse into a bare ``1`` after cleanup.
    if ":" in label:
        label = f"ipv6-{label.replace(':', '-')}"
    if port:
        label = f"{label}_{port}"
    label = re.sub(r"[^A-Za-z0-9._-]+", "-", label)
    label = re.sub(r"-{2,}", "-", label).strip("-._") or "target"
    return f"{label}-scan-{scan_id}.{extension.lstrip('.')}"


async def build_report_summary(scan_id: int, db: AsyncSession) -> ReportSummary:
    """Build summary statistics for a report."""
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()

    # Count API routes by discovery type
    api_findings = [f for f in findings if f.finding_type == "api_endpoint"]
    observed_api = len([f for f in api_findings if f.extra_data and f.extra_data.get('discovery_type') == 'observed'])
    inferred_api = len([f for f in api_findings if f.extra_data and f.extra_data.get('discovery_type') == 'inferred'])

    open_ports_findings = [f for f in findings if f.finding_type == "open_ports"]
    open_ports_count = sum(
        len((f.extra_data or {}).get("open_ports", {})) for f in open_ports_findings
    )

    risk_score, risk_level = compute_risk(findings)

    summary = ReportSummary(
        # NOTE: the actual finding_type the phases emit is
        # "endpoint_discovered", not "endpoint" -- this previously always
        # matched zero findings regardless of how many endpoints were found.
        total_endpoints=len([f for f in findings if f.finding_type == "endpoint_discovered"]),
        api_routes=observed_api,  # Only count observed APIs as confirmed
        api_candidates=inferred_api,  # Inferred API candidates
        # NOTE: no finding_type actually contains the substring "auth" --
        # access_control (fired on HTTP 403s) is the closest real signal
        # that some authentication/access-control mechanism is present.
        authentication_mechanisms=len([f for f in findings if f.finding_type == "access_control"]),
        debug_interfaces=len([f for f in findings if "debug" in f.title.lower()]),
        suspicious_parameters=len([f for f in findings if f.finding_type == "suspicious_parameter"]),
        possible_vulns=len([
            f for f in findings
            if f.finding_type in {"potential_vulnerability", "idor_candidate"}
        ]),
        missing_controls=len([
            f for f in findings
            if f.finding_type in {"missing_security_header", "misconfigured_header"}
        ]),
        open_ports_found=open_ports_count,
        high_risk_ports=len([f for f in findings if f.finding_type == "high_risk_open_port"]),
        cves_found=len([f for f in findings if f.finding_type == "cve_match"]),
        critical_cves=len([f for f in findings if f.finding_type == "cve_match" and f.severity == "critical"]),
        verified_cves=len([
            f for f in findings
            if f.finding_type == "cve_match"
            and (f.extra_data or {}).get("applicability_verified")
        ]),
        risk_score=risk_score,
        risk_level=risk_level,
    )
    return summary


async def build_report_highlights(scan_id: int, db: AsyncSession) -> ReportHighlights:
    """Pull human-readable highlights out of specific phases' raw result_data
    -- technologies, response/security headers, DNS/WHOIS/geolocation, open
    ports -- so a reader doesn't have to dig through each phase's full JSON
    blob to find them."""
    events_result = await db.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id)
    )
    events = {e.phase_name: (e.result_data or {}) for e in events_result.scalars().all()}

    tech_data = events.get("tech_detection", {})
    technologies = sorted({t.get("technology") for t in tech_data.get("technologies", []) if t.get("technology")})

    http_data = events.get("http_fingerprinting", {})
    server_info = http_data.get("server_info") or {}
    response_headers = {k: v for k, v in server_info.items() if isinstance(v, str)} or None

    headers_data = events.get("security_headers", {})
    present = headers_data.get("present_headers") or []
    missing = headers_data.get("missing_headers") or []
    security_headers_present = [
        h.get("name", str(h)) if isinstance(h, dict) else str(h) for h in present
    ]
    security_headers_missing = [
        h.get("name", str(h)) if isinstance(h, dict) else str(h) for h in missing
    ]

    host_data = events.get("host_intel", {})
    port_data = events.get("port_scan", {})
    cdn_waf_data = tech_data.get("cdn_waf") or {}
    subdomains_data = host_data.get("subdomains") or {}
    dnssec_data = host_data.get("dnssec") or {}

    api_data = events.get("api_discovery", {})
    js_data = events.get("js_analysis", {})
    param_data = events.get("param_discovery", {})

    api_endpoint_urls = [e.get("url") for e in (api_data.get("api_endpoints") or []) if e.get("url")]
    js_endpoint_urls = js_data.get("extracted_endpoints") or []
    discovered_endpoints = sorted(set(api_endpoint_urls) | set(js_endpoint_urls))

    api_documentation = sorted(set((api_data.get("swagger_docs") or []) + (api_data.get("graphql_endpoints") or [])))

    url_parameters = sorted({
        p.get("name") for p in (param_data.get("url_parameters") or []) if p.get("name")
    })

    cve_data = events.get("cve_lookup", {})
    cve_matches = sorted(
        cve_data.get("matches") or [],
        key=lambda m: -(m.get("cvss_score") or 0)
    )
    return ReportHighlights(
        technologies=technologies,
        cdn_waf=sorted(cdn_waf_data.keys()),
        response_headers=response_headers,
        security_headers_present=security_headers_present,
        security_headers_missing=security_headers_missing,
        dns_records=host_data.get("dns_records") or None,
        resolved_ips=host_data.get("resolved_ips") or [],
        hostnames=host_data.get("hostnames") or [],
        whois=host_data.get("whois") or None,
        geolocation=host_data.get("geolocation") or None,
        open_ports=port_data.get("open_ports") or None,
        subdomains=subdomains_data.get("subdomains") or [],
        dnssec_enabled=dnssec_data.get("enabled"),
        ip_reputation=host_data.get("ip_reputation") or None,
        discovered_endpoints=discovered_endpoints[:300],
        api_documentation=api_documentation,
        url_parameters=url_parameters[:200],
        cve_matches=cve_matches,
        cve_lookup_note=cve_data.get("note"),
        cve_lookup_errors=cve_data.get("errors") or [],
    )


async def build_graph_tree(scan_id: int, db: AsyncSession) -> Optional[Dict]:
    """Build tree structure from graph nodes."""
    nodes_result = await db.execute(
        select(GraphNode).where(GraphNode.scan_id == scan_id)
    )
    nodes = nodes_result.scalars().all()

    if not nodes:
        return None

    # Build tree structure
    node_map = {n.node_id: {"id": n.node_id, "label": n.label, "type": n.node_type, "children": [], "extra_data": n.extra_data} for n in nodes}
    root = None

    for node in nodes:
        if node.parent_id is None:
            root = node_map[node.node_id]
        elif node.parent_id in node_map:
            node_map[node.parent_id]["children"].append(node_map[node.node_id])

    return root


@router.get("/{scan_id}", response_model=FullReport)
async def get_report(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Get full report for a scan."""
    # Get scan with target
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_result.scalar_one_or_none()

    # Get events
    events_result = await db.execute(
        select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.phase_order)
    )
    events = events_result.scalars().all()

    # Build phases list
    phases = [
        ReportPhaseResult(
            phase_name=e.phase_name,
            phase_order=e.phase_order,
            status=e.status,
            findings_count=e.findings_count or 0,
            data=e.result_data
        )
        for e in events
    ]

    # Get endpoints from findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id)
    )
    findings = findings_result.scalars().all()
    endpoints = [f.location for f in findings if f.location]

    # Build summary
    summary = await build_report_summary(scan_id, db)

    # Build highlights (technologies, headers, DNS/WHOIS/geo, open ports)
    highlights = await build_report_highlights(scan_id, db)

    # Build graph tree
    graph_tree = await build_graph_tree(scan_id, db)

    return FullReport(
        scan_id=scan.id,
        target_name=target.name if target else "Unknown",
        target_url=target.url if target else "",
        status=scan.status,
        summary=summary,
        highlights=highlights,
        phases=phases,
        endpoints=endpoints[:100],  # Limit to 100
        graph_tree=graph_tree,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )


@router.get("/{scan_id}/export/json")
async def export_json(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export report as JSON."""
    report = await get_report(scan_id, db)
    return JSONResponse(
        content=json.loads(report.model_dump_json()),
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_export_filename(report.target_url, scan_id, "json")}"'
            )
        },
    )


def _md_text(value, limit: int = None) -> str:
    """Render a possibly target-controlled value safely inside Markdown.

    The export is a plain-text file, but people open Markdown in renderers
    that allow raw HTML. Escaping HTML brackets, table pipes, brackets, and
    newlines means a hostile banner or endpoint cannot break the report
    structure or inject markup into a renderer.
    """
    text = "" if value is None else str(value)
    if limit is not None:
        text = text[:limit]
    text = text.replace("\\", "\\\\")
    text = text.replace("`", "'")
    text = text.replace("|", "\\|").replace("[", "\\[").replace("]", "\\]")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return " ".join(text.splitlines())


def _md_block(value, limit: int = 2000) -> str:
    """Escape evidence for a fenced code block while keeping line breaks."""
    text = "" if value is None else str(value)[:limit]
    return text.replace("```", "'''").replace("<", "&lt;").replace(">", "&gt;")


def _md_url(value) -> str:
    text = "" if value is None else str(value)
    return text if text.startswith("https://") else "#"


@router.get("/{scan_id}/export/markdown")
async def export_markdown(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export report as Markdown.

    Values come from target responses, so everything interpolated here is
    passed through _md_text(); URLs are restricted to HTTPS.
    """
    report = await get_report(scan_id, db)
    h = report.highlights

    md = f"""# Leadline Report

## Target Information
- **Name:** {_md_text(report.target_name)}
- **URL:** {_md_text(report.target_url)}
- **Status:** {_md_text(report.status)}
- **Completed:** {_md_text(report.completed_at)}

## Overall Risk: {_md_text(str(report.summary.risk_level).upper())} ({report.summary.risk_score}/100)
*Derived from the highest-severity findings present, not just total finding count.*

## Summary
| Metric | Count |
|--------|-------|
| Endpoints | {report.summary.total_endpoints} |
| API Routes | {report.summary.api_routes} |
| Auth Mechanisms | {report.summary.authentication_mechanisms} |
| Debug Interfaces | {report.summary.debug_interfaces} |
| Suspicious Parameters | {report.summary.suspicious_parameters} |
| Possible Vulnerabilities | {report.summary.possible_vulns} |
| Missing Controls | {report.summary.missing_controls} |
| Open Ports Found | {report.summary.open_ports_found} |
| High Risk Ports | {report.summary.high_risk_ports} |
| CVE Candidates | {report.summary.cves_found} |
| Verified CVEs (CPE range) | {report.summary.verified_cves} |
| Critical CVE Candidates | {report.summary.critical_cves} |

## Highlights
"""
    if h.technologies:
        md += f"\n**Technologies detected:** {_md_text(', '.join(h.technologies))}\n"
    if h.cdn_waf:
        md += f"\n**CDN/WAF detected:** {_md_text(', '.join(h.cdn_waf))}\n"
    if h.response_headers:
        md += "\n**Response headers:**\n"
        for k, v in h.response_headers.items():
            md += f"- `{_md_text(k, 200)}: {_md_text(v, 500)}`\n"
    if h.security_headers_present or h.security_headers_missing:
        md += f"\n**Security headers present:** {_md_text(', '.join(h.security_headers_present)) or 'none'}\n"
        md += f"\n**Security headers missing:** {_md_text(', '.join(h.security_headers_missing)) or 'none'}\n"
    if h.resolved_ips:
        md += f"\n**Resolved IPs:** {_md_text(', '.join(h.resolved_ips))}\n"
    if h.hostnames:
        md += f"\n**Hostnames (reverse DNS):** {_md_text(', '.join(h.hostnames))}\n"
    if h.geolocation and h.geolocation.get("country"):
        geo = h.geolocation
        md += (
            f"\n**Geolocation:** {_md_text(geo.get('city', ''))}, {_md_text(geo['country'])}"
            f" -- {_md_text(geo.get('isp') or geo.get('org') or 'unknown ISP/org')}"
            f" ({_md_text(geo.get('asn', 'unknown ASN'))})\n"
        )
    if h.whois and h.whois.get("parsed"):
        p = h.whois["parsed"]
        md += (
            f"\n**WHOIS:** Registrar: {_md_text(p.get('registrar', 'unknown'))},"
            f" Created: {_md_text(p.get('creation_date', 'unknown'))},"
            f" Expires: {_md_text(p.get('expiration_date', 'unknown'))}\n"
        )
    if h.dnssec_enabled is not None:
        md += f"\n**DNSSEC:** {'Enabled' if h.dnssec_enabled else 'Not enabled'}\n"
    if h.ip_reputation and h.ip_reputation.get("listed") is not None:
        rep = h.ip_reputation
        if rep.get("listed"):
            md += f"\n**IP Reputation:** LISTED -- {_md_text(', '.join(rep.get('reasons', [])))}\n"
        else:
            md += "\n**IP Reputation:** Clean (Spamhaus ZEN)\n"
    if h.subdomains:
        shown = ", ".join(_md_text(item) for item in h.subdomains[:50])
        suffix = " ..." if len(h.subdomains) > 50 else ""
        md += f"\n**Subdomains found ({len(h.subdomains)}):** {shown}{suffix}\n"
    if h.open_ports:
        md += "\n**Open ports:**\n\n| Port | Service | Detail |\n|------|---------|--------|\n"
        for port, info in h.open_ports.items():
            info = info or {}
            detail = (
                info.get("version_guess")
                or (info.get("tls") or {}).get("subject_cn")
                or (info.get("banner") or "")[:60]
            )
            md += (
                f"| {_md_text(port)} | {_md_text(info.get('service', ''))}"
                f" | {_md_text(detail)} |\n"
            )

    if h.cve_matches or h.cve_lookup_note:
        md += "\n### CVE Correlations\n"
        md += (
            "\n> Verified rows matched a CPE version range. Unverified rows are NVD "
            "keyword candidates and require manual confirmation before reporting.\n"
        )
        if h.cve_lookup_note:
            md += f"\n> {_md_text(h.cve_lookup_note)}\n"
        if h.cve_matches:
            md += (
                "\n| CVE | Severity | Score | Product/Version | Applicability | NVD | ExploitDB |\n"
                "|-----|----------|-------|------------------|---------------|-----|-----------|\n"
            )
            for cve in h.cve_matches:
                applicability = "CPE range" if cve.get("applicability_verified") else "keyword only"
                md += (
                    f"| {_md_text(cve.get('cve_id', ''))} | {_md_text(cve.get('cvss_severity', 'unscored'))}"
                    f" | {_md_text(cve.get('cvss_score', '-'))}"
                    f" | {_md_text(cve.get('product', ''))} {_md_text(cve.get('version', ''))}"
                    f" | {applicability}"
                    f" | [NVD]({_md_url(cve.get('nvd_url'))})"
                    f" | [ExploitDB]({_md_url(cve.get('exploitdb_search_url'))}) |\n"
                )

    if h.api_documentation:
        md += f"\n**Exposed API documentation:** {_md_text(', '.join(h.api_documentation))}\n"
    if h.discovered_endpoints:
        md += f"\n### Discovered Endpoints ({len(h.discovered_endpoints)})\n\n"
        for ep in h.discovered_endpoints[:200]:
            md += f"- {_md_text(ep, 1000)}\n"
    if h.url_parameters:
        md += f"\n**URL/form parameters seen:** {_md_text(', '.join(h.url_parameters[:100]))}\n"

    findings = await _load_findings(scan_id, db)
    md += f"\n## Findings ({len(findings)})\n"
    if not findings:
        md += "\nNo findings were recorded for this scan.\n"
    else:
        for f in findings:
            triage = f.triage_status or (
                "false_positive" if f.is_false_positive else "open"
            )
            md += (
                f"\n### [{_md_text((f.severity or 'info').upper(), 20)}] "
                f"{_md_text(f.title, 300)}\n"
                f"\n- **Type:** {_md_text(f.finding_type, 100)}\n"
            )
            if f.location:
                md += f"- **Location:** `{_md_text(f.location, 500)}`\n"
            if triage != "open":
                md += f"- **Triage:** {_md_text(triage, 40)}\n"
            if f.description:
                md += f"\n**Description:** {_md_text(f.description, 2000)}\n"
            if f.evidence:
                md += f"\n**Evidence:**\n\n```text\n{_md_block(f.evidence)}\n```\n"
            if f.remediation:
                md += f"\n**Remediation:** {_md_text(f.remediation, 2000)}\n"

    md += "\n## Phases\n"
    for phase in report.phases:
        md += (
            f"\n### {_md_text(phase.phase_name)}\n"
            f"- Status: {_md_text(phase.status)}\n"
            f"- Findings: {phase.findings_count}\n"
        )

    md += "\n## Endpoints\n"
    for ep in report.endpoints[:50]:
        md += f"- `{_md_text(ep, 1000)}`\n"

    return PlainTextResponse(
        content=md,
        media_type="text/markdown",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_export_filename(report.target_url, scan_id, "md")}"'
            )
        },
    )


@router.get("/{scan_id}/export/html")
async def export_html(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export a scan report as a self-contained HTML file.

    Every value here is attacker-influenced: target names, URLs, response
    headers, banners, extracted endpoints, CVE descriptions. Escape them all
    before interpolation, and set a restrictive CSP on the response so an
    exported report cannot execute target-supplied markup when opened.
    """
    report = await get_report(scan_id, db)
    h = report.highlights

    def e(value) -> str:
        return html_escape("" if value is None else str(value), quote=True)

    def safe_https_url(value) -> str:
        return value if isinstance(value, str) and value.startswith("https://") else "#"

    risk_color = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#2563eb",
    }.get(str(report.summary.risk_level), "#6b7280")

    parts = []
    add = parts.append

    add(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Leadline Report - {e(report.target_name)}</title>
<style>
    body {{ font-family: system-ui, -apple-system, Arial, sans-serif; margin: 40px; color: #1f2937; }}
    h1 {{ color: #111827; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin: 20px 0; }}
    .card {{ background: #f5f5f5; padding: 16px; border-radius: 8px; }}
    .card h3 {{ margin: 0 0 8px 0; color: #666; font-size: 13px; text-transform: uppercase; letter-spacing: .04em; }}
    .card .value {{ font-size: 24px; font-weight: 700; color: #111827; }}
    table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
    th {{ background: #f9fafb; }}
    .endpoint {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }}
    .note {{ color: #92400e; background: #fef3c7; padding: 10px; border-radius: 6px; }}
    .finding {{ border: 1px solid #e5e7eb; border-radius: 8px; padding: 14px 16px; margin: 14px 0; page-break-inside: avoid; }}
    .finding-head {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 6px; }}
    .sev {{ display: inline-block; padding: 2px 7px; border-radius: 4px; color: #fff; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }}
    .sev-critical {{ background: #dc2626; }}
    .sev-high {{ background: #ea580c; }}
    .sev-medium {{ background: #ca8a04; }}
    .sev-low {{ background: #2563eb; }}
    .sev-info {{ background: #6b7280; }}
    .muted {{ color: #6b7280; font-size: 12px; }}
    .evidence {{ white-space: pre-wrap; overflow-wrap: anywhere; background: #f9fafb; border-left: 3px solid #9ca3af; padding: 10px 12px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: #1f2937; }}
    .triage {{ background: #f3f4f6; color: #4b5563; padding: 2px 7px; border-radius: 4px; font-size: 11px; }}
</style>
</head>
<body>
<h1>Leadline Report</h1>
<p><strong>Target:</strong> {e(report.target_name)} ({e(report.target_url)})</p>
<p><strong>Status:</strong> {e(report.status)} | <strong>Completed:</strong> {e(report.completed_at)}</p>
<h2 style="color:{risk_color}">Overall Risk: {e(str(report.summary.risk_level).upper())} ({e(report.summary.risk_score)}/100)</h2>
<p><em>Derived from the highest-severity findings present, not just total finding count. Header and CVE results are indicative and require verification.</em></p>

<h2>Summary</h2>
<div class="summary">
""")

    cards = [
        ("Endpoints", report.summary.total_endpoints),
        ("API Routes", report.summary.api_routes),
        ("Auth Mechanisms", report.summary.authentication_mechanisms),
        ("Debug Interfaces", report.summary.debug_interfaces),
        ("Suspicious Params", report.summary.suspicious_parameters),
        ("Possible Vulns", report.summary.possible_vulns),
        ("Missing Controls", report.summary.missing_controls),
        ("Open Ports", report.summary.open_ports_found),
        ("High Risk Ports", report.summary.high_risk_ports),
        ("CVE Candidates", report.summary.cves_found),
        ("Verified CVEs", report.summary.verified_cves),
    ]
    for label, value in cards:
        add(f'<div class="card"><h3>{e(label)}</h3><div class="value">{e(value)}</div></div>\n')
    add("</div>\n<h2>Highlights</h2>\n")

    def para(label, text):
        add(f"<p><strong>{e(label)}:</strong> {e(text)}</p>\n")

    if h.technologies:
        para("Technologies", ", ".join(h.technologies))
    if h.cdn_waf:
        para("CDN/WAF", ", ".join(h.cdn_waf))
    if h.response_headers:
        add("<h3>Response headers</h3>\n<pre class=\"evidence\">")
        for key, value in h.response_headers.items():
            add(f"{e(key)}: {e(value)}\n")
        add("</pre>\n")
    if h.security_headers_present:
        para("Security headers present", ", ".join(h.security_headers_present))
    if h.security_headers_missing:
        para("Security headers missing", ", ".join(h.security_headers_missing))
    if h.resolved_ips:
        para("Resolved IPs", ", ".join(h.resolved_ips))
    if h.hostnames:
        para("Hostnames", ", ".join(h.hostnames))
    if h.geolocation and h.geolocation.get("country"):
        geo = h.geolocation
        location = ", ".join(x for x in (geo.get("city"), geo.get("country")) if x)
        para("Geolocation", f"{location} -- {geo.get('isp') or geo.get('org') or 'unknown ISP/org'}")
    if h.whois and h.whois.get("parsed"):
        para("WHOIS registrar", h.whois["parsed"].get("registrar", "unknown"))
    if h.dnssec_enabled is not None:
        para("DNSSEC", "Enabled" if h.dnssec_enabled else "Not enabled")
    if h.ip_reputation and h.ip_reputation.get("listed") is not None:
        if h.ip_reputation.get("listed"):
            para("IP reputation", "LISTED -- " + ", ".join(h.ip_reputation.get("reasons", [])))
        else:
            para("IP reputation", "Clean (Spamhaus ZEN)")
    if h.subdomains:
        para("Subdomains found", ", ".join(h.subdomains[:50]))
    if h.open_ports:
        add("<h3>Open Ports</h3>\n<table><tr><th>Port</th><th>Service</th><th>Detail</th></tr>\n")
        for port, info in h.open_ports.items():
            info = info or {}
            detail = (
                info.get("version_guess")
                or (info.get("tls") or {}).get("subject_cn")
                or (info.get("banner") or "")[:60]
            )
            add(f"<tr><td>{e(port)}</td><td>{e(info.get('service', ''))}</td><td>{e(detail)}</td></tr>\n")
        add("</table>\n")

    if h.cve_matches or h.cve_lookup_note:
        add("<h3>CVE Correlations</h3>\n")
        if h.cve_lookup_note:
            add(f'<p class="note">{e(h.cve_lookup_note)}</p>\n')
        if h.cve_matches:
            add(
                "<p>Verified rows matched a CPE version range. Keyword-only rows are "
                "NVD candidates and require manual confirmation.</p>\n"
            )
            add(
                "<table><tr><th>CVE</th><th>Severity</th><th>Score</th>"
                "<th>Product</th><th>Applicability</th><th>Links</th></tr>\n"
            )
            for c in h.cve_matches:
                nvd = safe_https_url(c.get("nvd_url"))
                exploit = safe_https_url(c.get("exploitdb_search_url"))
                links = (
                    f'<a href="{e(nvd)}" rel="noopener noreferrer">NVD</a> / '
                    f'<a href="{e(exploit)}" rel="noopener noreferrer">ExploitDB</a>'
                )
                applicability = (
                    "CPE range" if c.get("applicability_verified") else "keyword only"
                )
                add(
                    f"<tr><td>{e(c.get('cve_id', ''))}</td><td>{e(c.get('cvss_severity', 'unscored'))}</td>"
                    f"<td>{e(c.get('cvss_score', '-'))}</td><td>{e(c.get('product', ''))} {e(c.get('version', ''))}</td>"
                    f"<td>{applicability}</td><td>{links}</td></tr>\n"
                )
            add("</table>\n")

    if h.api_documentation:
        para("Exposed API documentation", ", ".join(h.api_documentation))
    if h.discovered_endpoints:
        add(f"<h3>Discovered Endpoints ({e(len(h.discovered_endpoints))})</h3>\n<ul>\n")
        for ep in h.discovered_endpoints[:200]:
            add(f"<li>{e(ep)}</li>\n")
        add("</ul>\n")
    if h.url_parameters:
        para("URL/form parameters seen", ", ".join(h.url_parameters[:100]))

    findings = await _load_findings(scan_id, db)
    add(f"<h2>Findings ({len(findings)})</h2>\n")
    if not findings:
        add("<p>No findings were recorded for this scan.</p>\n")
    else:
        for f in findings:
            severity = (f.severity or "info").lower()
            if severity not in ("critical", "high", "medium", "low"):
                severity = "info"
            triage = f.triage_status or (
                "false_positive" if f.is_false_positive else "open"
            )
            triage_html = (
                f'<span class="triage">{e(triage.replace("_", " "))}</span>'
                if triage != "open" else ""
            )
            add('<div class="finding">\n')
            add(
                f'<div class="finding-head"><span class="sev sev-{severity}">'
                f'{e(severity)}</span><strong>{e(f.title)}</strong>'
                f'<span class="muted">{e((f.finding_type or "").replace("_", " "))}</span>'
                f'{triage_html}</div>\n'
            )
            if f.location:
                add(f'<div class="muted endpoint">{e(f.location)}</div>\n')
            if f.description:
                add(f"<p>{e(f.description)}</p>\n")
            if f.evidence:
                add(
                    '<div class="muted"><strong>Evidence</strong></div>\n'
                    f'<pre class="evidence">{e(f.evidence)}</pre>\n'
                )
            if f.remediation:
                add(f"<p><strong>Remediation:</strong> {e(f.remediation)}</p>\n")
            add("</div>\n")

    add("<h2>Phases</h2>\n<table><tr><th>Phase</th><th>Status</th><th>Findings</th></tr>\n")
    for phase in report.phases:
        add(f"<tr><td>{e(phase.phase_name)}</td><td>{e(phase.status)}</td><td>{e(phase.findings_count)}</td></tr>\n")
    add("</table>\n")

    if report.endpoints:
        add("<h2>Endpoints</h2>\n<ul>\n")
        for ep in report.endpoints[:50]:
            add(f'<li><span class="endpoint">{e(ep)}</span></li>\n')
        add("</ul>\n")

    add("</body>\n</html>\n")

    return HTMLResponse(
        content="".join(parts),
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_export_filename(report.target_url, scan_id, "html")}"'
            ),
            # Defense in depth: nothing in a report needs to load or execute.
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/{scan_id}/export/pdf")
async def export_pdf(scan_id: int, db: AsyncSession = Depends(get_db)):
    """Export report as a formatted PDF."""
    report = await get_report(scan_id, db)

    # get_report()'s FullReport only carries aggregate summary counts, not
    # the individual findings -- fetch those directly so the PDF can list
    # each one (title, severity, evidence, remediation) rather than just
    # totals.
    findings = await _load_findings(scan_id, db)

    pdf_bytes = generate_report_pdf(
        scan_id=report.scan_id,
        target_name=report.target_name,
        target_url=report.target_url,
        status=report.status,
        created_at=report.created_at,
        completed_at=report.completed_at,
        summary=report.summary.model_dump(),
        highlights=report.highlights.model_dump(),
        phases=[p.model_dump() for p in report.phases],
        findings=[
            {
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "location": f.location,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "triage_status": f.triage_status or (
                    "false_positive" if f.is_false_positive else "open"
                ),
            }
            for f in findings
        ],
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{_export_filename(report.target_url, scan_id, "pdf")}"'
            )
        },
    )
