"""Target history: timeline snapshots and scan-to-scan diffs.

Kept separate from the report router so the same logic can serve the API,
the UI, and future exports without duplicating fingerprint/diff rules.
"""
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Finding, Scan, ScanEvent, Target
from app.risk import compute_risk, severity_counts


ENDPOINT_TYPES = {"endpoint_discovered", "api_endpoint"}
TERMINAL_STATUSES = {"completed", "stopped"}


def _iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _finding_key(finding: Finding) -> str:
    metadata = finding.extra_data or {}
    if metadata.get("cve_id"):
        return f"cve:{metadata['cve_id']}"
    location = (finding.location or "").strip()
    title = " ".join((finding.title or "").lower().split())
    return f"{finding.finding_type or 'unknown'}|{location}|{title}"


def serialize_finding(finding: Finding) -> Dict[str, Any]:
    triage_status = finding.triage_status or (
        "false_positive" if finding.is_false_positive else "open"
    )
    return {
        "id": finding.id,
        "key": _finding_key(finding),
        "type": finding.finding_type,
        "severity": finding.severity,
        "title": finding.title,
        "description": (finding.description or "")[:1200],
        "location": finding.location,
        "evidence": (finding.evidence or "")[:1200],
        "remediation": (finding.remediation or "")[:1200],
        "metadata": finding.extra_data or {},
        "is_false_positive": bool(finding.is_false_positive),
        "triage_status": triage_status,
        "triage_note": finding.triage_note,
        "triaged_at": _iso(finding.triaged_at),
        "created_at": _iso(finding.created_at),
    }


def _events_by_phase(events: Iterable[ScanEvent]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    for event in events:
        result[event.phase_name] = event.result_data or {}
    return result


def _endpoints(findings: Iterable[Finding], phases: Dict[str, Dict[str, Any]]) -> List[str]:
    endpoints = set()

    for finding in findings:
        if finding.finding_type in ENDPOINT_TYPES and finding.location:
            endpoints.add(finding.location)

    for item in (phases.get("api_discovery") or {}).get("api_endpoints") or []:
        if isinstance(item, dict) and item.get("url"):
            endpoints.add(item["url"])

    for url in (phases.get("js_analysis") or {}).get("extracted_endpoints") or []:
        if isinstance(url, str):
            endpoints.add(url)

    graph = phases.get("graph_builder") or {}
    for node in graph.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        if node.get("type") in {"endpoint", "api", "admin", "debug", "javascript"}:
            value = node.get("id") or node.get("label")
            if value:
                endpoints.add(value)

    return sorted(endpoints)[:1000]


def _ports(phases: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    result: Dict[str, Dict[str, Any]] = {}
    raw = (phases.get("port_scan") or {}).get("open_ports") or {}
    for port, info in raw.items():
        info = info or {}
        tls = info.get("tls") or {}
        result[str(port)] = {
            "service": info.get("service"),
            "version": info.get("version_guess"),
            "banner": (info.get("banner") or "")[:200] or None,
            "tls_subject": tls.get("subject_cn"),
            "tls_issuer": tls.get("issuer_cn"),
            "tls_expires": tls.get("not_after"),
        }
    return dict(sorted(result.items(), key=lambda item: int(item[0])))


def _dns_records(phases: Dict[str, Dict[str, Any]]) -> Dict[str, List[str]]:
    raw = (phases.get("host_intel") or {}).get("dns_records") or {}
    if not isinstance(raw, dict):
        return {}
    records: Dict[str, List[str]] = {}
    for record_type, values in raw.items():
        if record_type.startswith("_") or values is None:
            continue
        if not isinstance(values, list):
            values = [values]
        records[record_type] = sorted({str(value) for value in values})
    return records


def _whois(phases: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    whois = (phases.get("host_intel") or {}).get("whois") or {}
    parsed = whois.get("parsed") or {}
    return {
        "registrar": parsed.get("registrar"),
        "created": parsed.get("creation_date"),
        "expires": parsed.get("expiration_date"),
        "updated": parsed.get("updated_date"),
        "name_servers": sorted(parsed.get("name_servers") or []),
    }


def _technologies(phases: Dict[str, Dict[str, Any]]) -> List[str]:
    tech_data = phases.get("tech_detection") or {}
    return sorted({
        item.get("technology")
        for item in tech_data.get("technologies") or []
        if isinstance(item, dict) and item.get("technology")
    })


def build_snapshot(
    scan: Scan,
    findings: List[Finding],
    events: List[ScanEvent],
) -> Dict[str, Any]:
    phases = _events_by_phase(events)
    host = phases.get("host_intel") or {}
    scores = severity_counts(findings)
    risk_score, risk_level = compute_risk(findings)

    subdomains = (host.get("subdomains") or {}).get("subdomains") or []
    security_headers = phases.get("security_headers") or {}

    started = scan.started_at or scan.created_at
    finished = scan.completed_at
    duration = None
    if started and finished:
        try:
            duration = max(0, int((finished - started).total_seconds()))
        except TypeError:
            # Older SQLite rows can mix naive/aware datetimes.
            duration = None

    serialized = {}
    for finding in findings:
        item = serialize_finding(finding)
        serialized[item["key"]] = item

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "progress": scan.progress,
        "current_phase": scan.current_phase,
        "created_at": _iso(scan.created_at),
        "started_at": _iso(scan.started_at),
        "completed_at": _iso(scan.completed_at),
        "duration_seconds": duration,
        "error_message": scan.error_message,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "severity_counts": scores,
        "finding_count": len(findings),
        "verified_cves": len([
            f for f in findings
            if f.finding_type == "cve_match"
            and (f.extra_data or {}).get("applicability_verified")
        ]),
        "unverified_cves": len([
            f for f in findings
            if f.finding_type == "cve_match"
            and not (f.extra_data or {}).get("applicability_verified")
        ]),
        "findings": serialized,
        "endpoints": _endpoints(findings, phases),
        "resolved_ips": sorted({str(ip) for ip in (host.get("resolved_ips") or [])}),
        "hostnames": sorted({str(name) for name in (host.get("hostnames") or [])}),
        "dns_records": _dns_records(phases),
        "subdomains": sorted({str(name) for name in subdomains}),
        "whois": _whois(phases),
        "dnssec_enabled": (host.get("dnssec") or {}).get("enabled"),
        "ip_reputation": host.get("ip_reputation"),
        "ports": _ports(phases),
        "technologies": _technologies(phases),
        "cdn_waf": sorted(((phases.get("tech_detection") or {}).get("cdn_waf") or {}).keys()),
        "security_headers_present": sorted({
            item.get("name", str(item)) if isinstance(item, dict) else str(item)
            for item in security_headers.get("present_headers") or []
        }),
        "security_headers_missing": sorted({
            item.get("name", str(item)) if isinstance(item, dict) else str(item)
            for item in security_headers.get("missing_headers") or []
        }),
    }


def _diff_sets(previous: Iterable[str], current: Iterable[str]) -> Dict[str, List[str]]:
    before, after = set(previous), set(current)
    return {"added": sorted(after - before), "removed": sorted(before - after)}


def _diff_ports(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    before, after = set(previous), set(current)
    changed = []
    for port in sorted(before & after, key=lambda value: int(value)):
        if previous[port] != current[port]:
            changed.append({
                "port": port,
                "before": previous[port],
                "after": current[port],
            })
    return {
        "opened": sorted(after - before, key=lambda value: int(value)),
        "closed": sorted(before - after, key=lambda value: int(value)),
        "changed": changed,
    }


def _diff_dns(previous: Dict[str, List[str]], current: Dict[str, List[str]]) -> Dict[str, Any]:
    added: Dict[str, List[str]] = {}
    removed: Dict[str, List[str]] = {}
    for record_type in set(previous) | set(current):
        change = _diff_sets(previous.get(record_type, []), current.get(record_type, []))
        if change["added"]:
            added[record_type] = change["added"]
        if change["removed"]:
            removed[record_type] = change["removed"]
    return {"added": added, "removed": removed}


def _diff_whois(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    changed = {}
    for field in set(previous) | set(current):
        if previous.get(field) != current.get(field):
            changed[field] = {"before": previous.get(field), "after": current.get(field)}
    return changed


def diff_snapshots(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, Any]:
    previous_findings = previous.get("findings") or {}
    current_findings = current.get("findings") or {}

    new_findings = [
        current_findings[key] for key in sorted(set(current_findings) - set(previous_findings))
    ]
    removed_findings = [
        previous_findings[key] for key in sorted(set(previous_findings) - set(current_findings))
    ]

    changed_findings = []
    for key in sorted(set(previous_findings) & set(current_findings)):
        before, after = previous_findings[key], current_findings[key]
        changes = []
        for field in ("severity", "title", "triage_status", "is_false_positive"):
            if before.get(field) != after.get(field):
                changes.append({
                    "field": field,
                    "before": before.get(field),
                    "after": after.get(field),
                })
        if changes:
            changed_findings.append({"key": key, "before": before, "after": after, "changes": changes})

    ports = _diff_ports(previous.get("ports") or {}, current.get("ports") or {})
    endpoints = _diff_sets(previous.get("endpoints") or [], current.get("endpoints") or [])
    ips = _diff_sets(previous.get("resolved_ips") or [], current.get("resolved_ips") or [])
    subdomains = _diff_sets(previous.get("subdomains") or [], current.get("subdomains") or [])
    technologies = _diff_sets(previous.get("technologies") or [], current.get("technologies") or [])
    cdn_waf = _diff_sets(previous.get("cdn_waf") or [], current.get("cdn_waf") or [])
    headers = _diff_sets(
        previous.get("security_headers_present") or [],
        current.get("security_headers_present") or [],
    )

    summary = {
        "new_findings": len(new_findings),
        "removed_findings": len(removed_findings),
        "changed_findings": len(changed_findings),
        "ports_opened": len(ports["opened"]),
        "ports_closed": len(ports["closed"]),
        "ports_changed": len(ports["changed"]),
        "endpoints_added": len(endpoints["added"]),
        "endpoints_removed": len(endpoints["removed"]),
        "ips_added": len(ips["added"]),
        "ips_removed": len(ips["removed"]),
        "subdomains_added": len(subdomains["added"]),
        "subdomains_removed": len(subdomains["removed"]),
        "technologies_added": len(technologies["added"]),
        "technologies_removed": len(technologies["removed"]),
    }

    return {
        "from_scan": _snapshot_summary(previous),
        "to_scan": _snapshot_summary(current),
        "summary": summary,
        "findings": {
            "new": new_findings,
            "removed": removed_findings,
            "changed": changed_findings,
        },
        "endpoints": endpoints,
        "ports": ports,
        "resolved_ips": ips,
        "subdomains": subdomains,
        "technologies": technologies,
        "cdn_waf": cdn_waf,
        "security_headers_present": headers,
        "dns_records": _diff_dns(previous.get("dns_records") or {}, current.get("dns_records") or {}),
        "whois": _diff_whois(previous.get("whois") or {}, current.get("whois") or {}),
        "dnssec": {
            "before": previous.get("dnssec_enabled"),
            "after": current.get("dnssec_enabled"),
            "changed": previous.get("dnssec_enabled") != current.get("dnssec_enabled"),
        },
    }


def _snapshot_summary(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    keys = (
        "scan_id", "status", "created_at", "completed_at", "duration_seconds",
        "risk_score", "risk_level", "severity_counts", "finding_count",
        "verified_cves", "unverified_cves",
    )
    return {key: snapshot.get(key) for key in keys}


async def load_target_history(db: AsyncSession, target: Target) -> Dict[str, Any]:
    """Return a target timeline plus the latest full diff.

    Snapshots are built from findings and phase events in two batched queries
    so a target with dozens of scans does not produce an N+1 query pattern.
    """
    scans = (await db.execute(
        select(Scan)
        .where(Scan.target_id == target.id)
        .order_by(Scan.created_at.asc(), Scan.id.asc())
    )).scalars().all()

    scan_ids = [scan.id for scan in scans]
    findings_by_scan: Dict[int, List[Finding]] = {scan_id: [] for scan_id in scan_ids}
    events_by_scan: Dict[int, List[ScanEvent]] = {scan_id: [] for scan_id in scan_ids}

    if scan_ids:
        findings = (await db.execute(
            select(Finding).where(Finding.scan_id.in_(scan_ids)).order_by(Finding.id.asc())
        )).scalars().all()
        for finding in findings:
            findings_by_scan.setdefault(finding.scan_id, []).append(finding)

        events = (await db.execute(
            select(ScanEvent).where(ScanEvent.scan_id.in_(scan_ids)).order_by(ScanEvent.phase_order.asc())
        )).scalars().all()
        for event in events:
            events_by_scan.setdefault(event.scan_id, []).append(event)

    snapshots = [
        build_snapshot(scan, findings_by_scan.get(scan.id, []), events_by_scan.get(scan.id, []))
        for scan in scans
    ]

    terminal = [snapshot for snapshot in snapshots if snapshot["status"] in TERMINAL_STATUSES]
    latest_diff = None
    if len(terminal) >= 2:
        latest_diff = diff_snapshots(terminal[-2], terminal[-1])

    # Compact change counts against the previous terminal scan, for the
    # timeline. Full details stay in latest_diff / the diff endpoint.
    previous_terminal = None
    timeline = []
    for snapshot in snapshots:
        changes = None
        if snapshot["status"] in TERMINAL_STATUSES and previous_terminal is not None:
            changes = diff_snapshots(previous_terminal, snapshot)["summary"]
        timeline.append({
            **_snapshot_summary(snapshot),
            "progress": snapshot["progress"],
            "current_phase": snapshot["current_phase"],
            "error_message": snapshot["error_message"],
            "changes": changes,
        })
        if snapshot["status"] in TERMINAL_STATUSES:
            previous_terminal = snapshot

    return {
        "target": {
            "id": target.id,
            "name": target.name,
            "url": target.url,
            "notes": target.notes,
            "is_active": target.is_active,
            "created_at": _iso(target.created_at),
            "updated_at": _iso(target.updated_at),
            "custom_headers": sorted((target.custom_headers or {}).keys()),
        },
        "scans": timeline,
        "latest_diff": latest_diff,
        "totals": {
            "scans": len(scans),
            "completed": len([s for s in scans if s.status == "completed"]),
            "failed": len([s for s in scans if s.status == "failed"]),
            "latest_scan_id": scans[-1].id if scans else None,
            "first_scan_at": _iso(scans[0].created_at) if scans else None,
            "latest_scan_at": _iso(scans[-1].created_at) if scans else None,
        },
    }


async def load_diff(
    db: AsyncSession,
    target: Target,
    from_scan_id: int,
    to_scan_id: int,
) -> Dict[str, Any]:
    scans = (await db.execute(
        select(Scan).where(
            Scan.id.in_([from_scan_id, to_scan_id]),
            Scan.target_id == target.id,
        )
    )).scalars().all()
    by_id = {scan.id: scan for scan in scans}
    if from_scan_id not in by_id or to_scan_id not in by_id:
        raise ValueError("Both scans must exist and belong to this target")

    snapshots = {}
    for scan_id in (from_scan_id, to_scan_id):
        scan = by_id[scan_id]
        findings = (await db.execute(
            select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.id.asc())
        )).scalars().all()
        events = (await db.execute(
            select(ScanEvent).where(ScanEvent.scan_id == scan_id).order_by(ScanEvent.phase_order.asc())
        )).scalars().all()
        snapshots[scan_id] = build_snapshot(scan, list(findings), list(events))

    return diff_snapshots(snapshots[from_scan_id], snapshots[to_scan_id])
