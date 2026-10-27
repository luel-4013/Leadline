"""Unit tests for scan diffing, CPE version matching, and triage defaults.

These tests do not need network access or a database.
"""
from app.api.reports import _export_filename
from app.history import diff_snapshots
from app.recon.cve_lookup import (
    CVELookupPhase,
    _compare_versions,
    _cpe_prefix,
)


def test_export_filename_uses_target_host_and_scan_id():
    assert (
        _export_filename("https://example.com:8443/app", 7, "pdf")
        == "example.com_8443-scan-7.pdf"
    )
    assert (
        _export_filename("192.168.1.10", 3, ".json")
        == "192.168.1.10-scan-3.json"
    )


def test_export_filename_rejects_path_characters():
    name = _export_filename("https://bad host/../../etc/passwd", 1, "html")
    assert name == "bad-host-scan-1.html"
    assert "/" not in name and "\\" not in name


def _finding(key, title, severity="low", triage="open"):
    return {
        "id": 1,
        "key": key,
        "type": "test",
        "severity": severity,
        "title": title,
        "description": "",
        "location": "/",
        "metadata": {},
        "is_false_positive": triage == "false_positive",
        "triage_status": triage,
        "triage_note": None,
        "triaged_at": None,
        "created_at": None,
    }


def _snapshot(scan_id, findings=None, endpoints=None, ports=None, ips=None):
    return {
        "scan_id": scan_id,
        "status": "completed",
        "created_at": "2026-01-01T00:00:00",
        "completed_at": "2026-01-01T00:01:00",
        "duration_seconds": 60,
        "risk_score": 15,
        "risk_level": "low",
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 1, "info": 0},
        "finding_count": len(findings or {}),
        "verified_cves": 0,
        "unverified_cves": 0,
        "findings": findings or {},
        "endpoints": endpoints or [],
        "ports": ports or {},
        "resolved_ips": ips or [],
        "subdomains": [],
        "technologies": [],
        "cdn_waf": [],
        "dns_records": {},
        "whois": {},
        "dnssec_enabled": None,
        "security_headers_present": [],
    }


def test_diff_detects_new_removed_and_changed_findings():
    previous = _snapshot(1, findings={
        "keep": _finding("keep", "Keep me"),
        "gone": _finding("gone", "Gone"),
        "change": _finding("change", "Change", "low"),
    })
    current = _snapshot(2, findings={
        "keep": _finding("keep", "Keep me"),
        "change": _finding("change", "Change", "high"),
        "new": _finding("new", "New"),
    })

    diff = diff_snapshots(previous, current)
    assert diff["summary"]["new_findings"] == 1
    assert diff["summary"]["removed_findings"] == 1
    assert diff["summary"]["changed_findings"] == 1
    assert diff["findings"]["new"][0]["key"] == "new"
    assert diff["findings"]["removed"][0]["key"] == "gone"
    assert diff["findings"]["changed"][0]["changes"][0]["field"] == "severity"


def test_diff_detects_port_and_endpoint_drift():
    previous = _snapshot(
        1,
        endpoints=["/a", "/b"],
        ports={"22": {"service": "ssh"}, "80": {"service": "http"}},
        ips=["10.0.0.1"],
    )
    current = _snapshot(
        2,
        endpoints=["/b", "/c"],
        ports={"22": {"service": "ssh"}, "443": {"service": "https"}},
        ips=["10.0.0.1", "10.0.0.2"],
    )

    diff = diff_snapshots(previous, current)
    assert diff["ports"]["opened"] == ["443"]
    assert diff["ports"]["closed"] == ["80"]
    assert diff["endpoints"]["added"] == ["/c"]
    assert diff["endpoints"]["removed"] == ["/a"]
    assert diff["resolved_ips"]["added"] == ["10.0.0.2"]


def test_version_comparison_handles_suffixes_and_prereleases():
    assert _compare_versions("1.24.0", "1.24") == 0
    assert _compare_versions("1.25.0", "1.24.9") > 0
    assert _compare_versions("8.9p1", "8.9") > 0
    assert _compare_versions("1.0rc1", "1.0") < 0
    assert _compare_versions("2.0", "2.0.0") == 0


def test_cpe_prefix_extraction():
    assert _cpe_prefix("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*") == "cpe:2.3:a:nginx:nginx"
    assert _cpe_prefix("not-a-cpe") is None


def test_version_in_cpe_range():
    phase = CVELookupPhase("http://example.test", {})

    criteria = "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert phase._version_in_cpe_range("1.24.0", criteria, {
        "versionStartIncluding": "1.20.0",
        "versionEndExcluding": "1.25.3",
    })
    assert not phase._version_in_cpe_range("1.25.3", criteria, {
        "versionStartIncluding": "1.20.0",
        "versionEndExcluding": "1.25.3",
    })

    exact = "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    assert phase._version_in_cpe_range("1.24.0", exact, {})
    assert not phase._version_in_cpe_range("1.24.1", exact, {})
    # Distro package revisions are the same upstream version.
    assert phase._version_in_cpe_range("1.24.0-1ubuntu2", exact, {})
    assert phase._version_in_cpe_range("1.24.0+deb12u1", exact, {})


def test_cpe_match_requires_a_field_boundary():
    phase = CVELookupPhase("http://example.test", {})
    cve = {
        "configurations": [{
            "nodes": [{
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:nginx:nginx_plus:*:*:*:*:*:*:*:*",
                }],
            }],
        }],
    }
    assert phase._match_version(cve, "cpe:2.3:a:nginx:nginx", "1.24.0") is None
