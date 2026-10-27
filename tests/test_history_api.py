"""Integration tests for the history/diff/triage API.

Seeds two completed scans directly through a separate async engine, then
exercises the same endpoints the UI uses. No network access required.
"""
import asyncio
import os
from datetime import datetime, timedelta

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.models import Finding, Scan, ScanEvent


def _seed_two_scans(target_id: int):
    async def seed():
        engine = create_async_engine(os.environ["DATABASE_URL"])
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        base = datetime(2026, 1, 1, 12, 0, 0)

        async with session_maker() as db:
            first = Scan(
                target_id=target_id,
                status="completed",
                progress=100.0,
                started_at=base,
                completed_at=base + timedelta(seconds=30),
            )
            db.add(first)
            await db.flush()

            db.add_all([
                Finding(
                    scan_id=first.id,
                    finding_type="missing_security_header",
                    severity="low",
                    title="Missing Security Header: X-Frame-Options",
                    location="http://target.test/",
                    evidence="Server: nginx/1.24.0",
                    remediation="Add an X-Frame-Options or frame-ancestors policy.",
                ),
                Finding(
                    scan_id=first.id,
                    finding_type="endpoint_discovered",
                    severity="info",
                    title="Endpoint discovered",
                    location="/old",
                ),
                ScanEvent(
                    scan_id=first.id,
                    phase_name="port_scan",
                    phase_order=3,
                    status="completed",
                    result_data={"open_ports": {"80": {"service": "http"}}},
                ),
            ])

            second = Scan(
                target_id=target_id,
                status="completed",
                progress=100.0,
                started_at=base + timedelta(hours=1),
                completed_at=base + timedelta(hours=1, seconds=30),
            )
            db.add(second)
            await db.flush()

            db.add_all([
                Finding(
                    scan_id=second.id,
                    finding_type="missing_security_header",
                    severity="high",
                    title="Missing Security Header: X-Frame-Options",
                    location="http://target.test/",
                ),
                Finding(
                    scan_id=second.id,
                    finding_type="endpoint_discovered",
                    severity="info",
                    title="Endpoint discovered",
                    location="/new",
                ),
                ScanEvent(
                    scan_id=second.id,
                    phase_name="port_scan",
                    phase_order=3,
                    status="completed",
                    result_data={"open_ports": {"443": {"service": "https"}}},
                ),
            ])
            await db.commit()
            result = (first.id, second.id)
            await engine.dispose()
            return result

    return asyncio.run(seed())


def _delete_scans(scan_ids):
    async def delete():
        engine = create_async_engine(os.environ["DATABASE_URL"])
        session_maker = async_sessionmaker(engine, expire_on_commit=False)
        async with session_maker() as db:
            for scan_id in scan_ids:
                scan = await db.get(Scan, scan_id)
                if scan:
                    await db.delete(scan)
            await db.commit()
            await engine.dispose()

    asyncio.run(delete())


def test_history_diff_and_triage(client):
    created = client.post("/api/targets", json={
        "name": "History API Test",
        "url": "history-api.test",
        "notes": "seeded",
    })
    assert created.status_code == 201
    target_id = created.json()["id"]
    first_id, second_id = _seed_two_scans(target_id)

    history = client.get(f"/api/targets/{target_id}/history")
    assert history.status_code == 200
    data = history.json()
    assert len(data["scans"]) == 2
    assert data["scans"][0]["changes"] is None
    assert data["scans"][1]["changes"]["new_findings"] == 1
    assert data["scans"][1]["changes"]["removed_findings"] == 1
    assert data["scans"][1]["changes"]["ports_opened"] == 1
    assert data["scans"][1]["changes"]["ports_closed"] == 1

    assert data["latest_diff"]["from_scan"]["scan_id"] == first_id
    assert data["latest_diff"]["to_scan"]["scan_id"] == second_id
    assert data["latest_diff"]["summary"]["changed_findings"] == 1

    diff = client.get(
        f"/api/targets/{target_id}/history/diff",
        params={"from_scan_id": first_id, "to_scan_id": second_id},
    )
    assert diff.status_code == 200
    assert diff.json()["endpoints"] == {"added": ["/new"], "removed": ["/old"]}

    # Triage the changed finding from the second scan.
    second_findings = client.get("/api/findings", params={"scan_id": second_id}).json()
    header_finding = next(
        f for f in second_findings
        if f["type"] == "missing_security_header"
    )
    triage = client.patch(
        f"/api/findings/{header_finding['id']}",
        json={"triage_status": "false_positive", "triage_note": "Covered by CSP"},
    )
    assert triage.status_code == 200
    triaged = triage.json()
    assert triaged["triage_status"] == "false_positive"
    assert triaged["is_false_positive"] is True
    assert triaged["triage_note"] == "Covered by CSP"

    # Reopen and verify the boolean stays in sync.
    reopened = client.patch(
        f"/api/findings/{header_finding['id']}",
        json={"triage_status": "open"},
    ).json()
    assert reopened["triage_status"] == "open"
    assert reopened["is_false_positive"] is False

    _delete_scans([first_id, second_id])
    client.delete(f"/api/targets/{target_id}")


def test_exports_are_named_after_target_and_include_findings(client):
    created = client.post("/api/targets", json={
        "name": "Export Format Test",
        "url": "https://export.example:8443/app",
    })
    assert created.status_code == 201
    target_id = created.json()["id"]
    first_id, second_id = _seed_two_scans(target_id)
    base = f"export.example_8443-scan-{first_id}"

    json_export = client.get(f"/api/reports/{first_id}/export/json")
    assert json_export.status_code == 200
    assert f'filename="{base}.json"' in json_export.headers["content-disposition"]
    json_findings = json_export.json()["findings"]
    assert len(json_findings) == 2
    assert json_findings[0]["title"] == "Missing Security Header: X-Frame-Options"
    assert "Server: nginx/1.24.0" in json_findings[0]["evidence"]

    markdown_export = client.get(f"/api/reports/{first_id}/export/markdown")
    assert markdown_export.status_code == 200
    assert f'filename="{base}.md"' in markdown_export.headers["content-disposition"]
    assert "## Findings (2)" in markdown_export.text
    assert "Server: nginx/1.24.0" in markdown_export.text

    html_export = client.get(f"/api/reports/{first_id}/export/html")
    assert html_export.status_code == 200
    assert f'filename="{base}.html"' in html_export.headers["content-disposition"]
    assert "Evidence" in html_export.text
    assert "Server: nginx/1.24.0" in html_export.text

    pdf_export = client.get(f"/api/reports/{first_id}/export/pdf")
    assert pdf_export.status_code == 200
    assert pdf_export.headers["content-type"] == "application/pdf"
    assert f'filename="{base}.pdf"' in pdf_export.headers["content-disposition"]

    _delete_scans([first_id, second_id])
    client.delete(f"/api/targets/{target_id}")


def test_completed_scan_cannot_be_restarted(client):
    """Re-running a terminal scan would duplicate events and findings."""
    created = client.post("/api/targets", json={
        "name": "Restart Guard Test",
        "url": "restart-guard.test",
    })
    assert created.status_code == 201
    target_id = created.json()["id"]
    first_id, second_id = _seed_two_scans(target_id)

    response = client.post(f"/api/scans/{first_id}/start")
    assert response.status_code == 400
    assert "Only pending scans can be started" in response.json()["detail"]

    _delete_scans([first_id, second_id])
    client.delete(f"/api/targets/{target_id}")


def test_delete_scan_removes_history(client):
    created = client.post("/api/targets", json={
        "name": "Delete Scan Test",
        "url": "delete-scan.test",
    })
    assert created.status_code == 201
    target_id = created.json()["id"]
    first_id, second_id = _seed_two_scans(target_id)

    response = client.delete(f"/api/scans/{first_id}")
    assert response.status_code == 204

    history = client.get(f"/api/targets/{target_id}/history").json()
    assert len(history["scans"]) == 1
    assert history["scans"][0]["scan_id"] == second_id
    assert history["latest_diff"] is None

    _delete_scans([second_id])
    client.delete(f"/api/targets/{target_id}")
