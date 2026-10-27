"""Findings API: list findings and update triage state.

The target history view needs a way to mark a finding acknowledged or false
positive without editing the database by hand. This router is intentionally
small: it only exposes finding reads and the triage fields.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_db
from app.history import serialize_finding
from app.models import Finding
from app.schemas import FindingTriageUpdate

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
async def list_findings(
    scan_id: Optional[int] = Query(None, ge=1),
    db: AsyncSession = Depends(get_db),
) -> List[dict]:
    """List findings, optionally filtered to one scan."""
    query = select(Finding).order_by(Finding.id.asc())
    if scan_id is not None:
        query = query.where(Finding.scan_id == scan_id)
    result = await db.execute(query)
    return [serialize_finding(finding) for finding in result.scalars().all()]


@router.get("/{finding_id}")
async def get_finding(finding_id: int, db: AsyncSession = Depends(get_db)) -> dict:
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return serialize_finding(finding)


@router.patch("/{finding_id}")
async def update_finding_triage(
    finding_id: int,
    update: FindingTriageUpdate,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Update a finding's triage state.

    `is_false_positive` is kept in sync with `triage_status` so older report
    code and newer timeline code always agree.
    """
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    data = update.model_dump(exclude_unset=True)

    if "is_false_positive" in data and data["is_false_positive"] is not None:
        finding.is_false_positive = data["is_false_positive"]
        if data["is_false_positive"]:
            finding.triage_status = "false_positive"
        elif finding.triage_status in (None, "false_positive"):
            finding.triage_status = "open"

    if data.get("triage_status") is not None:
        finding.triage_status = data["triage_status"]
        finding.is_false_positive = data["triage_status"] == "false_positive"

    if "triage_note" in data:
        finding.triage_note = data["triage_note"]

    if data:
        finding.triaged_at = datetime.now()

    await db.commit()
    await db.refresh(finding)
    return serialize_finding(finding)
