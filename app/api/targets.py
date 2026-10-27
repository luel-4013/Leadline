"""
Leadline - Targets API Router
Phase 2: Target Management - CRUD operations for targets
"""
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List

from app.db import get_db
from app.models import Target
from app.schemas import TargetCreate, TargetUpdate, TargetResponse
from app.history import load_target_history, load_diff

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("", response_model=List[TargetResponse])
async def list_targets(db: AsyncSession = Depends(get_db)):
    """List all targets."""
    result = await db.execute(select(Target).order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
async def create_target(target: TargetCreate, db: AsyncSession = Depends(get_db)):
    """Create a new target."""
    # Check for duplicate URL
    existing = await db.execute(select(Target).where(Target.url == target.url))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target with this URL already exists"
        )

    db_target = Target(**target.model_dump())
    db.add(db_target)
    await db.commit()
    await db.refresh(db_target)
    return db_target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: int, db: AsyncSession = Depends(get_db)):
    """Get a specific target by ID."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    return target


@router.put("/{target_id}", response_model=TargetResponse)
async def update_target(
    target_id: int,
    target_update: TargetUpdate,
    db: AsyncSession = Depends(get_db)
):
    """Update an existing target."""
    # Check if target exists
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    # Update fields
    update_data = target_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(target, field, value)

    await db.commit()
    await db.refresh(target)
    return target


@router.get("/{target_id}/history")
async def get_target_history(target_id: int, db: AsyncSession = Depends(get_db)):
    """Timeline of scans for a target, with the latest scan-to-scan diff.

    History is kept until the target is deleted; there is no automatic
    retention window.
    """
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return await load_target_history(db, target)


@router.get("/{target_id}/history/diff")
async def get_target_diff(
    target_id: int,
    from_scan_id: int = Query(..., ge=1),
    to_scan_id: int = Query(..., ge=1),
    db: AsyncSession = Depends(get_db),
):
    """Full diff between two scans that belong to the same target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    try:
        return await load_diff(db, target, from_scan_id, to_scan_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_target(target_id: int, db: AsyncSession = Depends(get_db)):
    """Delete a target."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()

    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Target not found"
        )

    await db.delete(target)
    await db.commit()
    return None
