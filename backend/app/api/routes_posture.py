"""Posture trends: history series for the dashboard (security team only —
snapshots are org-wide, unlike /api/stats which scopes per role)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.db import get_db
from backend.app.services import posture

router = APIRouter(prefix="/api/posture", tags=["posture"])


@router.get("/trends")
def get_trends(
    days: int = Query(90, ge=7, le=365),
    db: Session = Depends(get_db),
):
    """Snapshot series (from first snapshot onward) + retroactive MTTR/velocity."""
    return posture.trends(db, days=days)


@router.post("/snapshot")
def snapshot_now(db: Session = Depends(get_db)):
    """Take a snapshot now. Bypasses the hourly throttle but still honors a
    60s floor (and the cross-process lock), so it can't be looped into
    unbounded table growth / aggregate-scan load."""
    snap = posture.take_snapshot(db, force=True)
    if snap is None:
        return {"skipped": True, "reason": "a snapshot was taken moments ago"}
    return {"skipped": False, "taken_at": snap.taken_at.isoformat(), "open_total": snap.open_total}
