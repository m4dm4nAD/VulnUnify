"""Lifecycle maintenance endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.db import get_db
from backend.app.services.lifecycle import recompute_all

router = APIRouter(prefix="/api/lifecycle", tags=["lifecycle"])


@router.post("/recompute")
def recompute(db: Session = Depends(get_db)):
    """Re-derive sla_due_at + effective_status for every finding.

    Run after changing SLA settings or to flush snoozes that expired between
    syncs. The scheduler/sync path keeps these fresh during normal operation.
    """
    count = recompute_all(db)
    return {"recomputed": count}
