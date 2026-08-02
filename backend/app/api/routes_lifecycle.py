"""Lifecycle maintenance endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.services import audit
from backend.app.services.lifecycle import recompute_all

router = APIRouter(prefix="/api/lifecycle", tags=["lifecycle"])


@router.post("/recompute")
def recompute(request: Request, db: Session = Depends(get_db),
              actor: User = Depends(require_security)):
    """Re-derive sla_due_at + effective_status for every finding.

    Run after changing SLA settings or to flush snoozes that expired between
    syncs. The scheduler/sync path keeps these fresh during normal operation.
    """
    count = recompute_all(db)
    audit.record(db, "lifecycle.recompute", f"recomputed lifecycle for {count} findings",
                 actor=actor, request=request, details={"recomputed": count})
    return {"recomputed": count}
