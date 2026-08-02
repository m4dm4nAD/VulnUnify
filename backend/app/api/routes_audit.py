"""Audit trail (security_admin only — rows carry IPs and config-change detail)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security_admin
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.services import audit

router = APIRouter(prefix="/api/audit", tags=["audit"],
                   dependencies=[Depends(require_security_admin)])


@router.get("")
def list_audit(
    actor: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    q: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Newest-first audit rows; `action` matches exactly or as a prefix group
    (action=finding matches finding.triage, finding.assign, ...)."""
    return audit.search(db, actor=actor, action=action, target_type=target_type,
                        target_id=target_id, q=q, limit=limit, offset=offset)


@router.get("/actions")
def list_actions(db: Session = Depends(get_db), _: User = Depends(require_security_admin)):
    """Distinct action names present, for the filter dropdown."""
    return audit.actions(db)
