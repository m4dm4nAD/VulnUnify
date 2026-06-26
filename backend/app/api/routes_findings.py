"""Findings API: list/detail/triage/assign + dashboard stats.

Access is role-scoped: security_admin/security_user see everything; a dev only
ever sees findings assigned to them. The scope is applied in SQL, so a dev
cannot read or act on a finding outside their queue.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, case, func, select, true
from sqlalchemy.orm import Session, joinedload

from backend.app.api.deps import require_security, require_user
from backend.app.db import get_db
from backend.app.models.asset import Asset
from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.models.user import User
from backend.app.schemas.finding import (
    FindingDetail,
    FindingOut,
    FindingPage,
    StatsOut,
    TriageIn,
)
from backend.app.schemas.user import AssignIn
from backend.app.services.lifecycle import apply_lifecycle

router = APIRouter(prefix="/api", tags=["findings"])

_SUPPRESSED = ("false_positive", "accepted_risk", "snoozed")
_SECURITY_ROLES = ("security_admin", "security_user")
_LOADS = (joinedload(Finding.asset), joinedload(Finding.assigned_user))

# Rank used so the default sort puts critical findings first.
_SEV_RANK = case(
    (Finding.severity == "critical", 4),
    (Finding.severity == "high", 3),
    (Finding.severity == "medium", 2),
    (Finding.severity == "low", 1),
    else_=0,
)
_SORT_COLS = {
    "severity": _SEV_RANK,
    "status": Finding.effective_status,
    "title": Finding.title,
    "source": Finding.source,
    "age": Finding.first_seen,  # older first_seen == higher age
}


def _scope(actor: User):
    """Row-level scope: only the security team sees everything; every other role
    (dev, or any unknown/future role) is restricted to findings assigned to them."""
    if actor.role in _SECURITY_ROLES:
        return true()
    return Finding.assigned_user_id == actor.id


def _overdue_clause():
    return and_(
        Finding.effective_status == "open",
        Finding.sla_due_at.is_not(None),
        Finding.sla_due_at < utcnow(),
    )


@router.get("/findings", response_model=FindingPage)
def list_findings(
    db: Session = Depends(get_db),
    actor: User = Depends(require_user),
    source: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    effective_status: str | None = None,
    triage_state: str | None = None,
    assigned_to: int | None = Query(None, description="filter by assignee (security only)"),
    overdue: bool | None = Query(None, description="only SLA-breached open findings"),
    q: str | None = Query(None, description="substring match on title"),
    sort: str = Query("severity", description="severity|status|title|source|age"),
    order: str = Query("desc", description="asc|desc"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """List findings (devs see only their assigned ones), critical-first by default."""
    stmt = select(Finding).options(*_LOADS).where(_scope(actor))
    if source:
        stmt = stmt.where(Finding.source == source)
    if category:
        stmt = stmt.where(Finding.category == category)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if effective_status:
        stmt = stmt.where(Finding.effective_status == effective_status)
    if triage_state:
        stmt = stmt.where(Finding.triage_state == triage_state)
    if assigned_to is not None and actor.role in _SECURITY_ROLES:
        stmt = stmt.where(Finding.assigned_user_id == assigned_to)
    if overdue:
        stmt = stmt.where(_overdue_clause())
    if q:
        stmt = stmt.where(Finding.title.ilike(f"%{q}%"))

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))

    col = _SORT_COLS.get(sort, _SEV_RANK)
    descending = order != "asc"
    if sort == "age":
        descending = not descending  # "age desc" means oldest (earliest first_seen) first
    stmt = stmt.order_by(col.desc() if descending else col.asc(), Finding.id.desc())
    rows = db.scalars(stmt.limit(limit).offset(offset)).all()
    return FindingPage(total=total or 0, limit=limit, offset=offset, items=rows)


def _load_for_actor(db: Session, finding_id: int, actor: User) -> Finding:
    finding = db.scalar(select(Finding).options(*_LOADS).where(Finding.id == finding_id))
    # 404 (not 403) for devs out of scope, so existence isn't leaked.
    if finding is None or (actor.role == "dev" and finding.assigned_user_id != actor.id):
        raise HTTPException(404, "finding not found")
    return finding


@router.get("/findings/{finding_id}", response_model=FindingDetail)
def get_finding(
    finding_id: int, db: Session = Depends(get_db), actor: User = Depends(require_user)
):
    """Full finding detail, including the original source payload (`raw`)."""
    return _load_for_actor(db, finding_id, actor)


@router.post("/findings/{finding_id}/triage", response_model=FindingOut)
def triage_finding(
    finding_id: int,
    body: TriageIn,
    db: Session = Depends(get_db),
    actor: User = Depends(require_user),
):
    """Apply a triage decision. Devs may triage only their own assigned findings."""
    finding = _load_for_actor(db, finding_id, actor)
    finding.triage_state = body.state.value
    finding.triage_reason = body.reason
    finding.triage_until = body.until
    finding.triaged_at = utcnow()
    finding.triaged_by = actor.username
    apply_lifecycle(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/findings/{finding_id}/assign", response_model=FindingOut)
def assign_finding(
    finding_id: int,
    body: AssignIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_security),
):
    """Assign (or unassign with user_id=null) a finding. Security team only."""
    finding = db.scalar(select(Finding).options(*_LOADS).where(Finding.id == finding_id))
    if finding is None:
        raise HTTPException(404, "finding not found")
    if body.user_id is not None and db.get(User, body.user_id) is None:
        raise HTTPException(404, "assignee user not found")
    finding.assigned_user_id = body.user_id
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db), actor: User = Depends(require_user)):
    """Aggregate counts (scoped to the actor). Breakdowns count OPEN findings."""
    scope = _scope(actor)
    open_only = Finding.effective_status == "open"

    def count(*where) -> int:
        return db.scalar(select(func.count()).select_from(Finding).where(scope, *where)) or 0

    def grouped(column):
        rows = db.execute(
            select(column, func.count()).where(scope, open_only).group_by(column)
        ).all()
        return {str(k): v for k, v in rows}

    breached_rows = db.execute(
        select(Finding.severity, func.count())
        .where(scope, _overdue_clause())
        .group_by(Finding.severity)
    ).all()

    if actor.role == "dev":
        total_assets = db.scalar(
            select(func.count(func.distinct(Finding.asset_id))).where(scope)
        )
    else:
        total_assets = db.scalar(select(func.count()).select_from(Asset))

    return StatsOut(
        total_findings=count(),
        total_assets=total_assets or 0,
        open_findings=count(open_only),
        resolved_findings=count(Finding.effective_status == "resolved"),
        suppressed_findings=count(Finding.effective_status.in_(_SUPPRESSED)),
        sla_breached=count(_overdue_clause()),
        by_severity=grouped(Finding.severity),
        by_category=grouped(Finding.category),
        by_source=grouped(Finding.source),
        breached_by_severity={str(k): v for k, v in breached_rows},
    )
