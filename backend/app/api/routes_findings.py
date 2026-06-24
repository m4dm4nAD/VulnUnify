"""Read + triage API for the unified findings, plus dashboard stats."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import and_, func, select
from sqlalchemy.orm import Session, joinedload

from backend.app.db import get_db
from backend.app.models.asset import Asset
from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.schemas.finding import FindingOut, FindingPage, StatsOut, TriageIn
from backend.app.services.lifecycle import apply_lifecycle

router = APIRouter(prefix="/api", tags=["findings"])

_SUPPRESSED = ("false_positive", "accepted_risk", "snoozed")


def _overdue_clause():
    """An open finding past its SLA deadline."""
    return and_(
        Finding.effective_status == "open",
        Finding.sla_due_at.is_not(None),
        Finding.sla_due_at < utcnow(),
    )


@router.get("/findings", response_model=FindingPage)
def list_findings(
    db: Session = Depends(get_db),
    source: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    effective_status: str | None = None,
    triage_state: str | None = None,
    overdue: bool | None = Query(None, description="only SLA-breached open findings"),
    q: str | None = Query(None, description="substring match on title"),
    limit: int = Query(50, le=500),
    offset: int = 0,
):
    """List normalized findings across all tools, with filters."""
    stmt = select(Finding).options(joinedload(Finding.asset))
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
    if overdue:
        stmt = stmt.where(_overdue_clause())
    if q:
        stmt = stmt.where(Finding.title.ilike(f"%{q}%"))

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.order_by(Finding.id.desc()).limit(limit).offset(offset)).all()
    return FindingPage(total=total or 0, limit=limit, offset=offset, items=rows)


@router.get("/findings/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    finding = db.scalar(
        select(Finding).options(joinedload(Finding.asset)).where(Finding.id == finding_id)
    )
    if finding is None:
        raise HTTPException(404, "finding not found")
    return finding


@router.post("/findings/{finding_id}/triage", response_model=FindingOut)
def triage_finding(finding_id: int, body: TriageIn, db: Session = Depends(get_db)):
    """Apply a local triage decision (false positive / accepted risk / snooze).

    This survives connector re-syncs — the source can keep reporting the finding,
    but VulnUnify keeps showing your decision until you reset it to `active`.
    """
    finding = db.scalar(
        select(Finding).options(joinedload(Finding.asset)).where(Finding.id == finding_id)
    )
    if finding is None:
        raise HTTPException(404, "finding not found")

    finding.triage_state = body.state.value
    finding.triage_reason = body.reason
    finding.triage_until = body.until
    finding.triaged_at = utcnow()
    finding.triaged_by = body.by
    apply_lifecycle(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    """Aggregate counts powering the dashboard. Breakdowns count OPEN findings."""
    open_only = Finding.effective_status == "open"

    def count(*where) -> int:
        return db.scalar(select(func.count()).select_from(Finding).where(*where)) or 0

    def grouped(column):
        rows = db.execute(
            select(column, func.count()).where(open_only).group_by(column)
        ).all()
        return {str(k): v for k, v in rows}

    breached_rows = db.execute(
        select(Finding.severity, func.count()).where(_overdue_clause()).group_by(Finding.severity)
    ).all()

    return StatsOut(
        total_findings=db.scalar(select(func.count()).select_from(Finding)) or 0,
        total_assets=db.scalar(select(func.count()).select_from(Asset)) or 0,
        open_findings=count(open_only),
        resolved_findings=count(Finding.effective_status == "resolved"),
        suppressed_findings=count(Finding.effective_status.in_(_SUPPRESSED)),
        sla_breached=count(_overdue_clause()),
        by_severity=grouped(Finding.severity),
        by_category=grouped(Finding.category),
        by_source=grouped(Finding.source),
        breached_by_severity={str(k): v for k, v in breached_rows},
    )
