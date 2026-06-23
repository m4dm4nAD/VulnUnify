"""Read API for the unified findings + dashboard stats."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from backend.app.db import get_db
from backend.app.models.asset import Asset
from backend.app.models.finding import Finding
from backend.app.schemas.finding import FindingOut, FindingPage, StatsOut

router = APIRouter(prefix="/api", tags=["findings"])


@router.get("/findings", response_model=FindingPage)
def list_findings(
    db: Session = Depends(get_db),
    source: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    status: str | None = None,
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
    if status:
        stmt = stmt.where(Finding.status == status)
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


@router.get("/stats", response_model=StatsOut)
def stats(db: Session = Depends(get_db)):
    """Aggregate counts powering the dashboard summary cards."""

    def grouped(column):
        rows = db.execute(select(column, func.count()).group_by(column)).all()
        return {str(k): v for k, v in rows}

    return StatsOut(
        total_findings=db.scalar(select(func.count()).select_from(Finding)) or 0,
        total_assets=db.scalar(select(func.count()).select_from(Asset)) or 0,
        by_severity=grouped(Finding.severity),
        by_category=grouped(Finding.category),
        by_source=grouped(Finding.source),
    )
