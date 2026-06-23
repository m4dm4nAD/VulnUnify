"""Connector inventory + status."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.connectors.registry import all_connectors
from backend.app.db import get_db
from backend.app.models.connector_run import ConnectorRun
from backend.app.schemas.finding import ConnectorRunOut, ConnectorStatus

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


@router.get("", response_model=list[ConnectorStatus])
def list_connectors(db: Session = Depends(get_db)):
    """List every registered connector, whether it's configured, and its last run."""
    out: list[ConnectorStatus] = []
    for c in all_connectors():
        last = db.scalar(
            select(ConnectorRun)
            .where(ConnectorRun.connector == c.name)
            .order_by(ConnectorRun.started_at.desc())
            .limit(1)
        )
        out.append(
            ConnectorStatus(
                name=c.name,
                category=c.category.value,
                configured=c.is_configured(),
                last_run_at=last.started_at if last else None,
                last_status=last.status if last else None,
                last_findings_count=last.findings_count if last else None,
            )
        )
    return out


@router.get("/runs", response_model=list[ConnectorRunOut])
def list_runs(db: Session = Depends(get_db), limit: int = 50):
    return db.scalars(
        select(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(limit)
    ).all()
