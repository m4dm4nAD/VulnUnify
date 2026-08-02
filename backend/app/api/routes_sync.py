"""Trigger connector syncs."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security
from backend.app.connectors.registry import get_connector
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.finding import ConnectorRunOut
from backend.app.scheduler import schedule_status
from backend.app.services import audit
from backend.app.services.ingest import sync_all, sync_connector

router = APIRouter(prefix="/api/sync", tags=["sync"])


@router.post("", response_model=list[ConnectorRunOut])
def sync_everything(request: Request, db: Session = Depends(get_db),
                    actor: User = Depends(require_security)):
    """Run every configured connector and ingest its findings.

    No posture snapshot here: new findings carry in_kev=False / risk_score=0
    until intel.refresh rescoring runs (scheduler path), so a snapshot at this
    point would persist systematically under-reported KEV/risk numbers.
    """
    runs = sync_all(db)
    audit.record(db, "sync.trigger", "triggered a sync of all connectors",
                 actor=actor, request=request,
                 details={"connectors": len(runs),
                          "findings": sum(r.findings_count for r in runs)})
    return runs


@router.get("/schedule")
def get_schedule():
    """Whether the background scheduler is on, its interval, and next run time."""
    return schedule_status()


@router.post("/{connector_name}", response_model=ConnectorRunOut)
def sync_one(connector_name: str, request: Request, db: Session = Depends(get_db),
             actor: User = Depends(require_security)):
    connector = get_connector(connector_name)
    if connector is None:
        raise HTTPException(404, f"unknown connector: {connector_name}")
    run = sync_connector(db, connector)
    audit.record(db, "sync.trigger", f"triggered a sync of {connector_name}",
                 actor=actor, request=request, target_type="connector",
                 target_id=connector_name,
                 details={"status": run.status, "findings": run.findings_count})
    return run
