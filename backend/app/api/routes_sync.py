"""Trigger connector syncs."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.connectors.registry import get_connector
from backend.app.db import get_db
from backend.app.schemas.finding import ConnectorRunOut
from backend.app.scheduler import schedule_status
from backend.app.services.ingest import sync_all, sync_connector

router = APIRouter(prefix="/api/sync", tags=["sync"])


@router.post("", response_model=list[ConnectorRunOut])
def sync_everything(db: Session = Depends(get_db)):
    """Run every configured connector and ingest its findings.

    No posture snapshot here: new findings carry in_kev=False / risk_score=0
    until intel.refresh rescoring runs (scheduler path), so a snapshot at this
    point would persist systematically under-reported KEV/risk numbers.
    """
    return sync_all(db)


@router.get("/schedule")
def get_schedule():
    """Whether the background scheduler is on, its interval, and next run time."""
    return schedule_status()


@router.post("/{connector_name}", response_model=ConnectorRunOut)
def sync_one(connector_name: str, db: Session = Depends(get_db)):
    connector = get_connector(connector_name)
    if connector is None:
        raise HTTPException(404, f"unknown connector: {connector_name}")
    return sync_connector(db, connector)
