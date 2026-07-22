"""Asset inventory API: browse assets + set business criticality.

Criticality feeds the risk score, so setting it here rescopes that asset's
findings. Security-team only.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.services import assets

router = APIRouter(prefix="/api/assets", tags=["assets"])


class CriticalityIn(BaseModel):
    criticality: str   # critical | high | medium | low


@router.get("")
def list_assets(db: Session = Depends(get_db), _: User = Depends(require_security)):
    """All assets with open-finding count, top risk, and KEV exposure."""
    return assets.list_assets(db)


@router.patch("/{asset_id}")
def set_criticality(asset_id: int, body: CriticalityIn,
                    db: Session = Depends(get_db), _: User = Depends(require_security)):
    """Set an asset's business criticality (rescoring its findings)."""
    try:
        row = assets.set_criticality(db, asset_id, body.criticality)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if row is None:
        raise HTTPException(404, "asset not found")
    return row
