"""Recent error log (read-only). Security team only."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from backend.app.api.deps import require_security
from backend.app.models.user import User
from backend.app.services import errorlog

router = APIRouter(prefix="/api/errors", tags=["errors"])


class ErrorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    message: str
    detail: str | None
    created_at: datetime


@router.get("", response_model=list[ErrorOut])
def list_errors(limit: int = 100, _: User = Depends(require_security)):
    return errorlog.recent(limit)
