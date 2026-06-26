"""Record and read persisted errors. Logging must never raise."""
from __future__ import annotations

import structlog
from sqlalchemy import select

from backend.app.db import SessionLocal
from backend.app.models.error_log import ErrorLog

log = structlog.get_logger()


def record(source: str, message: str, detail: str | None = None) -> None:
    """Persist an error. Swallows its own failures so it can't break callers."""
    try:
        with SessionLocal() as db:
            db.add(
                ErrorLog(source=(source or "")[:128], message=(message or "")[:512], detail=detail)
            )
            db.commit()
    except Exception as exc:  # noqa: BLE001
        log.error("errorlog.record_failed", error=str(exc))


def recent(limit: int = 100) -> list[ErrorLog]:
    with SessionLocal() as db:
        return db.scalars(select(ErrorLog).order_by(ErrorLog.id.desc()).limit(limit)).all()
