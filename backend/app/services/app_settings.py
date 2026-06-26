"""Runtime-editable app settings (SLA windows + sync interval).

DB values override the env/.env defaults. Values are cached in-process and the
cache is invalidated on update, so hot paths (e.g. SLA recompute over every
finding) don't hit the database per call.
"""
from __future__ import annotations

import threading

import structlog
from sqlalchemy import select

from backend.app.config import settings
from backend.app.db import SessionLocal
from backend.app.models.app_setting import AppSetting

log = structlog.get_logger()

# Editable keys -> their env/.env default attribute on Settings.
EDITABLE_KEYS = (
    "sync_interval_minutes",
    "sla_critical_days",
    "sla_high_days",
    "sla_medium_days",
    "sla_low_days",
)

_cache: dict[str, int] | None = None
_lock = threading.Lock()  # the scheduler thread reads while requests may update


def _load() -> dict[str, int]:
    global _cache
    with _lock:
        if _cache is None:
            values = {k: int(getattr(settings, k)) for k in EDITABLE_KEYS}  # env defaults
            with SessionLocal() as db:
                for row in db.scalars(select(AppSetting)):
                    if row.key in values:
                        try:
                            values[row.key] = int(row.value)
                        except (TypeError, ValueError):
                            pass
            _cache = values
        return dict(_cache)  # return a copy so callers can't mutate the shared cache


def get(key: str) -> int:
    return _load()[key]


def all_settings() -> dict[str, int]:
    return dict(_load())


def update(values: dict[str, int]) -> dict[str, int]:
    """Persist overrides for known keys and invalidate the cache."""
    global _cache
    with SessionLocal() as db:
        for key, val in values.items():
            if key not in EDITABLE_KEYS:
                continue
            row = db.get(AppSetting, key)
            if row is None:
                db.add(AppSetting(key=key, value=str(int(val))))
            else:
                row.value = str(int(val))
        db.commit()
    with _lock:
        _cache = None
    log.info("app_settings.updated", keys=sorted(values))
    return all_settings()
