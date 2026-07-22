"""Runtime-editable app settings (SLA windows, sync interval, notifications).

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
from backend.app.services import crypto

log = structlog.get_logger()

# Editable keys -> the type their value is cast to. Each key's env/.env default
# is the same-named attribute on Settings.
EDITABLE_KEYS: dict[str, type] = {
    "sync_interval_minutes": int,
    "sla_critical_days": int,
    "sla_high_days": int,
    "sla_medium_days": int,
    "sla_low_days": int,
    "notify_risk_threshold": int,
    "notify_slack_webhook_url": str,
}

# Keys whose DB value is encrypted at rest (same Fernet key as connector
# credentials). A Slack webhook URL is a bearer credential: anyone holding it
# can post to the channel.
SECRET_KEYS = {"notify_slack_webhook_url"}

_cache: dict[str, int | str] | None = None
_lock = threading.Lock()  # the scheduler thread reads while requests may update


def _load() -> dict[str, int | str]:
    global _cache
    with _lock:
        if _cache is None:
            values = {k: cast(getattr(settings, k)) for k, cast in EDITABLE_KEYS.items()}
            with SessionLocal() as db:
                for row in db.scalars(select(AppSetting)):
                    if row.key not in values:
                        continue
                    raw = row.value
                    if row.key in SECRET_KEYS and raw:
                        try:
                            raw = crypto.decrypt(raw)
                        except crypto.InvalidToken:
                            # SECRET_KEY rotated; fall back to the env default.
                            log.warning("app_settings.undecryptable", key=row.key)
                            continue
                    try:
                        values[row.key] = EDITABLE_KEYS[row.key](raw)
                    except (TypeError, ValueError):
                        pass
            _cache = values
        return dict(_cache)  # return a copy so callers can't mutate the shared cache


def get(key: str) -> int | str:
    return _load()[key]


def all_settings() -> dict[str, int | str]:
    return dict(_load())


def update(values: dict[str, int | str]) -> dict[str, int | str]:
    """Persist overrides for known keys and invalidate the cache."""
    global _cache
    with SessionLocal() as db:
        for key, val in values.items():
            if key not in EDITABLE_KEYS:
                continue
            stored = str(EDITABLE_KEYS[key](val))
            if key in SECRET_KEYS and stored:
                stored = crypto.encrypt(stored)
            row = db.get(AppSetting, key)
            if row is None:
                db.add(AppSetting(key=key, value=stored))
            else:
                row.value = stored
        db.commit()
    with _lock:
        _cache = None
    log.info("app_settings.updated", keys=sorted(values))
    return all_settings()


def reset_cache() -> None:
    """Drop the in-process cache (used by tests after truncating the DB)."""
    global _cache
    with _lock:
        _cache = None
