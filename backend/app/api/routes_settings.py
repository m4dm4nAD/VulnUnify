"""App settings: scheduler + SLA policy. Viewable by the security team,
editable by security_admin (changes apply live)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security_admin
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.scheduler import reschedule, schedule_status
from backend.app.schemas.setting import SettingsUpdateIn
from backend.app.services import app_settings, audit
from backend.app.services.lifecycle import recompute_all

router = APIRouter(prefix="/api/settings", tags=["settings"])


def _current() -> dict:
    s = app_settings.all_settings()
    return {
        "scheduler": schedule_status(),
        "sla_days": {
            "critical": s["sla_critical_days"],
            "high": s["sla_high_days"],
            "medium": s["sla_medium_days"],
            "low": s["sla_low_days"],
        },
    }


@router.get("")
def get_settings():
    """Current scheduler state + SLA policy."""
    return _current()


@router.put("")
def update_settings(
    body: SettingsUpdateIn,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_security_admin),
):
    """Edit the sync interval and/or SLA windows; changes take effect immediately."""
    values = body.model_dump(exclude_none=True)
    if values:
        before = {k: app_settings.get(k) for k in values}
        app_settings.update(values)
        # Record right after the change is durable, before the derived-data work
        # (recompute/reschedule) that could still raise — else a persisted config
        # change could leave no trail entry.
        changed = audit.diff(before, values)
        if changed:
            audit.record(db, "settings.update", "updated scheduler/SLA settings",
                         actor=actor, request=request, details=changed)
        if any(k.startswith("sla_") for k in values):
            recompute_all(db)  # re-derive sla_due_at for every finding
        if "sync_interval_minutes" in values:
            reschedule(values["sync_interval_minutes"])
    return _current()
