"""Read-only settings the UI surfaces (non-secret config)."""
from __future__ import annotations

from fastapi import APIRouter

from backend.app.config import settings
from backend.app.scheduler import schedule_status

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
def get_settings():
    """Non-secret runtime config: scheduler state and the SLA policy.

    These are configured via environment variables (.env); this endpoint just
    exposes the current values so the Settings page can display them.
    """
    return {
        "scheduler": schedule_status(),
        "sla_days": {
            "critical": settings.sla_critical_days,
            "high": settings.sla_high_days,
            "medium": settings.sla_medium_days,
            "low": settings.sla_low_days,
        },
    }
