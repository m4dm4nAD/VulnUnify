"""Editable app-settings schema."""
from __future__ import annotations

from pydantic import BaseModel, Field

_DAYS = Field(None, ge=0, le=3650)


class SettingsUpdateIn(BaseModel):
    sync_interval_minutes: int | None = Field(None, ge=0, le=10080)  # up to a week
    sla_critical_days: int | None = _DAYS
    sla_high_days: int | None = _DAYS
    sla_medium_days: int | None = _DAYS
    sla_low_days: int | None = _DAYS
