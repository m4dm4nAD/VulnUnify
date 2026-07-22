"""Notification settings schema."""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class NotificationSettingsIn(BaseModel):
    # None = leave unchanged; "" = clear the webhook (disables notifications).
    webhook_url: str | None = Field(None, max_length=1024)
    # 0 disables the high-risk rule (KEV + SLA-breach alerts still fire).
    risk_threshold: int | None = Field(None, ge=0, le=100)

    @field_validator("webhook_url")
    @classmethod
    def _http_scheme(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if v and not v.startswith(("https://", "http://")):
            raise ValueError("webhook_url must be an http(s) URL")
        return v
