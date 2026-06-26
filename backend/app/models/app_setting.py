"""AppSetting: a runtime-editable override for a config value (key/value).

When present, it overrides the corresponding environment/.env default. Used for
the SLA windows and sync interval so they can be changed from the UI without a
restart.
"""
from __future__ import annotations

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(256))
