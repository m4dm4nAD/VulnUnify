"""Asset: the host, cloud resource, or repository a finding is about."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Canonical identifier, unique per asset (hostname, IP, cloud id, repo URL).
    identifier: Mapped[str] = mapped_column(String(512), unique=True, index=True)
    asset_type: Mapped[str] = mapped_column(String(32), index=True)
    name: Mapped[str | None] = mapped_column(String(512))
    cloud_provider: Mapped[str | None] = mapped_column(String(32))
    region: Mapped[str | None] = mapped_column(String(64))
    asset_metadata: Mapped[dict] = mapped_column(JSONB, default=dict)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    findings: Mapped[list["Finding"]] = relationship(  # noqa: F821
        back_populates="asset", cascade="all, delete-orphan"
    )
