"""Finding: one normalized issue from one source, linked to an asset."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Dedup/upsert key — see NormalizedFinding.fingerprint().
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True, index=True)

    source: Mapped[str] = mapped_column(String(64), index=True)
    source_finding_id: Mapped[str] = mapped_column(String(256))
    category: Mapped[str] = mapped_column(String(32), index=True)

    title: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    raw_severity: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32), index=True, default="open")

    cve_ids: Mapped[list] = mapped_column(JSONB, default=list)
    cwe_ids: Mapped[list] = mapped_column(JSONB, default=list)
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))

    location: Mapped[dict] = mapped_column(JSONB, default=dict)
    remediation: Mapped[str | None] = mapped_column(Text)
    refs: Mapped[list] = mapped_column(JSONB, default=list)
    tags: Mapped[dict] = mapped_column(JSONB, default=dict)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)

    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    asset: Mapped["Asset"] = relationship(back_populates="findings")  # noqa: F821
