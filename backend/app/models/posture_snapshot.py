"""PostureSnapshot: a periodic point-in-time rollup of security posture.

Findings are upserted in place, so without these rows historical posture is
unrecoverable — trends only exist from the first snapshot onward. Taken by the
scheduler (and on startup / manual sync), throttled to at most one per hour by
services/posture.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class PostureSnapshot(Base):
    __tablename__ = "posture_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    taken_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    # Open findings, total and by severity (effective_status == "open").
    open_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_critical: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_high: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_medium: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_low: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    open_info: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    resolved_total: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    # Exposure: open findings that are KEV-listed / past their SLA deadline.
    kev_open: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    sla_breached_open: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    avg_risk_open: Mapped[float] = mapped_column(Float, default=0.0, server_default="0")

    # Open count per source, e.g. {"tenable": 12, "wiz": 4}.
    by_source: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
