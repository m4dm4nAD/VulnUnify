"""NotificationLog: one row per (finding, event) alert that was delivered.

The unique constraint is the dedup mechanism — an event fires at most once per
finding, so repeated scheduler runs don't re-alert on the same thing.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class NotificationLog(Base):
    __tablename__ = "notification_log"
    __table_args__ = (
        UniqueConstraint("finding_id", "event", name="uq_notification_log_finding_event"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    # What fired: high_risk | kev | sla_breach (see services/notifications).
    event: Mapped[str] = mapped_column(String(32))
    # The finding's risk score at send time, for post-hoc context.
    risk_score: Mapped[float | None] = mapped_column(Float)
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
