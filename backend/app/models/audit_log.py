"""AuditLog: who did what, when — an append-only trail of security-relevant actions.

One row per action: auth events, triage/assignment, config and user changes,
manual sync/intel triggers. actor_username is denormalized so history survives
user deletion (actor_id goes NULL, the name stays); a NULL username means the
system itself (scheduler). Secret VALUES are never stored — hooks record which
keys changed, not what they were set to.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class AuditLog(Base):
    __tablename__ = "audit_log"
    __table_args__ = (
        # "history of this object" lookups (e.g. one finding's triage trail)
        Index("ix_audit_log_target", "target_type", "target_id"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    actor_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    actor_username: Mapped[str | None] = mapped_column(String(128), index=True)
    ip: Mapped[str | None] = mapped_column(String(64))

    # Dotted verb, e.g. "auth.login", "finding.triage", "connector.configure".
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(32))
    target_id: Mapped[str | None] = mapped_column(String(256))

    # One human-readable line; structured before/after specifics go in details.
    summary: Mapped[str] = mapped_column(String(512))
    details: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
