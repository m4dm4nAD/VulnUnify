"""Finding: one normalized issue from one source, linked to an asset."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base, TimestampMixin, utcnow


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

    # Status as reported by the source connector.
    source_status: Mapped[str] = mapped_column(String(32), default="open")
    # Status VulnUnify shows, derived from lifecycle + triage (see services/lifecycle).
    effective_status: Mapped[str] = mapped_column(String(32), index=True, default="open")

    # Lifecycle: set when the source stops reporting the finding; cleared on reopen.
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Triage: a local human decision that survives connector re-syncs.
    triage_state: Mapped[str] = mapped_column(String(32), default="active", index=True)
    triage_reason: Mapped[str | None] = mapped_column(Text)
    triage_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triaged_by: Mapped[str | None] = mapped_column(String(128))

    # SLA deadline derived from first_seen + per-severity window.
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

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

    # Assignment: the dev (or any user) responsible for this finding.
    assigned_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    assigned_user: Mapped["User | None"] = relationship("User")  # noqa: F821

    @property
    def assigned_username(self) -> str | None:
        return self.assigned_user.username if self.assigned_user else None

    @property
    def age_days(self) -> int | None:
        """Days since the finding was first seen."""
        if self.first_seen is None:
            return None
        return (utcnow() - self.first_seen).days

    @property
    def sla_breached(self) -> bool:
        """True when an open finding is past its SLA deadline."""
        return bool(
            self.sla_due_at is not None
            and self.effective_status == "open"
            and self.sla_due_at < utcnow()
        )
