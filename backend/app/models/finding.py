"""Finding: one normalized issue from one source, linked to an asset."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text, false
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
    source_status: Mapped[str] = mapped_column(String(32), default="open", server_default="open")
    # Status VulnUnify shows, derived from lifecycle + triage (see services/lifecycle).
    effective_status: Mapped[str] = mapped_column(
        String(32), index=True, default="open", server_default="open"
    )

    # Lifecycle: set when the source stops reporting the finding; cleared on reopen.
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Set when a previously-resolved finding is reported active again, so MTTR
    # measures the recurrence (reopened_at -> resolved_at), not the full lifetime.
    reopened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Triage: a local human decision that survives connector re-syncs.
    triage_state: Mapped[str] = mapped_column(
        String(32), default="active", server_default="active", index=True
    )
    triage_reason: Mapped[str | None] = mapped_column(Text)
    triage_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    triaged_by: Mapped[str | None] = mapped_column(String(128))

    # SLA deadline derived from first_seen + per-severity window.
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # Composite risk score (0..100) from severity/CVSS + threat intel (KEV, EPSS)
    # + asset criticality. Recomputed by services/intel; stored + indexed so the
    # findings queue can sort by "what to fix first" rather than raw severity.
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, server_default="0", index=True)
    # Denormalized threat-intel flags (max across the finding's CVEs), set during
    # risk recompute so the findings list can badge/filter without a per-CVE join.
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), index=True)
    epss_score: Mapped[float | None] = mapped_column(Float)   # 0..1, highest of its CVEs
    watchlisted: Mapped[bool] = mapped_column(  # custom feed
        Boolean, default=False, server_default=false(), index=True
    )

    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    cwe_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    cvss_base_score: Mapped[float | None] = mapped_column(Float)
    cvss_vector: Mapped[str | None] = mapped_column(String(128))

    location: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    remediation: Mapped[str | None] = mapped_column(Text)
    refs: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    tags: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    raw: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")

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
