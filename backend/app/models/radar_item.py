"""RadarItem: one post that passed the vuln-relevance funnel, normalized.

This is ambient early-warning intel, NOT a finding (a finding is tied to one of
your assets; a researcher's post about a vuln in the wild is not). Items are
correlated to findings by CVE and surfaced on the Radar page; a human confirms
or dismisses. Treat every item as an unconfirmed lead until corroborated.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, String, Text, UniqueConstraint, false,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base, TimestampMixin


class RadarItem(Base, TimestampMixin):
    __tablename__ = "radar_items"
    __table_args__ = (
        # Dedup: a given post is ingested once, even across re-polls / boosts.
        UniqueConstraint("platform", "external_id", name="uq_radar_item_platform_extid"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("radar_sources.id", ondelete="SET NULL"), index=True
    )

    platform: Mapped[str] = mapped_column(String(16))
    external_id: Mapped[str] = mapped_column(String(512))   # post id / uri on the platform
    url: Mapped[str | None] = mapped_column(String(1024))
    author_handle: Mapped[str] = mapped_column(String(255), index=True)
    author_display: Mapped[str | None] = mapped_column(String(255))
    posted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)

    text: Mapped[str] = mapped_column(Text)

    # Extracted / classified fields.
    cve_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    products: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    vuln_type: Mapped[str | None] = mapped_column(String(64))       # rce | lpe | ...
    severity_hint: Mapped[str | None] = mapped_column(String(16))
    poc_mentioned: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())
    summary: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, server_default="0", index=True)
    # Which signals fired (cve/keywords/links/llm) — provenance for the score.
    signals: Mapped[dict] = mapped_column(JSONB, default=dict, server_default="{}")
    classified_by: Mapped[str] = mapped_column(String(16), default="heuristic",
                                               server_default="heuristic")

    # new (unreviewed) | confirmed | dismissed — a human triage decision.
    status: Mapped[str] = mapped_column(String(16), default="new",
                                        server_default="new", index=True)
    # Open findings whose CVEs this item mentions (the correlation payoff).
    matched_finding_ids: Mapped[list] = mapped_column(JSONB, default=list, server_default="[]")
    # Set once when a matched-finding alert is sent, so it fires at most once.
    alerted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
