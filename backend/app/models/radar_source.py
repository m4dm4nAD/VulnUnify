"""RadarSource: a curated account whose posts we scan for vulnerability chatter.

The allowlist IS the primary signal/noise control — we only ever read from
hand-picked researchers/orgs, never the open firehose. Platforms are free,
keyless public APIs (Mastodon, Bluesky).
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, func, true
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class RadarSource(Base):
    __tablename__ = "radar_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    platform: Mapped[str] = mapped_column(String(16), index=True)   # mastodon | bluesky
    # mastodon: local username; bluesky: the actor handle (e.g. name.bsky.social)
    handle: Mapped[str] = mapped_column(String(255))
    # mastodon home instance host (e.g. infosec.exchange); null for bluesky
    instance: Mapped[str | None] = mapped_column(String(255))
    display_name: Mapped[str | None] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    # 1..10, nudges an item's confidence — a high-trust source's chatter ranks up.
    trust_weight: Mapped[int] = mapped_column(Integer, default=5, server_default="5")

    # Resolved account id (mastodon numeric id / bluesky DID), cached after lookup.
    account_ref: Mapped[str | None] = mapped_column(String(255))
    # Last post seen, so each poll only pulls what's new (mastodon since_id / a
    # bluesky timestamp watermark).
    cursor: Mapped[str | None] = mapped_column(String(255))

    last_polled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(16))     # ok | error
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
