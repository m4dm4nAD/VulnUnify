"""IntelFeed: a configured threat-intelligence source.

Two built-in feeds ship enabled (CISA KEV, EPSS) and can be toggled but not
deleted; users add their own `cve_list` feeds — any URL that yields CVE ids —
whose CVEs get flagged as watchlisted and nudged up in risk. Run status is
recorded per feed so the UI can show freshness / failures.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Integer, String, Text, false, func, true
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base

# Feed kinds. kev/epss are built-in fetchers; cve_list is the user-addable type.
FEED_KINDS = ("kev", "epss", "cve_list")


class IntelFeed(Base):
    __tablename__ = "intel_feeds"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(16))          # kev | epss | cve_list
    url: Mapped[str | None] = mapped_column(String(1024))  # source URL (cve_list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())
    builtin: Mapped[bool] = mapped_column(  # kev/epss — can't delete
        Boolean, default=False, server_default=false()
    )

    # Last-run status, for the feeds page.
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(16))    # ok | error
    last_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")  # CVEs contributed
    last_error: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
