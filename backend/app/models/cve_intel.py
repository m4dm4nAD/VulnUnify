"""CveIntel: threat-intelligence facts about a CVE, used to prioritize findings.

One row per CVE that appears in our findings. Populated by intel feeds (CISA KEV,
EPSS, and user-added custom sources) and joined to findings by CVE id to drive the
composite `risk_score`. Findings reference CVEs many-to-one, so intel lives here
(per CVE) rather than duplicated on every finding row.
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, String, false, func
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base, utcnow


class CveIntel(Base):
    __tablename__ = "cve_intel"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. CVE-2021-44228

    # CISA Known Exploited Vulnerabilities — actively exploited in the wild.
    in_kev: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false(), index=True)
    kev_date_added: Mapped[date | None] = mapped_column(Date)
    kev_ransomware: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    # EPSS (FIRST.org) — probability of exploitation in the next 30 days.
    epss_score: Mapped[float | None] = mapped_column(Float)        # 0..1
    epss_percentile: Mapped[float | None] = mapped_column(Float)   # 0..1

    # Flagged by a user-added custom feed (a CVE the org is actively watching).
    watchlisted: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=false(), index=True
    )

    # Which feed(s) last touched this row (comma-joined), for provenance in the UI.
    sources: Mapped[str | None] = mapped_column(String(256))

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now()
    )
