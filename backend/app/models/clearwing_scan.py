"""ClearwingScan: an on-demand source-code vulnerability hunt.

EXPERIMENTAL (lab). Wraps Clearwing's `sourcehunt` pipeline as a background job.
Each scan targets a Git repo, runs for a while (minutes→hours), and on success
ingests its findings into the unified findings table under source "clearwing".
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base


class ClearwingScan(Base):
    __tablename__ = "clearwing_scans"

    id: Mapped[int] = mapped_column(primary_key=True)

    repo_url: Mapped[str] = mapped_column(String(1024))
    branch: Mapped[str] = mapped_column(String(256), default="main")
    depth: Mapped[str] = mapped_column(String(16), default="standard")   # quick|standard|deep
    budget_usd: Mapped[float] = mapped_column(Float, default=0.0)

    # Pipeline options (deepened sourcehunt). Off by default — exploit development
    # and PR creation are opt-in per scan.
    exploit: Mapped[bool] = mapped_column(Boolean, default=False)         # multi-turn exploit dev
    auto_patch: Mapped[bool] = mapped_column(Boolean, default=False)      # generate validated patches
    auto_pr: Mapped[bool] = mapped_column(Boolean, default=False)         # open a draft PR via gh
    disclosures: Mapped[bool] = mapped_column(Boolean, default=False)     # MITRE/HackerOne templates

    # queued | running | succeeded | failed
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    stage: Mapped[str | None] = mapped_column(String(32))                # coarse pipeline stage
    activity: Mapped[str | None] = mapped_column(String(256))            # live "doing X" detail
    session_id: Mapped[str | None] = mapped_column(String(128))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text)

    # Richer result metrics from SourceHuntResult.
    verified_count: Mapped[int] = mapped_column(Integer, default=0)
    exploited_count: Mapped[int] = mapped_column(Integer, default=0)
    files_ranked: Mapped[int] = mapped_column(Integer, default=0)
    files_hunted: Mapped[int] = mapped_column(Integer, default=0)
    tokens_used: Mapped[int] = mapped_column(Integer, default=0)
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    exit_code: Mapped[int | None] = mapped_column(Integer)

    # Report artifacts, read from SourceHuntResult.output_paths and stored inline.
    sarif: Mapped[str | None] = mapped_column(Text)                      # SARIF JSON (GH code scanning)
    report_markdown: Mapped[str | None] = mapped_column(Text)            # human-readable markdown report

    # Who started it (kept even if the user is later deleted).
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    user: Mapped["User | None"] = relationship("User")  # noqa: F821

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
