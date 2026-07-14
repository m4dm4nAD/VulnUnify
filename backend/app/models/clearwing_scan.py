"""ClearwingScan: an on-demand source-code vulnerability hunt.

EXPERIMENTAL (lab). Wraps Clearwing's `sourcehunt` pipeline as a background job.
Each scan targets a Git repo, runs for a while (minutes→hours), and on success
ingests its findings into the unified findings table under source "clearwing".
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base


class ClearwingScan(Base):
    __tablename__ = "clearwing_scans"

    id: Mapped[int] = mapped_column(primary_key=True)

    repo_url: Mapped[str] = mapped_column(String(1024))
    branch: Mapped[str] = mapped_column(String(256), default="main")
    depth: Mapped[str] = mapped_column(String(16), default="standard")   # quick|standard|deep
    budget_usd: Mapped[float] = mapped_column(Float, default=0.0)

    # queued | running | succeeded | failed
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    stage: Mapped[str | None] = mapped_column(String(32))                # current pipeline stage
    session_id: Mapped[str | None] = mapped_column(String(128))
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    cost_usd: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text)

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
