"""PackageScan: a stored record of a self-service /scan run.

The /scan endpoint stays ephemeral for the *watchlist* (it never adds to the
persistent inventory), but we keep a lightweight history of what was searched —
which packages a developer checked, when, and by whom — for auditing and trend
visibility. The searched packages are stored inline as JSON rather than as
watchlist rows, so a dev's ad-hoc check never pollutes the shared watchlist.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.models.base import Base


class PackageScan(Base):
    __tablename__ = "package_scans"

    id: Mapped[int] = mapped_column(primary_key=True)

    # Who ran the scan. Kept (SET NULL) even if the user is later deleted.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    user: Mapped["User | None"] = relationship("User")  # noqa: F821

    filename: Mapped[str] = mapped_column(String(512))

    checked: Mapped[int] = mapped_column(Integer, default=0)       # packages with an exact version
    vulnerable: Mapped[int] = mapped_column(Integer, default=0)    # of those, how many had >=1 vuln
    total_vulns: Mapped[int] = mapped_column(Integer, default=0)

    ecosystems: Mapped[list] = mapped_column(JSONB, default=list)
    # The packages that were searched: [{ecosystem, name, version, vuln_count}].
    packages: Mapped[list] = mapped_column(JSONB, default=list)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
