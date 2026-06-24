"""WatchedPackage: a dependency we observe for supply-chain risk.

Populated by parsing manifests/lockfiles. The OSV connector reads this inventory
and emits findings for known-vulnerable and malicious package versions.
"""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.models.base import Base


class WatchedPackage(Base):
    __tablename__ = "watched_packages"
    __table_args__ = (
        UniqueConstraint("ecosystem", "name", "version", "source", name="uq_watched_package"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ecosystem: Mapped[str] = mapped_column(String(32), index=True)   # OSV name: npm, PyPI, Go
    name: Mapped[str] = mapped_column(String(512), index=True)
    version: Mapped[str] = mapped_column(String(128))
    source: Mapped[str] = mapped_column(String(256))                 # manifest / project label

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
