"""Manage the watched-package inventory (import from manifests, list, delete)."""
from __future__ import annotations

import structlog
from sqlalchemy import delete as sql_delete
from sqlalchemy import func, select

from backend.app.db import SessionLocal
from backend.app.models.base import utcnow
from backend.app.models.watched_package import WatchedPackage
from backend.app.services.manifests import parse_manifest

log = structlog.get_logger()


def import_manifest(filename: str, content: str, source: str | None = None) -> dict:
    """Parse a manifest and upsert its packages under a source label."""
    parsed = parse_manifest(filename, content)
    src = (source or filename).strip()[:256]
    now = utcnow()
    added = 0
    with SessionLocal() as db:
        for p in parsed:
            existing = db.scalar(
                select(WatchedPackage).where(
                    WatchedPackage.ecosystem == p.ecosystem,
                    WatchedPackage.name == p.name,
                    WatchedPackage.version == p.version,
                    WatchedPackage.source == src,
                )
            )
            if existing:
                existing.last_seen = now
            else:
                db.add(
                    WatchedPackage(
                        ecosystem=p.ecosystem, name=p.name, version=p.version,
                        source=src, first_seen=now, last_seen=now,
                    )
                )
                added += 1
        db.commit()
    log.info("packages.imported", source=src, parsed=len(parsed), added=added)
    return {
        "source": src,
        "parsed": len(parsed),
        "added": added,
        "ecosystems": sorted({p.ecosystem for p in parsed}),
    }


def list_packages(ecosystem: str | None = None, source: str | None = None):
    with SessionLocal() as db:
        stmt = select(WatchedPackage).order_by(WatchedPackage.ecosystem, WatchedPackage.name)
        if ecosystem:
            stmt = stmt.where(WatchedPackage.ecosystem == ecosystem)
        if source:
            stmt = stmt.where(WatchedPackage.source == source)
        return db.scalars(stmt).all()


def summary() -> dict:
    """Counts by ecosystem + by source, for the Packages page header."""
    with SessionLocal() as db:
        total = db.scalar(select(func.count()).select_from(WatchedPackage)) or 0
        by_eco = dict(
            db.execute(
                select(WatchedPackage.ecosystem, func.count()).group_by(WatchedPackage.ecosystem)
            ).all()
        )
    return {"total": total, "by_ecosystem": {str(k): v for k, v in by_eco.items()}}


def delete_package(package_id: int) -> bool:
    with SessionLocal() as db:
        pkg = db.get(WatchedPackage, package_id)
        if pkg is None:
            return False
        db.delete(pkg)
        db.commit()
        return True


def clear_source(source: str) -> int:
    with SessionLocal() as db:
        result = db.execute(
            sql_delete(WatchedPackage).where(WatchedPackage.source == source)
        )
        db.commit()
        return result.rowcount or 0
