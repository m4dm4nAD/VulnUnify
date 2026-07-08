"""Manage the watched-package inventory (import from manifests, list, delete)
plus the self-service scan history (what devs searched via /scan)."""
from __future__ import annotations

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from backend.app.db import SessionLocal
from backend.app.models.base import utcnow
from backend.app.models.package_scan import PackageScan
from backend.app.models.watched_package import WatchedPackage
from backend.app.services.manifests import ParsedPackage, parse_manifest

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


# --- self-service scan history ---

def record_scan(
    *,
    user_id: int | None,
    filename: str,
    parsed: list[ParsedPackage],
    results: list[dict],
) -> int:
    """Persist what a /scan searched: every parsed package plus its vuln count.

    `parsed` is the full list of packages that were checked; `results` is the
    OSV subset that came back vulnerable (as produced by osv_scan.scan).
    """
    vuln_counts = {
        (r["ecosystem"], r["name"], r["version"]): len(r["vulns"]) for r in results
    }
    pkgs = [
        {
            "ecosystem": p.ecosystem,
            "name": p.name,
            "version": p.version,
            "vuln_count": vuln_counts.get((p.ecosystem, p.name, p.version), 0),
        }
        for p in parsed
    ]
    with SessionLocal() as db:
        scan = PackageScan(
            user_id=user_id,
            filename=filename[:512],
            checked=len(parsed),
            vulnerable=len(results),
            total_vulns=sum(len(r["vulns"]) for r in results),
            ecosystems=sorted({p.ecosystem for p in parsed}),
            packages=pkgs,
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    log.info("packages.scan_recorded", scan_id=scan_id, filename=filename,
             user_id=user_id, checked=len(parsed), vulnerable=len(results))
    return scan_id


def list_scans(limit: int = 50) -> list[dict]:
    """Most-recent scans first, with the searching user's name resolved."""
    with SessionLocal() as db:
        scans = db.scalars(
            select(PackageScan)
            .options(joinedload(PackageScan.user))  # avoid an N+1 on s.user.username
            .order_by(PackageScan.created_at.desc())
            .limit(limit)
        ).all()
        return [
            {
                "id": s.id,
                "filename": s.filename,
                "checked": s.checked,
                "vulnerable": s.vulnerable,
                "total_vulns": s.total_vulns,
                "ecosystems": s.ecosystems,
                "packages": s.packages,
                "username": s.user.username if s.user else None,
                "created_at": s.created_at,
            }
            for s in scans
        ]
