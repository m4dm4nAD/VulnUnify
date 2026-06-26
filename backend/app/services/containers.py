"""Import uploaded container scan reports and summarize scanned images."""
from __future__ import annotations

import structlog
from sqlalchemy import case, func, select

from backend.app.db import SessionLocal
from backend.app.models.asset import Asset
from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.services.container_reports import parse_report
from backend.app.services.ingest import ingest_findings
from backend.app.services.lifecycle import apply_lifecycle

log = structlog.get_logger()


def import_report(tool: str, content: str) -> dict:
    """Parse a scan report, ingest its findings, and resolve fixed ones per image.

    Resolution is scoped to (source, image) so re-uploading a scan resolves
    vulnerabilities that are no longer present for that image — without touching
    other images or sources.
    """
    findings = parse_report(tool, content)
    seen_by_image: dict[str, set] = {}
    for f in findings:
        seen_by_image.setdefault(f.asset.identifier, set()).add(f.fingerprint())

    if not findings:
        return {"tool": tool, "images": [], "findings": 0, "resolved": 0}

    source = findings[0].source
    with SessionLocal() as db:
        result = ingest_findings(db, findings)
        resolved = 0
        for image, seen in seen_by_image.items():
            asset = db.scalar(select(Asset).where(Asset.identifier == image))
            if asset is None:
                continue
            stale = db.scalars(
                select(Finding).where(
                    Finding.source == source,
                    Finding.asset_id == asset.id,
                    Finding.resolved_at.is_(None),
                )
            )
            for finding in stale:
                if finding.fingerprint not in seen:
                    finding.resolved_at = utcnow()
                    apply_lifecycle(finding)
                    resolved += 1
        db.commit()
    log.info("containers.imported", tool=tool, images=len(seen_by_image),
             findings=result["total"], resolved=resolved)
    return {"tool": tool, "images": sorted(seen_by_image), "findings": result["total"],
            "resolved": resolved}


def list_images() -> list[dict]:
    """Container images with their open-finding counts (for the Containers page)."""
    with SessionLocal() as db:
        rows = db.execute(
            select(
                Asset.identifier,
                func.count(Finding.id),
                func.sum(case((Finding.severity == "critical", 1), else_=0)),
            )
            .join(Finding, Finding.asset_id == Asset.id)
            .where(Finding.category == "container", Finding.effective_status == "open")
            .group_by(Asset.identifier)
            .order_by(func.count(Finding.id).desc())
        ).all()
    return [{"image": img, "open": int(n), "critical": int(c or 0)} for img, n, c in rows]
