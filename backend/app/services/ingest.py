"""Ingestion + sync orchestration.

`sync_connector` runs one connector and writes its findings; `sync_all` walks
the registry. Assets and findings are upserted (no duplicates across repeated
syncs) using the asset identifier and the finding fingerprint as natural keys.
"""
from __future__ import annotations

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.connectors.base import BaseConnector, NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import FindingStatus
from backend.app.models.asset import Asset
from backend.app.models.base import utcnow
from backend.app.models.connector_run import ConnectorRun
from backend.app.models.finding import Finding
from backend.app.services.lifecycle import apply_lifecycle, resolve_missing

log = structlog.get_logger()


def _upsert_asset(db: Session, na: NormalizedAsset) -> Asset:
    asset = db.scalar(select(Asset).where(Asset.identifier == na.identifier))
    if asset is None:
        asset = Asset(identifier=na.identifier, first_seen=utcnow())
        db.add(asset)
    asset.asset_type = na.asset_type.value
    asset.name = na.name or asset.name
    asset.cloud_provider = na.cloud_provider or asset.cloud_provider
    asset.region = na.region or asset.region
    if na.metadata:
        asset.asset_metadata = {**(asset.asset_metadata or {}), **na.metadata}
    asset.last_seen = utcnow()
    db.flush()
    return asset


def _upsert_finding(db: Session, nf: NormalizedFinding, asset: Asset) -> bool:
    """Returns True if a new finding was created, False if an existing one updated."""
    fp = nf.fingerprint()
    finding = db.scalar(select(Finding).where(Finding.fingerprint == fp))
    created = finding is None
    if finding is None:
        finding = Finding(fingerprint=fp, first_seen=nf.first_seen or utcnow())
        db.add(finding)

    finding.source = nf.source
    finding.source_finding_id = nf.source_finding_id
    finding.category = nf.category.value
    finding.title = nf.title
    finding.description = nf.description
    finding.severity = nf.severity.value
    finding.raw_severity = nf.raw_severity
    finding.source_status = nf.status.value
    finding.cve_ids = nf.cve_ids
    finding.cwe_ids = nf.cwe_ids
    finding.cvss_base_score = nf.cvss_base_score
    finding.cvss_vector = nf.cvss_vector
    finding.location = nf.location
    finding.remediation = nf.remediation
    finding.refs = nf.references
    finding.tags = nf.tags
    finding.raw = nf.raw
    finding.last_seen = nf.last_seen or utcnow()
    finding.asset = asset

    # Lifecycle: the source telling us it's fixed resolves it; otherwise being
    # present in the pull means it's active again (reopen if it was resolved).
    if nf.status == FindingStatus.FIXED:
        finding.resolved_at = nf.last_seen or utcnow()
    else:
        finding.resolved_at = None

    # Triage fields are intentionally left untouched here so local decisions
    # survive re-syncs. Recompute the derived fields from what we just set.
    apply_lifecycle(finding)
    return created


def ingest_findings(db: Session, findings: list[NormalizedFinding]) -> dict[str, int]:
    created = updated = 0
    for nf in findings:
        asset = _upsert_asset(db, nf.asset)
        if _upsert_finding(db, nf, asset):
            created += 1
        else:
            updated += 1
    db.commit()
    return {"created": created, "updated": updated, "total": len(findings)}


def sync_connector(db: Session, connector: BaseConnector) -> ConnectorRun:
    run = ConnectorRun(connector=connector.name, status="success", started_at=utcnow())
    db.add(run)
    db.flush()

    if not connector.is_configured():
        run.status = "skipped"
        run.error = "connector not configured (missing credentials)"
        run.finished_at = utcnow()
        db.commit()
        log.info("connector.skipped", connector=connector.name)
        return run

    try:
        findings = connector.fetch()
        result = ingest_findings(db, findings)
        # Auto-resolve anything previously open from this source but not in this pull.
        if connector.supports_auto_resolve:
            seen = {f.fingerprint() for f in findings}
            result["resolved"] = resolve_missing(db, connector.name, seen)
        run.findings_count = result["total"]
        run.status = "success"
        log.info("connector.synced", connector=connector.name, **result)
    except Exception as exc:  # noqa: BLE001 — record any connector failure, keep others running
        import traceback

        from backend.app.services import errorlog

        db.rollback()
        run = db.merge(run)
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        errorlog.record(f"connector:{connector.name}", run.error, traceback.format_exc())
        log.error("connector.error", connector=connector.name, error=str(exc))
    finally:
        run.finished_at = utcnow()
        db.commit()
    return run


def sync_all(db: Session) -> list[ConnectorRun]:
    from backend.app.connectors.registry import all_connectors

    return [sync_connector(db, c) for c in all_connectors()]
