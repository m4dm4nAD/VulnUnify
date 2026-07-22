"""Asset inventory + business-criticality management.

Assets are created by ingestion; this exposes them for browsing and lets the
security team set each one's business criticality — which tilts the risk score
of every finding on that asset (see services/risk). Changing criticality
rescopes just that asset's findings.
"""
from __future__ import annotations

from sqlalchemy import Select, and_, func, nulls_last, select
from sqlalchemy.orm import Session

from backend.app.models.asset import Asset
from backend.app.models.finding import Finding
from backend.app.services import intel

CRITICALITY_LEVELS = ("critical", "high", "medium", "low")


def _summary_query() -> Select:
    open_ = Finding.effective_status == "open"
    max_risk = func.max(Finding.risk_score)
    return (
        select(
            Asset.id, Asset.identifier, Asset.asset_type, Asset.name,
            Asset.cloud_provider, Asset.region, Asset.criticality,
            func.count(Finding.id).filter(open_).label("open_findings"),
            func.coalesce(max_risk, 0.0).label("max_risk"),
            func.count(Finding.id).filter(and_(Finding.in_kev, open_)).label("kev_open"),
        )
        .outerjoin(Finding, Finding.asset_id == Asset.id)
        .group_by(Asset.id)
        .order_by(nulls_last(max_risk.desc()), Asset.identifier)
    )


def _row(r) -> dict:
    return {
        "id": r.id, "identifier": r.identifier, "asset_type": r.asset_type,
        "name": r.name, "cloud_provider": r.cloud_provider, "region": r.region,
        "criticality": r.criticality, "open_findings": r.open_findings,
        "max_risk": round(r.max_risk or 0.0, 1), "kev_open": r.kev_open,
    }


def list_assets(db: Session) -> list[dict]:
    """All assets with open-finding count, top risk, and KEV exposure."""
    return [_row(r) for r in db.execute(_summary_query()).all()]


def set_criticality(db: Session, asset_id: int, criticality: str) -> dict | None:
    """Set an asset's criticality and rescore its findings. Returns its summary."""
    if criticality not in CRITICALITY_LEVELS:
        raise ValueError(f"criticality must be one of {CRITICALITY_LEVELS}")
    asset = db.get(Asset, asset_id)
    if asset is None:
        return None
    asset.criticality = criticality
    db.commit()
    intel.recompute_risk(db, asset_id=asset_id)   # criticality tilts every finding's risk
    row = db.execute(_summary_query().where(Asset.id == asset_id)).first()
    return _row(row) if row else None
