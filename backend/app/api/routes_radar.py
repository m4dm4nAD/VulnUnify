"""Vuln radar: ambient threat-intel from curated researcher accounts. Security
team reads it; confirm/dismiss and manual poll are audited."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security, require_security_admin
from backend.app.db import get_db
from backend.app.models.radar_item import RadarItem
from backend.app.models.radar_source import RadarSource
from backend.app.models.user import User
from backend.app.services import audit, radar

router = APIRouter(prefix="/api/radar", tags=["radar"])

_STATUSES = {"new", "confirmed", "dismissed"}


def _item_out(r: RadarItem) -> dict:
    return {
        "id": r.id, "platform": r.platform, "url": r.url,
        "author_handle": r.author_handle, "author_display": r.author_display,
        "posted_at": r.posted_at.isoformat() if r.posted_at else None,
        "text": r.text, "cve_ids": r.cve_ids, "products": r.products,
        "vuln_type": r.vuln_type, "severity_hint": r.severity_hint,
        "poc_mentioned": r.poc_mentioned, "summary": r.summary,
        "confidence": r.confidence, "classified_by": r.classified_by,
        "status": r.status, "matched_finding_ids": r.matched_finding_ids,
        "signals": r.signals,
    }


@router.get("")
def list_items(
    status: str | None = None,
    matched: bool = False,
    q: str | None = None,
    min_confidence: float = Query(0.0, ge=0.0, le=1.0),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    _: User = Depends(require_security),
):
    """Newest-first radar items with filters."""
    where = [RadarItem.confidence >= min_confidence]
    if status in _STATUSES:
        where.append(RadarItem.status == status)
    if matched:
        where.append(func.jsonb_array_length(RadarItem.matched_finding_ids) > 0)
    if q:
        where.append(RadarItem.text.icontains(q, autoescape=True))
    total = db.scalar(select(func.count()).select_from(RadarItem).where(*where)) or 0
    rows = db.scalars(
        select(RadarItem).where(*where)
        .order_by(RadarItem.posted_at.desc().nullslast(), RadarItem.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return {"total": total, "limit": limit, "offset": offset,
            "items": [_item_out(r) for r in rows]}


@router.get("/sources")
def list_sources(db: Session = Depends(get_db), _: User = Depends(require_security)):
    rows = db.scalars(select(RadarSource).order_by(RadarSource.trust_weight.desc())).all()
    return [{
        "id": s.id, "platform": s.platform, "handle": s.handle, "instance": s.instance,
        "display_name": s.display_name, "enabled": s.enabled, "trust_weight": s.trust_weight,
        "last_polled_at": s.last_polled_at.isoformat() if s.last_polled_at else None,
        "last_status": s.last_status, "last_error": s.last_error,
    } for s in rows]


@router.post("/{item_id}/status")
def set_status(item_id: int, request: Request, body: dict,
               db: Session = Depends(get_db), actor: User = Depends(require_security)):
    """Confirm or dismiss a radar item (human triage)."""
    new_status = body.get("status")
    if new_status not in _STATUSES:
        raise HTTPException(400, f"status must be one of {sorted(_STATUSES)}")
    item = db.get(RadarItem, item_id)
    if item is None:
        raise HTTPException(404, "radar item not found")
    before = item.status
    item.status = new_status
    db.commit()
    if before != new_status:
        audit.record(db, "radar.triage",
                     f"{new_status} radar item from {item.author_handle}",
                     actor=actor, request=request, target_type="radar_item",
                     target_id=item_id, details={"status": {"from": before, "to": new_status}})
    return _item_out(item)


@router.post("/poll")
def poll_now(request: Request, db: Session = Depends(get_db),
             actor: User = Depends(require_security_admin)):
    """Poll all enabled sources immediately."""
    result = radar.poll(db)
    audit.record(db, "radar.poll", "triggered a radar poll",
                 actor=actor, request=request, details=result)
    return result
