"""Threat-intelligence enrichment API: refresh the feeds + report coverage.

Refresh pulls the default feeds (CISA KEV, EPSS) for the CVEs in our findings and
recomputes every finding's risk_score. Security-team only.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.services import intel

router = APIRouter(prefix="/api/intel", tags=["intel"])


class FeedIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    url: str = Field(min_length=4, max_length=1024)


class FeedToggle(BaseModel):
    enabled: bool


@router.get("/status")
def status(db: Session = Depends(get_db), _: User = Depends(require_security)):
    """Intel coverage: how many CVEs enriched, how many KEV, last refresh time."""
    return intel.status(db)


@router.post("/refresh")
def refresh(db: Session = Depends(get_db), _: User = Depends(require_security)):
    """Run every enabled feed over our findings' CVEs and recompute risk scores.
    Blocks briefly on the feed fetch; returns a summary of what was enriched."""
    return intel.refresh(db)


@router.get("/feeds")
def list_feeds(db: Session = Depends(get_db), _: User = Depends(require_security)):
    """All configured feeds (built-in KEV/EPSS + custom) with last-run status."""
    return intel.list_feeds(db)


@router.post("/feeds", status_code=201)
def add_feed(body: FeedIn, db: Session = Depends(get_db), _: User = Depends(require_security)):
    """Add a custom CVE-list feed (any URL that yields CVE ids)."""
    try:
        return intel.add_feed(db, name=body.name, url=body.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.patch("/feeds/{feed_id}")
def toggle_feed(feed_id: int, body: FeedToggle, db: Session = Depends(get_db),
                _: User = Depends(require_security)):
    """Enable/disable a feed (built-ins included)."""
    feed = intel.set_enabled(db, feed_id, body.enabled)
    if feed is None:
        raise HTTPException(404, "feed not found")
    return feed


@router.delete("/feeds/{feed_id}", status_code=204)
def delete_feed(feed_id: int, db: Session = Depends(get_db), _: User = Depends(require_security)):
    """Delete a custom feed (built-ins can be disabled but not removed)."""
    if not intel.delete_feed(db, feed_id):
        raise HTTPException(400, "feed not found or is built-in (disable it instead)")
