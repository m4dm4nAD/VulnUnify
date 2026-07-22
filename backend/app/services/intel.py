"""Threat-intelligence enrichment.

Pulls per-CVE facts from feeds — CISA KEV (actively exploited) and EPSS (exploit
probability) ship enabled by default — into the `cve_intel` table, keyed to the
CVEs that actually appear in our findings, then recomputes each finding's
composite `risk_score`. Custom feeds slot in later via the same upsert path.

Nothing here creates findings; it only enriches and prioritizes what connectors
already ingested.
"""
from __future__ import annotations

import re
from datetime import date, datetime

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from backend.app.config import settings
from backend.app.models.base import utcnow
from backend.app.models.cve_intel import CveIntel
from backend.app.models.finding import Finding
from backend.app.models.intel_feed import IntelFeed
from backend.app.services.risk import compute_risk

log = structlog.get_logger()

_HTTP_TIMEOUT = 60.0
_EPSS_BATCH = 100        # CVEs per EPSS API request (keeps the URL well under limits)


# --- helpers ---

def _float(v) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _parse_date(s: str | None) -> date | None:
    try:
        return datetime.strptime(s, "%Y-%m-%d").date() if s else None
    except (TypeError, ValueError):
        return None


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def finding_cves(db: Session) -> set[str]:
    """Distinct CVE ids referenced by any finding (uppercased)."""
    rows = db.execute(
        select(func.jsonb_array_elements_text(Finding.cve_ids))
        .where(func.jsonb_array_length(Finding.cve_ids) > 0)
    ).scalars().all()
    return {r.upper() for r in rows if r and r.upper().startswith("CVE-")}


# --- feed fetchers (pure network; return {cve: {...}}) ---

def fetch_kev() -> dict[str, dict]:
    """All CISA KEV entries, keyed by CVE id."""
    resp = httpx.get(settings.kev_feed_url, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    out: dict[str, dict] = {}
    for v in resp.json().get("vulnerabilities", []):
        cid = (v.get("cveID") or "").strip().upper()
        if cid:
            out[cid] = {
                "date_added": _parse_date(v.get("dateAdded")),
                "ransomware": (v.get("knownRansomwareCampaignUse") or "").strip().lower() == "known",
            }
    return out


def fetch_epss(cves: list[str]) -> dict[str, dict]:
    """EPSS score + percentile for the given CVEs (batched)."""
    out: dict[str, dict] = {}
    with httpx.Client(timeout=_HTTP_TIMEOUT) as client:
        for batch in _chunks(sorted(cves), _EPSS_BATCH):
            resp = client.get(settings.epss_api_url, params={"cve": ",".join(batch)})
            resp.raise_for_status()
            for row in resp.json().get("data", []):
                cid = (row.get("cve") or "").upper()
                if cid:
                    out[cid] = {"score": _float(row.get("epss")),
                                "percentile": _float(row.get("percentile"))}
    return out


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


def fetch_cve_list(url: str) -> set[str]:
    """Extract CVE ids from an arbitrary custom feed URL.

    Deliberately tolerant: we regex `CVE-YYYY-NNNN` out of the raw response, so a
    user's feed can be a JSON array, a newline list, a CSV, or an advisory page —
    whatever they can point a URL at.
    """
    resp = httpx.get(url, timeout=_HTTP_TIMEOUT, follow_redirects=True)
    resp.raise_for_status()
    return {m.group(0).upper() for m in _CVE_RE.finditer(resp.text)}


# --- orchestration ---

def refresh(db: Session) -> dict:
    """Run every enabled feed over our findings' CVEs, upsert intel, recompute risk."""
    cves = sorted(finding_cves(db))
    feeds = list(db.scalars(select(IntelFeed).where(IntelFeed.enabled.is_(True))))
    now = utcnow()

    kev_data: dict[str, dict] = {}
    epss_data: dict[str, dict] = {}
    watchlist: dict[str, set[str]] = {}   # cve -> feed name(s) that flagged it

    for feed in feeds:
        try:
            if feed.kind == "kev":
                kev_data = fetch_kev(); count = len(kev_data)
            elif feed.kind == "epss":
                epss_data = fetch_epss(cves) if cves else {}; count = len(epss_data)
            elif feed.kind == "cve_list" and feed.url:
                found = fetch_cve_list(feed.url)
                for c in found:
                    watchlist.setdefault(c, set()).add(feed.name)
                count = len(found)
            else:
                count = 0
            feed.last_status, feed.last_error, feed.last_count = "ok", None, count
        except Exception as exc:  # noqa: BLE001 — one bad feed shouldn't abort the rest
            feed.last_status, feed.last_error, feed.last_count = "error", f"{type(exc).__name__}: {exc}", 0
            log.warning("intel.feed_failed", feed=feed.name, error=str(exc))
        feed.last_run_at = now
    db.commit()

    kev_hits = epss_hits = watch_hits = 0
    for cve in cves:
        intel = db.get(CveIntel, cve) or CveIntel(cve_id=cve)
        srcs: set[str] = set()
        k = kev_data.get(cve)
        intel.in_kev = k is not None
        intel.kev_date_added = k["date_added"] if k else None
        intel.kev_ransomware = bool(k and k["ransomware"])
        if k:
            srcs.add("kev"); kev_hits += 1
        e = epss_data.get(cve)
        if e:
            intel.epss_score, intel.epss_percentile = e["score"], e["percentile"]
            srcs.add("epss"); epss_hits += 1
        w = watchlist.get(cve)
        intel.watchlisted = bool(w)
        if w:
            srcs |= w; watch_hits += 1
        intel.sources = ",".join(sorted(srcs)) or None
        intel.updated_at = now
        db.add(intel)
    db.commit()

    scored = recompute_risk(db)
    log.info("intel.refreshed", cves=len(cves), kev=kev_hits, epss=epss_hits,
             watch=watch_hits, feeds=len(feeds), scored=scored)
    return {"cves": len(cves), "kev": kev_hits, "epss": epss_hits,
            "watchlisted": watch_hits, "feeds": len(feeds), "findings_scored": scored}


def recompute_risk(db: Session, asset_id: int | None = None) -> int:
    """Re-derive risk_score for findings from current intel + asset criticality.

    Pass `asset_id` to rescore just one asset's findings (e.g. after its
    criticality changes); omit it to rescore everything (after a feed refresh).
    """
    intel = {c.cve_id: c for c in db.scalars(select(CveIntel))}
    stmt = select(Finding).options(joinedload(Finding.asset))
    if asset_id is not None:
        stmt = stmt.where(Finding.asset_id == asset_id)
    findings = db.scalars(stmt).all()
    for f in findings:
        cs = [intel[c.upper()] for c in (f.cve_ids or []) if c and c.upper() in intel]
        in_kev = any(c.in_kev for c in cs)
        epss = max([c.epss_score or 0.0 for c in cs], default=0.0)
        watch = any(c.watchlisted for c in cs)
        f.risk_score = compute_risk(
            severity=f.severity, cvss=f.cvss_base_score, in_kev=in_kev,
            kev_ransomware=any(c.kev_ransomware for c in cs), epss_score=epss,
            watchlisted=watch, asset_criticality=(f.asset.criticality if f.asset else "medium"),
        )
        # Denormalized flags for the findings list (badge + filter without a join).
        f.in_kev = in_kev
        f.epss_score = epss or None
        f.watchlisted = watch
    db.commit()
    return len(findings)


def status(db: Session) -> dict:
    """Coverage summary for the intel page."""
    total = db.scalar(select(func.count()).select_from(CveIntel)) or 0
    kev = db.scalar(select(func.count()).select_from(CveIntel).where(CveIntel.in_kev)) or 0
    watch = db.scalar(select(func.count()).select_from(CveIntel).where(CveIntel.watchlisted)) or 0
    last = db.scalar(select(func.max(CveIntel.updated_at)))
    feeds = db.scalar(select(func.count()).select_from(IntelFeed)) or 0
    return {
        "cve_intel_rows": total,
        "kev_count": kev,
        "watchlisted_count": watch,
        "finding_cves": len(finding_cves(db)),
        "last_updated": last,
        "feeds": feeds,
    }


# --- feed management ---

def _feed_out(f: IntelFeed) -> dict:
    return {
        "id": f.id, "name": f.name, "kind": f.kind, "url": f.url,
        "enabled": f.enabled, "builtin": f.builtin,
        "last_run_at": f.last_run_at, "last_status": f.last_status,
        "last_count": f.last_count, "last_error": f.last_error,
    }


def seed_builtin(db: Session) -> None:
    """Ensure the built-in KEV + EPSS feeds exist (idempotent; called on startup)."""
    existing = {f.name for f in db.scalars(select(IntelFeed))}
    for name, kind, url in (
        ("kev", "kev", settings.kev_feed_url),
        ("epss", "epss", settings.epss_api_url),
    ):
        if name not in existing:
            db.add(IntelFeed(name=name, kind=kind, url=url, enabled=True, builtin=True))
    db.commit()


def list_feeds(db: Session) -> list[dict]:
    feeds = db.scalars(
        select(IntelFeed).order_by(IntelFeed.builtin.desc(), IntelFeed.name)
    )
    return [_feed_out(f) for f in feeds]


def add_feed(db: Session, *, name: str, url: str) -> dict:
    """Add a custom CVE-list feed."""
    name = (name or "").strip()[:128]
    url = (url or "").strip()
    if not name or not url:
        raise ValueError("name and url are required")
    if db.scalar(select(IntelFeed).where(IntelFeed.name == name)):
        raise ValueError(f"a feed named {name!r} already exists")
    feed = IntelFeed(name=name, kind="cve_list", url=url, enabled=True, builtin=False)
    db.add(feed)
    db.commit()
    return _feed_out(feed)


def set_enabled(db: Session, feed_id: int, enabled: bool) -> dict | None:
    feed = db.get(IntelFeed, feed_id)
    if feed is None:
        return None
    feed.enabled = bool(enabled)
    db.commit()
    return _feed_out(feed)


def delete_feed(db: Session, feed_id: int) -> bool:
    """Delete a custom feed. Built-ins can be disabled but not removed."""
    feed = db.get(IntelFeed, feed_id)
    if feed is None or feed.builtin:
        return False
    db.delete(feed)
    db.commit()
    return True
