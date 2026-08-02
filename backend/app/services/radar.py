"""Vuln radar: pull posts from curated researcher accounts, filter for genuine
vulnerability chatter, and correlate to our findings.

Signal/noise is handled in layers, cheapest first:
  1. Source allowlist — we only ever read hand-picked accounts (radar_sources).
  2. Structural funnel (this module, free/deterministic) — CVE ids, vuln
     keywords, links to advisory domains -> a heuristic confidence score.
  3. Optional LLM classify/extract (services/radar_llm, off by default) — the
     precision layer that rejects jokes / old references / opinion.
Items are ambient THREAT INTEL, not findings; a human confirms them.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime, timedelta, timezone

import httpx
import structlog
from sqlalchemy import func, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.models.radar_item import RadarItem
from backend.app.models.radar_source import RadarSource
from backend.app.services import app_settings

log = structlog.get_logger()

_HTTP_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
_MAX_PER_POLL = 40           # posts pulled per source per poll
_MAX_BODY_BYTES = 8 * 1024 * 1024   # cap the response body a source can stream at us
# Cursor sanity ceiling for Mastodon snowflake ids (comfortably above real ids
# for centuries) — rejects a bogus huge id that would otherwise wedge the source.
_MAX_MASTODON_ID = 10 ** 19

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]+>")   # strip HTML from Mastodon content

# Vuln-relevant keywords -> weight toward the confidence score.
_KEYWORDS = {
    "rce": 0.25, "remote code execution": 0.25, "unauthenticated": 0.2,
    "0day": 0.3, "0-day": 0.3, "zero-day": 0.3, "zeroday": 0.3,
    "exploit": 0.15, "poc": 0.2, "proof of concept": 0.2, "patch": 0.1,
    "advisory": 0.15, "vulnerability": 0.15, "vuln": 0.1, "cvss": 0.15,
    "privilege escalation": 0.2, "lpe": 0.2, "sqli": 0.15, "xss": 0.1,
    "actively exploited": 0.3, "in the wild": 0.2, "buffer overflow": 0.15,
}
_POC_HINTS = ("poc", "proof of concept", "exploit code", "github.com", "gist.github")
_ADVISORY_DOMAINS = (
    "nvd.nist.gov", "cve.org", "github.com/advisories", "githubsecurity",
    "cisa.gov", "exploit-db.com", "packetstorm", "zerodayinitiative", "msrc.microsoft",
    "seclists.org", "openwall.com/lists", "talosintelligence.com",
)
_VULN_TYPES = {
    "rce": "rce", "remote code execution": "rce", "lpe": "lpe",
    "privilege escalation": "lpe", "sqli": "sqli", "sql injection": "sqli",
    "xss": "xss", "ssrf": "ssrf", "path traversal": "path_traversal",
    "deserialization": "deserialization", "buffer overflow": "memory",
}


# --- structural signal extraction (free, deterministic) ---

def _clean(text: str) -> str:
    stripped = html.unescape(_TAG_RE.sub(" ", text or ""))
    return re.sub(r"\s+", " ", stripped).strip()


def _kw_present(keyword: str, lower: str) -> bool:
    # Word-boundary match so 'vuln' doesn't also fire inside 'vulnerability' and
    # 'exploit' inside 'exploited' — that double-counting inflated confidence.
    return re.search(r"(?<!\w)" + re.escape(keyword) + r"(?!\w)", lower) is not None


def extract_signals(post_text: str) -> dict:
    """Pull CVEs / keywords / links from post text and score vuln-relevance 0..1."""
    lower = post_text.lower()
    cves = sorted({m.group(0).upper() for m in _CVE_RE.finditer(post_text)})
    kw_hits = [k for k in _KEYWORDS if _kw_present(k, lower)]
    domains = [d for d in _ADVISORY_DOMAINS if d in lower]
    poc = any(h in lower for h in _POC_HINTS)
    vuln_type = next((v for k, v in _VULN_TYPES.items() if k in lower), None)

    score = 0.0
    if cves:
        score += 0.5 + 0.1 * min(len(cves), 3)   # a CVE id is the strongest signal
    score += sum(_KEYWORDS[k] for k in kw_hits)
    if domains:
        score += 0.2
    confidence = max(0.0, min(1.0, score))
    return {
        "cve_ids": cves,
        "signals": {"keywords": kw_hits, "domains": domains, "poc": poc},
        "poc_mentioned": poc,
        "vuln_type": vuln_type,
        "confidence": round(confidence, 2),
    }


# --- source resolution + adapters (free/keyless public APIs) ---

def _get_json(url: str, params: dict):
    """GET + parse JSON, streaming with a hard body-size cap so a hostile or
    compromised instance in the allowlist can't OOM the worker with a huge body
    that trickles under the per-read timeout."""
    with httpx.stream("GET", url, params=params, timeout=_HTTP_TIMEOUT) as resp:
        resp.raise_for_status()
        body = bytearray()
        for chunk in resp.iter_bytes():
            body += chunk
            if len(body) > _MAX_BODY_BYTES:
                raise ValueError(f"radar: response body exceeded {_MAX_BODY_BYTES} bytes")
    return json.loads(body)


def _resolve_mastodon(source: RadarSource) -> str | None:
    """Look up a Mastodon account id from handle@instance (cached on the row)."""
    if source.account_ref:
        return source.account_ref
    inst = source.instance or "infosec.exchange"
    return (_get_json(f"https://{inst}/api/v1/accounts/lookup",
                      {"acct": source.handle}) or {}).get("id")


def fetch_mastodon(source: RadarSource) -> list[dict]:
    inst = source.instance or "infosec.exchange"
    acct_id = _resolve_mastodon(source)
    if not acct_id:
        return []
    source.account_ref = acct_id
    params = {"limit": _MAX_PER_POLL, "exclude_replies": "true", "exclude_reblogs": "true"}
    if source.cursor:
        # min_id (not since_id) so a burst of >limit posts between polls is caught
        # up over subsequent polls instead of silently skipped.
        params["min_id"] = source.cursor
    out = []
    for s in _get_json(f"https://{inst}/api/v1/accounts/{acct_id}/statuses", params):
        out.append({
            "external_id": str(s["id"]),
            "url": s.get("url"),
            "author_handle": f"@{source.handle}@{inst}",
            "author_display": (s.get("account") or {}).get("display_name"),
            "posted_at": s.get("created_at"),
            "text": _clean(s.get("content", "")),
        })
    return out


def fetch_bluesky(source: RadarSource) -> list[dict]:
    feed = _get_json(
        "https://public.api.bsky.app/xrpc/app.bsky.feed.getAuthorFeed",
        {"actor": source.handle, "limit": _MAX_PER_POLL, "filter": "posts_no_replies"},
    )
    out = []
    for entry in (feed or {}).get("feed", []):
        post = entry.get("post") or {}
        record = post.get("record") or {}
        if record.get("reply"):
            continue
        uri = post.get("uri", "")
        rkey = uri.rsplit("/", 1)[-1] if uri else ""
        author = post.get("author") or {}
        handle = author.get("handle", source.handle)
        out.append({
            "external_id": uri,
            "url": f"https://bsky.app/profile/{handle}/post/{rkey}" if rkey else None,
            "author_handle": handle,
            "author_display": author.get("displayName"),
            "posted_at": record.get("createdAt") or post.get("indexedAt"),
            "text": _clean(record.get("text", "")),
        })
    return out


# Dispatch by name (not by captured function object) so tests can monkeypatch
# radar.fetch_mastodon / radar.fetch_bluesky on the module.
_ADAPTER_NAMES = {"mastodon": "fetch_mastodon", "bluesky": "fetch_bluesky"}


# --- ingest one source ---

def _iso(v: str | None) -> datetime | None:
    """Parse the common ISO-8601 shapes the platforms return ('...Z' / offset).
    Always returns a timezone-AWARE datetime (assumes UTC when the string carries
    no offset — Bluesky's client-authored createdAt often doesn't) so comparisons
    against utcnow() can't raise a naive-vs-aware TypeError."""
    if not v:
        return None
    try:
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _too_old(posted_at: str | None) -> bool:
    dt = _iso(posted_at)
    if dt is None:
        return False
    return dt < utcnow() - timedelta(days=int(settings.radar_max_age_days))


def _trunc(v, n):
    return v[:n] if isinstance(v, str) else v


def _severity(v) -> str | None:
    """Only accept a known severity band from the LLM; drop free-form text."""
    return v if v in ("critical", "high", "medium", "low") else None


def _ingest_source(db: Session, source: RadarSource) -> int:
    from backend.app.services import radar_llm  # local: optional, may hit the network

    fname = _ADAPTER_NAMES.get(source.platform)
    fetch = globals().get(fname) if fname else None
    if fetch is None:
        return 0
    posts = fetch(source)
    min_conf = float(settings.radar_min_confidence)
    llm_on = settings.radar_llm_enabled and bool(settings.anthropic_api_key)
    trust_adj = (int(source.trust_weight or 5) - 5) * 0.02   # nudge by source trust
    newest_cursor = source.cursor
    created = 0

    for post in posts:
        # Advance the watermark BEFORE processing so a single bad post can't make
        # the source re-fetch (and re-classify) the same batch every poll.
        newest_cursor = _max_cursor(source.platform, newest_cursor, post["external_id"])
        try:
            if _process_post(db, source, post, min_conf, llm_on, trust_adj, radar_llm):
                created += 1
        except Exception as exc:  # noqa: BLE001 — one bad post can't fail the source
            db.rollback()
            log.warning("radar.post_failed", source=source.handle, error=str(exc))

    source.cursor = newest_cursor
    source.last_polled_at = utcnow()
    source.last_status = "ok"
    source.last_error = None
    db.commit()
    return created


def _process_post(db, source, post, min_conf, llm_on, trust_adj, radar_llm) -> bool:
    if _too_old(post.get("posted_at")):
        return False
    # Dedup BEFORE any paid LLM call — a source that re-serves recent posts (all
    # Bluesky polls do) must not re-bill classification for rows we already have.
    if db.scalar(select(RadarItem.id).where(
            RadarItem.platform == source.platform,
            RadarItem.external_id == post["external_id"])):
        return False

    sig = extract_signals(post["text"])
    confidence = min(1.0, max(0.0, sig["confidence"] + trust_adj))
    classified_by, summary, products, severity = "heuristic", None, [], None
    vuln_type = sig["vuln_type"]
    signals = dict(sig["signals"])

    if confidence < 0.15 and not sig["cve_ids"]:
        return False
    if llm_on:
        verdict = radar_llm.classify(post["text"])
        if verdict is not None:
            if not verdict.get("is_vuln"):
                return False   # LLM rejected it as non-vuln / noise
            classified_by = "llm"
            summary = verdict.get("summary")
            products = verdict.get("products") or []
            severity = _severity(verdict.get("severity_hint"))
            vuln_type = verdict.get("vuln_type") or vuln_type
            confidence = min(1.0, max(confidence, float(verdict.get("confidence") or 0) + trust_adj))
            # Store LLM-inferred CVEs for reference only — they are NOT used for
            # correlation/alerting (a crafted post can manipulate the classifier),
            # so alerts fire only on CVEs literally present in the post text.
            extra = sorted(set(verdict.get("cve_ids") or []) - set(sig["cve_ids"]))
            if extra:
                signals["llm_cve_ids"] = extra
    if confidence < min_conf:
        return False

    sp = db.begin_nested()   # savepoint: a concurrent-poll race or bad row can't
    try:                     # poison the rest of the batch or stall the cursor
        item = RadarItem(
            source_id=source.id, platform=source.platform,
            external_id=_trunc(post["external_id"], 512),
            url=_trunc(post.get("url"), 1024),
            author_handle=_trunc(post["author_handle"], 255),
            author_display=_trunc(post.get("author_display"), 255),
            posted_at=_iso(post.get("posted_at")), text=_trunc(post["text"], 8000),
            cve_ids=sig["cve_ids"],   # structural (regex from the post) — trusted
            products=[_trunc(p, 255) for p in products][:50],
            vuln_type=_trunc(vuln_type, 64), severity_hint=severity,
            poc_mentioned=sig["poc_mentioned"], summary=summary,
            confidence=round(confidence, 2), signals=signals, classified_by=classified_by,
        )
        _correlate(db, item, sig["cve_ids"])
        db.add(item)
        db.flush()
        sp.commit()
        return True
    except IntegrityError:   # a concurrent poll inserted this same post first
        sp.rollback()
        return False


def _max_cursor(platform: str, current: str | None, candidate: str) -> str | None:
    """Mastodon ids are increasing ints; bluesky uses full uris (compare lexically
    as a best-effort watermark)."""
    if platform == "mastodon":
        try:
            cand = int(candidate)
        except (ValueError, TypeError):
            return current if current is not None else candidate
        if cand > _MAX_MASTODON_ID:   # bogus/hostile huge id would wedge the source
            return current
        return candidate if current is None or cand > int(current) else current
    if current is None:
        return candidate
    return max(current, candidate)


# --- correlation: match radar CVEs against our OPEN findings ---

def _correlate(db: Session, item: RadarItem, cves) -> None:
    """Set matched_finding_ids to OPEN findings sharing any of `cves` (uppercased
    both sides — connectors store CVE ids in mixed case)."""
    if not cves:
        item.matched_finding_ids = []
        return
    rows = db.execute(text(
        "SELECT DISTINCT f.id FROM findings f, "
        "jsonb_array_elements_text(f.cve_ids) AS e(cve) "
        "WHERE f.effective_status = 'open' AND upper(e.cve) = ANY(:cves)"
    ), {"cves": [c.upper() for c in cves]}).scalars().all()
    item.matched_finding_ids = list(rows)


def recorrelate(db: Session) -> None:
    """Re-match recent, still-unmatched items against current open findings —
    the early-warning case where the radar item PRECEDES the finding. Newly
    matched items then become eligible for a match alert."""
    cutoff = utcnow() - timedelta(days=int(settings.radar_max_age_days) + 7)
    stale = db.scalars(
        select(RadarItem).where(
            RadarItem.created_at >= cutoff,
            func.jsonb_array_length(RadarItem.matched_finding_ids) == 0,
            func.jsonb_array_length(RadarItem.cve_ids) > 0)
    ).all()
    for item in stale:
        _correlate(db, item, item.cve_ids)
    db.commit()


# --- top-level poll (scheduler / manual) ---

def poll(db: Session) -> dict:
    """Poll every enabled source; returns a per-source summary."""
    if not settings.radar_enabled:
        return {"enabled": False, "sources": 0, "new_items": 0}
    sources = db.scalars(select(RadarSource).where(RadarSource.enabled.is_(True))).all()
    total = 0
    for source in sources:
        try:
            total += _ingest_source(db, source)
        except Exception as exc:  # noqa: BLE001 — one bad source can't stop the rest
            db.rollback()
            source.last_polled_at = utcnow()
            source.last_status = "error"
            source.last_error = str(exc)[:500]
            db.commit()
            log.warning("radar.source_failed", source=source.handle, error=str(exc))
    recorrelate(db)   # catch items that predate a now-open finding
    _alert_matches(db)
    log.info("radar.poll_done", sources=len(sources), new_items=total)
    return {"enabled": True, "sources": len(sources), "new_items": total}


def prune(db: Session) -> int:
    days = int(settings.radar_retention_days)
    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    # Keep confirmed items regardless of age; prune unreviewed/dismissed noise.
    n = db.query(RadarItem).filter(
        RadarItem.created_at < cutoff, RadarItem.status != "confirmed").delete()
    db.commit()
    return n


# --- self-contained match alert to the notifications webhook (fires once/item) ---

def _alert_matches(db: Session) -> None:
    url = str(app_settings.get("notify_slack_webhook_url")).strip()
    if not url:
        return
    # SKIP LOCKED so a concurrent poll (scheduled job vs manual POST /api/radar/poll)
    # can't grab the same pending rows and double-send the alert.
    pending = db.scalars(
        select(RadarItem).where(
            RadarItem.alerted_at.is_(None),
            func.jsonb_array_length(RadarItem.matched_finding_ids) > 0)
        .limit(20).with_for_update(skip_locked=True)
    ).all()
    for item in pending:
        msg = (f":satellite: *Radar* — {item.author_handle} mentioned "
               f"{', '.join(item.cve_ids) or 'a vuln'} which matches "
               f"{len(item.matched_finding_ids)} open finding(s)\n{item.url or ''}")
        try:
            httpx.post(url, json={"text": msg}, timeout=_HTTP_TIMEOUT).raise_for_status()
            item.alerted_at = utcnow()
            db.commit()
        except httpx.HTTPError as exc:
            db.rollback()
            log.warning("radar.alert_failed", error=str(exc))
            return


# --- seed curated sources (verified free-API accounts) ---

_SEED = [
    # Verified to resolve on their home instances (2026-08-02). A starter set —
    # curate/expand via the DB. Bluesky ships empty (handles vary; add your own).
    ("mastodon", "GossiTheDog", "cyberplace.social", "Kevin Beaumont", 9),
    ("mastodon", "campuscodi", "mastodon.social", "Catalin Cimpanu", 8),
    ("mastodon", "briankrebs", "infosec.exchange", "Brian Krebs", 7),
    ("mastodon", "todb", "infosec.exchange", "Tod Beardsley", 7),
    ("mastodon", "da_667", "infosec.exchange", "da_667", 6),
    ("mastodon", "cR0w", "infosec.exchange", "cR0w", 6),
]


def seed_sources(db: Session) -> int:
    """Insert the starter allowlist if the table is empty (idempotent)."""
    if db.scalar(select(func.count()).select_from(RadarSource)):
        return 0
    for platform, handle, instance, name, weight in _SEED:
        db.add(RadarSource(platform=platform, handle=handle, instance=instance,
                           display_name=name, trust_weight=weight, enabled=True))
    db.commit()
    return len(_SEED)
