"""Audit trail: record + query security-relevant actions.

record() is called AFTER the audited operation has succeeded and commits on its
own; a failing audit write must never fail (or roll back) the operation itself,
so every error is swallowed into a log line. That trades a hole in the trail
for availability — acceptable here; flip the try/except if the trail must be
tamper-evident-complete.

Secret VALUES never go in `details` — hooks record which keys changed, not the
contents (see routes_connectors / routes_notifications call sites).
"""
from __future__ import annotations

from datetime import timedelta
from urllib.parse import urlsplit, urlunsplit

import structlog
from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db import SessionLocal
from backend.app.models.audit_log import AuditLog
from backend.app.models.base import utcnow
from backend.app.models.user import User

log = structlog.get_logger()


def _client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    # The socket peer is the only unspoofable source. X-Forwarded-For is trusted
    # ONLY when an operator asserts a header-overwriting proxy is in front
    # (TRUST_PROXY_HEADERS); otherwise a client could forge the recorded IP.
    if settings.trust_proxy_headers:
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


def record(
    db: Session | None,
    action: str,
    summary: str,
    *,
    actor: User | None = None,
    actor_username: str | None = None,   # for failed logins: attempted name, no User
    request: Request | None = None,
    target_type: str | None = None,
    target_id: object = None,
    details: dict | None = None,
) -> None:
    """Append one audit row; never raises. db=None opens (and closes) its own
    session — for handlers whose services manage their own sessions."""
    own_session = db is None
    try:
        session = SessionLocal() if own_session else db
        try:
            session.add(AuditLog(
                action=action,
                summary=summary[:512],
                actor_id=actor.id if actor else None,
                actor_username=(actor.username if actor else actor_username),
                ip=_client_ip(request),
                target_type=target_type,
                target_id=str(target_id)[:256] if target_id is not None else None,
                details=details or {},
            ))
            session.commit()
        finally:
            if own_session:
                session.close()
    except Exception as exc:  # noqa: BLE001 — an audit failure must not break the operation
        if not own_session:
            try:
                db.rollback()
            except Exception:  # noqa: BLE001
                pass
        log.error("audit.record_failed", action=action, error=str(exc))


_SECRET_QUERY_KEYS = ("apikey", "api_key", "token", "key", "secret", "password", "access_token")


def redact_url(url: str) -> str:
    """Strip userinfo and secret-ish query params so a credentialed feed URL
    isn't stored verbatim in the trail."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc
    if "@" in netloc:  # user:pass@host -> ***@host
        netloc = "***@" + netloc.rsplit("@", 1)[1]
    query = parts.query
    if query and any(k in query.lower() for k in _SECRET_QUERY_KEYS):
        query = "<redacted>"
    return urlunsplit((parts.scheme, netloc, parts.path, query, parts.fragment))


def diff(before: dict, after: dict) -> dict:
    """{field: {"from": x, "to": y}} for the keys that actually changed."""
    return {
        k: {"from": before.get(k), "to": after.get(k)}
        for k in after
        if before.get(k) != after.get(k)
    }


def search(
    db: Session,
    *,
    actor: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    q: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    where = []
    if actor:
        # autoescape so a literal _ / % in the filter isn't treated as a wildcard
        where.append(AuditLog.actor_username.icontains(actor, autoescape=True))
    if action:
        # exact action or a whole prefix group ("finding" matches "finding.*")
        where.append((AuditLog.action == action)
                     | AuditLog.action.startswith(f"{action}.", autoescape=True))
    if target_type:
        where.append(AuditLog.target_type == target_type)
    if target_id:
        where.append(AuditLog.target_id == str(target_id))
    if q:
        where.append(AuditLog.summary.icontains(q, autoescape=True))
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*where)) or 0
    rows = db.scalars(
        select(AuditLog).where(*where)
        .order_by(AuditLog.at.desc(), AuditLog.id.desc())
        .limit(limit).offset(offset)
    ).all()
    return {
        "total": total, "limit": limit, "offset": offset,
        "items": [
            {
                "id": r.id, "at": r.at.isoformat() if r.at else None,
                "actor": r.actor_username, "ip": r.ip, "action": r.action,
                "target_type": r.target_type, "target_id": r.target_id,
                "summary": r.summary, "details": r.details,
            }
            for r in rows
        ],
    }


def actions(db: Session) -> list[str]:
    """Distinct actions present, for the UI filter dropdown."""
    return sorted(db.scalars(select(AuditLog.action).distinct()).all())


def prune() -> int:
    """Delete rows older than AUDIT_RETENTION_DAYS (0 = keep forever). Runs in
    its own session so it can't be poisoned by, or leak into, a caller's
    transaction, and records a system row so trail truncation is self-evident."""
    days = int(settings.audit_retention_days)
    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    with SessionLocal() as db:
        n = db.query(AuditLog).filter(AuditLog.at < cutoff).delete()
        db.commit()
    if n:
        log.info("audit.pruned", rows=n, older_than_days=days)
        record(None, "audit.prune", f"pruned {n} audit rows older than {days}d",
               details={"rows": n, "older_than_days": days})
    return n
