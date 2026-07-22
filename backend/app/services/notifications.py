"""Outbound alerting: a batched digest to a Slack-compatible incoming webhook.

Three events, each fired at most once per finding (enforced by the unique
(finding_id, event) constraint on notification_log):

  * high_risk  — an open finding at/above the configured risk threshold
  * kev        — an open finding matching a CISA KEV (actively exploited) CVE
  * sla_breach — an open finding past its SLA deadline

One run produces at most one webhook message (a digest grouped by event), so a
first sync against a big backlog doesn't flood the channel. Log rows are only
written after a successful post — delivery failures retry naturally on the
next scheduler tick.
"""
from __future__ import annotations

from urllib.parse import urlsplit

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, joinedload

from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.models.notification_log import NotificationLog
from backend.app.services import app_settings

log = structlog.get_logger()

_HTTP_TIMEOUT = 15.0
_MAX_PER_EVENT = 500   # dedup rows written per event per run; the rest go next run
_SHOWN_PER_EVENT = 10  # findings listed in the message; the rest are just counted

_HEADINGS = {
    "high_risk": "High risk (score ≥ {threshold})",
    "kev": "Known exploited (CISA KEV)",
    "sla_breach": "SLA breached",
}


def _webhook_url() -> str:
    return str(app_settings.get("notify_slack_webhook_url")).strip()


def mask_webhook(url: str) -> str | None:
    """Host + last 4 chars, so the UI can show what's configured without the token."""
    if not url:
        return None
    host = urlsplit(url).netloc or "webhook"
    return f"{host}/…{url[-4:]}"


# --- selection ---

def _pending(db: Session) -> dict[str, list[Finding]]:
    """Open findings per event that haven't been alerted on yet."""
    threshold = int(app_settings.get("notify_risk_threshold"))
    conditions = {
        "high_risk": (Finding.risk_score >= threshold) if threshold > 0 else None,
        "kev": Finding.in_kev.is_(True),
        "sla_breach": Finding.sla_due_at < utcnow(),
    }
    out: dict[str, list[Finding]] = {}
    for event, cond in conditions.items():
        if cond is None:  # threshold 0 disables the high-risk rule
            continue
        already = select(NotificationLog.finding_id).where(NotificationLog.event == event)
        rows = db.scalars(
            select(Finding)
            .options(joinedload(Finding.asset))
            .where(Finding.effective_status == "open", cond, Finding.id.not_in(already))
            .order_by(Finding.risk_score.desc(), Finding.id)
            .limit(_MAX_PER_EVENT)
        ).all()
        if rows:
            out[event] = rows
    return out


# --- formatting (Slack mrkdwn; degrades fine on Mattermost/Rocket.Chat) ---

def _line(f: Finding) -> str:
    asset = (f.asset.name or f.asset.identifier) if f.asset else "unknown asset"
    title = f.title if len(f.title) <= 120 else f.title[:117] + "…"
    cve = f" {f.cve_ids[0]}" if f.cve_ids else ""
    return f"• `{f.risk_score:.0f}` {f.severity}{cve} — {title} ({asset}, via {f.source})"


def format_digest(pending: dict[str, list[Finding]], threshold: int) -> str:
    total = sum(len(v) for v in pending.values())
    noun = "finding needs" if total == 1 else "findings need"
    parts = [f":rotating_light: *VulnUnify* — {total} {noun} attention"]
    for event, findings in pending.items():
        heading = _HEADINGS[event].format(threshold=threshold)
        parts.append(f"\n*{heading}* — {len(findings)}")
        parts.extend(_line(f) for f in findings[:_SHOWN_PER_EVENT])
        if len(findings) > _SHOWN_PER_EVENT:
            parts.append(f"_…and {len(findings) - _SHOWN_PER_EVENT} more_")
    return "\n".join(parts)


# --- delivery ---

def _post(url: str, text: str) -> None:
    resp = httpx.post(url, json={"text": text}, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()


def run(db: Session) -> dict:
    """Send one digest for everything new; record what was sent. Raises
    httpx.HTTPError when the webhook rejects the post (nothing is recorded)."""
    url = _webhook_url()
    if not url:
        return {"enabled": False, "sent": 0, "events": {}}
    pending = _pending(db)
    if not pending:
        return {"enabled": True, "sent": 0, "events": {}}

    _post(url, format_digest(pending, int(app_settings.get("notify_risk_threshold"))))

    rows = [
        {"finding_id": f.id, "event": event, "risk_score": f.risk_score}
        for event, findings in pending.items()
        for f in findings
    ]
    # ON CONFLICT DO NOTHING: a concurrent run may have logged some of these
    # between our select and now; the message was sent either way.
    db.execute(pg_insert(NotificationLog).values(rows).on_conflict_do_nothing(
        constraint="uq_notification_log_finding_event"))
    db.commit()

    events = {e: len(v) for e, v in pending.items()}
    log.info("notifications.sent", total=len(rows), **events)
    return {"enabled": True, "sent": len(rows), "events": events}


def send_test() -> None:
    """Post a test message to the configured webhook. ValueError if unset."""
    url = _webhook_url()
    if not url:
        raise ValueError("no webhook URL configured")
    _post(url, ":white_check_mark: *VulnUnify* test notification — the webhook works.")


def status(db: Session) -> dict:
    url = _webhook_url()
    last = db.scalar(select(func.max(NotificationLog.sent_at)))
    return {
        "configured": bool(url),
        "webhook_display": mask_webhook(url),
        "risk_threshold": int(app_settings.get("notify_risk_threshold")),
        "sent_total": db.scalar(select(func.count()).select_from(NotificationLog)) or 0,
        "last_sent_at": last.isoformat() if last else None,
    }
