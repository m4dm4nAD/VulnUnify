"""Finding lifecycle: SLA computation, effective-status derivation, auto-resolve.

The two axes that feed `effective_status`:
  * lifecycle  — `resolved_at` is set when the source stops reporting a finding
  * triage     — a local human decision (`triage_state` / `triage_until`)
`effective_status` is recomputed whenever either axis changes (ingest, triage,
auto-resolve) and on a full recompute pass.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import structlog
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.connectors.enums import EffectiveStatus, TriageState
from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.services import app_settings

log = structlog.get_logger()


def sla_days_for(severity: str) -> int | None:
    """SLA window in days for a severity, or None if the severity has no SLA."""
    return {
        "critical": app_settings.get("sla_critical_days"),
        "high": app_settings.get("sla_high_days"),
        "medium": app_settings.get("sla_medium_days"),
        "low": app_settings.get("sla_low_days"),
        "info": None,
    }.get(severity)


def compute_sla_due(first_seen: datetime | None, severity: str) -> datetime | None:
    days = sla_days_for(severity)
    if first_seen is None or days is None:
        return None
    return first_seen + timedelta(days=days)


def compute_effective_status(
    resolved_at: datetime | None,
    triage_state: str | None,
    triage_until: datetime | None,
    now: datetime | None = None,
) -> str:
    """Derive the effective status from lifecycle + triage (see precedence below)."""
    now = now or utcnow()
    state = triage_state or TriageState.ACTIVE.value

    # Human "not a real risk" decisions win over everything.
    if state == TriageState.FALSE_POSITIVE.value:
        return EffectiveStatus.FALSE_POSITIVE.value
    if state == TriageState.ACCEPTED_RISK.value:
        return EffectiveStatus.ACCEPTED_RISK.value
    # Then lifecycle: gone from the source.
    if resolved_at is not None:
        return EffectiveStatus.RESOLVED.value
    # An unexpired snooze mutes it; an expired one falls through to open.
    if state == TriageState.SNOOZED.value and (triage_until is None or triage_until > now):
        return EffectiveStatus.SNOOZED.value
    return EffectiveStatus.OPEN.value


def apply_lifecycle(finding: Finding) -> None:
    """Recompute the derived fields (sla_due_at, effective_status) on a finding."""
    finding.sla_due_at = compute_sla_due(finding.first_seen, finding.severity)
    finding.effective_status = compute_effective_status(
        finding.resolved_at, finding.triage_state, finding.triage_until
    )


def resolve_missing(db: Session, source: str, seen_fingerprints: set[str]) -> int:
    """Mark still-open findings from `source` that weren't in this sync as resolved.

    Assumes the connector returned its complete current open set (the default).
    Connectors that do partial/filtered pulls should set
    `supports_auto_resolve = False` so this is skipped for them.
    """
    stmt = select(Finding).where(
        Finding.source == source, Finding.resolved_at.is_(None)
    )
    resolved = 0
    for finding in db.scalars(stmt):
        if finding.fingerprint in seen_fingerprints:
            continue
        finding.resolved_at = utcnow()
        apply_lifecycle(finding)
        resolved += 1
    db.commit()
    if resolved:
        log.info("lifecycle.auto_resolved", source=source, count=resolved)
    return resolved


def recompute_all(db: Session) -> int:
    """Re-derive sla_due_at + effective_status for every finding.

    Used to backfill after a schema change and to flush expired snoozes that
    fell between syncs.
    """
    findings = list(db.scalars(select(Finding)))
    for finding in findings:
        apply_lifecycle(finding)
    db.commit()
    return len(findings)
