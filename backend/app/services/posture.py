"""Posture history: periodic snapshots + trend series for the dashboard.

Snapshots capture what can't be reconstructed later (open counts by severity,
KEV/SLA exposure — findings are upserted in place). MTTR and new-vs-resolved
velocity are computed retroactively from first_seen/resolved_at, so those
series have history from day one.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import structlog
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.models.base import utcnow
from backend.app.models.finding import Finding
from backend.app.models.posture_snapshot import PostureSnapshot

log = structlog.get_logger()

# At most one snapshot per hour, however many sync ticks / restarts happen.
# force= bypasses this but still honors a short floor, so a scripted loop on
# POST /api/posture/snapshot can't grow the table / hammer the aggregates.
_MIN_INTERVAL = timedelta(hours=1)
_FORCE_MIN_INTERVAL = timedelta(seconds=60)

# App-wide advisory lock id for "a snapshot is being taken" (any unique int).
_SNAPSHOT_LOCK_ID = 0x706F5354  # "poST"

_SEVERITIES = ("critical", "high", "medium", "low", "info")


# --- snapshots ---

def take_snapshot(db: Session, force: bool = False) -> PostureSnapshot | None:
    """Record current posture; returns None when a recent snapshot makes it a no-op."""
    now = utcnow()
    # Serialize concurrent writers (multi-worker boot, scheduler tick vs manual
    # POST): the xact-scoped advisory lock is released by the commit below, and
    # the throttle check runs under it so read-then-insert can't race.
    if not db.scalar(select(func.pg_try_advisory_xact_lock(_SNAPSHOT_LOCK_ID))):
        return None
    latest = db.scalar(select(func.max(PostureSnapshot.taken_at)))
    if latest is not None and now - latest < (_FORCE_MIN_INTERVAL if force else _MIN_INTERVAL):
        return None

    is_open = Finding.effective_status == "open"
    by_sev = dict(db.execute(
        select(Finding.severity, func.count()).where(is_open).group_by(Finding.severity)
    ).all())
    by_source = dict(db.execute(
        select(Finding.source, func.count()).where(is_open).group_by(Finding.source)
    ).all())

    snap = PostureSnapshot(
        taken_at=now,
        open_total=sum(by_sev.values()),
        open_critical=by_sev.get("critical", 0),
        open_high=by_sev.get("high", 0),
        open_medium=by_sev.get("medium", 0),
        open_low=by_sev.get("low", 0),
        open_info=by_sev.get("info", 0),
        resolved_total=db.scalar(
            select(func.count()).select_from(Finding)
            .where(Finding.effective_status == "resolved")
        ) or 0,
        kev_open=db.scalar(
            select(func.count()).select_from(Finding).where(is_open, Finding.in_kev.is_(True))
        ) or 0,
        sla_breached_open=db.scalar(
            select(func.count()).select_from(Finding)
            .where(is_open, Finding.sla_due_at < now)
        ) or 0,
        avg_risk_open=float(db.scalar(select(func.avg(Finding.risk_score)).where(is_open)) or 0.0),
        by_source=by_source,
    )
    db.add(snap)
    db.commit()
    log.info("posture.snapshot", open=snap.open_total, kev=snap.kev_open,
             sla_breached=snap.sla_breached_open)
    return snap


def _snapshot_series(db: Session, days: int) -> list[dict]:
    """Snapshots in the window, downsampled to the last one of each day."""
    cutoff = utcnow() - timedelta(days=days)
    rows = db.scalars(
        select(PostureSnapshot)
        .where(PostureSnapshot.taken_at >= cutoff)
        .order_by(PostureSnapshot.taken_at)
    ).all()
    by_day: dict[str, PostureSnapshot] = {}
    for s in rows:  # ordered ascending, so the last write per day wins
        by_day[s.taken_at.date().isoformat()] = s
    return [
        {
            "taken_at": s.taken_at.isoformat(),
            "open_total": s.open_total,
            "by_severity": {sev: getattr(s, f"open_{sev}") for sev in _SEVERITIES},
            "resolved_total": s.resolved_total,
            "kev_open": s.kev_open,
            "sla_breached_open": s.sla_breached_open,
            "avg_risk_open": round(s.avg_risk_open, 1),
            "by_source": s.by_source,
        }
        for s in by_day.values()
    ]


# --- retroactive series (work with pre-snapshot history) ---

def week_buckets(now: datetime, weeks: int) -> list[datetime]:
    """Start-of-week (Monday 00:00 UTC) datetimes for the trailing window."""
    this_week = (now - timedelta(days=now.weekday())).replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    return [this_week - timedelta(weeks=i) for i in range(weeks - 1, -1, -1)]


def _weekly_counts(db: Session, column, cutoff: datetime, *extra_where) -> dict[str, int]:
    week = func.date_trunc("week", column)  # one expression object: SELECT and GROUP BY must match
    rows = db.execute(
        select(week, func.count()).where(column >= cutoff, *extra_where).group_by(week)
    ).all()
    return {week.date().isoformat(): n for week, n in rows}


def _velocity(db: Session, weeks: int) -> list[dict]:
    """New vs resolved findings per ISO week for the trailing window.

    "Resolved" requires effective_status == "resolved" so triage decisions
    (false_positive / accepted_risk) never count as remediation — matching the
    snapshot series' resolved_total. Counts derive from the mutable resolved_at
    column, so a week's bar can shrink later if a finding reopens.
    """
    buckets = week_buckets(utcnow(), weeks)
    new = _weekly_counts(db, Finding.first_seen, buckets[0])
    resolved = _weekly_counts(db, Finding.resolved_at, buckets[0],
                              Finding.effective_status == "resolved")
    return [
        {
            "week_start": b.date().isoformat(),
            "new": new.get(b.date().isoformat(), 0),
            "resolved": resolved.get(b.date().isoformat(), 0),
        }
        for b in buckets
    ]


def _mttr(db: Session, days: int) -> dict:
    """Mean days to remediate, for findings resolved in the window.

    The span starts at reopened_at when the finding came back after an earlier
    fix (so a reopen measures the recurrence, not the full lifetime), and only
    genuinely-resolved findings count — not false_positive/accepted_risk ones
    whose source merely stopped reporting them.
    """
    cutoff = utcnow() - timedelta(days=days)
    started_at = func.coalesce(Finding.reopened_at, Finding.first_seen)
    resolved_in_window = (
        Finding.effective_status == "resolved",
        Finding.resolved_at.is_not(None),
        Finding.first_seen.is_not(None),
        Finding.resolved_at >= cutoff,
        Finding.resolved_at > started_at,  # defensive: sources can report odd timestamps
    )
    seconds = func.avg(func.extract("epoch", Finding.resolved_at - started_at))
    overall = db.scalar(select(seconds).where(*resolved_in_window))
    rows = db.execute(
        select(Finding.severity, seconds, func.count())
        .where(*resolved_in_window)
        .group_by(Finding.severity)
    ).all()
    to_days = lambda s: round(float(s) / 86400, 1) if s is not None else None  # noqa: E731
    return {
        "overall_days": to_days(overall),
        "by_severity": {sev: {"days": to_days(secs), "count": n} for sev, secs, n in rows},
    }


def trends(db: Session, days: int = 90) -> dict:
    """Everything the trends dashboard needs in one call."""
    return {
        "days": days,
        "snapshots": _snapshot_series(db, days),
        "velocity": _velocity(db, weeks=max(1, min(days // 7, 26))),
        "mttr": _mttr(db, days),
    }
