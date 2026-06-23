"""Background scheduler that periodically runs every configured connector.

Uses APScheduler's threaded BackgroundScheduler (not the async one) so the job
can use the regular synchronous SQLAlchemy session. Controlled by
SYNC_INTERVAL_MINUTES — when 0, the scheduler is never started and sync only
happens via POST /api/sync.
"""
from __future__ import annotations

import structlog
from apscheduler.schedulers.background import BackgroundScheduler

from backend.app.config import settings
from backend.app.db import SessionLocal
from backend.app.services.ingest import sync_all
from backend.app.services.lifecycle import recompute_all

log = structlog.get_logger()

_JOB_ID = "sync_all_connectors"
scheduler = BackgroundScheduler()


def run_scheduled_sync() -> None:
    """The scheduled job: sync every connector in its own DB session."""
    db = SessionLocal()
    try:
        runs = sync_all(db)
        synced = sum(r.findings_count for r in runs)
        # Flush snoozes that expired since the last run.
        recompute_all(db)
        log.info("scheduler.sync_done", connectors=len(runs), findings=synced)
    except Exception as exc:  # noqa: BLE001 — never let a bad run kill the scheduler thread
        log.error("scheduler.sync_failed", error=str(exc))
    finally:
        db.close()


def start_scheduler() -> None:
    interval = settings.sync_interval_minutes
    if interval <= 0:
        log.info("scheduler.disabled")
        return
    scheduler.add_job(
        run_scheduled_sync,
        trigger="interval",
        minutes=interval,
        id=_JOB_ID,
        max_instances=1,      # don't overlap a long sync with the next tick
        coalesce=True,        # collapse missed ticks into one
        replace_existing=True,
    )
    scheduler.start()
    log.info("scheduler.started", interval_minutes=interval)


def shutdown_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)


def schedule_status() -> dict:
    job = scheduler.get_job(_JOB_ID) if scheduler.running else None
    return {
        "enabled": settings.sync_interval_minutes > 0,
        "interval_minutes": settings.sync_interval_minutes,
        "running": scheduler.running,
        "next_run_at": job.next_run_time.isoformat() if job and job.next_run_time else None,
    }
