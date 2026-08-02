"""Notification config + manual triggers. Status is viewable by the security
team; editing the webhook or sending is security_admin only."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security_admin
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.notification import NotificationSettingsIn
from backend.app.services import app_settings, audit, notifications

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
def get_status(db: Session = Depends(get_db)):
    """Masked webhook, threshold, and delivery counters."""
    return notifications.status(db)


@router.put("/settings")
def update_settings(
    body: NotificationSettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    actor: User = Depends(require_security_admin),
):
    """Set/clear the webhook URL and/or the high-risk threshold."""
    values: dict = {}
    if body.webhook_url is not None:
        values["notify_slack_webhook_url"] = body.webhook_url
    if body.risk_threshold is not None:
        values["notify_risk_threshold"] = body.risk_threshold
    if values:
        app_settings.update(values)
        # The webhook URL is a credential: audit set/cleared, never the value.
        details: dict = {}
        if body.webhook_url is not None:
            details["webhook"] = "cleared" if body.webhook_url == "" else "set"
        if body.risk_threshold is not None:
            details["risk_threshold"] = body.risk_threshold
        audit.record(db, "notification.settings", "updated notification settings",
                     actor=actor, request=request, details=details)
    return notifications.status(db)


@router.post("/test")
def send_test(request: Request, db: Session = Depends(get_db),
              actor: User = Depends(require_security_admin)):
    """Post a test message so admins can verify the webhook end-to-end."""
    try:
        notifications.send_test()
    except ValueError:
        raise HTTPException(status_code=400, detail="no webhook URL configured")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"webhook delivery failed: {exc}")
    # Pushes finding data to the configured webhook — an egress action, audited.
    audit.record(db, "notification.test", "sent a test notification to the webhook",
                 actor=actor, request=request)
    return {"ok": True}


@router.post("/run")
def run_now(request: Request, db: Session = Depends(get_db),
            actor: User = Depends(require_security_admin)):
    """Evaluate the rules and send a digest immediately (same as a scheduler tick)."""
    try:
        result = notifications.run(db)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"webhook delivery failed: {exc}")
    # Egress of finding data to the webhook; record what went out.
    audit.record(db, "notification.run",
                 f"pushed a notification digest ({result.get('sent', 0)} findings)",
                 actor=actor, request=request, details=result)
    return result
