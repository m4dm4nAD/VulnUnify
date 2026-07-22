"""Notification config + manual triggers. Status is viewable by the security
team; editing the webhook or sending is security_admin only."""
from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security_admin
from backend.app.db import get_db
from backend.app.models.user import User
from backend.app.schemas.notification import NotificationSettingsIn
from backend.app.services import app_settings, notifications

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
def get_status(db: Session = Depends(get_db)):
    """Masked webhook, threshold, and delivery counters."""
    return notifications.status(db)


@router.put("/settings")
def update_settings(
    body: NotificationSettingsIn,
    db: Session = Depends(get_db),
    _: User = Depends(require_security_admin),
):
    """Set/clear the webhook URL and/or the high-risk threshold."""
    values: dict = {}
    if body.webhook_url is not None:
        values["notify_slack_webhook_url"] = body.webhook_url
    if body.risk_threshold is not None:
        values["notify_risk_threshold"] = body.risk_threshold
    if values:
        app_settings.update(values)
    return notifications.status(db)


@router.post("/test")
def send_test(_: User = Depends(require_security_admin)):
    """Post a test message so admins can verify the webhook end-to-end."""
    try:
        notifications.send_test()
    except ValueError:
        raise HTTPException(status_code=400, detail="no webhook URL configured")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"webhook delivery failed: {exc}")
    return {"ok": True}


@router.post("/run")
def run_now(db: Session = Depends(get_db), _: User = Depends(require_security_admin)):
    """Evaluate the rules and send a digest immediately (same as a scheduler tick)."""
    try:
        return notifications.run(db)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"webhook delivery failed: {exc}")
