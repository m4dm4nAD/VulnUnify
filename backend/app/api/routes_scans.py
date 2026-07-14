"""Clearwing source-code scans (EXPERIMENTAL / lab).

Start an on-demand `sourcehunt` against a Git repo, list scans, and check
whether the Clearwing library is available. Findings land in the unified
findings list under source "clearwing". Security-team only.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from backend.app.api.deps import require_security, require_security_admin
from backend.app.models.user import User
from backend.app.schemas.finding import ConfigUpdateIn, ConnectorConfigOut
from backend.app.schemas.scan import ClearwingStatusOut, ScanOut, ScanStartIn
from backend.app.services import clearwing

router = APIRouter(prefix="/api/clearwing", tags=["clearwing"])


@router.get("/status", response_model=ClearwingStatusOut)
def status(_: User = Depends(require_security)):
    """Whether the Clearwing library is importable + whether an LLM key is set."""
    available, reason = clearwing.is_available()
    return ClearwingStatusOut(
        available=available, reason=reason, key_configured=clearwing.key_configured()
    )


@router.get("/config", response_model=ConnectorConfigOut)
def get_config(_: User = Depends(require_security_admin)):
    """Clearwing LLM credentials (secrets masked). Admin only."""
    return clearwing.config_view()


@router.put("/config", response_model=ConnectorConfigOut)
def update_config(body: ConfigUpdateIn, _: User = Depends(require_security_admin)):
    """Store LLM credentials (encrypted). Empty value clears a key."""
    try:
        clearwing.set_config(body.values)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return clearwing.config_view()


@router.delete("/config", response_model=ConnectorConfigOut)
def reset_config(_: User = Depends(require_security_admin)):
    """Clear all stored Clearwing credentials (revert to container env)."""
    clearwing.clear_config()
    return clearwing.config_view()


@router.post("/scan", response_model=ScanOut, status_code=202)
def start_scan(body: ScanStartIn, user: User = Depends(require_security)):
    """Queue a source-code scan. Runs in the background; poll GET /scans/{id}."""
    scan_id = clearwing.start_scan(
        user_id=user.id, repo_url=body.repo_url, branch=body.branch,
        depth=body.depth, budget_usd=body.budget_usd,
    )
    scan = clearwing.get_scan(scan_id)
    if scan is None:
        raise HTTPException(500, "scan could not be created")
    return scan


@router.get("/scans", response_model=list[ScanOut])
def list_scans(limit: int = Query(50, ge=1, le=200), _: User = Depends(require_security)):
    return clearwing.list_scans(limit=limit)


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, _: User = Depends(require_security)):
    scan = clearwing.get_scan(scan_id)
    if scan is None:
        raise HTTPException(404, "scan not found")
    return scan
