"""Connector inventory + status."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.deps import require_security_admin
from backend.app.config import settings
from backend.app.connectors.base import BaseConnector
from backend.app.connectors.registry import all_connectors, get_connector
from backend.app.models.user import User
from backend.app.db import get_db
from backend.app.models.connector_run import ConnectorRun
from backend.app.schemas.finding import (
    ConfigFieldOut,
    ConfigUpdateIn,
    ConnectorConfigOut,
    ConnectorRunOut,
    ConnectorStatus,
)
from backend.app.services import audit, credentials

router = APIRouter(prefix="/api/connectors", tags=["connectors"])


def _config_payload(c: BaseConnector) -> ConnectorConfigOut:
    """Build the (secret-masked) config view for a connector."""
    overrides = credentials.load_overrides(c.name)
    fields: list[ConfigFieldOut] = []
    for f in c.config_fields:
        db_set = f.key in overrides
        env_val = str(getattr(settings, f.key, "") or "")
        is_set = db_set or bool(env_val)
        if f.secret:
            value = ""                       # never expose secret values
            display = "•••••••• (set)" if is_set else ""
        else:
            value = overrides.get(f.key, env_val)
            display = value
        fields.append(
            ConfigFieldOut(
                key=f.key, label=f.label, secret=f.secret, required=f.required,
                placeholder=f.placeholder, is_set=is_set,
                source="db" if db_set else ("env" if env_val else "unset"),
                value=value, display=display,
            )
        )
    return ConnectorConfigOut(name=c.name, configured=c.is_configured(), fields=fields)


def _require(name: str) -> BaseConnector:
    c = get_connector(name)
    if c is None:
        raise HTTPException(404, f"unknown connector: {name}")
    return c


@router.get("", response_model=list[ConnectorStatus])
def list_connectors(db: Session = Depends(get_db)):
    """List every registered connector, whether it's configured, and its last run."""
    # Latest run per connector in one query (DISTINCT ON), plus one batch
    # credential load — avoids a query per connector.
    latest = db.scalars(
        select(ConnectorRun)
        .order_by(ConnectorRun.connector, ConnectorRun.started_at.desc())
        .distinct(ConnectorRun.connector)
    )
    last_by_name = {r.connector: r for r in latest}
    overrides = credentials.load_all_overrides()

    out: list[ConnectorStatus] = []
    for c in all_connectors():
        c._overrides = overrides.get(c.name, {})  # prime cache so is_configured() won't query
        last = last_by_name.get(c.name)
        out.append(
            ConnectorStatus(
                name=c.name,
                category=c.category.value,
                configured=c.is_configured(),
                last_run_at=last.started_at if last else None,
                last_status=last.status if last else None,
                last_findings_count=last.findings_count if last else None,
                last_error=last.error if last else None,
            )
        )
    return out


@router.get("/runs", response_model=list[ConnectorRunOut])
def list_runs(db: Session = Depends(get_db), limit: int = Query(50, ge=1, le=500)):
    return db.scalars(
        select(ConnectorRun).order_by(ConnectorRun.started_at.desc()).limit(limit)
    ).all()


@router.get("/{name}/config", response_model=ConnectorConfigOut)
def get_config(name: str, _: User = Depends(require_security_admin)):
    """The connector's configurable fields and whether each is set (secrets masked)."""
    return _config_payload(_require(name))


@router.put("/{name}/config", response_model=ConnectorConfigOut)
def update_config(name: str, body: ConfigUpdateIn, request: Request,
                  actor: User = Depends(require_security_admin)):
    """Store credential/config overrides (encrypted). Empty value clears a key."""
    connector = _require(name)
    allowed = {f.key for f in connector.config_fields}
    unknown = set(body.values) - allowed
    if unknown:
        raise HTTPException(400, f"unknown config keys: {sorted(unknown)}")
    credentials.set_values(name, body.values)
    # Audit the KEYS touched, never the values (they're credentials).
    audit.record(None, "connector.configure", f"configured connector {name}",
                 actor=actor, request=request, target_type="connector", target_id=name,
                 details={"set": sorted(k for k, v in body.values.items() if v != ""),
                          "cleared": sorted(k for k, v in body.values.items() if v == "")})
    return _config_payload(_require(name))   # fresh instance reloads overrides


@router.delete("/{name}/config", response_model=ConnectorConfigOut)
def reset_config(name: str, request: Request, actor: User = Depends(require_security_admin)):
    """Clear all stored overrides for a connector (revert to env/.env)."""
    _require(name)
    cleared = credentials.clear(name)
    audit.record(None, "connector.reset", f"reset connector {name} to .env config",
                 actor=actor, request=request, target_type="connector", target_id=name,
                 details={"cleared_rows": cleared})
    return _config_payload(_require(name))
