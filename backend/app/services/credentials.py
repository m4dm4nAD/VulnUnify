"""Store and resolve UI-managed connector credentials.

Values are encrypted at rest. `load_overrides` returns the decrypted overrides
for a connector; connectors fall back to env/.env for any key not overridden.
"""
from __future__ import annotations

import structlog
from sqlalchemy import delete as sql_delete
from sqlalchemy import select

from backend.app.db import SessionLocal
from backend.app.models.base import utcnow
from backend.app.models.connector_credential import ConnectorCredential
from backend.app.services import crypto

log = structlog.get_logger()


def _decrypt_row(row: ConnectorCredential, into: dict[str, str]) -> None:
    try:
        into[row.key] = crypto.decrypt(row.value)
    except crypto.InvalidToken:
        # Wrong/rotated SECRET_KEY — ignore so one bad row can't break sync.
        log.warning("credentials.undecryptable", connector=row.connector, key=row.key)


def load_overrides(connector: str) -> dict[str, str]:
    """Decrypted {key: value} overrides for one connector (skips undecryptable rows)."""
    out: dict[str, str] = {}
    with SessionLocal() as db:
        rows = db.scalars(
            select(ConnectorCredential).where(ConnectorCredential.connector == connector)
        )
        for row in rows:
            _decrypt_row(row, out)
    return out


def load_all_overrides() -> dict[str, dict[str, str]]:
    """Decrypted overrides for every connector in one query: {connector: {key: value}}."""
    out: dict[str, dict[str, str]] = {}
    with SessionLocal() as db:
        for row in db.scalars(select(ConnectorCredential)):
            _decrypt_row(row, out.setdefault(row.connector, {}))
    return out


def set_values(connector: str, values: dict[str, str]) -> None:
    """Upsert overrides. An empty-string value clears that key's override."""
    with SessionLocal() as db:
        for key, raw in values.items():
            existing = db.scalar(
                select(ConnectorCredential).where(
                    ConnectorCredential.connector == connector,
                    ConnectorCredential.key == key,
                )
            )
            if raw == "":
                if existing:
                    db.delete(existing)
                continue
            token = crypto.encrypt(raw)
            if existing:
                existing.value = token
                existing.updated_at = utcnow()
            else:
                db.add(
                    ConnectorCredential(
                        connector=connector, key=key, value=token, updated_at=utcnow()
                    )
                )
        db.commit()
    log.info("credentials.updated", connector=connector, keys=sorted(values))


def clear(connector: str) -> int:
    """Remove all overrides for a connector (reverts it to env/.env)."""
    with SessionLocal() as db:
        result = db.execute(
            sql_delete(ConnectorCredential).where(ConnectorCredential.connector == connector)
        )
        db.commit()
        return result.rowcount or 0
