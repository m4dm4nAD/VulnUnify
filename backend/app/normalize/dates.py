"""Shared date parsing for connector payloads.

Connectors hand back timestamps in two shapes: ISO-8601 strings (often with a
trailing 'Z') and Unix epoch seconds. Both parsers return an aware datetime or
None on anything unparseable — ingestion falls back to utcnow() for None.
"""
from __future__ import annotations

from datetime import datetime, timezone


def parse_iso(value) -> datetime | None:
    """Parse an ISO-8601 timestamp (tolerating a trailing 'Z')."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def parse_epoch(value) -> datetime | None:
    """Parse Unix epoch seconds into an aware UTC datetime."""
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None
