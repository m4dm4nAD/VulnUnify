"""Shared API helpers for turning upload/parse failures into uniform 400s.

Manifest, lockfile, SBOM, and container-report parsing all raise the same small
set of exceptions; this keeps every upload route mapping them to HTTP 400 the
same way instead of each hand-rolling (and diverging on) the try/except.
"""
from __future__ import annotations

import json
from contextlib import contextmanager

from fastapi import HTTPException


@contextmanager
def parse_400(what: str = "file"):
    """Map parse failures (bad value / malformed JSON / unexpected shape) to 400."""
    try:
        yield
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(400, f"could not parse {what}: {exc}") from exc
