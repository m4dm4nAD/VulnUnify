"""Container scan ingestion (manual upload) + scanned-image summary. Security only."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException

from backend.app.api.deps import require_security
from backend.app.models.user import User
from backend.app.schemas.container import ContainerImportIn
from backend.app.services import containers

router = APIRouter(prefix="/api/containers", tags=["containers"])


@router.post("/import")
def import_report(body: ContainerImportIn, _: User = Depends(require_security)):
    """Upload a container scan report (e.g. `snyk container test --json`)."""
    try:
        return containers.import_report(body.tool, body.content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise HTTPException(400, f"could not parse report: {exc}")


@router.get("/images")
def list_images(_: User = Depends(require_security)):
    return containers.list_images()
