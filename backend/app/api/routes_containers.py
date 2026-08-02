"""Container scan ingestion (manual upload) + scanned-image summary. Security only."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from backend.app.api.deps import require_security
from backend.app.api.errors import parse_400
from backend.app.models.user import User
from backend.app.schemas.container import ContainerImportIn
from backend.app.services import audit, containers

router = APIRouter(prefix="/api/containers", tags=["containers"])


@router.post("/import")
def import_report(body: ContainerImportIn, request: Request,
                  actor: User = Depends(require_security)):
    """Upload a container scan report (e.g. `snyk container test --json`)."""
    with parse_400("report"):
        result = containers.import_report(body.tool, body.content)
    audit.record(None, "container.import", f"imported {body.tool} container report",
                 actor=actor, request=request, details={"tool": body.tool})
    return result


@router.get("/images")
def list_images(_: User = Depends(require_security)):
    return containers.list_images()
