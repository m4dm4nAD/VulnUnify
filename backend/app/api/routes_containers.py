"""Container scan ingestion (manual upload) + scanned-image summary. Security only."""
from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.app.api.deps import require_security
from backend.app.api.errors import parse_400
from backend.app.models.user import User
from backend.app.schemas.container import ContainerImportIn
from backend.app.services import containers

router = APIRouter(prefix="/api/containers", tags=["containers"])


@router.post("/import")
def import_report(body: ContainerImportIn, _: User = Depends(require_security)):
    """Upload a container scan report (e.g. `snyk container test --json`)."""
    with parse_400("report"):
        return containers.import_report(body.tool, body.content)


@router.get("/images")
def list_images(_: User = Depends(require_security)):
    return containers.list_images()
