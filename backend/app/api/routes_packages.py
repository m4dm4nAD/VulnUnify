"""Watched-package inventory: import manifests, list, delete. Security team only."""
from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException

from backend.app.api.deps import require_security
from backend.app.models.user import User
from backend.app.schemas.package import PackageImportIn, WatchedPackageOut
from backend.app.services import packages

router = APIRouter(prefix="/api/packages", tags=["packages"])


@router.post("/import")
def import_packages(body: PackageImportIn, _: User = Depends(require_security)):
    """Parse a manifest/lockfile and add its packages to the watchlist."""
    try:
        return packages.import_manifest(body.filename, body.content, body.source)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"invalid manifest JSON: {exc}")


@router.get("", response_model=list[WatchedPackageOut])
def list_watched(
    ecosystem: str | None = None,
    source: str | None = None,
    _: User = Depends(require_security),
):
    return packages.list_packages(ecosystem=ecosystem, source=source)


@router.get("/summary")
def packages_summary(_: User = Depends(require_security)):
    return packages.summary()


@router.delete("/{package_id}", status_code=204)
def delete_watched(package_id: int, _: User = Depends(require_security)):
    if not packages.delete_package(package_id):
        raise HTTPException(404, "package not found")
