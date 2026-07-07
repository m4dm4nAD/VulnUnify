"""Package inventory + on-demand scanning.

The persistent watchlist (import/list/delete) is security-team only. The
`/scan` endpoint is open to any logged-in user (devs included): it parses an
uploaded file and queries OSV live, returning results. It does not touch the
watchlist, but it records a history entry of what was searched (which packages,
by whom, when) so the security team can review scan activity via `/scans`.
"""
from __future__ import annotations

import json

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException

from backend.app.api.deps import require_security, require_user
from backend.app.models.user import User
from backend.app.schemas.package import (
    PackageImportIn,
    PackageScanIn,
    PackageScanOut,
    PackageScanRecordOut,
    WatchedPackageOut,
)
from backend.app.services import osv_scan, packages
from backend.app.services.manifests import parse_manifest

log = structlog.get_logger()

router = APIRouter(prefix="/api/packages", tags=["packages"])


@router.post("/scan", response_model=PackageScanOut)
def scan_packages(body: PackageScanIn, user: User = Depends(require_user)):
    """Parse an uploaded file, check its packages against OSV, and record the search."""
    try:
        parsed = parse_manifest(body.filename, body.content)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except json.JSONDecodeError as exc:
        raise HTTPException(400, f"invalid file (expected JSON): {exc}")
    try:
        results = osv_scan.scan(parsed)
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"OSV lookup failed: {exc}")
    # Persist what was searched. A history-write failure must not deny the dev
    # their results, so log and carry on rather than 500-ing the scan.
    try:
        packages.record_scan(
            user_id=user.id, filename=body.filename, parsed=parsed, results=results
        )
    except Exception:  # noqa: BLE001 - best-effort audit trail
        log.warning("packages.scan_record_failed", filename=body.filename, exc_info=True)
    return PackageScanOut(
        checked=len(parsed),
        vulnerable=len(results),
        total_vulns=sum(len(r["vulns"]) for r in results),
        ecosystems=sorted({p.ecosystem for p in parsed}),
        results=results,
    )


@router.get("/scans", response_model=list[PackageScanRecordOut])
def list_scans(limit: int = 50, _: User = Depends(require_security)):
    """History of self-service scans: what was searched, by whom, when."""
    return packages.list_scans(limit=limit)


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
