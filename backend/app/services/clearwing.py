"""Clearwing sourcehunt integration (EXPERIMENTAL / lab).

Runs Clearwing's `SourceHuntRunner` as a background job against a Git repo and
ingests the resulting findings into the unified findings table as source
"clearwing". Clearwing is an optional, heavy dependency with its own LLM config
(ANTHROPIC_API_KEY / CLEARWING_*), so it is imported lazily and a missing/failed
install degrades to a clean job error rather than breaking the app.

Note (lab): each scan runs in a daemon thread. A process restart orphans an
in-flight scan; `reset_stuck_scans()` marks such rows failed on startup.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import traceback
from dataclasses import asdict, is_dataclass

import structlog
from sqlalchemy import select, update
from sqlalchemy.orm import joinedload

from backend.app.connectors.base import NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import AssetType, FindingCategory, Severity
from backend.app.db import SessionLocal
from backend.app.models.base import utcnow
from backend.app.models.clearwing_scan import ClearwingScan
from backend.app.services import credentials, errorlog
from backend.app.services.ingest import ingest_findings

log = structlog.get_logger()

DEPTHS = ("quick", "standard", "deep")

_SEVERITY = {
    "critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
    "low": Severity.LOW, "info": Severity.INFO,
}

# LLM credentials for Clearwing, managed from the Connectors page and stored
# encrypted (reusing the connector credential store, bucket "clearwing"). Each
# maps to the environment variable Clearwing itself reads at scan time.
CLEARWING_CRED = "clearwing"
# (stored key, env var Clearwing reads, label, secret)
CONFIG_FIELDS = (
    ("anthropic_api_key", "ANTHROPIC_API_KEY", "Anthropic API key", True),
    ("clearwing_base_url", "CLEARWING_BASE_URL", "Custom base URL (OpenAI-compatible)", False),
    ("clearwing_api_key", "CLEARWING_API_KEY", "Custom API key", True),
    ("clearwing_model", "CLEARWING_MODEL", "Model override", False),
)


def _apply_env_creds() -> None:
    """Push DB-stored LLM creds into the environment so SourceHuntRunner picks
    them up. Stored values win; anything unset falls back to the container env."""
    ov = credentials.load_overrides(CLEARWING_CRED)
    for key, env_var, _label, _secret in CONFIG_FIELDS:
        if ov.get(key):
            os.environ[env_var] = ov[key]


def key_configured() -> bool:
    """Whether at least one LLM key is available (DB override or container env)."""
    ov = credentials.load_overrides(CLEARWING_CRED)
    if ov.get("anthropic_api_key") or ov.get("clearwing_api_key"):
        return True
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("CLEARWING_API_KEY"))


def config_view() -> dict:
    """Masked config view (same shape as connector config) for the settings UI."""
    ov = credentials.load_overrides(CLEARWING_CRED)
    fields = []
    for key, env_var, label, secret in CONFIG_FIELDS:
        db_set = key in ov
        env_val = os.environ.get(env_var, "")
        is_set = db_set or bool(env_val)
        if secret:
            value, display = "", ("•••••••• (set)" if is_set else "")
        else:
            value, display = ov.get(key, env_val), ov.get(key, env_val)
        fields.append({
            "key": key, "label": label, "secret": secret, "required": False,
            "placeholder": None, "is_set": is_set,
            "source": "db" if db_set else ("env" if env_val else "unset"),
            "value": value, "display": display,
        })
    return {"name": "clearwing", "configured": key_configured(), "fields": fields}


def set_config(values: dict) -> None:
    allowed = {k for k, *_ in CONFIG_FIELDS}
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"unknown config keys: {sorted(unknown)}")
    credentials.set_values(CLEARWING_CRED, values)


def clear_config() -> None:
    credentials.clear(CLEARWING_CRED)


def is_available() -> tuple[bool, str]:
    """Whether the Clearwing library is importable in this environment."""
    try:
        import clearwing.sourcehunt.runner  # noqa: F401
        return True, ""
    except Exception as exc:  # noqa: BLE001 - any import problem means "unavailable"
        return False, f"{type(exc).__name__}: {exc}"


def to_normalized(repo_url: str, f: dict) -> NormalizedFinding:
    """Map one Clearwing Finding (as a dict) to a VulnUnify NormalizedFinding.

    Kept pure (dict in, NormalizedFinding out) so it can be exercised without
    Clearwing installed. Field names follow clearwing.findings.types.Finding.
    """
    sev_raw = (f.get("severity") or "info").lower()
    cves = [c for c in (f.get("cve"), f.get("related_cve")) if c]
    cwes = [f["cwe"]] if f.get("cwe") else []
    ftype = (f.get("finding_type") or "").strip()
    title = (ftype.replace("_", " ") or (f.get("description") or "").strip()
             or "Clearwing finding")[:200]
    fid = f.get("id") or f"{ftype}:{f.get('file', '')}:{f.get('line_number', '')}"

    return NormalizedFinding(
        source="clearwing",
        source_finding_id=str(fid),
        category=FindingCategory.SAST,
        title=title,
        description=f.get("description") or f.get("details") or None,
        severity=_SEVERITY.get(sev_raw, Severity.INFO),
        raw_severity=sev_raw,
        cve_ids=cves,
        cwe_ids=cwes,
        cvss_base_score=f.get("cvss"),
        location={"path": f.get("file"), "line": f.get("line_number"),
                  "end_line": f.get("end_line")},
        remediation=f.get("auto_patch") or None,
        references=[],
        tags={
            "evidence_level": f.get("evidence_level"),
            "confidence": f.get("confidence"),
            "verified": f.get("verified"),
            "exploit_success": f.get("exploit_success"),
            "discovered_by": f.get("discovered_by"),
            "clearwing_finding_type": ftype or None,
        },
        asset=NormalizedAsset(
            asset_type=AssetType.REPOSITORY, identifier=repo_url, name=repo_url
        ),
        raw=f,
    )


def start_scan(*, user_id: int | None, repo_url: str, branch: str, depth: str,
               budget_usd: float) -> int:
    """Create a queued scan and kick off its background thread. Returns the id."""
    with SessionLocal() as db:
        scan = ClearwingScan(
            repo_url=repo_url.strip(), branch=(branch or "main").strip(),
            depth=depth if depth in DEPTHS else "standard",
            budget_usd=budget_usd, status="queued", created_by=user_id,
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id
    threading.Thread(target=_run, args=(scan_id,), daemon=True).start()
    log.info("clearwing.scan_queued", scan_id=scan_id, repo_url=repo_url, depth=depth)
    return scan_id


def _set(scan_id: int, **fields) -> None:
    with SessionLocal() as db:
        db.execute(update(ClearwingScan).where(ClearwingScan.id == scan_id).values(**fields))
        db.commit()


def _clone_repo(repo_url: str, branch: str, dest: str) -> None:
    """Clone repo_url@branch into `dest`, which we own for the scan's lifetime.

    Why we clone instead of letting Clearwing do it: clearwing 1.0.0's
    preprocessor clones into a `tempfile.TemporaryDirectory` owned by a throwaway
    `SourceAnalyzer`, then reassigns that owner mid-run. The finalizer deletes the
    checkout *before* analysis, so every scan enumerates 0 files and "succeeds"
    with 0 findings. Handing the runner a `local_path` skips its self-deleting
    clone entirely (see `_run`).
    """
    base = ["git", "clone", "--depth", "1"]
    proc = subprocess.run(
        [*base, "--branch", branch, repo_url, dest],
        capture_output=True, text=True, timeout=300,
    )
    if proc.returncode == 0:
        return
    # Branch may not exist (or isn't a branch) — retry on the default branch.
    shutil.rmtree(dest, ignore_errors=True)   # drop any partial checkout first
    proc = subprocess.run(
        [*base, repo_url, dest], capture_output=True, text=True, timeout=300,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {proc.stderr.strip() or proc.stdout.strip()}")


def _run(scan_id: int) -> None:
    _set(scan_id, status="running", stage="preprocess", started_at=utcnow())

    try:
        from clearwing.sourcehunt.runner import SourceHuntRunner
    except Exception as exc:  # noqa: BLE001 - clearwing not installed / broken import
        _set(scan_id, status="failed", finished_at=utcnow(),
             error=f"Clearwing is not available in this environment: {type(exc).__name__}: {exc}. "
                   "Install it (uv sync in the clearwing repo, or pip install) and set an LLM key "
                   "(ANTHROPIC_API_KEY / CLEARWING_*).")
        log.warning("clearwing.unavailable", scan_id=scan_id, error=str(exc))
        return

    _apply_env_creds()   # DB-managed LLM keys → environment for the runner

    with SessionLocal() as db:
        scan = db.get(ClearwingScan, scan_id)
        repo_url, branch, depth, budget = scan.repo_url, scan.branch, scan.depth, scan.budget_usd

    try:
        # We clone into a dir we own (cleaned up on block exit) and pass it as
        # local_path so Clearwing doesn't use its self-deleting clone. See
        # _clone_repo. The workdir must outlive runner.run(), so it wraps it.
        with tempfile.TemporaryDirectory(prefix="vulnunify-clearwing-") as workdir:
            repo_dir = os.path.join(workdir, "repo")
            _set(scan_id, stage="clone")
            _clone_repo(repo_url, branch, repo_dir)

            _set(scan_id, stage="scan")
            runner = SourceHuntRunner(
                repo_url=repo_url, local_path=repo_dir, branch=branch,
                depth=depth, budget_usd=budget,
                no_exploit=True,             # discovery + verification only, for now
                output_formats=["json"],
            )
            result = runner.run()            # blocks; LLM clients resolve from env/config

            findings = result.findings or []
            normalized = [to_normalized(repo_url, _as_dict(f)) for f in findings]
            with SessionLocal() as db:
                ingest_findings(db, normalized)

        _set(scan_id, status="succeeded", stage="report", finished_at=utcnow(),
             findings_count=len(findings), cost_usd=float(getattr(result, "cost_usd", 0.0) or 0.0),
             session_id=str(getattr(result, "session_id", "") or "") or None)
        log.info("clearwing.scan_done", scan_id=scan_id, findings=len(findings))
    except Exception as exc:  # noqa: BLE001 - surface any runner failure on the job
        _set(scan_id, status="failed", finished_at=utcnow(),
             error=f"{type(exc).__name__}: {exc}")
        errorlog.record(f"clearwing:scan:{scan_id}", f"{type(exc).__name__}: {exc}",
                        traceback.format_exc())
        log.error("clearwing.scan_failed", scan_id=scan_id, error=str(exc))


def _as_dict(f) -> dict:
    """Clearwing Findings are dataclasses; accept dicts too (for testing)."""
    if is_dataclass(f) and not isinstance(f, type):
        return asdict(f)
    if isinstance(f, dict):
        return f
    return dict(getattr(f, "__dict__", {}))


def reset_stuck_scans() -> int:
    """Mark scans left 'running' by a previous process as failed (called on startup)."""
    with SessionLocal() as db:
        rows = db.execute(
            update(ClearwingScan)
            .where(ClearwingScan.status.in_(("queued", "running")))
            .values(status="failed", finished_at=utcnow(),
                    error="Interrupted by a server restart.")
        )
        db.commit()
        return rows.rowcount or 0


def list_scans(limit: int = 50) -> list[dict]:
    with SessionLocal() as db:
        scans = db.scalars(
            select(ClearwingScan)
            .options(joinedload(ClearwingScan.user))
            .order_by(ClearwingScan.created_at.desc())
            .limit(limit)
        ).all()
        return [_out(s) for s in scans]


def get_scan(scan_id: int) -> dict | None:
    with SessionLocal() as db:
        scan = db.get(ClearwingScan, scan_id)
        return _out(scan) if scan else None


def _out(s: ClearwingScan) -> dict:
    return {
        "id": s.id, "repo_url": s.repo_url, "branch": s.branch, "depth": s.depth,
        "budget_usd": s.budget_usd, "status": s.status, "stage": s.stage,
        "findings_count": s.findings_count, "cost_usd": s.cost_usd,
        "session_id": s.session_id, "error": s.error,
        "username": s.user.username if s.user else None,
        "created_at": s.created_at, "started_at": s.started_at, "finished_at": s.finished_at,
    }
