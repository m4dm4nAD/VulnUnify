"""VulnUnify API entrypoint."""
from __future__ import annotations

import logging
import traceback
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.app.api import (
    routes_assets,
    routes_auth,
    routes_connectors,
    routes_containers,
    routes_errors,
    routes_findings,
    routes_intel,
    routes_lifecycle,
    routes_notifications,
    routes_packages,
    routes_posture,
    routes_settings,
    routes_sync,
    routes_users,
)
from backend.app.api.deps import require_security, require_user
from backend.app.config import settings
from backend.app.db import SessionLocal
from backend.app.scheduler import shutdown_scheduler, start_scheduler
from backend.app.services import errorlog, intel
from backend.app.services.auth import seed_initial_admin

# One level drives both stdlib logging and structlog, so LOG_LEVEL actually
# takes effect (structlog previously hardcoded INFO, ignoring the setting).
_LOG_LEVEL = getattr(logging, settings.log_level.upper(), logging.INFO)
logging.basicConfig(level=_LOG_LEVEL)
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(_LOG_LEVEL))


@asynccontextmanager
async def lifespan(app: FastAPI):
    with SessionLocal() as db:
        seed_initial_admin(db)
        intel.seed_builtin(db)   # ensure the KEV + EPSS feeds exist
    # Posture history accrues even with sync off: the startup snapshot runs as a
    # one-shot background job so its aggregate scans never delay /health.
    start_scheduler()
    try:
        yield
    finally:
        shutdown_scheduler()


app = FastAPI(
    title="VulnUnify",
    version="0.1.0",
    description="Unified vulnerability, cloud-posture, and SAST findings.",
    lifespan=lifespan,
)

# The dashboard is served same-origin, so CORS is only needed when the API is
# called from another origin. Off by default (no wildcard); set CORS_ALLOW_ORIGINS
# to an explicit list to enable credentialed cross-origin access.
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

_MAX_BODY_BYTES = 32 * 1024 * 1024  # 32 MB cap on uploads (manifests/scan reports)
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.middleware("http")
async def _limit_body_size(request: Request, call_next):
    # Fast reject on a declared oversized length. The hard enforcement lives on
    # the request schemas (max_length on upload `content` fields), which also
    # covers chunked bodies that omit Content-Length.
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > _MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "request body too large"})
    return await call_next(request)


@app.middleware("http")
async def _origin_check(request: Request, call_next):
    """CSRF defense-in-depth: in production, reject state-changing requests whose
    browser Origin isn't same-origin (or an allowed CORS origin). Complements the
    SameSite=Lax cookie. Non-browser clients (no Origin header) are unaffected."""
    if settings.is_production and request.method in _MUTATING_METHODS:
        origin = request.headers.get("origin")
        if origin:
            allowed = {str(request.base_url).rstrip("/"), *settings.cors_origins}
            if origin.rstrip("/") not in allowed:
                return JSONResponse(
                    status_code=403, content={"detail": "cross-origin request blocked"}
                )
    return await call_next(request)


@app.middleware("http")
async def _revalidate_static(request: Request, call_next):
    """Force browsers to revalidate the dashboard's static assets so an edit is
    picked up on the next load (StaticFiles still answers 304 when unchanged),
    instead of silently serving a stale cached page/script/style."""
    response = await call_next(request)
    path = request.url.path
    if request.method == "GET" and (path == "/" or path.endswith((".html", ".css", ".js"))):
        response.headers["Cache-Control"] = "no-cache"
    return response

# Auth router is open. Findings + users do per-route role checks internally;
# the rest are security-team only (devs are 403'd at the router boundary).
app.include_router(routes_auth.router)

_logged_in = [Depends(require_user)]
_security = [Depends(require_security)]
app.include_router(routes_findings.router, dependencies=_logged_in)
app.include_router(routes_users.router, dependencies=_logged_in)
app.include_router(routes_connectors.router, dependencies=_security)
app.include_router(routes_sync.router, dependencies=_security)
app.include_router(routes_intel.router, dependencies=_security)
app.include_router(routes_assets.router, dependencies=_security)
app.include_router(routes_lifecycle.router, dependencies=_security)
app.include_router(routes_settings.router, dependencies=_security)
app.include_router(routes_notifications.router, dependencies=_security)
app.include_router(routes_posture.router, dependencies=_security)
# Packages: only /scan is open to all logged-in users (self-service dep check);
# watchlist import/list/delete enforce require_security per-route.
app.include_router(routes_packages.router, dependencies=_logged_in)
app.include_router(routes_containers.router, dependencies=_security)
app.include_router(routes_errors.router, dependencies=_security)


@app.exception_handler(Exception)
async def _on_unhandled(request: Request, exc: Exception):
    """Persist unexpected (500) errors and return a generic detail to the client."""
    errorlog.record(f"api:{request.url.path}", f"{type(exc).__name__}: {exc}",
                    traceback.format_exc())
    return JSONResponse(status_code=500, content={"detail": "internal server error"})


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


# Serve the static dashboard at / (built/placeholder files live in ../frontend).
_frontend = Path(__file__).resolve().parents[2] / "frontend"
if _frontend.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend), html=True), name="frontend")
