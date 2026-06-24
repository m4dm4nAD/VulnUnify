"""VulnUnify API entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.api import (
    routes_auth,
    routes_connectors,
    routes_findings,
    routes_lifecycle,
    routes_settings,
    routes_sync,
    routes_users,
)
from backend.app.api.deps import require_security, require_user
from backend.app.config import settings
from backend.app.db import SessionLocal
from backend.app.scheduler import shutdown_scheduler, start_scheduler
from backend.app.services.auth import seed_initial_admin

logging.basicConfig(level=settings.log_level)
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))


@asynccontextmanager
async def lifespan(app: FastAPI):
    with SessionLocal() as db:
        seed_initial_admin(db)
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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth router is open. Findings + users do per-route role checks internally;
# the rest are security-team only (devs are 403'd at the router boundary).
app.include_router(routes_auth.router)

_logged_in = [Depends(require_user)]
_security = [Depends(require_security)]
app.include_router(routes_findings.router, dependencies=_logged_in)
app.include_router(routes_users.router, dependencies=_logged_in)
app.include_router(routes_connectors.router, dependencies=_security)
app.include_router(routes_sync.router, dependencies=_security)
app.include_router(routes_lifecycle.router, dependencies=_security)
app.include_router(routes_settings.router, dependencies=_security)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


# Serve the static dashboard at / (built/placeholder files live in ../frontend).
_frontend = Path(__file__).resolve().parents[2] / "frontend"
if _frontend.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend), html=True), name="frontend")
