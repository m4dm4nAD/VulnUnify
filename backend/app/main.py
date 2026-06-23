"""VulnUnify API entrypoint."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.api import routes_connectors, routes_findings, routes_sync
from backend.app.config import settings
from backend.app.scheduler import shutdown_scheduler, start_scheduler

logging.basicConfig(level=settings.log_level)
structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(logging.INFO))


@asynccontextmanager
async def lifespan(app: FastAPI):
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

app.include_router(routes_findings.router)
app.include_router(routes_connectors.router)
app.include_router(routes_sync.router)


@app.get("/health", tags=["meta"])
def health():
    return {"status": "ok"}


# Serve the static dashboard at / (built/placeholder files live in ../frontend).
_frontend = Path(__file__).resolve().parents[2] / "frontend"
if _frontend.is_dir():
    app.mount("/", StaticFiles(directory=str(_frontend), html=True), name="frontend")
