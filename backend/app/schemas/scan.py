"""Clearwing scan API schemas (experimental)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class ScanStartIn(BaseModel):
    repo_url: str = Field(min_length=3, max_length=1024)
    branch: str = Field("main", max_length=256)
    depth: Literal["quick", "standard", "deep"] = "standard"
    budget_usd: float = Field(0, ge=0, le=1000)
    # Deepened pipeline options (all opt-in; off by default for safety).
    exploit: bool = False        # multi-turn exploit development (verifies impact)
    auto_patch: bool = False     # generate + validate fix patches
    auto_pr: bool = False        # open a draft PR with the patch (needs a git token)
    disclosures: bool = False    # emit MITRE/HackerOne disclosure templates


class ScanOut(BaseModel):
    id: int
    repo_url: str
    branch: str
    depth: str
    budget_usd: float
    # options
    exploit: bool
    auto_patch: bool
    auto_pr: bool
    disclosures: bool
    # lifecycle
    status: str
    stage: str | None
    activity: str | None       # live "doing X" detail while running
    error: str | None
    session_id: str | None
    # metrics
    findings_count: int
    verified_count: int
    exploited_count: int
    files_ranked: int
    files_hunted: int
    tokens_used: int
    duration_seconds: float | None
    exit_code: int | None
    cost_usd: float
    # artifacts (content fetched separately via the artifact endpoints)
    has_sarif: bool
    has_report: bool
    username: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ClearwingStatusOut(BaseModel):
    available: bool           # the clearwing library is importable
    reason: str
    key_configured: bool      # an LLM key is set (DB override or container env)
