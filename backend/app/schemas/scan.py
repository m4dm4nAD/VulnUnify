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


class ScanOut(BaseModel):
    id: int
    repo_url: str
    branch: str
    depth: str
    budget_usd: float
    status: str
    stage: str | None
    findings_count: int
    cost_usd: float
    session_id: str | None
    error: str | None
    username: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ClearwingStatusOut(BaseModel):
    available: bool           # the clearwing library is importable
    reason: str
    key_configured: bool      # an LLM key is set (DB override or container env)
