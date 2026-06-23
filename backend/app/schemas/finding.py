"""Pydantic response models for the API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    identifier: str
    asset_type: str
    name: str | None
    cloud_provider: str | None
    region: str | None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    source: str
    category: str
    title: str
    description: str | None
    severity: str
    raw_severity: str | None
    status: str
    cve_ids: list
    cwe_ids: list
    cvss_base_score: float | None
    location: dict
    remediation: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    asset: AssetOut


class FindingPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingOut]


class ConnectorStatus(BaseModel):
    name: str
    category: str
    configured: bool
    last_run_at: datetime | None = None
    last_status: str | None = None
    last_findings_count: int | None = None


class ConnectorRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    connector: str
    status: str
    findings_count: int
    error: str | None
    started_at: datetime
    finished_at: datetime | None


class StatsOut(BaseModel):
    total_findings: int
    total_assets: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_source: dict[str, int]
