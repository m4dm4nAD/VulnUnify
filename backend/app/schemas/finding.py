"""Pydantic response models for the API."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from backend.app.connectors.enums import TriageState


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
    source_status: str
    effective_status: str
    cve_ids: list
    cwe_ids: list
    cvss_base_score: float | None
    location: dict
    remediation: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    resolved_at: datetime | None
    # triage
    triage_state: str
    triage_reason: str | None
    triage_until: datetime | None
    triaged_at: datetime | None
    triaged_by: str | None
    # SLA / age (sla_due_at stored; age_days + sla_breached are computed properties)
    sla_due_at: datetime | None
    age_days: int | None
    sla_breached: bool
    asset: AssetOut


class TriageIn(BaseModel):
    """Apply a local triage decision to a finding."""
    state: TriageState
    reason: str | None = None
    until: datetime | None = None   # used when state == snoozed
    by: str | None = None


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


class ConfigFieldOut(BaseModel):
    key: str
    label: str
    secret: bool
    required: bool
    placeholder: str | None
    is_set: bool
    source: str          # db | env | unset
    value: str           # actual value for non-secret fields; "" for secrets
    display: str         # what to show (masked for secrets)


class ConnectorConfigOut(BaseModel):
    name: str
    configured: bool
    fields: list[ConfigFieldOut]


class ConfigUpdateIn(BaseModel):
    # {settings_key: value}. Empty string clears that key's override.
    values: dict[str, str]


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
    open_findings: int
    resolved_findings: int
    suppressed_findings: int       # false_positive + accepted_risk + snoozed
    sla_breached: int
    # The breakdowns below count OPEN findings only (what's actionable).
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_source: dict[str, int]
    # Open findings past their SLA deadline, per severity (subset of by_severity).
    breached_by_severity: dict[str, int]
