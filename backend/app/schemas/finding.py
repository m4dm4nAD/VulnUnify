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
    # assignment
    assigned_user_id: int | None
    assigned_username: str | None
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


class FindingDetail(FindingOut):
    """Full single-finding view, including the original source payload."""
    cvss_vector: str | None
    refs: list          # reference URLs
    tags: dict
    raw: dict           # the unmodified record from the source tool


class TriageIn(BaseModel):
    """Apply a local triage decision to a finding."""
    state: TriageState
    reason: str | None = None
    until: datetime | None = None   # used when state == snoozed


class FindingPage(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingOut]


class FindingGroup(BaseModel):
    """A set of findings correlated as one logical vulnerability (see services/correlation)."""
    key: str
    title: str                     # representative (highest-severity member) title
    severity: str                  # worst severity across members
    effective_status: str          # "open" if any member is open, else representative's
    count: int                     # findings in the group
    duplicate_count: int           # count - 1 (extra rows beyond the first)
    open_count: int
    sources: list[str]             # distinct sources contributing
    categories: list[str]
    cve_ids: list[str]             # union across members
    first_seen: datetime | None
    last_seen: datetime | None
    sla_breached: bool
    representative_id: int         # finding id to open for detail
    members: list[FindingOut]      # every underlying finding, preserved


class FindingGroupPage(BaseModel):
    total: int                     # number of groups (not findings)
    limit: int
    offset: int
    items: list[FindingGroup]


class ConnectorStatus(BaseModel):
    name: str
    category: str
    configured: bool
    last_run_at: datetime | None = None
    last_status: str | None = None
    last_findings_count: int | None = None
    last_error: str | None = None


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
    # De-duplication: distinct logical vulnerabilities vs. how many rows are dupes.
    unique_vulnerabilities: int
    duplicate_findings: int        # total_findings - unique_vulnerabilities
    # The breakdowns below count OPEN findings only (what's actionable).
    by_severity: dict[str, int]
    by_category: dict[str, int]
    by_source: dict[str, int]
    # Open findings past their SLA deadline, per severity (subset of by_severity).
    breached_by_severity: dict[str, int]
