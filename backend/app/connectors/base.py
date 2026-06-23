"""The connector contract.

Every integration — whether it talks REST, GraphQL, PowerShell, or MCP —
produces a list of `NormalizedFinding`. The ingestion service handles the rest
(dedup, upsert, asset linking), so connectors only worry about *fetch + map*.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime

from pydantic import BaseModel, Field

from backend.app.connectors.enums import (
    AssetType,
    FindingCategory,
    FindingStatus,
    Severity,
)


class NormalizedAsset(BaseModel):
    """The thing a finding is about: a host, a cloud resource, a repo, etc."""
    asset_type: AssetType = AssetType.UNKNOWN
    # Canonical, stable identifier (hostname, IP, cloud resource id, repo URL).
    identifier: str
    name: str | None = None
    cloud_provider: str | None = None   # aws | azure | gcp | ...
    region: str | None = None
    metadata: dict = Field(default_factory=dict)


class NormalizedFinding(BaseModel):
    """The unified finding shape produced by all connectors."""
    source: str                         # connector name, e.g. "tenable"
    source_finding_id: str              # native id within the source tool
    category: FindingCategory
    title: str
    severity: Severity
    asset: NormalizedAsset

    description: str | None = None
    raw_severity: str | None = None     # the source's own label, preserved
    status: FindingStatus = FindingStatus.OPEN

    cve_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cvss_base_score: float | None = None
    cvss_vector: str | None = None

    # Where the finding lives — file:line for SAST, port/service for network,
    # resource path for cloud. Free-form so each category can use what fits.
    location: dict = Field(default_factory=dict)
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)
    tags: dict = Field(default_factory=dict)

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    raw: dict = Field(default_factory=dict)  # full original payload, for audit/debug

    def fingerprint(self) -> str:
        """Stable identity used to dedup/upsert across repeated syncs.

        Two findings with the same fingerprint are the *same issue* and the
        newer one updates the older. Built from source + asset + native id so
        the same finding re-ingested doesn't create a duplicate row.
        """
        key = "|".join(
            [
                self.source,
                self.asset.identifier,
                self.source_finding_id,
                # location discriminates multiple hits of one rule on one asset
                self.location.get("path", "") if self.location else "",
                str(self.location.get("line", "")) if self.location else "",
            ]
        )
        return hashlib.sha256(key.encode("utf-8")).hexdigest()


class BaseConnector(ABC):
    """Subclass this to add a tool. Three things are required:

    * `name`     — unique slug used in config, the API, and the `source` field
    * `category` — the default finding category for this tool
    * `is_configured()` — whether credentials are present
    * `fetch()`  — pull from the tool and return NormalizedFinding objects
    """

    name: str = "base"
    category: FindingCategory = FindingCategory.VULNERABILITY
    # When True, findings previously seen from this source but absent in a sync
    # are auto-resolved. Set False for connectors that do partial/filtered pulls.
    supports_auto_resolve: bool = True

    @abstractmethod
    def is_configured(self) -> bool:
        """True when required credentials/config are present."""

    @abstractmethod
    def fetch(self) -> list[NormalizedFinding]:
        """Pull findings from the source tool and normalize them."""
