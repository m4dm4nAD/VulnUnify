"""The connector contract.

Every integration — whether it talks REST, GraphQL, PowerShell, or MCP —
produces a list of `NormalizedFinding`. The ingestion service handles the rest
(dedup, upsert, asset linking), so connectors only worry about *fetch + map*.
"""
from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from datetime import datetime

import httpx
from pydantic import BaseModel, Field

from backend.app.config import settings
from backend.app.connectors.enums import (
    AssetType,
    FindingCategory,
    FindingStatus,
    Severity,
)
from backend.app.services import credentials as cred_store

# Shared HTTP timeouts for all REST/GraphQL connectors (seconds).
HTTP_TIMEOUT = 60.0        # data requests (exports, paged pulls)
TOKEN_TIMEOUT = 30.0       # OAuth token exchanges


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


class ConfigField(BaseModel):
    """One configurable setting for a connector, used to render its config form.

    `key` is both the env/.env settings attribute and the DB override key.
    """
    key: str
    label: str
    secret: bool = False        # render as a password input; never returned via API
    required: bool = True
    placeholder: str | None = None


class BaseConnector(ABC):
    """Subclass this to add a tool. Required pieces:

    * `name`     — unique slug used in config, the API, and the `source` field
    * `category` — the default finding category for this tool
    * `config_fields` — settings the UI can manage (keys also map to env/.env)
    * `is_configured()` — whether credentials are present
    * `fetch()`  — pull from the tool and return NormalizedFinding objects

    Read settings via `self.config("key")` so UI-managed (DB) credentials
    override env/.env values transparently.
    """

    name: str = "base"
    category: FindingCategory = FindingCategory.VULNERABILITY
    # When True, findings previously seen from this source but absent in a sync
    # are auto-resolved. Set False for connectors that do partial/filtered pulls.
    supports_auto_resolve: bool = True
    config_fields: list[ConfigField] = []

    _overrides: dict[str, str] | None = None

    def config(self, key: str) -> str:
        """Resolve a setting: DB override (UI-managed) first, else env/.env."""
        if self._overrides is None:
            self._overrides = cred_store.load_overrides(self.name)
        if key in self._overrides:
            return self._overrides[key]
        return str(getattr(settings, key, "") or "")

    def is_configured(self) -> bool:
        """True when every `required` config field has a value.

        Derived from `config_fields` so it can't drift from the declared form;
        override only for non-standard rules. A connector with no fields (e.g.
        a public API) is always configured.
        """
        return all(self.config(f.key) for f in self.config_fields if f.required)

    # -- shared HTTP helpers (used by REST/GraphQL connectors) --

    def _rest_client(
        self,
        *,
        base_url_key: str | None = None,
        headers: dict | None = None,
        auth: httpx.Auth | None = None,
        verify: bool = True,
    ) -> httpx.Client:
        """A configured httpx.Client with the shared timeout.

        `base_url_key` is a config key resolved to the client's base URL.
        """
        return httpx.Client(
            base_url=self.config(base_url_key) if base_url_key else "",
            headers=headers or {},
            auth=auth,
            verify=verify,
            timeout=HTTP_TIMEOUT,
        )

    def _oauth_token(
        self, token_url: str, *, data: dict, auth: httpx.Auth | None = None
    ) -> str:
        """OAuth2 client-credentials token exchange, shared by OAuth connectors."""
        resp = httpx.post(token_url, data=data, auth=auth, timeout=TOKEN_TIMEOUT)
        resp.raise_for_status()
        token = resp.json().get("access_token")
        if not token:
            raise RuntimeError(f"{self.name}: no access_token in token response")
        return token

    @abstractmethod
    def fetch(self) -> list[NormalizedFinding]:
        """Pull findings from the source tool and normalize them."""
