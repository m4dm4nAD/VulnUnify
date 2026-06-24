"""Aikido Security connector  (modality: REST API; SAST / SCA / secrets / IaC).

Auth is OAuth2 client-credentials (HTTP Basic on the token endpoint); findings
come from the issues export:
  POST {base}/oauth/token        (Basic client_id:client_secret)
  GET  {base}/public/v1/issues/export?page=N&per_page=...
Docs: https://apidocs.aikido.dev/

Aikido covers several issue classes, so this connector picks the normalized
category per issue from its `type` rather than using a single fixed one.
"""
from __future__ import annotations

from datetime import datetime, timezone

import httpx

from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus
from backend.app.normalize import severity as sev

# Aikido issue type -> normalized category.
_CATEGORY_MAP = {
    "sast": FindingCategory.SAST,
    "open_source": FindingCategory.SCA,
    "open_source_dependency": FindingCategory.SCA,
    "leaked_secret": FindingCategory.SECRET,
    "secret": FindingCategory.SECRET,
    "iac": FindingCategory.IAC,
    "cloud": FindingCategory.CLOUD_POSTURE,
    "container": FindingCategory.CONTAINER,
}
_STATUS_MAP = {
    "open": FindingStatus.OPEN,
    "closed": FindingStatus.FIXED,
    "ignored": FindingStatus.SUPPRESSED,
    "snoozed": FindingStatus.SUPPRESSED,
}
_PER_PAGE = 100


class AikidoConnector(BaseConnector):
    name = "aikido"
    category = FindingCategory.SAST  # default; overridden per issue in _normalize
    config_fields = [
        ConfigField(key="aikido_client_id", label="Client ID"),
        ConfigField(key="aikido_client_secret", label="Client secret", secret=True),
        ConfigField(key="aikido_base_url", label="Base URL", required=False,
                    placeholder="https://app.aikido.dev/api"),
    ]

    def is_configured(self) -> bool:
        return bool(self.config("aikido_client_id") and self.config("aikido_client_secret"))

    def _get_token(self) -> str:
        resp = httpx.post(
            f"{self.config('aikido_base_url')}/oauth/token",
            data={"grant_type": "client_credentials"},
            auth=httpx.BasicAuth(self.config("aikido_client_id"), self.config("aikido_client_secret")),
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def fetch(self) -> list[NormalizedFinding]:
        token = self._get_token()
        findings: list[NormalizedFinding] = []
        with httpx.Client(
            base_url=self.config("aikido_base_url"),
            headers={"Authorization": f"Bearer {token}"},
            timeout=60.0,
        ) as client:
            page = 0
            while True:
                resp = client.get(
                    "/public/v1/issues/export",
                    params={"page": page, "per_page": _PER_PAGE, "filter_status": "open"},
                )
                resp.raise_for_status()
                batch = resp.json()
                if not batch:
                    break
                findings.extend(self._normalize(i) for i in batch)
                if len(batch) < _PER_PAGE:
                    break
                page += 1
        return findings

    def _normalize(self, issue: dict) -> NormalizedFinding:
        issue_type = (issue.get("type") or "").lower()
        category = _CATEGORY_MAP.get(issue_type, FindingCategory.SAST)
        repo = issue.get("code_repo_name") or "unknown-repo"
        cve = issue.get("cve_id")

        return NormalizedFinding(
            source=self.name,
            source_finding_id=str(issue.get("id")),
            category=category,
            title=issue.get("rule") or issue.get("rule_id") or f"Aikido {issue_type} issue",
            description=issue.get("description"),
            severity=sev.from_label(issue.get("severity")),
            raw_severity=issue.get("severity"),
            status=_STATUS_MAP.get((issue.get("status") or "open").lower(), FindingStatus.OPEN),
            asset=NormalizedAsset(
                asset_type=AssetType.REPOSITORY,
                identifier=repo,
                name=repo,
            ),
            cve_ids=[cve] if cve else [],
            location={
                "path": issue.get("file_path"),
                "line": issue.get("start_line"),
                "package": issue.get("affected_package"),
            },
            tags={
                "type": issue_type,
                "rule_id": issue.get("rule_id"),
                "severity_score": issue.get("severity_score"),
                "affected_package_version": issue.get("affected_package_version"),
            },
            first_seen=_epoch_dt(issue.get("first_detected_at")),
            raw=issue,
        )


def _epoch_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (ValueError, TypeError, OSError):
        return None
