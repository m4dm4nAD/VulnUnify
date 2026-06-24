"""Semgrep connector  (modality: REST API, SAST).

Pulls from the Semgrep AppSec Platform findings API:
GET /api/v1/deployments/{slug}/findings   (Authorization: Bearer <token>)
Docs: https://semgrep.dev/api/v1/docs/
"""
from __future__ import annotations

import re

import httpx

from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus
from backend.app.normalize import severity as sev
from backend.app.normalize.dates import parse_iso

_STATE_MAP = {
    "open": FindingStatus.OPEN,
    "fixed": FindingStatus.FIXED,
    "removed": FindingStatus.FIXED,
    "muted": FindingStatus.SUPPRESSED,
    "ignored": FindingStatus.SUPPRESSED,
}
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)


class SemgrepConnector(BaseConnector):
    name = "semgrep"
    category = FindingCategory.SAST
    config_fields = [
        ConfigField(key="semgrep_app_token", label="App token", secret=True),
        ConfigField(key="semgrep_deployment_slug", label="Deployment slug"),
        ConfigField(key="semgrep_base_url", label="Base URL", required=False,
                    placeholder="https://semgrep.dev/api"),
    ]

    def is_configured(self) -> bool:
        return bool(self.config("semgrep_app_token") and self.config("semgrep_deployment_slug"))

    def fetch(self) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        page = 0
        page_size = 100
        url = f"/api/v1/deployments/{self.config('semgrep_deployment_slug')}/findings"
        with httpx.Client(
            base_url=self.config("semgrep_base_url"),
            headers={"Authorization": f"Bearer {self.config('semgrep_app_token')}"},
            timeout=60.0,
        ) as client:
            while True:
                resp = client.get(url, params={"page": page, "page_size": page_size})
                resp.raise_for_status()
                batch = resp.json().get("findings", [])
                if not batch:
                    break
                findings.extend(self._normalize(f) for f in batch)
                if len(batch) < page_size:
                    break
                page += 1
        return findings

    def _normalize(self, item: dict) -> NormalizedFinding:
        rule = item.get("rule", {}) or {}
        location = item.get("location", {}) or {}
        repo = item.get("repository", {}) or {}
        repo_name = repo.get("name", "unknown-repo")

        cwes = []
        for name in rule.get("cwe_names", []) or []:
            cwes.extend(_CWE_RE.findall(name))

        return NormalizedFinding(
            source=self.name,
            source_finding_id=str(item.get("id") or item.get("match_based_id", "")),
            category=self.category,
            title=item.get("rule_name") or rule.get("name") or "Semgrep finding",
            description=rule.get("message") or item.get("rule_message"),
            severity=sev.from_label(item.get("severity")),
            raw_severity=item.get("severity"),
            status=_STATE_MAP.get((item.get("state") or "open").lower(), FindingStatus.OPEN),
            asset=NormalizedAsset(
                asset_type=AssetType.REPOSITORY,
                identifier=repo.get("url") or repo_name,
                name=repo_name,
                metadata={"branch": item.get("ref")},
            ),
            cwe_ids=sorted(set(cwes)),
            location={
                "path": location.get("file_path"),
                "line": location.get("line") or (location.get("start") or {}).get("line"),
                "column": location.get("column"),
            },
            tags={"owasp": rule.get("owasp_names", []), "confidence": item.get("confidence")},
            first_seen=parse_iso(item.get("created_at")),
            last_seen=parse_iso(item.get("relevant_since") or item.get("created_at")),
            raw=item,
        )
