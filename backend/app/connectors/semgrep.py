"""Semgrep connector  (modality: REST API, SAST).

Pulls from the Semgrep AppSec Platform findings API:
GET /api/v1/deployments/{slug}/findings   (Authorization: Bearer <token>)
Docs: https://semgrep.dev/api/v1/docs/
"""
from __future__ import annotations

import re

import httpx

from backend.app.config import settings
from backend.app.connectors.base import BaseConnector, NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus, Severity
from backend.app.normalize import severity as sev

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

    def is_configured(self) -> bool:
        return bool(settings.semgrep_app_token and settings.semgrep_deployment_slug)

    def fetch(self) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        page = 0
        page_size = 100
        url = f"/api/v1/deployments/{settings.semgrep_deployment_slug}/findings"
        with httpx.Client(
            base_url=settings.semgrep_base_url,
            headers={"Authorization": f"Bearer {settings.semgrep_app_token}"},
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
            first_seen=_parse_dt(item.get("created_at")),
            last_seen=_parse_dt(item.get("relevant_since") or item.get("created_at")),
            raw=item,
        )


def _parse_dt(value):
    from datetime import datetime

    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
