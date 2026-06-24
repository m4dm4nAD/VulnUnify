"""SonarQube / SonarCloud connector  (modality: REST API, SAST).

Pulls vulnerability-type issues from the web API:
  GET /api/issues/search?types=VULNERABILITY   (auth: token as Basic username)
Docs: https://next.sonarqube.com/sonarqube/web_api/api/issues

SonarQube's 5 severities map onto our scale precisely (BLOCKER>CRITICAL>MAJOR>
MINOR>INFO), so this connector uses its own mapping rather than the generic one.
The issues search is capped by Sonar at 10k results (page*size); scope with
SONARQUBE_PROJECT_KEYS if you have more.
"""
from __future__ import annotations

from datetime import datetime

import httpx

from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus, Severity

_SEVERITY_MAP = {
    "BLOCKER": Severity.CRITICAL,
    "CRITICAL": Severity.HIGH,
    "MAJOR": Severity.MEDIUM,
    "MINOR": Severity.LOW,
    "INFO": Severity.INFO,
}
_RESOLUTION_MAP = {
    "FIXED": FindingStatus.FIXED,
    "REMOVED": FindingStatus.FIXED,
    "WONTFIX": FindingStatus.ACCEPTED_RISK,
    "FALSE-POSITIVE": FindingStatus.SUPPRESSED,
}
_OPEN_STATUSES = {"OPEN", "CONFIRMED", "REOPENED"}
_PAGE_SIZE = 500


class SonarQubeConnector(BaseConnector):
    name = "sonarqube"
    category = FindingCategory.SAST
    config_fields = [
        ConfigField(key="sonarqube_token", label="Token", secret=True),
        ConfigField(key="sonarqube_base_url", label="Base URL", required=False,
                    placeholder="https://sonarcloud.io"),
        ConfigField(key="sonarqube_organization", label="Organization", required=False,
                    placeholder="required for SonarCloud"),
        ConfigField(key="sonarqube_project_keys", label="Project keys", required=False,
                    placeholder="comma-separated (optional)"),
    ]

    def is_configured(self) -> bool:
        return bool(self.config("sonarqube_token"))

    def fetch(self) -> list[NormalizedFinding]:
        params = {"types": "VULNERABILITY", "ps": _PAGE_SIZE}
        if self.config("sonarqube_organization"):
            params["organization"] = self.config("sonarqube_organization")
        if self.config("sonarqube_project_keys"):
            params["componentKeys"] = self.config("sonarqube_project_keys")

        findings: list[NormalizedFinding] = []
        with httpx.Client(
            base_url=self.config("sonarqube_base_url"),
            auth=httpx.BasicAuth(self.config("sonarqube_token"), ""),
            timeout=60.0,
        ) as client:
            page = 1
            while True:
                resp = client.get("/api/issues/search", params={**params, "p": page})
                resp.raise_for_status()
                body = resp.json()
                # Map project key -> human name from the components listing.
                names = {
                    c["key"]: c.get("name")
                    for c in body.get("components", [])
                    if c.get("qualifier") == "TRK"
                }
                for issue in body.get("issues", []):
                    findings.append(self._normalize(issue, names))
                # Sonar caps paging at 10k; stop at the end or the ceiling.
                if page * _PAGE_SIZE >= min(body.get("total", 0), 10000):
                    break
                page += 1
        return findings

    def _normalize(self, issue: dict, project_names: dict) -> NormalizedFinding:
        project = issue.get("project", "")
        component = issue.get("component", "")
        # component looks like "projectKey:path/to/file.js" — strip the project prefix.
        path = component.split(":", 1)[1] if ":" in component else component

        resolution = issue.get("resolution")
        if resolution:
            status = _RESOLUTION_MAP.get(resolution, FindingStatus.FIXED)
        elif issue.get("status") in _OPEN_STATUSES:
            status = FindingStatus.OPEN
        else:
            status = FindingStatus.FIXED

        cwes = [t.upper() for t in issue.get("tags", []) if t.lower().startswith("cwe")]

        return NormalizedFinding(
            source=self.name,
            source_finding_id=issue["key"],
            category=self.category,
            title=issue.get("message") or issue.get("rule") or "SonarQube vulnerability",
            severity=_SEVERITY_MAP.get(issue.get("severity"), Severity.INFO),
            raw_severity=issue.get("severity"),
            status=status,
            asset=NormalizedAsset(
                asset_type=AssetType.REPOSITORY,
                identifier=project,
                name=project_names.get(project) or project,
            ),
            cwe_ids=cwes,
            location={"path": path, "line": issue.get("line")},
            tags={"rule": issue.get("rule"), "sonar_tags": issue.get("tags")},
            first_seen=_parse_dt(issue.get("creationDate")),
            last_seen=_parse_dt(issue.get("updateDate")),
            raw=issue,
        )


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
