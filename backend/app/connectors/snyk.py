"""Snyk connector  (modality: REST API, container image scanning).

Pulls vulnerability issues for container projects from the Snyk API and emits
`container` findings (source "snyk"), the same shape the manual report upload
produces. Auth: header `Authorization: token <SNYK_TOKEN>`.
Flow (v1 API): list org projects -> filter container origins ->
POST aggregated-issues per project. Docs: https://snyk.docs.apiary.io/
"""
from __future__ import annotations

import httpx

from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory
from backend.app.normalize import severity as sev

# Snyk project "type" values for OS-level container scans, and container origins.
_CONTAINER_TYPES = {"deb", "apk", "rpm", "linux", "dockerfile"}
_CONTAINER_ORIGINS = {"docker-hub", "ecr", "acr", "gcr", "quay", "harbor", "artifactory-cr",
                      "google-artifact-cr", "github-cr", "nexus-cr", "docker-cr", "cli"}


class SnykConnector(BaseConnector):
    name = "snyk"
    category = FindingCategory.CONTAINER
    config_fields = [
        ConfigField(key="snyk_token", label="API token", secret=True),
        ConfigField(key="snyk_org_id", label="Organization ID"),
        ConfigField(key="snyk_base_url", label="Base URL", required=False,
                    placeholder="https://api.snyk.io"),
    ]

    def is_configured(self) -> bool:
        return bool(self.config("snyk_token") and self.config("snyk_org_id"))

    def fetch(self) -> list[NormalizedFinding]:
        org = self.config("snyk_org_id")
        findings: list[NormalizedFinding] = []
        with httpx.Client(
            base_url=self.config("snyk_base_url"),
            headers={"Authorization": f"token {self.config('snyk_token')}",
                     "Content-Type": "application/json"},
            timeout=60.0,
        ) as client:
            resp = client.get(f"/v1/org/{org}/projects")
            resp.raise_for_status()
            for project in resp.json().get("projects", []):
                if not _is_container(project):
                    continue
                image = project.get("name") or project.get("id")
                issues = client.post(
                    f"/v1/org/{org}/project/{project['id']}/aggregated-issues",
                    json={"includeDescription": True},
                )
                issues.raise_for_status()
                for issue in issues.json().get("issues", []):
                    if issue.get("issueType") != "vuln":
                        continue  # skip license issues
                    findings.append(self._normalize(image, issue))
        return findings

    def _normalize(self, image: str, issue: dict) -> NormalizedFinding:
        data = issue.get("issueData", {}) or {}
        ident = data.get("identifiers") or {}
        pkg = issue.get("pkgName")
        versions = issue.get("pkgVersions") or []
        ver = versions[0] if versions else ""
        fixed = data.get("nearestFixedInVersion")
        return NormalizedFinding(
            source=self.name,
            source_finding_id=f"{data.get('id')}:{pkg}:{ver}",
            category=self.category,
            title=data.get("title") or data.get("id") or "Container vulnerability",
            description=data.get("description"),
            severity=sev.from_label(data.get("severity")),
            raw_severity=data.get("severity"),
            asset=NormalizedAsset(
                asset_type=AssetType.CONTAINER_IMAGE, identifier=image, name=image
            ),
            cve_ids=[c for c in ident.get("CVE", []) if c],
            cwe_ids=[c for c in ident.get("CWE", []) if c],
            cvss_base_score=data.get("cvssScore"),
            cvss_vector=data.get("cvssV3") or data.get("CVSSv3"),
            remediation=f"Upgrade {pkg} to {fixed}" if fixed else None,
            references=[data["url"]] if data.get("url") else [],
            location={"package": pkg, "version": ver},
            tags={"snyk_id": data.get("id"), "is_fixed": issue.get("isFixed")},
            raw=issue,
        )


def _is_container(project: dict) -> bool:
    return (
        project.get("type") in _CONTAINER_TYPES
        or (project.get("origin") or "") in _CONTAINER_ORIGINS
    )
