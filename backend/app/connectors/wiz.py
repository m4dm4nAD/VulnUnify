"""Wiz connector  (modality: GraphQL API, CSPM).

Auth is OAuth2 client-credentials; findings come from the GraphQL `issues` query
(Wiz Issues correlate security-graph risks to cloud resources), paginated via a
cursor. Docs: https://win.wiz.io/reference/quickstart  /  .../issues
"""
from __future__ import annotations

from datetime import datetime

import httpx

from backend.app.config import settings
from backend.app.connectors.base import BaseConnector, NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus
from backend.app.normalize import severity as sev

# Audience for the client-credentials grant. Modern tenants use "wiz-api";
# some older tenants use "beyond-api".
_AUTH_AUDIENCE = "wiz-api"

# Wiz issue status -> normalized status.
_STATUS_MAP = {
    "OPEN": FindingStatus.OPEN,
    "IN_PROGRESS": FindingStatus.OPEN,
    "RESOLVED": FindingStatus.FIXED,
    "REJECTED": FindingStatus.ACCEPTED_RISK,
}

# Only pull issues that still need attention by default.
_ISSUES_QUERY = """
query Issues($first: Int, $after: String, $filterBy: IssueFilters) {
  issues(first: $first, after: $after, filterBy: $filterBy,
         orderBy: {field: SEVERITY, direction: DESC}) {
    nodes {
      id
      severity
      status
      type
      createdAt
      updatedAt
      sourceRule {
        __typename
        ... on Control { id name description resolutionRecommendation }
        ... on CloudConfigurationRule { id name description remediationInstructions }
        ... on CloudEventRule { id name description }
      }
      entitySnapshot {
        id
        name
        type
        nativeType
        cloudPlatform
        providerId
        cloudProviderURL
        region
        subscriptionId
        subscriptionExternalId
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""


class WizConnector(BaseConnector):
    name = "wiz"
    category = FindingCategory.CLOUD_POSTURE

    def is_configured(self) -> bool:
        return bool(settings.wiz_client_id and settings.wiz_client_secret)

    def _get_token(self) -> str:
        resp = httpx.post(
            settings.wiz_auth_url,
            data={
                "grant_type": "client_credentials",
                "audience": _AUTH_AUDIENCE,
                "client_id": settings.wiz_client_id,
                "client_secret": settings.wiz_client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30.0,
        )
        resp.raise_for_status()
        return resp.json()["access_token"]

    def fetch(self) -> list[NormalizedFinding]:
        token = self._get_token()
        findings: list[NormalizedFinding] = []
        after: str | None = None
        variables = {
            "first": 100,
            "after": None,
            "filterBy": {"status": ["OPEN", "IN_PROGRESS"]},
        }
        with httpx.Client(
            base_url=settings.wiz_api_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=60.0,
        ) as client:
            while True:
                variables["after"] = after
                resp = client.post("", json={"query": _ISSUES_QUERY, "variables": variables})
                resp.raise_for_status()
                payload = resp.json()
                if "errors" in payload:
                    raise RuntimeError(f"Wiz GraphQL errors: {payload['errors']}")
                issues = payload["data"]["issues"]
                findings.extend(self._normalize(node) for node in issues["nodes"])
                page = issues["pageInfo"]
                if not page["hasNextPage"]:
                    break
                after = page["endCursor"]
        return findings

    def _normalize(self, node: dict) -> NormalizedFinding:
        rule = node.get("sourceRule") or {}
        entity = node.get("entitySnapshot") or {}

        identifier = (
            entity.get("providerId") or entity.get("id") or entity.get("name") or "unknown"
        )
        platform = entity.get("cloudPlatform")
        remediation = rule.get("resolutionRecommendation") or rule.get("remediationInstructions")
        url = entity.get("cloudProviderURL")

        return NormalizedFinding(
            source=self.name,
            source_finding_id=node["id"],
            category=self.category,
            title=rule.get("name") or "Wiz issue",
            description=rule.get("description"),
            severity=sev.from_label(node.get("severity")),
            raw_severity=node.get("severity"),
            status=_STATUS_MAP.get(node.get("status", "OPEN"), FindingStatus.OPEN),
            asset=NormalizedAsset(
                asset_type=AssetType.CLOUD_RESOURCE,
                identifier=str(identifier),
                name=entity.get("name"),
                cloud_provider=platform.lower() if platform else None,
                region=entity.get("region"),
                metadata={
                    "native_type": entity.get("nativeType"),
                    "subscription_id": entity.get("subscriptionId"),
                    "subscription_external_id": entity.get("subscriptionExternalId"),
                },
            ),
            remediation=remediation,
            location={
                "resource_id": entity.get("providerId"),
                "native_type": entity.get("nativeType"),
                "region": entity.get("region"),
            },
            references=[url] if url else [],
            tags={"issue_type": node.get("type"), "rule_type": rule.get("__typename")},
            first_seen=_parse_dt(node.get("createdAt")),
            last_seen=_parse_dt(node.get("updatedAt")),
            raw=node,
        )


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
