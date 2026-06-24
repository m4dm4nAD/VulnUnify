"""Trend Micro Vision One connector  (modality: REST API, CSPM).

Pulls failing Cloud Posture checks (Conformity-style misconfigurations):
  GET {base}/beta/cloudPosture/checks      (auth: Bearer <TREND_API_KEY>)
Results are paged via a `nextLink` absolute URL.
Docs: https://automation.trendmicro.com/xdr/api-v3
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

# Conformity risk levels -> normalized severity.
_RISK_MAP = {
    "EXTREME": Severity.CRITICAL,
    "VERY_HIGH": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


class TrendConnector(BaseConnector):
    name = "trend"
    category = FindingCategory.CLOUD_POSTURE
    config_fields = [
        ConfigField(key="trend_api_key", label="API key", secret=True),
        ConfigField(key="trend_base_url", label="Base URL", required=False,
                    placeholder="https://api.xdr.trendmicro.com"),
    ]

    def is_configured(self) -> bool:
        return bool(self.config("trend_api_key"))

    def fetch(self) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        with httpx.Client(
            base_url=self.config("trend_base_url"),
            headers={"Authorization": f"Bearer {self.config('trend_api_key')}"},
            timeout=60.0,
        ) as client:
            # First page relative; subsequent pages are absolute nextLink URLs.
            url = "/beta/cloudPosture/checks"
            params = {"filter": "status eq 'FAILURE'", "top": 200}
            while url:
                resp = client.get(url, params=params)
                resp.raise_for_status()
                body = resp.json()
                for check in body.get("items", []):
                    if check.get("status") == "SUCCESS":
                        continue
                    findings.append(self._normalize(check))
                url = body.get("nextLink")
                params = None  # nextLink already encodes paging state
        return findings

    def _normalize(self, check: dict) -> NormalizedFinding:
        resource = check.get("resource") or check.get("resourceName") or "unknown-resource"
        provider = check.get("cloudProvider") or check.get("provider")

        return NormalizedFinding(
            source=self.name,
            source_finding_id=str(check.get("id")),
            category=self.category,
            title=check.get("ruleTitle") or check.get("message") or "Cloud posture check",
            description=check.get("message"),
            severity=_RISK_MAP.get(check.get("riskLevel"), Severity.INFO),
            raw_severity=check.get("riskLevel"),
            status=FindingStatus.OPEN,  # only FAILURE checks are ingested
            asset=NormalizedAsset(
                asset_type=AssetType.CLOUD_RESOURCE,
                identifier=str(resource),
                name=check.get("resourceName"),
                cloud_provider=provider.lower() if provider else None,
                region=check.get("region"),
                metadata={"account_id": check.get("accountId"), "service": check.get("service")},
            ),
            location={
                "resource": resource,
                "region": check.get("region"),
                "service": check.get("service"),
            },
            tags={"rule_id": check.get("ruleId"), "categories": check.get("categories")},
            first_seen=_parse_dt(check.get("createdDate")),
            last_seen=_parse_dt(check.get("updatedDate")),
            raw=check,
        )


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
