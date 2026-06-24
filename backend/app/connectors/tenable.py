"""Tenable.io connector  (modality: REST API).

Uses the Vulnerability Export API, which is Tenable's recommended way to pull
all findings: request an export, poll until chunks are ready, then download
each chunk. Docs: https://developer.tenable.com/reference/exports-vulns-request-export
"""
from __future__ import annotations

import time

import httpx

from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus, Severity
from backend.app.normalize import severity as sev
from backend.app.normalize.dates import parse_iso

_SEVERITY_BY_ID = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}
_STATE_MAP = {
    "OPEN": FindingStatus.OPEN,
    "REOPENED": FindingStatus.OPEN,
    "FIXED": FindingStatus.FIXED,
}


class TenableConnector(BaseConnector):
    name = "tenable"
    category = FindingCategory.VULNERABILITY
    config_fields = [
        ConfigField(key="tenable_access_key", label="Access key", secret=True),
        ConfigField(key="tenable_secret_key", label="Secret key", secret=True),
        ConfigField(key="tenable_base_url", label="Base URL", required=False,
                    placeholder="https://cloud.tenable.com"),
    ]

    def is_configured(self) -> bool:
        return bool(self.config("tenable_access_key") and self.config("tenable_secret_key"))

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.config("tenable_base_url"),
            headers={
                "X-ApiKeys": (
                    f"accessKey={self.config('tenable_access_key')};"
                    f"secretKey={self.config('tenable_secret_key')}"
                ),
                "Accept": "application/json",
            },
            timeout=60.0,
        )

    def fetch(self) -> list[NormalizedFinding]:
        with self._client() as client:
            export_uuid = self._request_export(client)
            chunks = self._wait_for_chunks(client, export_uuid)
            findings: list[NormalizedFinding] = []
            for chunk_id in chunks:
                resp = client.get(f"/vulns/export/{export_uuid}/chunks/{chunk_id}")
                resp.raise_for_status()
                for item in resp.json():
                    findings.append(self._normalize(item))
            return findings

    def _request_export(self, client: httpx.Client) -> str:
        # Pull only open/reopened findings; widen filters as needed.
        body = {"num_assets": 100, "filters": {"state": ["OPEN", "REOPENED"]}}
        resp = client.post("/vulns/export", json=body)
        resp.raise_for_status()
        return resp.json()["export_uuid"]

    def _wait_for_chunks(
        self, client: httpx.Client, export_uuid: str, max_wait_s: int = 120
    ) -> list[int]:
        deadline = time.monotonic() + max_wait_s
        while time.monotonic() < deadline:
            resp = client.get(f"/vulns/export/{export_uuid}/status")
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") in {"FINISHED", "ERROR"}:
                return data.get("chunks_available", [])
            time.sleep(3)
        raise TimeoutError(f"Tenable export {export_uuid} did not finish in {max_wait_s}s")

    def _normalize(self, item: dict) -> NormalizedFinding:
        asset = item.get("asset", {})
        plugin = item.get("plugin", {})
        identifier = (
            asset.get("hostname")
            or asset.get("fqdn")
            or asset.get("ipv4")
            or asset.get("uuid", "unknown")
        )
        sev_id = item.get("severity_id")
        severity = _SEVERITY_BY_ID.get(sev_id) or sev.from_label(item.get("severity"))

        return NormalizedFinding(
            source=self.name,
            source_finding_id=f"{asset.get('uuid', '')}:{plugin.get('id', '')}",
            category=self.category,
            title=plugin.get("name", "Unknown plugin"),
            description=plugin.get("description"),
            severity=severity,
            raw_severity=item.get("severity"),
            status=_STATE_MAP.get(item.get("state", "OPEN"), FindingStatus.OPEN),
            asset=NormalizedAsset(
                asset_type=AssetType.HOST,
                identifier=str(identifier),
                name=asset.get("hostname") or asset.get("fqdn"),
                metadata={"operating_system": asset.get("operating_system")},
            ),
            cve_ids=plugin.get("cve", []) or [],
            cvss_base_score=plugin.get("cvss3_base_score") or plugin.get("cvss_base_score"),
            cvss_vector=plugin.get("cvss3_vector", {}).get("raw")
            if isinstance(plugin.get("cvss3_vector"), dict)
            else None,
            location={
                "port": (item.get("port") or {}).get("port"),
                "protocol": (item.get("port") or {}).get("protocol"),
            },
            remediation=plugin.get("solution"),
            references=[se.get("url") for se in plugin.get("see_also", []) if se.get("url")]
            if isinstance(plugin.get("see_also"), list)
            else [],
            first_seen=parse_iso(item.get("first_found")),
            last_seen=parse_iso(item.get("last_found")),
            raw=item,
        )
