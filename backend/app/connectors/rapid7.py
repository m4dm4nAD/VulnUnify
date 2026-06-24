"""Rapid7 InsightVM connector  (modality: REST API, vulnerability scanning).

Targets the InsightVM Security Console REST API v3 (HTTP Basic auth):
  * GET /api/3/assets                       -> paged assets
  * GET /api/3/assets/{id}/vulnerabilities  -> a host's vulnerability findings
  * GET /api/3/vulnerabilities/{id}         -> the vuln definition (cached)
Docs: https://help.rapid7.com/insightvm/en-us/api/index.html

Each (asset, vulnerability) pair becomes one NormalizedFinding. Vulnerability
definitions are fetched once and cached, since many assets share the same vuln.
Remediation text lives behind /api/3/vulnerabilities/{id}/solutions and is left
out here to keep request volume bounded; add it if you need it.
"""
from __future__ import annotations

import httpx

from backend.app.config import settings
from backend.app.connectors.base import (
    BaseConnector,
    ConfigField,
    NormalizedAsset,
    NormalizedFinding,
)
from backend.app.connectors.enums import AssetType, FindingCategory, FindingStatus
from backend.app.normalize import severity as sev
from backend.app.normalize.dates import parse_iso

_PAGE_SIZE = 500


class Rapid7Connector(BaseConnector):
    name = "rapid7"
    category = FindingCategory.VULNERABILITY
    config_fields = [
        ConfigField(key="rapid7_base_url", label="Console URL",
                    placeholder="https://insightvm.example.com:3780"),
        ConfigField(key="rapid7_username", label="Username"),
        ConfigField(key="rapid7_password", label="Password", secret=True),
    ]

    def is_configured(self) -> bool:
        return bool(
            self.config("rapid7_base_url")
            and self.config("rapid7_username")
            and self.config("rapid7_password")
        )

    def _client(self) -> httpx.Client:
        return httpx.Client(
            base_url=self.config("rapid7_base_url"),
            auth=httpx.BasicAuth(self.config("rapid7_username"), self.config("rapid7_password")),
            verify=settings.rapid7_verify_ssl,  # bool; configured via env only
            headers={"Accept": "application/json"},
            timeout=60.0,
        )

    def fetch(self) -> list[NormalizedFinding]:
        findings: list[NormalizedFinding] = []
        vuln_cache: dict[str, dict] = {}
        with self._client() as client:
            for asset in self._paged(client, "/api/3/assets"):
                for finding in self._paged(
                    client, f"/api/3/assets/{asset['id']}/vulnerabilities"
                ):
                    vuln = self._vuln_detail(client, vuln_cache, finding["id"])
                    findings.append(self._normalize(asset, finding, vuln))
        return findings

    def _paged(self, client: httpx.Client, path: str):
        """Yield every resource across all pages of a v3 list endpoint."""
        page = 0
        while True:
            resp = client.get(path, params={"page": page, "size": _PAGE_SIZE})
            resp.raise_for_status()
            body = resp.json()
            yield from body.get("resources", [])
            meta = body.get("page", {})
            if page >= meta.get("totalPages", 1) - 1:
                break
            page += 1

    def _vuln_detail(self, client: httpx.Client, cache: dict[str, dict], vuln_id: str) -> dict:
        if vuln_id not in cache:
            resp = client.get(f"/api/3/vulnerabilities/{vuln_id}")
            resp.raise_for_status()
            cache[vuln_id] = resp.json()
        return cache[vuln_id]

    def _normalize(self, asset: dict, finding: dict, vuln: dict) -> NormalizedFinding:
        cvss = vuln.get("cvss", {}) or {}
        v3 = cvss.get("v3") or {}
        v2 = cvss.get("v2") or {}
        score = v3.get("score") if v3.get("score") is not None else v2.get("score")
        vector = v3.get("vector") or v2.get("vector")

        # Prefer CVSS-derived severity; fall back to Rapid7's own label.
        severity = sev.from_cvss(score) if score is not None else sev.from_label(
            vuln.get("severity")
        )

        identifier = asset.get("hostName") or asset.get("ip") or str(asset.get("id"))
        ports = [
            {"port": r.get("port"), "protocol": r.get("protocol")}
            for r in finding.get("results", [])
        ]

        return NormalizedFinding(
            source=self.name,
            source_finding_id=f"{asset.get('id')}:{finding.get('id')}",
            category=self.category,
            title=vuln.get("title") or finding.get("id"),
            description=(vuln.get("description") or {}).get("text"),
            severity=severity,
            raw_severity=vuln.get("severity"),
            status=FindingStatus.OPEN,  # this endpoint only returns active findings
            asset=NormalizedAsset(
                asset_type=AssetType.HOST,
                identifier=str(identifier),
                name=asset.get("hostName"),
                metadata={"os": asset.get("os"), "ip": asset.get("ip")},
            ),
            cve_ids=vuln.get("cves", []) or [],
            cvss_base_score=score,
            cvss_vector=vector,
            location={"ports": ports},
            tags={
                "risk_score": vuln.get("riskScore"),
                "exploits": vuln.get("exploits"),
                "malware_kits": vuln.get("malwareKits"),
                "finding_status": finding.get("status"),
            },
            first_seen=parse_iso(finding.get("since")),
            raw={"asset": asset, "finding": finding, "vulnerability": vuln},
        )
