"""OSV.dev connector — supply-chain observation over the watched-package inventory.

Reads WatchedPackage rows, batch-queries the OSV API (free, no auth), and emits
a finding per (advisory, package). Malicious-package advisories (MAL- ids, from
the OpenSSF malicious-packages dataset) are surfaced as critical supply_chain
findings; everything else is treated as an SCA vulnerability.
Docs: https://google.github.io/osv.dev/api/
"""
from __future__ import annotations

import httpx

from backend.app.connectors.base import BaseConnector, NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import AssetType, FindingCategory, Severity
from backend.app.normalize import severity as sev
from backend.app.normalize.dates import parse_iso

_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
_VULN = "https://api.osv.dev/v1/vulns/{id}"
_BATCH_SIZE = 500

# OSV ecosystem -> purl type, for a canonical asset identifier.
_PURL_TYPE = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo"}


class OsvConnector(BaseConnector):
    name = "osv"
    category = FindingCategory.SUPPLY_CHAIN
    config_fields = []  # public API, no credentials

    def is_configured(self) -> bool:
        return True  # always available; emits nothing if the watchlist is empty

    def fetch(self) -> list[NormalizedFinding]:
        packages = self._watched_packages()
        if not packages:
            return []
        findings: list[NormalizedFinding] = []
        detail_cache: dict[str, dict] = {}
        with httpx.Client(timeout=60.0) as client:
            for batch in _chunks(packages, _BATCH_SIZE):
                queries = [
                    {"package": {"ecosystem": p["ecosystem"], "name": p["name"]},
                     "version": p["version"]}
                    for p in batch
                ]
                resp = client.post(_QUERY_BATCH, json={"queries": queries})
                resp.raise_for_status()
                for pkg, result in zip(batch, resp.json().get("results", [])):
                    for stub in (result or {}).get("vulns", []) or []:
                        detail = self._vuln_detail(client, detail_cache, stub["id"])
                        findings.append(self._normalize(pkg, detail))
        return findings

    def _watched_packages(self) -> list[dict]:
        # Local import avoids a models<->connectors import cycle at module load.
        from sqlalchemy import select

        from backend.app.db import SessionLocal
        from backend.app.models.watched_package import WatchedPackage

        with SessionLocal() as db:
            rows = db.scalars(select(WatchedPackage)).all()
        uniq = {
            (r.ecosystem, r.name, r.version): {
                "ecosystem": r.ecosystem, "name": r.name, "version": r.version
            }
            for r in rows
        }
        return list(uniq.values())

    def _vuln_detail(self, client: httpx.Client, cache: dict[str, dict], vuln_id: str) -> dict:
        if vuln_id not in cache:
            resp = client.get(_VULN.format(id=vuln_id))
            resp.raise_for_status()
            cache[vuln_id] = resp.json()
        return cache[vuln_id]

    def _normalize(self, pkg: dict, vuln: dict) -> NormalizedFinding:
        vid = vuln.get("id", "")
        malicious = vid.startswith("MAL-")
        aliases = vuln.get("aliases", []) or []
        cves = [a for a in aliases if a.startswith("CVE-")]
        eco, name, version = pkg["ecosystem"], pkg["name"], pkg["version"]
        purl = f"pkg:{_PURL_TYPE.get(eco, eco.lower())}/{name}@{version}"
        summary = vuln.get("summary") or vid

        return NormalizedFinding(
            source=self.name,
            source_finding_id=f"{vid}:{eco}:{name}:{version}",
            category=FindingCategory.SUPPLY_CHAIN if malicious else FindingCategory.SCA,
            title=(f"Malicious package: {name}" if malicious else summary)[:1024],
            description=vuln.get("details"),
            severity=Severity.CRITICAL if malicious else _osv_severity(vuln),
            raw_severity="malicious" if malicious else None,
            asset=NormalizedAsset(
                asset_type=AssetType.PACKAGE,
                identifier=purl,
                name=f"{name}@{version}",
                metadata={"ecosystem": eco, "version": version},
            ),
            cve_ids=cves,
            references=[r["url"] for r in vuln.get("references", []) if r.get("url")],
            tags={"osv_id": vid, "malicious": malicious, "aliases": aliases},
            first_seen=parse_iso(vuln.get("published")),
            last_seen=parse_iso(vuln.get("modified")),
            raw=vuln,
        )


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


def _osv_severity(vuln: dict) -> Severity:
    """Best-effort severity from OSV's GHSA-style label (CVSS vectors are skipped)."""
    label = (vuln.get("database_specific") or {}).get("severity")
    if not label:
        for affected in vuln.get("affected", []):
            label = (affected.get("database_specific") or {}).get("severity")
            if label:
                break
    return sev.from_label(label) if label else Severity.MEDIUM
