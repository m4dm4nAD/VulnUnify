"""On-demand OSV lookups for ephemeral, self-service package scans.

Unlike the OSV *connector* (which reads the persistent watchlist and writes
Findings), this queries OSV live for a caller-supplied package list and returns
a plain summary. Nothing is persisted — used by the dev-facing "check this file"
flow so a developer can vet a package.json/SBOM without touching shared state.
"""
from __future__ import annotations

import httpx

from backend.app.connectors.osv import _osv_severity  # shared severity heuristic
from backend.app.services.manifests import ParsedPackage

_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
_VULN = "https://api.osv.dev/v1/vulns/{id}"
_BATCH_SIZE = 500


def scan(packages: list[ParsedPackage]) -> list[dict]:
    """Query OSV for each package; return one entry per vulnerable package.

    Result item: {ecosystem, name, version, vulns: [{id, summary, severity,
    malicious, cves, references}]}. Packages with no known vulns are omitted.
    """
    uniq = {
        (p.ecosystem, p.name, p.version): {
            "ecosystem": p.ecosystem, "name": p.name, "version": p.version
        }
        for p in packages
    }
    pkgs = list(uniq.values())
    if not pkgs:
        return []

    results: list[dict] = []
    detail_cache: dict[str, dict] = {}
    with httpx.Client(timeout=60.0) as client:
        for batch in _chunks(pkgs, _BATCH_SIZE):
            queries = [
                {"package": {"ecosystem": p["ecosystem"], "name": p["name"]},
                 "version": p["version"]}
                for p in batch
            ]
            resp = client.post(_QUERY_BATCH, json={"queries": queries})
            resp.raise_for_status()
            for pkg, result in zip(batch, resp.json().get("results", [])):
                vulns = [
                    _summarize(_detail(client, detail_cache, stub["id"]))
                    for stub in (result or {}).get("vulns", []) or []
                ]
                if vulns:
                    results.append({**pkg, "vulns": vulns})
    return results


def _detail(client: httpx.Client, cache: dict[str, dict], vuln_id: str) -> dict:
    if vuln_id not in cache:
        resp = client.get(_VULN.format(id=vuln_id))
        resp.raise_for_status()
        cache[vuln_id] = resp.json()
    return cache[vuln_id]


def _summarize(vuln: dict) -> dict:
    vid = vuln.get("id", "")
    malicious = vid.startswith("MAL-")
    aliases = vuln.get("aliases", []) or []
    return {
        "id": vid,
        "summary": (vuln.get("summary")
                    or ("Malicious package" if malicious else vid))[:512],
        "severity": "critical" if malicious else _osv_severity(vuln).value,
        "malicious": malicious,
        "cves": [a for a in aliases if a.startswith("CVE-")],
        "references": [r["url"] for r in vuln.get("references", []) if r.get("url")][:5],
    }


def _chunks(items: list, size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]
