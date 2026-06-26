"""Parse uploaded container scan reports into findings (manual ingestion).

The complement to the Snyk *API* connector: here a user uploads a scan report
file and each vulnerability becomes a `container` finding whose asset is the
scanned image. Supports Snyk (`snyk container test --json`) today; Prisma
(twistcli) and Wiz exports are drop-in additions via the parser registry.
"""
from __future__ import annotations

import json

from backend.app.connectors.base import NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import AssetType, FindingCategory
from backend.app.normalize import severity as sev

SUPPORTED_TOOLS = ("snyk", "prisma", "wiz")


def parse_report(tool: str, content: str) -> list[NormalizedFinding]:
    tool = (tool or "").lower()
    if tool == "snyk":
        return _parse_snyk(content)
    if tool == "prisma":
        return _parse_prisma(content)
    if tool == "wiz":
        return _parse_wiz(content)
    raise ValueError(f"unsupported tool '{tool}'; supported: {', '.join(SUPPORTED_TOOLS)}")


def _parse_snyk(content: str) -> list[NormalizedFinding]:
    data = json.loads(content)
    # `snyk container test --json` emits one object, or a list for multiple images.
    docs = data if isinstance(data, list) else [data]
    findings: list[NormalizedFinding] = []
    for doc in docs:
        image = doc.get("path") or _strip_prefix(doc.get("projectName")) or "unknown-image"
        pkg_mgr = doc.get("packageManager")
        seen: set = set()
        for vuln in doc.get("vulnerabilities", []) or []:
            key = (vuln.get("id"), vuln.get("packageName"), vuln.get("version"))
            if key in seen:
                continue  # Snyk lists a vuln once per dependency path
            seen.add(key)
            findings.append(_snyk_vuln(image, pkg_mgr, vuln))
    return findings


def _snyk_vuln(image: str, pkg_mgr, vuln: dict) -> NormalizedFinding:
    ident = vuln.get("identifiers") or {}
    pkg, ver = vuln.get("packageName"), vuln.get("version")
    fixed = vuln.get("nearestFixedInVersion")
    if not fixed and isinstance(vuln.get("fixedIn"), list) and vuln["fixedIn"]:
        fixed = vuln["fixedIn"][0]
    return NormalizedFinding(
        source="snyk",
        source_finding_id=f"{vuln.get('id')}:{pkg}:{ver}",
        category=FindingCategory.CONTAINER,
        title=vuln.get("title") or vuln.get("id") or "Container vulnerability",
        description=vuln.get("description"),
        severity=sev.from_label(vuln.get("severity")),
        raw_severity=vuln.get("severity"),
        asset=NormalizedAsset(
            asset_type=AssetType.CONTAINER_IMAGE,
            identifier=image,
            name=image,
            metadata={"package_manager": pkg_mgr},
        ),
        cve_ids=[c for c in ident.get("CVE", []) if c],
        cwe_ids=[c for c in ident.get("CWE", []) if c],
        cvss_base_score=vuln.get("cvssScore"),
        cvss_vector=vuln.get("CVSSv3"),
        remediation=f"Upgrade {pkg} to {fixed}" if fixed else None,
        references=[r["url"] for r in vuln.get("references", []) if isinstance(r, dict) and r.get("url")],
        location={"package": pkg, "version": ver},
        tags={"snyk_id": vuln.get("id"), "package_manager": pkg_mgr},
        raw=vuln,
    )


def _strip_prefix(name: str | None) -> str | None:
    # Snyk projectName looks like "docker-image|python:3.10-slim".
    return name.split("|", 1)[-1] if name else None


def _parse_prisma(content: str) -> list[NormalizedFinding]:
    """Prisma Cloud / twistcli image scan (`twistcli images scan --output-file`)."""
    data = json.loads(content)
    results = data if isinstance(data, list) else data.get("results", []) or []
    findings: list[NormalizedFinding] = []
    for result in results:
        image = result.get("name") or result.get("id") or "unknown-image"
        distro = result.get("distro")
        seen: set = set()
        for vuln in result.get("vulnerabilities", []) or []:
            vid, pkg = vuln.get("id"), vuln.get("packageName")
            ver = vuln.get("packageVersion")
            key = (vid, pkg, ver)
            if key in seen:
                continue
            seen.add(key)
            status = vuln.get("status") or ""
            findings.append(
                NormalizedFinding(
                    source="prisma",
                    source_finding_id=f"{vid}:{pkg}:{ver}",
                    category=FindingCategory.CONTAINER,
                    title=vuln.get("title") or vid or "Container vulnerability",
                    description=vuln.get("description"),
                    severity=sev.from_label(vuln.get("severity")),
                    raw_severity=vuln.get("severity"),
                    asset=NormalizedAsset(
                        asset_type=AssetType.CONTAINER_IMAGE, identifier=image, name=image,
                        metadata={"distro": distro},
                    ),
                    cve_ids=[vid] if str(vid).upper().startswith("CVE-") else [],
                    cvss_base_score=vuln.get("cvss"),
                    cvss_vector=vuln.get("vector"),
                    remediation=status if "fix" in status.lower() else None,
                    references=[vuln["link"]] if vuln.get("link") else [],
                    location={"package": pkg, "version": ver},
                    tags={"prisma_id": vid, "status": status},
                    raw=vuln,
                )
            )
    return findings


def _wiz_nodes(data) -> list:
    """Pull the finding nodes out of the various Wiz export shapes."""
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        return []
    root = data.get("data", data)
    vf = root.get("vulnerabilityFindings") if isinstance(root, dict) else None
    if isinstance(vf, dict) and "nodes" in vf:
        return vf["nodes"]
    if isinstance(vf, list):
        return vf
    return data.get("nodes", [])


def _parse_wiz(content: str) -> list[NormalizedFinding]:
    """Wiz vulnerability-findings export (GraphQL `vulnerabilityFindings` or a node list).

    Only findings on container images become `container` findings; non-container
    assets (VMs, etc.) in the export are skipped. Note: shares source "wiz" with
    the Wiz CSPM connector — don't run both for the same data.
    """
    findings: list[NormalizedFinding] = []
    seen: set = set()
    for node in _wiz_nodes(json.loads(content)):
        asset = node.get("vulnerableAsset") or {}
        atype = (asset.get("type") or "").upper()
        if atype and "CONTAINER" not in atype and "IMAGE" not in atype:
            continue
        image = asset.get("name") or asset.get("providerUniqueId") or "unknown-image"
        name = node.get("name") or node.get("id")  # CVE id
        pkg, ver = node.get("detailedName"), node.get("version")
        fixed = node.get("fixedVersion")
        key = (name, pkg, ver, image)
        if key in seen:
            continue
        seen.add(key)
        platform = asset.get("cloudPlatform")
        findings.append(
            NormalizedFinding(
                source="wiz",
                source_finding_id=f"{name}:{pkg}:{ver}",
                category=FindingCategory.CONTAINER,
                title=name or "Container vulnerability",
                description=node.get("CVEDescription") or node.get("description"),
                severity=sev.from_label(node.get("severity") or node.get("CVSSSeverity")),
                raw_severity=node.get("severity"),
                asset=NormalizedAsset(
                    asset_type=AssetType.CONTAINER_IMAGE,
                    identifier=image,
                    name=asset.get("name") or image,
                    cloud_provider=platform.lower() if platform else None,
                    region=asset.get("region"),
                    metadata={"native_type": asset.get("nativeType")},
                ),
                cve_ids=[name] if str(name).upper().startswith("CVE-") else [],
                cvss_base_score=node.get("score"),
                cvss_vector=node.get("cvssV3Vector"),
                remediation=node.get("remediation")
                or (f"Upgrade {pkg} to {fixed}" if fixed and pkg else None),
                references=[node["link"]] if node.get("link") else [],
                location={"package": pkg, "version": ver},
                tags={"wiz_id": node.get("id"), "has_exploit": node.get("hasExploit"),
                      "cisa_kev": node.get("hasCisaKevExploit"), "fixed_version": fixed},
                raw=node,
            )
        )
    return findings
