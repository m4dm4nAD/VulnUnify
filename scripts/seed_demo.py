"""Seed realistic demo data + threat-intel enrichment, to see the UI populated.

Ingests a spread of findings (real CVEs — some CISA KEV, some not — plus SAST /
cloud / secret findings with no CVE) across assets of differing business
criticality, then runs the live KEV + EPSS refresh so risk scores populate.

Run against a running stack:
    docker exec -i vulnunify-api-1 python < scripts/seed_demo.py
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from backend.app.connectors.base import NormalizedAsset, NormalizedFinding
from backend.app.connectors.enums import AssetType, FindingCategory, Severity
from backend.app.db import SessionLocal
from backend.app.models.asset import Asset
from backend.app.services import intel
from backend.app.services.ingest import ingest_findings

# identifier -> (asset type, business criticality)
ASSETS = {
    "prod-api-01": (AssetType.HOST, "critical"),
    "mail-01": (AssetType.HOST, "high"),
    "dev-laptop-14": (AssetType.HOST, "low"),
    "github.com/acme/webapp": (AssetType.REPOSITORY, "high"),
    "arn:aws:s3:::acme-data": (AssetType.CLOUD_RESOURCE, "high"),
}

# source, cve, title, severity, cvss, category, asset, days_ago
FINDINGS = [
    ("tenable", "CVE-2021-44228", "Apache Log4j2 RCE (Log4Shell)", "critical", 10.0, "vulnerability", "prod-api-01", 45),
    ("tenable", "CVE-2019-0708", "Windows RDP RCE (BlueKeep)", "critical", 9.8, "vulnerability", "prod-api-01", 12),
    ("tenable", "CVE-2018-15473", "OpenSSH Username Enumeration", "medium", 5.3, "vulnerability", "prod-api-01", 30),
    ("tenable", "CVE-2021-26855", "MS Exchange SSRF (ProxyLogon)", "critical", 9.8, "vulnerability", "mail-01", 20),
    ("tenable", "CVE-2016-2183", "SSL/TLS Birthday attack (SWEET32)", "medium", 5.9, "vulnerability", "mail-01", 5),
    ("rapid7", "CVE-2017-0144", "SMB RCE (EternalBlue)", "high", 8.1, "vulnerability", "dev-laptop-14", 8),
    ("rapid7", "CVE-2021-34527", "Windows Print Spooler RCE (PrintNightmare)", "high", 8.8, "vulnerability", "dev-laptop-14", 3),
    ("semgrep", None, "Reflected XSS in search handler", "high", None, "sast", "github.com/acme/webapp", 2),
    ("semgrep", None, "Hardcoded AWS secret key", "medium", None, "secret", "github.com/acme/webapp", 6),
    ("wiz", None, "S3 bucket publicly readable", "high", None, "cloud_posture", "arn:aws:s3:::acme-data", 1),
]


def _asset(ident: str) -> NormalizedAsset:
    at, _ = ASSETS[ident]
    return NormalizedAsset(asset_type=at, identifier=ident, name=ident)


def main() -> None:
    now = datetime.now(timezone.utc)
    findings = []
    for i, (src, cve, title, sev, cvss, cat, asset, days) in enumerate(FINDINGS):
        seen = now - timedelta(days=days)
        findings.append(NormalizedFinding(
            source=src, source_finding_id=f"demo-{i}", category=FindingCategory(cat),
            title=title, severity=Severity(sev), asset=_asset(asset),
            cve_ids=[cve] if cve else [], cvss_base_score=cvss, description=title,
            first_seen=seen, last_seen=now,
        ))

    with SessionLocal() as db:
        res = ingest_findings(db, findings)
        for ident, (_, crit) in ASSETS.items():
            db.execute(update(Asset).where(Asset.identifier == ident).values(criticality=crit))
        db.commit()
        summary = intel.refresh(db)   # live CISA KEV + EPSS, then rescore
    print("ingested:", res)
    print("intel:", summary)


if __name__ == "__main__":
    main()
