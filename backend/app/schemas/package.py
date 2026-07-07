"""Watched-package API schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class PackageImportIn(BaseModel):
    filename: str           # used to pick the parser (package-lock.json, requirements.txt, go.sum)
    content: str            # the file contents
    source: str | None = None  # label for where these deps came from (defaults to filename)


class WatchedPackageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ecosystem: str
    name: str
    version: str
    source: str
    first_seen: datetime


class PackageScanIn(BaseModel):
    filename: str           # picks the parser (package.json, lockfile, SBOM, …)
    content: str            # the file contents


class ScanVulnOut(BaseModel):
    id: str
    summary: str
    severity: str
    malicious: bool
    cves: list[str]
    references: list[str]


class ScanPackageOut(BaseModel):
    ecosystem: str
    name: str
    version: str
    vulns: list[ScanVulnOut]


class PackageScanOut(BaseModel):
    checked: int            # packages with a resolvable exact version
    vulnerable: int         # of those, how many have >=1 known vuln
    total_vulns: int
    ecosystems: list[str]
    results: list[ScanPackageOut]


class ScannedPackageOut(BaseModel):
    ecosystem: str
    name: str
    version: str
    vuln_count: int


class PackageScanRecordOut(BaseModel):
    """One stored /scan run: what was searched, by whom, and when."""
    id: int
    filename: str
    checked: int
    vulnerable: int
    total_vulns: int
    ecosystems: list[str]
    packages: list[ScannedPackageOut]
    username: str | None
    created_at: datetime
