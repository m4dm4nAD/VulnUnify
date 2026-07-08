"""Watched-package API schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

# Upper bound on uploaded file contents (matches the 32 MB request-body cap and
# enforces it even for chunked bodies that omit Content-Length).
MAX_CONTENT_LEN = 32 * 1024 * 1024


class PackageImportIn(BaseModel):
    filename: str = Field(max_length=512)   # picks the parser (package-lock.json, requirements.txt)
    content: str = Field(max_length=MAX_CONTENT_LEN)   # the file contents
    source: str | None = Field(None, max_length=256)   # label (defaults to filename)


class WatchedPackageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ecosystem: str
    name: str
    version: str
    source: str
    first_seen: datetime


class PackageScanIn(BaseModel):
    filename: str = Field(max_length=512)   # picks the parser (package.json, lockfile, SBOM, …)
    content: str = Field(max_length=MAX_CONTENT_LEN)   # the file contents


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
