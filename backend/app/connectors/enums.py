"""Enumerations shared across the normalized data model."""
from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Higher = more severe. Useful for sorting/filtering."""
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class FindingCategory(str, Enum):
    """The class of problem a finding represents — drives how the UI groups it."""
    VULNERABILITY = "vulnerability"      # host/network CVEs (Tenable, Rapid7)
    CLOUD_POSTURE = "cloud_posture"      # CSPM misconfig (Wiz, Trend, Defender)
    SAST = "sast"                        # static code analysis (SonarQube, Semgrep, Aikido)
    SCA = "sca"                          # dependency / supply chain
    SECRET = "secret"                    # leaked credentials
    IAC = "iac"                          # infrastructure-as-code misconfig
    CONTAINER = "container"              # container image vulns


class FindingStatus(str, Enum):
    """Status as reported by the *source* connector (stored as source_status)."""
    OPEN = "open"
    FIXED = "fixed"
    SUPPRESSED = "suppressed"        # muted in the source tool
    ACCEPTED_RISK = "accepted_risk"  # risk-accepted / won't-fix


class TriageState(str, Enum):
    """A local human decision on a finding — survives connector re-syncs."""
    ACTIVE = "active"               # no decision yet
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    SNOOZED = "snoozed"             # muted until triage_until


class EffectiveStatus(str, Enum):
    """The status VulnUnify shows — derived from lifecycle + triage."""
    OPEN = "open"
    RESOLVED = "resolved"          # no longer reported by the source
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    SNOOZED = "snoozed"


class AssetType(str, Enum):
    HOST = "host"                  # server, workstation, IP
    CLOUD_RESOURCE = "cloud_resource"
    REPOSITORY = "repository"
    CONTAINER_IMAGE = "container_image"
    WEB_APP = "web_app"
    UNKNOWN = "unknown"
