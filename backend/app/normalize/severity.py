"""Severity normalization.

Every tool uses its own severity vocabulary (info/low/med/high/crit, 1-10
CVSS, P1-P4, BLOCKER/CRITICAL/MAJOR...). We map them all onto a single
ordered scale so findings are comparable across sources.
"""
from __future__ import annotations

from backend.app.connectors.enums import Severity

# Free-text label -> Severity. Lower-cased on lookup.
_LABEL_MAP: dict[str, Severity] = {
    # generic
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "severe": Severity.HIGH,        # Rapid7 InsightVM
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    "negligible": Severity.INFO,
    # SonarQube
    "blocker": Severity.CRITICAL,
    "major": Severity.HIGH,
    "minor": Severity.LOW,
    # Semgrep
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    # priority-style
    "p1": Severity.CRITICAL,
    "p2": Severity.HIGH,
    "p3": Severity.MEDIUM,
    "p4": Severity.LOW,
}


def from_label(label: str | None) -> Severity:
    """Map a vendor severity label to a normalized Severity."""
    if not label:
        return Severity.INFO
    return _LABEL_MAP.get(label.strip().lower(), Severity.INFO)


def from_cvss(score: float | None) -> Severity:
    """Map a CVSS base score (0.0-10.0) to a normalized Severity (CVSS v3 bands)."""
    if score is None:
        return Severity.INFO
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO
