"""Composite risk scoring.

Turns raw severity into a prioritization signal by folding in threat intelligence
(is it actively exploited? how likely is exploitation?) and business context (how
much does this asset matter). The score (0..100) is what the findings queue sorts
on, so a medium-severity CVE that's KEV-listed on a crown-jewel asset outranks a
critical on a throwaway dev box.

    score = min(100, base + kev + epss + watch) * criticality_multiplier

- base  : CVSS-derived (0..60) when a CVSS score is present, else a per-severity floor
- kev   : +40 if on CISA KEV (+45 if tied to a known ransomware campaign)
- epss  : up to +25, scaled by exploit-probability (0..1)
- watch : +20 if flagged by a custom "watchlist" feed
- mult  : asset criticality tilt (crown-jewel up, dev box down)
"""
from __future__ import annotations

# Floors used when a finding has no CVSS score (SAST, cloud posture, secrets…).
_SEVERITY_BASE = {"critical": 55.0, "high": 40.0, "medium": 25.0, "low": 10.0, "info": 2.0}
_CRITICALITY_MULT = {"critical": 1.3, "high": 1.15, "medium": 1.0, "low": 0.85}


def compute_risk(
    *,
    severity: str,
    cvss: float | None,
    in_kev: bool = False,
    kev_ransomware: bool = False,
    epss_score: float | None = None,
    watchlisted: bool = False,
    asset_criticality: str = "medium",
) -> float:
    """Return a 0..100 composite risk score. Pure + deterministic (easy to test)."""
    base = (cvss * 6.0) if cvss else _SEVERITY_BASE.get((severity or "").lower(), 2.0)
    kev = (45.0 if kev_ransomware else 40.0) if in_kev else 0.0
    epss = max(0.0, min(1.0, epss_score or 0.0)) * 25.0
    watch = 20.0 if watchlisted else 0.0
    mult = _CRITICALITY_MULT.get((asset_criticality or "medium").lower(), 1.0)
    return round(min(100.0, (base + kev + epss + watch) * mult), 1)
