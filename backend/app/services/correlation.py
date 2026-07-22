"""Correlation / de-duplication of findings (non-destructive).

The same real-world vulnerability is often reported more than once: one scanner
emits two advisories that share a CVE (e.g. OSV returning two GHSAs both aliased
to the same CVE), or two different tools each report the same CVE on the same
asset. The stored `fingerprint` deliberately keeps every source row distinct — we
never drop a source's record — so this layer groups those rows into one logical
vulnerability *for display*, computed at read time.

The correlation key is scoped **per asset** and layered by how strong the identity
signal is:

  1. CVE          — same CVE on the same asset is the same vulnerability, no matter
                    which tool or advisory reported it (covers within- and
                    cross-source duplication).
  2. CWE+location — no CVE, but two findings flag the same weakness (CWE) at the
                    same file:line: a strong same-issue signal across SAST tools.
  3. fingerprint  — nothing reliable to correlate on, so the finding is its own
                    group (we never merge on a fuzzy signal like title text).

A single representative CVE/CWE (the lexicographically smallest id) is used as the
canonical key, so grouping is deterministic; the common single-id case is exact.
"""
from __future__ import annotations

# Severity ordering, shared with the grouped API so a group takes its worst member.
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _canonical(items) -> str | None:
    """Smallest non-empty id from a list, as a stable canonical representative."""
    vals = sorted({str(i).strip() for i in (items or []) if str(i).strip()})
    return vals[0] if vals else None


def correlation_key_fields(
    asset_id, cve_ids, cwe_ids, location, fingerprint
) -> str:
    """Compute the correlation key from raw fields (used by aggregate queries)."""
    cve = _canonical(cve_ids)
    if cve:
        return f"{asset_id}|cve|{cve}"
    cwe = _canonical(cwe_ids)
    loc = location or {}
    path = str(loc.get("path", "") or "")
    line = str(loc.get("line", "") or "")
    if cwe and (path or line):
        return f"{asset_id}|cwe|{cwe}|{path}|{line}"
    return f"{asset_id}|fp|{fingerprint}"


def correlation_key(f) -> str:
    """Correlation key for a Finding (ORM) or any object with the same attributes."""
    return correlation_key_fields(
        getattr(f, "asset_id", "") or "", f.cve_ids, f.cwe_ids, f.location, f.fingerprint
    )


def _max_severity(members) -> str:
    return max((m.severity for m in members), key=lambda s: SEV_RANK.get(s, 0))


def group_findings(findings) -> list[dict]:
    """Collapse findings into correlated groups (one dict per logical vulnerability).

    Every input row is preserved as a member; the group surfaces aggregate fields
    (worst severity, union of sources/CVEs, open count) plus a representative id
    (the highest-severity member) to open in the detail view.
    """
    buckets: dict[str, list] = {}
    for f in findings:
        buckets.setdefault(correlation_key(f), []).append(f)

    groups: list[dict] = []
    for key, members in buckets.items():
        members = sorted(
            members, key=lambda m: (SEV_RANK.get(m.severity, 0), m.id or 0), reverse=True
        )
        rep = members[0]                      # highest-severity representative
        open_count = sum(1 for m in members if m.effective_status == "open")
        firsts = [m.first_seen for m in members if m.first_seen]
        lasts = [m.last_seen for m in members if m.last_seen]
        groups.append(
            {
                "key": key,
                "title": rep.title,
                "severity": _max_severity(members),
                # A group is "open" if any member is; else the representative's status.
                "effective_status": "open" if open_count else rep.effective_status,
                "count": len(members),
                "duplicate_count": len(members) - 1,
                "open_count": open_count,
                "sources": sorted({m.source for m in members}),
                "categories": sorted({m.category for m in members}),
                "cve_ids": sorted({c for m in members for c in (m.cve_ids or [])}),
                "first_seen": min(firsts) if firsts else None,
                "last_seen": max(lasts) if lasts else None,
                "sla_breached": any(m.sla_breached for m in members),
                "representative_id": rep.id,
                "members": members,
            }
        )
    return groups
