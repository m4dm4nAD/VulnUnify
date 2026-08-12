"""Resolve unpinned PyPI requirements to the concrete version pip would install.

The requirements.txt parser keeps unpinned entries (version LATEST) and range
specifiers (">=2,<3") — see services.manifests. OSV can only be queried with an
exact version, so before any scan those are resolved against the PyPI JSON
index: LATEST becomes the newest release, a range becomes the newest installable
release that satisfies it. (Caveat: the caller's Python version is unknown here,
so requires-python metadata is ignored — on an older Python, pip may pick an
older release than the one scanned.) The original spec is kept on
ParsedPackage.requested so the UI can show "2.31.0 (>=2)". Packages that don't
resolve (unknown name, no release in range) are returned separately so callers
can surface them instead of silently dropping them.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import httpx
import structlog
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from backend.app.services.manifests import LATEST, ParsedPackage, is_version_spec

log = structlog.get_logger()

_PYPI_JSON = "https://pypi.org/pypi/{name}/json"
_RESOLVE_LIMIT = 500   # per call — the scan route is open to every logged-in user
_WORKERS = 8


def resolve_specs(
    packages: list[ParsedPackage], *, client: httpx.Client | None = None
) -> tuple[list[ParsedPackage], list[str]]:
    """Resolve LATEST/range versions to exact ones via the PyPI index.

    Returns (resolved, unresolved): `resolved` is the input list with every
    resolvable spec replaced by a concrete version (exact pins pass through
    untouched) and duplicates that resolved to the same version collapsed;
    `unresolved` describes the rest, e.g. ["nosuchpkg (latest)"]. Raises
    httpx.HTTPError on network trouble (a 404 is "unresolved", not an error —
    the file may simply name a package that isn't on PyPI).
    """
    needs = [p for p in packages if p.ecosystem == "PyPI" and is_version_spec(p.version)]
    if not needs:
        return packages, []
    over_limit = set(needs[_RESOLVE_LIMIT:])
    if over_limit:
        log.warning("pypi.resolve_limit", skipped=len(over_limit), limit=_RESOLVE_LIMIT)
        needs = needs[:_RESOLVE_LIMIT]

    own_client = client is None
    client = client or httpx.Client(timeout=30.0, follow_redirects=True)
    try:
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            resolved = dict(zip(needs, pool.map(lambda p: _resolve_one(client, p), needs)))
    finally:
        if own_client:
            client.close()

    out: dict[tuple, ParsedPackage] = {}
    unresolved = []
    for p in packages:
        if p in over_limit:
            unresolved.append(f"{p.name} ({p.version}) — over the {_RESOLVE_LIMIT}-package limit")
        elif p not in resolved:
            out.setdefault((p.ecosystem, p.name, p.version), p)
        elif resolved[p] is not None:
            r = resolved[p]
            out.setdefault((r.ecosystem, r.name, r.version), r)
        else:
            unresolved.append(f"{p.name} ({p.version})")
    if unresolved:
        log.info("pypi.unresolved", packages=unresolved)
    return list(out.values()), unresolved


def _resolve_one(client: httpx.Client, pkg: ParsedPackage) -> ParsedPackage | None:
    resp = client.get(_PYPI_JSON.format(name=pkg.name))
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    try:
        data = resp.json()
    except ValueError as exc:  # 200 with a non-JSON body (proxy/CDN interference)
        raise httpx.HTTPError(f"PyPI returned non-JSON for {pkg.name}: {exc}") from exc
    if pkg.version == LATEST:
        version = data.get("info", {}).get("version")
    else:
        version = _best_match(pkg.version, data.get("releases", {}))
    if not version:
        return None
    return ParsedPackage(pkg.ecosystem, pkg.name, version, requested=pkg.version)


def _best_match(spec: str, releases: dict) -> str | None:
    """Newest release satisfying `spec` — what `pip install "name{spec}"` picks."""
    try:
        sset = SpecifierSet(spec)
    except InvalidSpecifier:
        return None
    versions: dict[Version, str] = {}   # parsed -> original release key ("3.08", not "3.8")
    for v, files in releases.items():
        try:
            parsed = Version(v)
        except InvalidVersion:
            continue
        # pip can only install releases that have at least one non-yanked file.
        if not files or all(f.get("yanked") for f in files):
            continue
        versions[parsed] = v
    # filter() applies pip's prerelease rule; fall back to prereleases when the
    # range matches nothing else (e.g. ">=2.0rc1" on a package with only rcs).
    matches = list(sset.filter(versions)) or list(sset.filter(versions, prereleases=True))
    return versions[max(matches)] if matches else None
