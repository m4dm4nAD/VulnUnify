"""Parse dependency manifests/lockfiles/SBOMs into (ecosystem, name, version) triples.

Ecosystem names match OSV's vocabulary ("npm", "PyPI", "Go") so parsed packages
can be queried directly. Only entries with *exact* versions are useful for
supply-chain matching, so unpinned ranges (e.g. package.json "^1.2.3" is fine,
but ">=1 <2", "*", "latest", or a git URL) are skipped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import unquote

SUPPORTED = (
    "package.json", "package-lock.json", "requirements*.txt", "go.sum",
    "CycloneDX (JSON)", "SPDX (JSON)",
)

# purl package type -> OSV ecosystem name.
_PURL_ECO = {
    "npm": "npm", "pypi": "PyPI", "golang": "Go", "cargo": "crates.io",
    "maven": "Maven", "gem": "RubyGems", "nuget": "NuGet",
    "composer": "Packagist", "hex": "Hex", "pub": "Pub",
}


@dataclass(frozen=True)
class ParsedPackage:
    ecosystem: str
    name: str
    version: str


def parse_manifest(filename: str, content: str) -> list[ParsedPackage]:
    base = filename.replace("\\", "/").split("/")[-1].lower()
    if base == "package-lock.json":
        return _parse_package_lock(content)
    if base == "package.json":
        return _parse_package_json(content)
    if base.startswith("requirements") and base.endswith(".txt"):
        return _parse_requirements(content)
    if base == "go.sum":
        return _parse_go_sum(content)
    # SBOM formats are identified by content, not filename (bom.json, *.cdx.json, …).
    sbom = _try_parse_sbom(content)
    if sbom is not None:
        return sbom
    raise ValueError(f"unsupported file '{filename}'; supported: {', '.join(SUPPORTED)}")


def _dedup(items) -> list[ParsedPackage]:
    return list({(p.ecosystem, p.name, p.version): p for p in items}.values())


def _parse_package_lock(content: str) -> list[ParsedPackage]:
    data = json.loads(content)
    out: list[ParsedPackage] = []
    packages = data.get("packages")
    if packages:  # lockfile v2/v3
        for path, info in packages.items():
            version = (info or {}).get("version")
            if not path or not version:
                continue  # root entry / no concrete version
            name = path.split("node_modules/")[-1]  # handles nested + @scope/name
            out.append(ParsedPackage("npm", name, version))
    else:  # lockfile v1

        def walk(deps):
            for name, info in (deps or {}).items():
                version = info.get("version")
                if version:
                    out.append(ParsedPackage("npm", name, version))
                walk(info.get("dependencies"))

        walk(data.get("dependencies"))
    return _dedup(out)


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")


def _parse_requirements(content: str) -> list[ParsedPackage]:
    out: list[ParsedPackage] = []
    for raw in content.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):  # skip -r/-e/options and blanks
            continue
        m = _REQ_RE.match(line)
        if m:
            name = re.sub(r"[-_.]+", "-", m.group(1)).lower()  # PEP 503 normalize
            out.append(ParsedPackage("PyPI", name, m.group(2)))
    return _dedup(out)


def _parse_go_sum(content: str) -> list[ParsedPackage]:
    out: list[ParsedPackage] = []
    for raw in content.splitlines():
        parts = raw.split()
        if len(parts) < 2:
            continue
        module, version = parts[0], parts[1]
        version = version.removesuffix("/go.mod")
        version = version[1:] if version.startswith("v") else version
        out.append(ParsedPackage("Go", module, version))
    return _dedup(out)


# Accept a concrete npm version, tolerating a leading ^ ~ = v. Ranges with
# spaces/operators, "*", "x" placeholders, "latest", and URLs won't match.
_NPM_CONCRETE = re.compile(r"^[\^~=v\s]*(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)\s*$")

_NPM_FIELDS = ("dependencies", "devDependencies",
               "optionalDependencies", "peerDependencies")


def _coerce_npm_version(spec: str) -> str | None:
    m = _NPM_CONCRETE.match(spec or "")
    return m.group(1) if m else None


def _parse_package_json(content: str) -> list[ParsedPackage]:
    data = json.loads(content)
    out: list[ParsedPackage] = []
    for field in _NPM_FIELDS:
        deps = data.get(field)
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            version = _coerce_npm_version(spec if isinstance(spec, str) else "")
            if version:  # skip ranges/tags/urls we can't resolve to a point version
                out.append(ParsedPackage("npm", name, version))
    return _dedup(out)


def _normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()  # PEP 503


def _parse_purl(purl: str) -> ParsedPackage | None:
    """Best-effort parse of a Package URL into an OSV (ecosystem, name, version)."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]  # drop subpath/qualifiers
    if "@" not in body:
        return None
    coord, version = body.rsplit("@", 1)
    version = unquote(version)
    parts = [unquote(p) for p in coord.split("/") if p]
    if len(parts) < 2 or not version:
        return None
    ptype = parts[0].lower()
    eco = _PURL_ECO.get(ptype)
    if not eco:
        return None
    segs = parts[1:]
    if ptype in ("npm", "golang"):
        name = "/".join(segs)          # @scope/name, or full module path
    elif ptype == "maven":
        name = ":".join(segs)          # group:artifact
    else:
        name = segs[-1]                # namespace rarely used for pypi/cargo/etc.
    if eco == "PyPI":
        name = _normalize_pypi(name)
    return ParsedPackage(eco, name, version)


def _try_parse_sbom(content: str):
    """Return packages if `content` is a recognized JSON SBOM, else None."""
    try:
        data = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("bomFormat") == "CycloneDX" or "components" in data:
        return _parse_cyclonedx(data)
    if data.get("spdxVersion") or "spdxVersion" in data:
        return _parse_spdx(data)
    return None


def _parse_cyclonedx(data: dict) -> list[ParsedPackage]:
    out: list[ParsedPackage] = []

    def walk(components):
        for comp in components or []:
            pkg = _parse_purl(comp.get("purl", ""))
            if pkg is None and comp.get("name") and comp.get("version"):
                pkg = _guess_from_type(comp)
            if pkg is not None:
                out.append(pkg)
            walk(comp.get("components"))  # nested sub-components

    walk(data.get("components"))
    return _dedup(out)


def _guess_from_type(comp: dict) -> ParsedPackage | None:
    """When a CycloneDX component has no purl, try its declared type as ecosystem."""
    eco = _PURL_ECO.get(str(comp.get("type", "")).lower())
    return ParsedPackage(eco, comp["name"], comp["version"]) if eco else None


def _parse_spdx(data: dict) -> list[ParsedPackage]:
    out: list[ParsedPackage] = []
    for pkg in data.get("packages") or []:
        purl = None
        for ref in pkg.get("externalRefs") or []:
            loc = ref.get("referenceLocator", "")
            if ref.get("referenceType") == "purl" or loc.startswith("pkg:"):
                purl = loc
                break
        parsed = _parse_purl(purl) if purl else None
        if parsed is not None:
            out.append(parsed)
    return _dedup(out)
