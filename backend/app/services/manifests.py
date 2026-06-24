"""Parse dependency manifests/lockfiles into (ecosystem, name, version) triples.

Ecosystem names match OSV's vocabulary ("npm", "PyPI", "Go") so parsed packages
can be queried directly. Only lockfiles with *exact* versions are useful for
supply-chain matching, so unpinned ranges are skipped.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

SUPPORTED = ("package-lock.json", "requirements*.txt", "go.sum")


@dataclass(frozen=True)
class ParsedPackage:
    ecosystem: str
    name: str
    version: str


def parse_manifest(filename: str, content: str) -> list[ParsedPackage]:
    base = filename.replace("\\", "/").split("/")[-1].lower()
    if base == "package-lock.json":
        return _parse_package_lock(content)
    if base.startswith("requirements") and base.endswith(".txt"):
        return _parse_requirements(content)
    if base == "go.sum":
        return _parse_go_sum(content)
    raise ValueError(f"unsupported manifest '{filename}'; supported: {', '.join(SUPPORTED)}")


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
