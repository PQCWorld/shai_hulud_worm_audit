"""Layer 1: lockfile scanner. Detect pinned compromised name@version pairs.

Supports:
  - npm:  package-lock.json (v1, v2, v3), npm-shrinkwrap.json
  - yarn: yarn.lock (v1 + berry plaintext)
  - pnpm: pnpm-lock.yaml (regex-based; no YAML dep)
  - pypi: requirements*.txt, poetry.lock (TOML-ish, regex), uv.lock, Pipfile.lock
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-001"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#11-wave-1--shai-hulud-v1-september-2025"

_NPM_LOCK_NAMES = {"package-lock.json", "npm-shrinkwrap.json"}
_YARN_LOCK_NAMES = {"yarn.lock"}
_PNPM_LOCK_NAMES = {"pnpm-lock.yaml"}
_PYPI_REQ_GLOBS = ("requirements*.txt", "constraints*.txt")
_PYPI_LOCK_NAMES = {"poetry.lock", "Pipfile.lock", "uv.lock"}

_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".ruff_cache"}


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    for path in _walk(ctx.root):
        name = path.name
        try:
            if name in _NPM_LOCK_NAMES and "npm" in ctx.ecosystems:
                yield from _scan_npm_lock(path, iocs)
            elif name in _YARN_LOCK_NAMES and "npm" in ctx.ecosystems:
                yield from _scan_yarn_lock(path, iocs)
            elif name in _PNPM_LOCK_NAMES and "npm" in ctx.ecosystems:
                yield from _scan_pnpm_lock(path, iocs)
            elif name in _PYPI_LOCK_NAMES and "pypi" in ctx.ecosystems:
                yield from _scan_pypi_lock(path, iocs)
            elif _matches_any(name, _PYPI_REQ_GLOBS) and "pypi" in ctx.ecosystems:
                yield from _scan_requirements(path, iocs)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue


def _walk(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        # Skip hidden/uninteresting tree branches early
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def _matches_any(name: str, globs: tuple[str, ...]) -> bool:
    from fnmatch import fnmatch

    return any(fnmatch(name, g) for g in globs)


def _finding(
    iocs: IOCSet,
    path: Path,
    ecosystem: str,
    name: str,
    version: str,
    evidence: str,
) -> Finding | None:
    hit = iocs.is_compromised(ecosystem, name, version)
    if not hit:
        return None
    return Finding(
        severity=Severity.CRITICAL,
        layer="lockfile",
        rule_id=RULE_ID,
        title=f"Lockfile pins compromised {ecosystem} package",
        evidence=evidence,
        path=path,
        package=name,
        version=version,
        ecosystem=ecosystem,
        reference=REF,
        recommendation=(
            "Remove the lockfile and node_modules/.venv, pin to a known-clean version, "
            "rotate every credential reachable from CI/dev machines that ran an install."
        ),
        extra={"sources": list(hit.sources)},
    )


# --- npm ---------------------------------------------------------------

def _scan_npm_lock(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))

    # npm v1: top-level "dependencies" recursive
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        yield from _walk_npm_v1_deps(deps, path, iocs)

    # npm v2/v3: "packages" object with paths
    packages = data.get("packages")
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict):
                continue
            name = meta.get("name")
            version = meta.get("version")
            if not name and key.startswith("node_modules/"):
                name = key[len("node_modules/") :].split("/node_modules/")[-1]
            if name and version:
                f = _finding(iocs, path, "npm", name, version, f"{key} -> {name}@{version}")
                if f:
                    yield f


def _walk_npm_v1_deps(deps: dict, path: Path, iocs: IOCSet) -> Iterator[Finding]:
    for name, meta in deps.items():
        if not isinstance(meta, dict):
            continue
        version = meta.get("version")
        if version:
            f = _finding(iocs, path, "npm", name, version, f"dependencies.{name}@{version}")
            if f:
                yield f
        nested = meta.get("dependencies")
        if isinstance(nested, dict):
            yield from _walk_npm_v1_deps(nested, path, iocs)


# --- yarn --------------------------------------------------------------

_YARN_VERSION_RE = re.compile(r'^\s+version[\s:]+"?(?P<version>[^"\s]+)"?')


def _scan_yarn_lock(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    current_names: list[str] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            stripped = line.rstrip("\n")
            # A yarn header is any non-indented line ending in ':' (other than the
            # special '__metadata:' / '# yarn lockfile v1' lines).
            if (
                stripped
                and not stripped.startswith((" ", "\t", "#"))
                and stripped.rstrip().endswith(":")
                and "@" in stripped
            ):
                current_names = _yarn_header_names(stripped)
                continue
            m = _YARN_VERSION_RE.match(line)
            if m and current_names:
                version = m.group("version")
                for name in current_names:
                    f_ = _finding(iocs, path, "npm", name, version, f"{name}@{version}")
                    if f_:
                        yield f_
                current_names = []


def _yarn_header_names(raw_line: str) -> list[str]:
    line = raw_line.strip().rstrip(":").strip()
    names: list[str] = []
    for piece in line.split(","):
        piece = piece.strip().strip('"').strip("'")
        # scoped: @scope/name@range
        if piece.startswith("@"):
            at = piece.find("@", 1)
            if at == -1:
                continue
            names.append(piece[:at])
        else:
            at = piece.find("@")
            if at == -1:
                continue
            names.append(piece[:at])
    return list(dict.fromkeys(names))


# --- pnpm --------------------------------------------------------------

_PNPM_ENTRY_RE = re.compile(
    r"^\s+(?P<key>'?(?:/(?:@[^/]+/)?[^@\s']+|(?:@[^/]+/)?[^@\s/]+)@(?P<version>[^:\s']+)'?):\s*$"
)


def _scan_pnpm_lock(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    """pnpm-lock.yaml is YAML; we do a tolerant regex pass over the 'packages:' map."""
    text = path.read_text(encoding="utf-8")
    in_packages = False
    for line in text.splitlines():
        if line.startswith("packages:"):
            in_packages = True
            continue
        if in_packages and line and not line.startswith(" ") and line.endswith(":"):
            in_packages = False
            continue
        if not in_packages:
            continue
        m = _PNPM_ENTRY_RE.match(line)
        if not m:
            continue
        key = m.group("key").strip("'")
        version = m.group("version").strip("'")
        # strip leading '/' if present
        if key.startswith("/"):
            key = key[1:]
        name, _, ver_from_key = key.rpartition("@")
        if not name:
            continue
        # Some pnpm versions have peer-suffix like "1.2.3(react@18)" — keep base
        version = version.split("(")[0]
        f = _finding(iocs, path, "npm", name, version, f"{name}@{version}")
        if f:
            yield f
        # ver_from_key may include the actual range; trust line's `version` token
        del ver_from_key


# --- pypi: requirements --------------------------------------------------

_REQ_LINE_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.+\-]+)")


def _scan_requirements(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE_RE.match(line)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        f = _finding(iocs, path, "pypi", name, version, f"{name}=={version}")
        if f:
            yield f


# --- pypi: lock files ---------------------------------------------------

_POETRY_NAME_RE = re.compile(r'^\s*name\s*=\s*"([^"]+)"')
_POETRY_VER_RE = re.compile(r'^\s*version\s*=\s*"([^"]+)"')


def _scan_pypi_lock(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.name == "Pipfile.lock":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return
        for section in ("default", "develop"):
            block = data.get(section)
            if not isinstance(block, dict):
                continue
            for name, meta in block.items():
                if not isinstance(meta, dict):
                    continue
                version = (meta.get("version") or "").lstrip("=").lstrip()
                if not version:
                    continue
                f = _finding(iocs, path, "pypi", name, version, f"{section}.{name}=={version}")
                if f:
                    yield f
        return

    # poetry.lock / uv.lock: TOML-like, regex over [[package]] blocks
    name = None
    version = None
    for line in text.splitlines():
        if line.startswith("[[package]]"):
            if name and version:
                f = _finding(iocs, path, "pypi", name, version, f"{name}=={version}")
                if f:
                    yield f
            name = None
            version = None
            continue
        if name is None:
            m = _POETRY_NAME_RE.match(line)
            if m:
                name = m.group(1)
                continue
        if version is None:
            m = _POETRY_VER_RE.match(line)
            if m:
                version = m.group(1)
    if name and version:
        f = _finding(iocs, path, "pypi", name, version, f"{name}=={version}")
        if f:
            yield f
