"""Layer 2: manifest scanner. Flags direct deps whose name has *ever* shipped a
compromised version (MEDIUM), and pinned-exact compromised versions (CRITICAL).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-002"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#22-sha-256-hashes-high-confidence-observed-in-the-wild"

_SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    for path in _walk(ctx.root):
        try:
            if path.name == "package.json" and "npm" in ctx.ecosystems:
                yield from _scan_package_json(path, iocs)
            elif path.name == "pyproject.toml" and "pypi" in ctx.ecosystems:
                yield from _scan_pyproject_toml(path, iocs)
            elif path.name in ("setup.py", "setup.cfg") and "pypi" in ctx.ecosystems:
                yield from _scan_setup(path, iocs)
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue


def _walk(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def _scan_package_json(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    for dep_field in (
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ):
        block = data.get(dep_field)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(spec, str):
                continue
            exact = _exact_version(spec)
            if exact:
                hit = iocs.is_compromised("npm", name, exact)
                if hit:
                    yield Finding(
                        severity=Severity.CRITICAL,
                        layer="manifest",
                        rule_id=RULE_ID,
                        title="Manifest pins compromised npm package",
                        evidence=f"{dep_field}.{name} @ {exact} (spec={spec!r})",
                        path=path,
                        package=name,
                        version=exact,
                        ecosystem="npm",
                        reference=REF,
                        recommendation=(
                            "Pin to a post-incident clean release and rotate any secret reachable "
                            "from CI/dev machines that ran an install."
                        ),
                    )
                    continue
            ever = iocs.package_ever_compromised("npm", name)
            if ever:
                yield Finding(
                    severity=Severity.MEDIUM,
                    layer="manifest",
                    rule_id=RULE_ID,
                    title="Dependency on a package that has shipped a compromised version",
                    evidence=f"{dep_field}.{name} spec={spec!r}; compromised versions: {sorted(ever)[:5]}",
                    path=path,
                    package=name,
                    version=None,
                    ecosystem="npm",
                    reference=REF,
                    recommendation=(
                        "Verify your resolved version is post-incident. Pin to a known-clean release "
                        "and enable `npm config set ignore-scripts true` on shared machines."
                    ),
                )


def _exact_version(spec: str) -> str | None:
    spec = spec.strip()
    if not spec:
        return None
    if re.fullmatch(r"\d+\.\d+\.\d+([+\-][\w.\-]+)?", spec):
        return spec
    if spec.startswith("=") and not spec.startswith("=="):
        v = spec[1:].strip()
        if re.fullmatch(r"\d+\.\d+\.\d+([+\-][\w.\-]+)?", v):
            return v
    return None


_PYPROJECT_DEP_RE = re.compile(r'"([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.+\-]+)"')


def _scan_pyproject_toml(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    text = path.read_text(encoding="utf-8")
    for m in _PYPROJECT_DEP_RE.finditer(text):
        name, version = m.group(1), m.group(2)
        hit = iocs.is_compromised("pypi", name, version)
        if hit:
            yield Finding(
                severity=Severity.CRITICAL,
                layer="manifest",
                rule_id=RULE_ID,
                title="pyproject.toml pins compromised PyPI package",
                evidence=f"{name}=={version}",
                path=path,
                package=name,
                version=version,
                ecosystem="pypi",
                reference=REF,
            )
        else:
            ever = iocs.package_ever_compromised("pypi", name)
            if ever:
                yield Finding(
                    severity=Severity.MEDIUM,
                    layer="manifest",
                    rule_id=RULE_ID,
                    title="Dependency on PyPI package with prior compromise",
                    evidence=f"{name} (compromised versions: {sorted(ever)[:5]})",
                    path=path,
                    package=name,
                    version=None,
                    ecosystem="pypi",
                    reference=REF,
                )


_SETUP_PIN_RE = re.compile(r"['\"]([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.+\-]+)['\"]")


def _scan_setup(path: Path, iocs: IOCSet) -> Iterator[Finding]:
    text = path.read_text(encoding="utf-8", errors="replace")
    for m in _SETUP_PIN_RE.finditer(text):
        name, version = m.group(1), m.group(2)
        if iocs.is_compromised("pypi", name, version):
            yield Finding(
                severity=Severity.CRITICAL,
                layer="manifest",
                rule_id=RULE_ID,
                title="setup.py/cfg pins compromised PyPI package",
                evidence=f"{name}=={version}",
                path=path,
                package=name,
                version=version,
                ecosystem="pypi",
                reference=REF,
            )
