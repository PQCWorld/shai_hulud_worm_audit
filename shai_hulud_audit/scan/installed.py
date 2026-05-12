"""Layer 3: installed-tree scanner. Walk node_modules/ and site-packages/ for
compromised name@version pairs in their own metadata files."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-003"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#33-detection-layers"


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    if "npm" in ctx.ecosystems:
        yield from _scan_node_modules(ctx.root, iocs)
    if "pypi" in ctx.ecosystems:
        yield from _scan_site_packages(ctx.root, iocs)


def _scan_node_modules(root: Path, iocs: IOCSet) -> Iterator[Finding]:
    for nm in root.rglob("node_modules"):
        if not nm.is_dir():
            continue
        for pkg_json in nm.rglob("package.json"):
            try:
                data = json.loads(pkg_json.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            name = data.get("name")
            version = data.get("version")
            if not name or not version:
                continue
            hit = iocs.is_compromised("npm", name, version)
            if hit:
                yield Finding(
                    severity=Severity.CRITICAL,
                    layer="installed",
                    rule_id=RULE_ID,
                    title="Installed npm package matches compromised version",
                    evidence=f"{name}@{version} installed at {pkg_json.parent}",
                    path=pkg_json,
                    package=name,
                    version=version,
                    ecosystem="npm",
                    reference=REF,
                    recommendation=(
                        "Treat this dev/CI host as potentially compromised. Rotate every secret "
                        "(see remediation playbook). Delete node_modules and reinstall."
                    ),
                    extra={"sources": list(hit.sources)},
                )


def _scan_site_packages(root: Path, iocs: IOCSet) -> Iterator[Finding]:
    for sp in root.rglob("site-packages"):
        if not sp.is_dir():
            continue
        # *.dist-info/METADATA contains Name + Version
        for meta in sp.rglob("METADATA"):
            try:
                text = meta.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            name = None
            version = None
            for line in text.splitlines():
                if line.lower().startswith("name:"):
                    name = line.split(":", 1)[1].strip()
                elif line.lower().startswith("version:"):
                    version = line.split(":", 1)[1].strip()
                if name and version:
                    break
            if not name or not version:
                continue
            hit = iocs.is_compromised("pypi", name, version)
            if hit:
                yield Finding(
                    severity=Severity.CRITICAL,
                    layer="installed",
                    rule_id=RULE_ID,
                    title="Installed PyPI package matches compromised version",
                    evidence=f"{name}=={version} installed at {meta.parent}",
                    path=meta,
                    package=name,
                    version=version,
                    ecosystem="pypi",
                    reference=REF,
                    extra={"sources": list(hit.sources)},
                )
