"""Layer 5: filename/path scanner."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-005"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#21-malicious-file-artifacts"

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}

_SKIP_DIRS = {".git"}

# Names that are far too generic to alarm on inside vendored dependency trees.
# Inside node_modules / site-packages we drop these to INFO (or suppress entirely).
_GENERIC_NAMES = {
    "data.json",
    "cloud.json",
    "contents.json",
    "environment.json",
    "bundle.js",
}

# Names that remain meaningful even when nested deep in vendored trees.
# Hash layer (SHAI-004) corroborates exact-payload matches.
_VENDORED_PARENTS = ("node_modules", "site-packages", ".venv", "venv", "vendor")


def _is_vendored(path: Path, root: Path) -> bool:
    try:
        rel = path.relative_to(root)
    except ValueError:
        return False
    return any(part in _VENDORED_PARENTS for part in rel.parts)


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    if not iocs.filenames:
        return
    for path in _walk(ctx.root):
        ioc = iocs.filenames.get(path.name)
        if not ioc:
            continue
        # Suppress in-tree own data files; we are reading our own IOC lists.
        if "shai_hulud_audit/ioc/data" in str(path):
            continue

        severity = _SEVERITY_MAP.get(ioc.severity, Severity.HIGH)
        vendored = _is_vendored(path, ctx.root)

        # Generic names under a vendored tree: drop to INFO (or skip outright).
        if path.name in _GENERIC_NAMES and vendored:
            if not ctx.paranoid:
                continue
            severity = Severity.INFO
        elif path.name == "bundle.js" and severity == Severity.CRITICAL:
            # At repo root or in source: still suspicious but high FP — MEDIUM.
            severity = Severity.MEDIUM

        yield Finding(
            severity=severity,
            layer="filename",
            rule_id=RULE_ID,
            title=f"Known Shai-Hulud filename detected: {path.name}",
            evidence=f"{path} (wave={ioc.wave})",
            path=path,
            reference=REF,
            recommendation=ioc.note or "Quarantine the file and audit lifecycle scripts that may invoke it.",
            extra={"wave": ioc.wave, "filename_severity": ioc.severity, "vendored": vendored},
        )


def _walk(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p
