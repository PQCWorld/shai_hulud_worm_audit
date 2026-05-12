"""Layer 4: hash scanner. SHA-256 every candidate file under the tree and compare
against the IOC hash list."""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-004"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#22-sha-256-hashes-high-confidence-observed-in-the-wild"

_CANDIDATE_EXT = {".js", ".mjs", ".cjs", ".pyz", ".sh", ".yml", ".yaml", ".plist", ".json"}
_MIN_SIZE = 1024            # ignore < 1 KB
_MAX_SIZE = 64 * 1024 * 1024  # cap at 64 MB per file
_SKIP_DIRS = {".git"}


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    if not iocs.hashes:
        return
    for path in _walk(ctx.root):
        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size < _MIN_SIZE or size > _MAX_SIZE:
            continue
        if path.suffix.lower() not in _CANDIDATE_EXT:
            continue
        digest = _sha256(path)
        if digest is None:
            continue
        hit = iocs.hashes.get(digest)
        if hit:
            yield Finding(
                severity=Severity.CRITICAL,
                layer="hash",
                rule_id=RULE_ID,
                title="File hash matches a known Shai-Hulud payload",
                evidence=f"sha256={digest} (hint={hit.filename_hint}, wave={hit.wave})",
                path=path,
                reference=REF,
                recommendation=(
                    "DO NOT EXECUTE this file. Quarantine, then follow the remediation playbook: "
                    "rotate every credential reachable from this host."
                ),
                extra={"sha256": digest, "wave": hit.wave, "hint": hit.filename_hint},
            )


def _walk(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p


def _sha256(path: Path) -> str | None:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None
