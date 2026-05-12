"""Layer 6: npm lifecycle-script scanner. Flag preinstall/postinstall/install
scripts that invoke any known Shai-Hulud payload filename."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-006"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#25-in-package-signals"

_LIFECYCLE_HOOKS = (
    "preinstall",
    "install",
    "postinstall",
    "prepare",
    "prepublishOnly",
    "preuninstall",
)

# Conservative payload tokens — match basename references in script bodies.
_PAYLOAD_TOKENS = {
    "bundle.js",
    "setup_bun.js",
    "bun_environment.js",
    "bun_installer.js",
    "router_init.js",
    "tanstack_runner.js",
    "setup.mjs",
    "transformers.pyz",
    "processor.sh",
    "migrate-repos.sh",
}

_SKIP_DIRS = {".git"}


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    tokens = set(_PAYLOAD_TOKENS) | set(iocs.filenames or [])
    for path in _walk(ctx.root):
        if path.name != "package.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        scripts = data.get("scripts")
        if not isinstance(scripts, dict):
            continue
        for hook in _LIFECYCLE_HOOKS:
            body = scripts.get(hook)
            if not isinstance(body, str) or not body:
                continue
            for tok in tokens:
                if _references(body, tok):
                    yield Finding(
                        severity=Severity.CRITICAL,
                        layer="lifecycle",
                        rule_id=RULE_ID,
                        title=f"npm lifecycle '{hook}' invokes Shai-Hulud payload filename",
                        evidence=f"{hook}: {body!r} (matches {tok})",
                        path=path,
                        reference=REF,
                        recommendation=(
                            "Remove the script entry, delete the referenced file, treat the host "
                            "as compromised, and rotate credentials."
                        ),
                        extra={"hook": hook, "matched_token": tok},
                    )
                    break


_BOUNDARY = re.compile(r"[\s'\"`;|&()<>]")


def _references(body: str, token: str) -> bool:
    if token not in body:
        return False
    # crude word-ish boundary check to avoid e.g. mybundle.js matching bundle.js
    idx = body.find(token)
    return not (
        idx > 0
        and not _BOUNDARY.match(body[idx - 1])
        and body[idx - 1] not in "/\\"
    )


def _walk(root: Path) -> Iterator[Path]:
    for p in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in p.parts):
            continue
        if p.is_file():
            yield p
