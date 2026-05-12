"""Layer 9 (optional --host): scan the developer machine for persistence and
artifacts left behind by the worm."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity

RULE_ID = "SHAI-009"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#24-network--host-iocs"


def scan(ctx: ScanContext, _iocs) -> Iterator[Finding]:
    if not ctx.enable_host:
        return
    home = Path(os.path.expanduser("~"))

    candidates: list[tuple[Path, Severity, str]] = [
        (home / "Library" / "LaunchAgents" / "com.user.gh-token-monitor.plist",
         Severity.CRITICAL, "macOS LaunchAgent persistence (gh-token-monitor)"),
        (home / ".config" / "systemd" / "user" / "gh-token-monitor.service",
         Severity.CRITICAL, "Linux systemd user persistence (gh-token-monitor)"),
        (Path("/etc/systemd/system/gh-token-monitor.service"),
         Severity.CRITICAL, "Linux systemd system persistence (gh-token-monitor)"),
    ]
    for path, severity, label in candidates:
        if path.exists():
            yield Finding(
                severity=severity,
                layer="host",
                rule_id=RULE_ID,
                title=f"Persistence artifact found: {label}",
                evidence=str(path),
                path=path,
                reference=REF,
                recommendation=(
                    "Disable and delete the service immediately. macOS: `launchctl unload <plist>`, "
                    "Linux: `systemctl --user disable --now gh-token-monitor`. Treat host as compromised."
                ),
            )

    # ~/.bun on a host you don't intentionally use — INFO only (Bun is legit too).
    bun = home / ".bun"
    if bun.exists():
        yield Finding(
            severity=Severity.INFO,
            layer="host",
            rule_id=RULE_ID,
            title="Bun runtime installed under ~/.bun",
            evidence=str(bun),
            path=bun,
            reference=REF,
            recommendation=(
                "Bun is legitimate — but if you never installed it yourself, this may be a Shai-Hulud "
                "2.0 leftover. Verify install provenance."
            ),
        )

    # .npmrc with a token outside the user's home (highly suspicious in CI)
    npmrc = home / ".npmrc"
    if npmrc.exists():
        try:
            text = npmrc.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        if "_authToken" in text or "authToken" in text.lower():
            yield Finding(
                severity=Severity.INFO,
                layer="host",
                rule_id=RULE_ID,
                title="~/.npmrc contains an authToken",
                evidence=str(npmrc),
                path=npmrc,
                reference=REF,
                recommendation=(
                    "Inventory: confirm you authored this token. Rotate proactively if your repo "
                    "had any other Shai-Hulud finding."
                ),
            )
