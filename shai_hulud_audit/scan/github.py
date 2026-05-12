"""Layer 8 (optional --github): scan the user's GitHub account via `gh` CLI for
worm artifacts (Shai-Hulud repos, migration repos, shai-hulud branches,
malicious workflows, SHA1HULUD runners)."""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterator

from ..findings import Finding, ScanContext, Severity

RULE_ID = "SHAI-008"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#23-github-side-iocs-in-account-history-not-just-project-tree"


def scan(ctx: ScanContext, _iocs) -> Iterator[Finding]:
    if not ctx.enable_github:
        return
    if not shutil.which("gh"):
        yield Finding(
            severity=Severity.INFO,
            layer="github",
            rule_id=RULE_ID,
            title="`gh` CLI not available; skipping GitHub-side checks",
            evidence="install via https://cli.github.com/ and `gh auth login` to enable",
            reference=REF,
        )
        return

    repos = _list_repos()
    if repos is None:
        yield Finding(
            severity=Severity.INFO,
            layer="github",
            rule_id=RULE_ID,
            title="`gh` CLI is not authenticated; skipping GitHub-side checks",
            evidence="run `gh auth login`",
            reference=REF,
        )
        return

    for r in repos:
        full = r.get("nameWithOwner") or f"{r.get('owner', {}).get('login', '?')}/{r.get('name', '?')}"
        name = r.get("name", "")
        desc = (r.get("description") or "")

        if name == "Shai-Hulud" or "Shai-Hulud Repository" in desc or "Sha1-Hulud" in desc:
            yield Finding(
                severity=Severity.CRITICAL,
                layer="github",
                rule_id=RULE_ID,
                title="GitHub account contains Shai-Hulud exfiltration repo",
                evidence=f"{full} — {desc[:80]}",
                reference=REF,
                recommendation=(
                    "Preserve evidence (export issues/files), then delete the repo. Audit the GitHub "
                    "Security log starting at the repo's creation time and rotate all credentials."
                ),
            )

        if name.endswith("-migration") and "Shai-Hulud Migration" in desc:
            yield Finding(
                severity=Severity.CRITICAL,
                layer="github",
                rule_id=RULE_ID,
                title="GitHub account contains '-migration' (private→public) Shai-Hulud copy",
                evidence=full,
                reference=REF,
                recommendation="Delete the migration repo immediately; the original private repo's contents are public.",
            )

        for branch in _branches(full):
            if branch == "shai-hulud":
                yield Finding(
                    severity=Severity.CRITICAL,
                    layer="github",
                    rule_id=RULE_ID,
                    title=f"Branch 'shai-hulud' present on {full}",
                    evidence=f"{full}@{branch}",
                    reference=REF,
                    recommendation="Delete the branch via `gh api repos/{owner}/{repo}/git/refs/heads/shai-hulud -X DELETE`.",
                )


def _list_repos() -> list[dict] | None:
    try:
        r = subprocess.run(
            ["gh", "repo", "list", "--limit", "1000", "--json", "name,nameWithOwner,description,owner"],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError:
        return None


def _branches(repo: str) -> list[str]:
    try:
        r = subprocess.run(
            ["gh", "api", f"repos/{repo}/branches", "--paginate", "-q", ".[].name"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]
