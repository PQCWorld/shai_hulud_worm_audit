"""Layer 7: git history scanner. Find historical IOC artifacts that have been
removed from the working tree but still live in the repo's git history."""

from __future__ import annotations

import subprocess
from collections.abc import Iterator
from pathlib import Path

from ..findings import Finding, ScanContext, Severity
from ..ioc.loader import IOCSet

RULE_ID = "SHAI-007"
REF = "https://github.com/PQCWorld/shai_hulud_worm_audit/blob/main/PLAN.md#33-detection-layers"


def scan(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    if not _is_git_repo(ctx.root):
        return
    filenames = sorted(iocs.filenames.keys())
    if not filenames:
        return

    # 1) git log --all -- <filename> for each malicious basename
    for name in filenames:
        commits = _commits_touching(ctx.root, name, ctx.since)
        if not commits:
            continue
        first = commits[0]
        last = commits[-1]
        severity = Severity.HIGH
        yield Finding(
            severity=severity,
            layer="git_history",
            rule_id=RULE_ID,
            title=f"Git history contains a Shai-Hulud filename ({name})",
            evidence=(
                f"{len(commits)} commit(s) touched **/{name}; "
                f"first {first[:12]}, last {last[:12]}"
            ),
            path=ctx.root,
            reference=REF,
            recommendation=(
                "Inspect the commit(s) with `git log --all -- <path>` and rotate every secret that "
                "was live in CI between the first and last timestamp."
            ),
            extra={"commits": commits[:20], "filename": name},
        )

    # 2) branches named exactly 'shai-hulud'
    for branch in _branches(ctx.root):
        if branch.endswith("/shai-hulud") or branch == "shai-hulud":
            yield Finding(
                severity=Severity.CRITICAL,
                layer="git_history",
                rule_id=RULE_ID,
                title="Repo contains a branch named 'shai-hulud'",
                evidence=f"branch: {branch}",
                path=ctx.root,
                reference=REF,
                recommendation=(
                    "Delete the branch locally (`git branch -D shai-hulud`) and remotely "
                    "(`git push origin --delete shai-hulud`). Audit the GitHub account audit log."
                ),
            )

    # 3) malicious workflow paths anywhere in history
    for path_ioc in (
        ".github/workflows/shai-hulud-workflow.yml",
        ".github/workflows/discussion.yaml",
    ):
        commits = _commits_for_path(ctx.root, path_ioc, ctx.since)
        if commits:
            yield Finding(
                severity=Severity.CRITICAL,
                layer="git_history",
                rule_id=RULE_ID,
                title=f"Git history shows malicious workflow file ({path_ioc})",
                evidence=f"{len(commits)} commit(s); first {commits[0][:12]}",
                path=ctx.root,
                reference=REF,
                recommendation=(
                    "Rewrite history to purge the file, force-push, then audit GH Actions logs "
                    "and rotate every secret the runner could read."
                ),
                extra={"commits": commits[:20], "workflow": path_ioc},
            )


def _is_git_repo(root: Path) -> bool:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return r.returncode == 0 and r.stdout.strip() == "true"
    except (OSError, subprocess.TimeoutExpired):
        return False


def _commits_touching(root: Path, basename: str, since: str | None) -> list[str]:
    """Return commit hashes that touched any path with this basename, across all refs."""
    cmd = [
        "git",
        "-C",
        str(root),
        "log",
        "--all",
        "--pretty=format:%H",
        "--diff-filter=A",
        "--",
        f"**/{basename}",
        basename,
    ]
    if since:
        cmd.insert(5, f"--since={since}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def _commits_for_path(root: Path, path: str, since: str | None) -> list[str]:
    cmd = [
        "git",
        "-C",
        str(root),
        "log",
        "--all",
        "--pretty=format:%H",
        "--",
        path,
    ]
    if since:
        cmd.insert(5, f"--since={since}")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]


def _branches(root: Path) -> list[str]:
    try:
        r = subprocess.run(
            ["git", "-C", str(root), "for-each-ref", "--format=%(refname:short)", "refs/heads/", "refs/remotes/"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.splitlines() if line.strip()]
