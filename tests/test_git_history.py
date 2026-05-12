from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from shai_hulud_audit.findings import ScanContext, Severity
from shai_hulud_audit.ioc.loader import default_ioc_dir, load
from shai_hulud_audit.scan import git_history


def _git(cwd: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@t")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "README.md").write_text("ok")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "init")
    return tmp_path


def test_finds_deleted_setup_bun_in_history(repo: Path):
    iocs = load(default_ioc_dir())
    bad = repo / "evil" / "setup_bun.js"
    bad.parent.mkdir(parents=True)
    bad.write_text("payload")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "add payload")
    bad.unlink()
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "remove payload")

    ctx = ScanContext(root=repo, ioc_dir=default_ioc_dir())
    findings = list(git_history.scan(ctx, iocs))
    assert any(
        f.severity == Severity.HIGH and "setup_bun.js" in f.title
        for f in findings
    )


def test_finds_shai_hulud_branch(repo: Path):
    iocs = load(default_ioc_dir())
    _git(repo, "checkout", "-q", "-b", "shai-hulud")
    _git(repo, "checkout", "-q", "main")
    ctx = ScanContext(root=repo, ioc_dir=default_ioc_dir())
    findings = list(git_history.scan(ctx, iocs))
    assert any(
        f.severity == Severity.CRITICAL and "shai-hulud" in f.title.lower()
        for f in findings
    )


def test_non_git_dir_yields_nothing(tmp_path: Path):
    iocs = load(default_ioc_dir())
    ctx = ScanContext(root=tmp_path, ioc_dir=default_ioc_dir())
    assert list(git_history.scan(ctx, iocs)) == []
