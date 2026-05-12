from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


def _run(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "shai_hulud_audit", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
    )


@pytest.fixture
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_clean_dir_exit_zero(project_root: Path, tmp_path: Path):
    (tmp_path / "package.json").write_text('{"name":"x","dependencies":{"react":"^18"}}')
    r = _run(["--no-git-history", str(tmp_path)], cwd=project_root)
    assert r.returncode == 0, r.stderr + r.stdout


def test_compromised_lockfile_exit_one(project_root: Path, tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/@ctrl/tinycolor": {"name": "@ctrl/tinycolor", "version": "4.1.2"}},
    }))
    r = _run(["--no-git-history", str(tmp_path)], cwd=project_root)
    assert r.returncode == 1, r.stderr + r.stdout
    assert "CRITICAL" in r.stdout or "Verdict" in r.stdout


def test_json_format(project_root: Path, tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/@ctrl/tinycolor": {"name": "@ctrl/tinycolor", "version": "4.1.2"}},
    }))
    r = _run(["--no-git-history", "--format", "json", str(tmp_path)], cwd=project_root)
    payload = json.loads(r.stdout)
    assert payload["summary"]["by_severity"]["CRITICAL"] >= 1


def test_sarif_format_parses(project_root: Path, tmp_path: Path):
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/@ctrl/tinycolor": {"name": "@ctrl/tinycolor", "version": "4.1.2"}},
    }))
    r = _run(["--no-git-history", "--format", "sarif", str(tmp_path)], cwd=project_root)
    sarif = json.loads(r.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"]
