from __future__ import annotations

import json
from pathlib import Path

import pytest

from shai_hulud_audit.findings import ScanContext
from shai_hulud_audit.ioc.loader import default_ioc_dir, load


@pytest.fixture(scope="session")
def real_iocs():
    return load(default_ioc_dir())


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    return tmp_path


def make_ctx(root: Path, **kw) -> ScanContext:
    return ScanContext(root=root, ioc_dir=default_ioc_dir(), **kw)


@pytest.fixture
def ctx_factory():
    return make_ctx


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
