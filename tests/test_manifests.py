from __future__ import annotations

import json

from shai_hulud_audit.findings import ScanContext, Severity
from shai_hulud_audit.ioc.loader import default_ioc_dir, load
from shai_hulud_audit.scan import manifests


def _ctx(root):
    return ScanContext(root=root, ioc_dir=default_ioc_dir())


def test_exact_pin_in_package_json_is_critical(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "x",
            "dependencies": {"@ctrl/tinycolor": "4.1.2"},
        }),
        encoding="utf-8",
    )
    findings = list(manifests.scan(_ctx(tmp_path), iocs))
    assert any(f.severity == Severity.CRITICAL and f.package == "@ctrl/tinycolor" for f in findings)


def test_range_spec_yields_medium(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "x",
            "dependencies": {"@ctrl/tinycolor": "^4.1.0"},
        }),
        encoding="utf-8",
    )
    findings = list(manifests.scan(_ctx(tmp_path), iocs))
    assert any(f.severity == Severity.MEDIUM and f.package == "@ctrl/tinycolor" for f in findings)


def test_pyproject_pin_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "pyproject.toml").write_text(
        '''
[project]
name = "x"
dependencies = ["mistralai==2.4.6", "requests==2.31.0"]
'''.strip(),
        encoding="utf-8",
    )
    findings = list(manifests.scan(_ctx(tmp_path), iocs))
    assert any(f.severity == Severity.CRITICAL and f.package == "mistralai" for f in findings)
