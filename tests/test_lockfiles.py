from __future__ import annotations

import json

from shai_hulud_audit.findings import ScanContext, Severity
from shai_hulud_audit.ioc.loader import default_ioc_dir, load
from shai_hulud_audit.scan import lockfiles


def _ctx(root):
    return ScanContext(root=root, ioc_dir=default_ioc_dir())


def test_npm_v3_lockfile_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package-lock.json").write_text(
        json.dumps({
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/@ctrl/tinycolor": {
                    "name": "@ctrl/tinycolor",
                    "version": "4.1.2",
                },
                "node_modules/react": {"name": "react", "version": "18.2.0"},
            },
        }, indent=2),
        encoding="utf-8",
    )
    findings = list(lockfiles.scan(_ctx(tmp_path), iocs))
    assert any(
        f.package == "@ctrl/tinycolor" and f.version == "4.1.2"
        and f.severity == Severity.CRITICAL
        for f in findings
    )


def test_npm_v1_nested_dep_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package-lock.json").write_text(
        json.dumps({
            "name": "demo",
            "lockfileVersion": 1,
            "dependencies": {
                "transitive": {
                    "version": "1.0.0",
                    "dependencies": {
                        "@ctrl/tinycolor": {"version": "4.1.1"},
                    },
                },
            },
        }, indent=2),
        encoding="utf-8",
    )
    findings = list(lockfiles.scan(_ctx(tmp_path), iocs))
    assert any(f.package == "@ctrl/tinycolor" and f.version == "4.1.1" for f in findings)


def test_yarn_lock_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "yarn.lock").write_text(
        '''
"@ctrl/tinycolor@^4.1.0", "@ctrl/tinycolor@4.1.2":
  version "4.1.2"
  resolved "https://registry.yarnpkg.com/@ctrl/tinycolor/-/tinycolor-4.1.2.tgz"
'''.lstrip(),
        encoding="utf-8",
    )
    findings = list(lockfiles.scan(_ctx(tmp_path), iocs))
    assert any(f.package == "@ctrl/tinycolor" and f.version == "4.1.2" for f in findings)


def test_pnpm_lock_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "pnpm-lock.yaml").write_text(
        '''
lockfileVersion: '6.0'
packages:
  /@ctrl/tinycolor@4.1.2:
    resolution: {integrity: sha512-FAKE==}
    engines: {node: '>=12'}
'''.lstrip(),
        encoding="utf-8",
    )
    findings = list(lockfiles.scan(_ctx(tmp_path), iocs))
    assert any(f.package == "@ctrl/tinycolor" and f.version == "4.1.2" for f in findings)


def test_requirements_txt_pypi_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "requirements.txt").write_text(
        "requests==2.31.0\nmistralai==2.4.6  # bad\nrich==13.7.0\n",
        encoding="utf-8",
    )
    findings = list(lockfiles.scan(_ctx(tmp_path), iocs))
    assert any(
        f.package == "mistralai" and f.version == "2.4.6" and f.ecosystem == "pypi"
        for f in findings
    )


def test_pipfile_lock_detected(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "Pipfile.lock").write_text(
        json.dumps({
            "default": {
                "mistralai": {"version": "==2.4.6", "hashes": []},
                "rich": {"version": "==13.7.0"},
            },
            "develop": {},
        }),
        encoding="utf-8",
    )
    findings = list(lockfiles.scan(_ctx(tmp_path), iocs))
    assert any(f.package == "mistralai" for f in findings)


def test_clean_project_no_findings(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package-lock.json").write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/react": {"name": "react", "version": "18.2.0"},
            },
        }),
        encoding="utf-8",
    )
    assert list(lockfiles.scan(_ctx(tmp_path), iocs)) == []
