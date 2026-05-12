from __future__ import annotations

import hashlib
import json

from shai_hulud_audit.findings import ScanContext, Severity
from shai_hulud_audit.ioc.loader import default_ioc_dir, load
from shai_hulud_audit.scan import filenames, hashes, lifecycle


def _ctx(root):
    return ScanContext(root=root, ioc_dir=default_ioc_dir())


def test_hash_match_critical(tmp_path):
    iocs = load(default_ioc_dir())
    target_hash = next(iter(iocs.hashes.keys()))
    # Generate content whose sha256 we deliberately do NOT have — instead, place
    # a known-hash placeholder by writing a synthetic file and asserting via
    # a monkeypatched IOC. Easier: write content and add its hash to a temp IOC.
    path = tmp_path / "payload.js"
    path.write_bytes(b"x" * 4096)
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    # Inject the actual hash into the loaded IOC set in-memory.
    from shai_hulud_audit.ioc.loader import HashIOC

    iocs.hashes[actual] = HashIOC(sha256=actual, filename_hint="payload.js", wave="test")
    findings = list(hashes.scan(_ctx(tmp_path), iocs))
    assert any(f.severity == Severity.CRITICAL and f.layer == "hash" for f in findings)
    del target_hash


def test_filename_critical_for_setup_bun(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "node_modules" / "evil").mkdir(parents=True)
    (tmp_path / "node_modules" / "evil" / "setup_bun.js").write_text("x")
    findings = list(filenames.scan(_ctx(tmp_path), iocs))
    assert any(f.severity == Severity.CRITICAL and "setup_bun.js" in f.title for f in findings)


def test_bare_bundle_js_is_downgraded(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "bundle.js").write_text("// just a webpack output\n")
    findings = list(filenames.scan(_ctx(tmp_path), iocs))
    matches = [f for f in findings if "bundle.js" in f.title]
    assert matches and all(f.severity == Severity.MEDIUM for f in matches)


def test_lifecycle_script_critical(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "x",
            "scripts": {"postinstall": "node bundle.js"},
        }),
        encoding="utf-8",
    )
    findings = list(lifecycle.scan(_ctx(tmp_path), iocs))
    assert any(
        f.severity == Severity.CRITICAL and f.layer == "lifecycle"
        and "postinstall" in f.title
        for f in findings
    )


def test_lifecycle_clean_script_no_finding(tmp_path):
    iocs = load(default_ioc_dir())
    (tmp_path / "package.json").write_text(
        json.dumps({
            "name": "x",
            "scripts": {"postinstall": "node ./dist/cli.js"},
        }),
        encoding="utf-8",
    )
    findings = list(lifecycle.scan(_ctx(tmp_path), iocs))
    assert findings == []
