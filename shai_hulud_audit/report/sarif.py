"""SARIF 2.1.0 report writer (minimal subset)."""

from __future__ import annotations

import json
from collections.abc import Iterable

from ..findings import Finding, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

_RULES = [
    ("SHAI-001", "Lockfile pins compromised package"),
    ("SHAI-002", "Manifest references compromised package"),
    ("SHAI-003", "Installed package matches compromised version"),
    ("SHAI-004", "File hash matches known Shai-Hulud payload"),
    ("SHAI-005", "Known Shai-Hulud filename present"),
    ("SHAI-006", "Lifecycle script invokes Shai-Hulud payload"),
    ("SHAI-007", "Git history contains Shai-Hulud artifact"),
    ("SHAI-008", "GitHub account contains Shai-Hulud artifact"),
    ("SHAI-009", "Host persistence artifact present"),
]


def write(findings: Iterable[Finding], buf) -> None:
    findings = list(findings)
    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "note"),
            "message": {"text": f"{f.title}: {f.evidence}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(f.path) if f.path else ""},
                }
            }] if f.path else [],
            "properties": {
                "severity": f.severity.label,
                "layer": f.layer,
                "package": f.package,
                "version": f.version,
                "ecosystem": f.ecosystem,
                "reference": f.reference,
                "recommendation": f.recommendation,
            },
        })
    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "shai-hulud-audit",
                    "informationUri": "https://github.com/PQCWorld/shai_hulud_worm_audit",
                    "rules": [
                        {"id": rid, "shortDescription": {"text": title}}
                        for rid, title in _RULES
                    ],
                }
            },
            "results": results,
        }],
    }
    json.dump(sarif, buf, indent=2)
    buf.write("\n")
