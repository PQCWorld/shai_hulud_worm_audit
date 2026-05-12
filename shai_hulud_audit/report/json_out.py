"""JSON report writer."""

from __future__ import annotations

import json
from collections.abc import Iterable

from ..findings import Finding


def write(findings: Iterable[Finding], buf, *, ioc_summary: dict | None = None) -> None:
    findings = list(findings)
    out = {
        "schema_version": 1,
        "tool": "shai-hulud-audit",
        "summary": {
            "total": len(findings),
            "by_severity": {
                "CRITICAL": sum(1 for f in findings if f.severity.label == "CRITICAL"),
                "HIGH": sum(1 for f in findings if f.severity.label == "HIGH"),
                "MEDIUM": sum(1 for f in findings if f.severity.label == "MEDIUM"),
                "LOW": sum(1 for f in findings if f.severity.label == "LOW"),
                "INFO": sum(1 for f in findings if f.severity.label == "INFO"),
            },
        },
        "ioc": ioc_summary or {},
        "findings": [f.to_dict() for f in findings],
    }
    json.dump(out, buf, indent=2, sort_keys=False)
    buf.write("\n")
