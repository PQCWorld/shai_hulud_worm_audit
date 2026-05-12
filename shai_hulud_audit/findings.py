"""Finding and severity model shared across scanners and reporters."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name


SEVERITY_BY_NAME = {s.name.lower(): s for s in Severity}


@dataclass
class Finding:
    """A single audit finding."""

    severity: Severity
    layer: str               # e.g. "lockfile", "hash", "git_history"
    rule_id: str             # e.g. "SHAI-001"
    title: str
    evidence: str            # short, single-line evidence string
    path: Path | None = None
    package: str | None = None
    version: str | None = None
    ecosystem: str | None = None     # "npm" | "pypi"
    reference: str | None = None     # url to a writeup
    recommendation: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.label,
            "layer": self.layer,
            "rule_id": self.rule_id,
            "title": self.title,
            "evidence": self.evidence,
            "path": str(self.path) if self.path else None,
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "reference": self.reference,
            "recommendation": self.recommendation,
            "extra": self.extra,
        }


@dataclass
class ScanContext:
    root: Path
    ioc_dir: Path
    enable_git_history: bool = True
    enable_host: bool = False
    enable_github: bool = False
    paranoid: bool = False
    ecosystems: tuple[str, ...] = ("npm", "pypi")
    since: str | None = None       # YYYY-MM-DD for git history
