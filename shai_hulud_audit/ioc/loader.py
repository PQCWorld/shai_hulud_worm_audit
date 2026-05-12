"""Load vendored IOC data into in-memory lookup tables."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class PackageIOC:
    ecosystem: str          # "npm" | "pypi"
    name: str
    version: str
    sources: tuple[str, ...] = ()

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name.lower(), self.version)


@dataclass(frozen=True)
class HashIOC:
    sha256: str
    filename_hint: str
    wave: str


@dataclass(frozen=True)
class FilenameIOC:
    name: str
    severity: str           # "critical" | "high" | "medium"
    wave: str
    note: str


@dataclass
class IOCSet:
    packages: dict[tuple[str, str, str], PackageIOC] = field(default_factory=dict)
    package_names: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    hashes: dict[str, HashIOC] = field(default_factory=dict)
    filenames: dict[str, FilenameIOC] = field(default_factory=dict)
    manifest: dict = field(default_factory=dict)

    def is_compromised(self, ecosystem: str, name: str, version: str) -> PackageIOC | None:
        return self.packages.get((ecosystem, name.lower(), version))

    def package_ever_compromised(self, ecosystem: str, name: str) -> set[str]:
        return self.package_names.get((ecosystem, name.lower()), set())

    @property
    def package_count(self) -> int:
        return len(self.packages)

    @property
    def hash_count(self) -> int:
        return len(self.hashes)

    @property
    def filename_count(self) -> int:
        return len(self.filenames)


def _strip_comment(line: str) -> str:
    return line.split("#", 1)[0].rstrip()


def _add_pkg(out: IOCSet, ecosystem: str, name: str, version: str, source: str) -> None:
    pkg = PackageIOC(ecosystem=ecosystem, name=name, version=version, sources=(source,))
    key = pkg.key
    existing = out.packages.get(key)
    if existing:
        merged_sources = tuple(sorted(set(existing.sources) | set(pkg.sources)))
        out.packages[key] = PackageIOC(
            ecosystem=existing.ecosystem,
            name=existing.name,
            version=existing.version,
            sources=merged_sources,
        )
    else:
        out.packages[key] = pkg
    out.package_names.setdefault((ecosystem, name.lower()), set()).add(version)


def _load_datadog_csv(path: Path, out: IOCSet, source_id: str) -> None:
    """Datadog CSV: package_name, package_versions (semicolon or comma list), [sources]."""
    with path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = (row.get("package_name") or "").strip()
            versions_field = (row.get("package_versions") or row.get("package_version") or "").strip()
            if not name or not versions_field:
                continue
            for v in _split_versions(versions_field):
                _add_pkg(out, "npm", name, v, source_id)


def _split_versions(field_value: str) -> list[str]:
    # Datadog CSVs have either a single version or a quoted list separated by
    # ", " or ";". Be liberal.
    candidates = []
    for piece in field_value.replace(";", ",").split(","):
        v = piece.strip().strip('"').strip("'")
        if v:
            candidates.append(v)
    return candidates


def _load_cobenian(path: Path, out: IOCSet, source_id: str) -> None:
    """Cobenian list: lines of '<eco>:<name>:<version>' or '<name>:<version>' (npm default)."""
    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = _strip_comment(raw).strip()
            if not line:
                continue
            parts = line.split(":")
            if len(parts) == 2:
                ecosystem, name, version = "npm", parts[0], parts[1]
            elif len(parts) >= 3:
                eco = parts[0].lower()
                if eco in ("npm", "pypi"):
                    ecosystem = eco
                    # rejoin remaining in case of scoped @name in middle
                    rest = ":".join(parts[1:])
                    if ":" not in rest:
                        continue
                    name, version = rest.rsplit(":", 1)
                else:
                    # treat whole line as bare npm 'name:version' with extra colons
                    ecosystem = "npm"
                    name, version = line.rsplit(":", 1)
            else:
                continue
            name = name.strip()
            version = version.strip()
            if not name or not version:
                continue
            _add_pkg(out, ecosystem, name, version, source_id)


def _load_hashes(path: Path, out: IOCSet) -> None:
    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = _strip_comment(raw).strip()
            if not line:
                continue
            parts = line.split()
            sha = parts[0].lower()
            hint = parts[1] if len(parts) > 1 else ""
            wave = parts[2] if len(parts) > 2 else ""
            if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
                out.hashes[sha] = HashIOC(sha256=sha, filename_hint=hint, wave=wave)


def _load_filenames(path: Path, out: IOCSet) -> None:
    with path.open(encoding="utf-8") as f:
        for raw in f:
            stripped = raw.rstrip("\n")
            if not stripped.strip() or stripped.lstrip().startswith("#"):
                continue
            # Whitespace-separated columns: name severity wave note...
            parts = stripped.split(maxsplit=3)
            if len(parts) < 3:
                continue
            name, severity, wave = parts[0], parts[1].lower(), parts[2]
            note = parts[3] if len(parts) == 4 else ""
            out.filenames[name] = FilenameIOC(
                name=name,
                severity=severity,
                wave=wave,
                note=note,
            )


def load(ioc_dir: Path) -> IOCSet:
    """Load all bundled IOC files from `ioc_dir`."""
    out = IOCSet()
    manifest_path = ioc_dir / "manifest.json"
    if manifest_path.exists():
        out.manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    for csv_name, source_id in (
        ("consolidated_iocs.csv", "datadog_consolidated"),
        ("shai-hulud-2.0.csv", "datadog_wave2"),
    ):
        p = ioc_dir / csv_name
        if p.exists():
            _load_datadog_csv(p, out, source_id)

    cobenian = ioc_dir / "compromised-packages.txt"
    if cobenian.exists():
        _load_cobenian(cobenian, out, "cobenian")

    hashes_p = ioc_dir / "hashes.txt"
    if hashes_p.exists():
        _load_hashes(hashes_p, out)

    filenames_p = ioc_dir / "filenames.txt"
    if filenames_p.exists():
        _load_filenames(filenames_p, out)

    return out


def default_ioc_dir() -> Path:
    return Path(__file__).parent / "data"
