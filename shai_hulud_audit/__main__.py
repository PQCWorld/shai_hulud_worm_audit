"""CLI entrypoint for `shai-hulud-audit`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .audit import run
from .findings import ScanContext, Severity
from .ioc.loader import default_ioc_dir, load
from .report import human, json_out, sarif


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="shai-hulud-audit",
        description="Audit a project for Shai-Hulud npm/PyPI supply-chain worm artifacts.",
    )
    p.add_argument("path", nargs="?", default=".", help="project directory to scan (default: .)")
    p.add_argument("--format", choices=("human", "json", "sarif"), default="human")
    p.add_argument("--output", "-o", help="write report to FILE (default: stdout)")
    p.add_argument("--ioc-dir", help="override the bundled IOC directory")
    p.add_argument("--update", action="store_true", help="refresh IOC lists from upstream and exit")
    p.add_argument("--offline", action="store_true", help="forbid any network access")
    p.add_argument("--no-git-history", action="store_true", help="skip git history scan")
    p.add_argument("--github", action="store_true", help="scan GitHub account via `gh` CLI")
    p.add_argument("--host", action="store_true", help="scan host for persistence artifacts")
    p.add_argument("--paranoid", action="store_true", help="enable extra heuristics")
    p.add_argument("--since", help="narrow git-history scan (YYYY-MM-DD)")
    p.add_argument(
        "--ecosystems",
        default="npm,pypi",
        help="comma-separated list of ecosystems to scan (default: npm,pypi)",
    )
    p.add_argument(
        "--fail-on",
        choices=("critical", "high", "medium", "low", "info"),
        default="high",
        help="exit non-zero if any finding at or above this severity is present",
    )
    p.add_argument("--version", action="version", version=f"shai-hulud-audit {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    ioc_dir = Path(args.ioc_dir) if args.ioc_dir else default_ioc_dir()

    if args.update:
        if args.offline:
            print("error: --update is incompatible with --offline", file=sys.stderr)
            return 10
        try:
            from .ioc.updater import refresh
        except ImportError:
            print("error: install the `update` extra: pip install shai-hulud-audit[update]", file=sys.stderr)
            return 10
        return refresh(ioc_dir)

    root = Path(args.path).resolve()
    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 10

    iocs = load(ioc_dir)
    ctx = ScanContext(
        root=root,
        ioc_dir=ioc_dir,
        enable_git_history=not args.no_git_history,
        enable_github=args.github,
        enable_host=args.host,
        paranoid=args.paranoid,
        ecosystems=tuple(e.strip() for e in args.ecosystems.split(",") if e.strip()),
        since=args.since,
    )

    findings = list(run(ctx, iocs))

    ioc_summary_str = (
        f"{iocs.package_count} packages, {iocs.hash_count} hashes, "
        f"{iocs.filename_count} filenames"
    )
    ioc_summary_obj = {
        "packages": iocs.package_count,
        "hashes": iocs.hash_count,
        "filenames": iocs.filename_count,
        "manifest": iocs.manifest,
    }

    from contextlib import nullcontext

    out_ctx = (
        open(args.output, "w", encoding="utf-8")  # noqa: SIM115
        if args.output
        else nullcontext(sys.stdout)
    )
    with out_ctx as out_stream:
        if args.format == "json":
            json_out.write(findings, out_stream, ioc_summary=ioc_summary_obj)
        elif args.format == "sarif":
            sarif.write(findings, out_stream)
        else:
            human.write(findings, out_stream, ioc_summary=ioc_summary_str)

    threshold = _severity_for(args.fail_on)
    if any(f.severity >= threshold for f in findings):
        return 1
    return 0


def _severity_for(name: str) -> Severity:
    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }[name]


if __name__ == "__main__":
    sys.exit(main())
