"""Top-level audit orchestrator: runs every enabled scan layer and yields findings."""

from __future__ import annotations

from collections.abc import Iterator

from .findings import Finding, ScanContext
from .ioc.loader import IOCSet
from .scan import (
    filenames,
    git_history,
    github,
    hashes,
    host,
    installed,
    lifecycle,
    lockfiles,
    manifests,
)


def run(ctx: ScanContext, iocs: IOCSet) -> Iterator[Finding]:
    yield from lockfiles.scan(ctx, iocs)
    yield from manifests.scan(ctx, iocs)
    yield from installed.scan(ctx, iocs)
    yield from hashes.scan(ctx, iocs)
    yield from filenames.scan(ctx, iocs)
    yield from lifecycle.scan(ctx, iocs)
    if ctx.enable_git_history:
        yield from git_history.scan(ctx, iocs)
    if ctx.enable_github:
        yield from github.scan(ctx, iocs)
    if ctx.enable_host:
        yield from host.scan(ctx, iocs)
