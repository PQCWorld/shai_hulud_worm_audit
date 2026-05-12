"""IOC list refresher. Pulls upstream sources listed in manifest.json,
validates them, writes new snapshots, and updates the manifest with fetched-at
timestamps + sha256s."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    requests = None  # type: ignore[assignment]

_MAX_BYTES = 16 * 1024 * 1024  # refuse anything > 16 MB


def refresh(ioc_dir: Path) -> int:
    manifest_path = ioc_dir / "manifest.json"
    if not manifest_path.exists():
        print(f"error: no manifest at {manifest_path}", file=sys.stderr)
        return 10
    if requests is None:
        print("error: `requests` is required for --update (pip install shai-hulud-audit[update])", file=sys.stderr)
        return 10

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    sources = manifest.get("sources", [])
    if not sources:
        print("error: manifest has no sources", file=sys.stderr)
        return 10

    updated_any = False
    for src in sources:
        url = src.get("url")
        local = src.get("local")
        if not url or not local:
            continue
        local_path = ioc_dir / local
        print(f"fetching {src['id']} <- {url}", file=sys.stderr)
        try:
            content = _fetch(url)
        except Exception as e:  # noqa: BLE001
            print(f"  ! failed: {e}", file=sys.stderr)
            continue
        if not _sane(content, local):
            print(f"  ! refused (failed sanity check): {url}", file=sys.stderr)
            continue
        old = local_path.read_bytes() if local_path.exists() else b""
        if old == content:
            print(f"  = unchanged ({len(content)} bytes)", file=sys.stderr)
            src["fetched_at"] = _now()
            continue
        local_path.write_bytes(content)
        src["fetched_at"] = _now()
        src["sha256"] = hashlib.sha256(content).hexdigest()
        src["bytes"] = len(content)
        updated_any = True
        print(f"  + updated ({len(content)} bytes)", file=sys.stderr)

    manifest["generated_at"] = _now()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("manifest updated." if updated_any else "no upstream changes.", file=sys.stderr)
    return 0


def _fetch(url: str) -> bytes:
    r = requests.get(url, timeout=60, stream=True)
    r.raise_for_status()
    buf = bytearray()
    for chunk in r.iter_content(chunk_size=64 * 1024):
        buf.extend(chunk)
        if len(buf) > _MAX_BYTES:
            raise ValueError("upstream payload exceeds 16 MB cap")
    return bytes(buf)


def _sane(content: bytes, local_name: str) -> bool:
    if not content or len(content) < 32:
        return False
    if local_name.endswith(".csv"):
        first_line = content.split(b"\n", 1)[0].decode("utf-8", errors="replace").lower()
        return "package" in first_line
    if local_name.endswith(".txt"):
        return content[0:1] in (b"#", b"@") or b":" in content[:512]
    return True


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
