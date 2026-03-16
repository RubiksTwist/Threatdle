"""Private runtime bundle export for live Netlify gameplay.

Unlike the static demo export, this bundle is intended to be shipped only with
server-side functions. It contains hidden answers and comparison payloads that
must never be published as static site assets.
"""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.ingest.base import ensure_directory, now_utc_iso
from threatdle.services.game_api import DEFAULT_GAME_TIMEZONE
from threatdle.services.static_demo_export import build_static_demo_bundle


def build_live_runtime_bundle(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    timezone_name: str = DEFAULT_GAME_TIMEZONE,
) -> dict[str, Any]:
    bundle = build_static_demo_bundle(connection, snapshot_id)
    bundle["exported_at"] = now_utc_iso()
    bundle["generated_for"] = "live_runtime"
    bundle["runtime_api_version"] = 1
    bundle["timezone"] = timezone_name
    return bundle


def export_live_runtime(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    out_dir: Path,
    timezone_name: str = DEFAULT_GAME_TIMEZONE,
) -> dict[str, Any]:
    bundle = build_live_runtime_bundle(connection, snapshot_id, timezone_name=timezone_name)
    out_dir = ensure_directory(out_dir.resolve())
    bundle_path = out_dir / "game-data.json"
    bundle_path.write_text(
        json.dumps(bundle, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return {
        "snapshot_id": snapshot_id,
        "timezone": timezone_name,
        "out_dir": str(out_dir),
        "bundle_path": str(bundle_path),
        "bundle_size_bytes": bundle_path.stat().st_size,
        "day_count": int(bundle["snapshot"]["day_count"]),
        "row_count": int(bundle["snapshot"]["row_count"]),
    }
