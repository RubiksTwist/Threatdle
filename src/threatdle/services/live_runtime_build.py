"""Build a private live runtime bundle directly from source inputs.

This is intended for deploy-time builds, where the database and snapshot
artifacts are created fresh as part of the build instead of being committed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.db.repositories import mark_snapshot_failed, mark_snapshot_ready
from threatdle.ingest.attack_flow import ingest_attack_flow
from threatdle.ingest.attack_stix import ingest_attack_stix
from threatdle.ingest.emulation_plans import ingest_emulation_plans
from threatdle.ingest.fetch import fetch_sources
from threatdle.ingest.incident_overrides import ingest_incident_overrides
from threatdle.ingest.misp import ingest_misp_actors
from threatdle.ingest.overrides import ingest_overrides
from threatdle.services.game_api import DEFAULT_GAME_TIMEZONE, _day_key_in_timezone
from threatdle.services.live_runtime_export import export_live_runtime
from threatdle.services.puzzle_generator import generate_puzzle_range
from threatdle.services.puzzle_views import build_puzzle_tables


def default_live_start_day(
    timezone_name: str = DEFAULT_GAME_TIMEZONE,
    *,
    now: datetime | None = None,
    days: int = 365,
) -> str:
    if days <= 0:
        raise ValueError("days must be positive")
    current_day = datetime.fromisoformat(_day_key_in_timezone(timezone_name, now=now)).date()
    start_day = current_day - timedelta(days=days - 1)
    return start_day.isoformat()


def default_live_snapshot_id(
    timezone_name: str = DEFAULT_GAME_TIMEZONE,
    *,
    now: datetime | None = None,
    commit_ref: str | None = None,
) -> str:
    current = now or datetime.now(UTC)
    day_key = _day_key_in_timezone(timezone_name, now=current)
    suffix = (commit_ref or "local").strip().lower()[:7]
    if not suffix:
        suffix = "local"
    return f"{day_key}-live-{suffix}"


def build_live_runtime_from_sources(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    root_dir: Path | None = None,
    out_dir: Path,
    timezone_name: str = DEFAULT_GAME_TIMEZONE,
    start_day: str | None = None,
    days: int = 365,
    theme_mode: str = "prefer",
    chain_mode: str = "linked",
) -> dict[str, Any]:
    if days <= 0:
        raise ValueError("--days must be positive")

    resolved_start_day = start_day or default_live_start_day(timezone_name, days=days)
    fetch_result = fetch_sources(connection, snapshot_id, root_dir=root_dir)

    try:
        ingest_result = {
            "attack_stix": ingest_attack_stix(connection, snapshot_id),
            "overrides_initial": ingest_overrides(connection, snapshot_id, root_dir=root_dir),
            "misp": ingest_misp_actors(connection, snapshot_id),
            "overrides_final": ingest_overrides(connection, snapshot_id, root_dir=root_dir),
            "attack_flow": ingest_attack_flow(connection, snapshot_id),
            "emulation_plans": ingest_emulation_plans(connection, snapshot_id),
            "incident_overrides": ingest_incident_overrides(connection, snapshot_id, root_dir=root_dir),
            "puzzle_tables": build_puzzle_tables(connection, snapshot_id),
        }
        mark_snapshot_ready(connection, snapshot_id)
    except Exception:
        mark_snapshot_failed(connection, snapshot_id)
        raise

    generation_result = generate_puzzle_range(
        connection,
        snapshot_id,
        resolved_start_day,
        days,
        theme_mode=theme_mode,
        chain_mode=chain_mode,
        force=True,
    )
    export_result = export_live_runtime(
        connection,
        snapshot_id,
        out_dir=out_dir,
        timezone_name=timezone_name,
    )
    return {
        "snapshot_id": snapshot_id,
        "timezone": timezone_name,
        "start_day": resolved_start_day,
        "days": days,
        "theme_mode": theme_mode,
        "chain_mode": chain_mode,
        "fetch": fetch_result,
        "ingest": ingest_result,
        "generate": generation_result,
        "export": export_result,
    }
