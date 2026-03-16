"""Static demo export helpers.

Builds a self-contained JSON bundle for one baked snapshot and copies the
public frontend into a deployable directory that can run without the local
Python API.
"""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sqlite3
from typing import Any

from threatdle.db.repositories import get_snapshot
from threatdle.ingest.base import ensure_directory, now_utc_iso
from threatdle.services.game_api import get_game_day, get_game_pool, get_game_summary
from threatdle.services.review_export import list_review_days


def _require_exportable_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> sqlite3.Row:
    snapshot = get_snapshot(connection, snapshot_id)
    if snapshot is None:
        raise ValueError(f"Unknown snapshot {snapshot_id}")
    if snapshot["status"] != "ready":
        raise ValueError(f"Snapshot {snapshot_id} is not ready")
    baked_row = connection.execute(
        """
        SELECT COUNT(*) AS row_count
        FROM puzzle_day
        WHERE snapshot_id = ?
        """,
        (snapshot_id,),
    ).fetchone()
    if baked_row is None or int(baked_row["row_count"] or 0) == 0:
        raise ValueError(f"Snapshot {snapshot_id} has no baked puzzle_day rows")
    return snapshot


def _build_snapshot_record(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, Any]:
    row = connection.execute(
        """
        SELECT
            pd.snapshot_id,
            s.status,
            s.ready_at,
            COUNT(*) AS row_count,
            COUNT(DISTINCT pd.day_key) AS day_count,
            MIN(pd.day_key) AS first_day,
            MAX(pd.day_key) AS last_day
        FROM puzzle_day pd
        LEFT JOIN snapshots s ON s.snapshot_id = pd.snapshot_id
        WHERE pd.snapshot_id = ?
        GROUP BY pd.snapshot_id, s.status, s.ready_at
        """,
        (snapshot_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Snapshot {snapshot_id} has no baked puzzle_day rows")
    return {
        "snapshot_id": row["snapshot_id"],
        "status": row["status"],
        "ready_at": row["ready_at"],
        "row_count": int(row["row_count"] or 0),
        "day_count": int(row["day_count"] or 0),
        "first_day": row["first_day"],
        "last_day": row["last_day"],
    }


def _build_actor_compare_map(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT ac.answer_key, ap.clue_payload_json
        FROM actor_candidates_v1 ac
        JOIN actor_profiles_v1 ap ON ap.snapshot_id = ac.snapshot_id AND ap.actor_id = ac.actor_id
        WHERE ac.snapshot_id = ?
        ORDER BY ac.answer_key
        """,
        (snapshot_id,),
    ).fetchall()
    compare: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = json.loads(row["clue_payload_json"])
        counts = payload.get("counts") or {}
        compare[str(row["answer_key"])] = {
            "country_code": payload.get("country_code"),
            "first_observed_year": payload.get("first_observed_year"),
            "target_categories": list(payload.get("target_categories") or []),
            "motivation_tags": list(payload.get("motivation_tags") or []),
            "malware_count": int(counts.get("malware_count") or 0),
            "technique_count": int(counts.get("technique_count") or 0),
        }
    return compare


def _build_malware_compare_map(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT mc.answer_key, mp.clue_payload_json
        FROM malware_candidates_v1 mc
        JOIN malware_profiles_v1 mp ON mp.snapshot_id = mc.snapshot_id AND mp.malware_id = mc.malware_id
        WHERE mc.snapshot_id = ?
        ORDER BY mc.answer_key
        """,
        (snapshot_id,),
    ).fetchall()
    compare: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = json.loads(row["clue_payload_json"])
        compare[str(row["answer_key"])] = {
            "platforms": list(payload.get("platforms") or []),
            "aliases": list(payload.get("aliases") or []),
            "actor_names": list(payload.get("actor_names") or []),
        }
    return compare


def _build_technique_compare_map(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, dict[str, Any]]:
    rows = connection.execute(
        """
        SELECT tc.answer_key, tp.clue_payload_json
        FROM technique_candidates_v1 tc
        JOIN technique_profiles_v1 tp ON tp.snapshot_id = tc.snapshot_id AND tp.technique_id = tc.technique_id
        WHERE tc.snapshot_id = ?
        ORDER BY tc.answer_key
        """,
        (snapshot_id,),
    ).fetchall()
    compare: dict[str, dict[str, Any]] = {}
    for row in rows:
        payload = json.loads(row["clue_payload_json"])
        compare[str(row["answer_key"])] = {
            "tactics": list(payload.get("tactics") or []),
            "platforms": list(payload.get("platforms") or []),
            "is_subtechnique": bool(payload.get("is_subtechnique")),
            "parent_name": payload.get("parent_name"),
        }
    return compare


def build_static_demo_bundle(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, Any]:
    """Build a self-contained static demo bundle for one snapshot."""
    _require_exportable_snapshot(connection, snapshot_id)
    snapshot_record = _build_snapshot_record(connection, snapshot_id)
    day_rows = list_review_days(connection, snapshot_id)
    day_keys = [str(row["day_key"]) for row in day_rows]

    game_days: dict[str, dict[str, Any]] = {}
    pools: dict[str, dict[str, list[dict[str, Any]]]] = {}
    answers: dict[str, dict[str, dict[str, Any]]] = {}
    summaries: dict[str, dict[str, Any]] = {}

    for day_key in day_keys:
        game_day = get_game_day(connection, snapshot_id, day_key)
        if game_day is None:
            raise ValueError(f"Snapshot {snapshot_id} is missing game day data for {day_key}")
        game_days[day_key] = game_day
        pools[day_key] = {
            "actor": get_game_pool(connection, snapshot_id, day_key, "actor"),
            "malware": get_game_pool(connection, snapshot_id, day_key, "malware"),
            "technique": get_game_pool(connection, snapshot_id, day_key, "technique"),
        }
        summaries[day_key] = get_game_summary(connection, snapshot_id, day_key)
        answer_rows = connection.execute(
            """
            SELECT mode, answer_json
            FROM puzzle_day
            WHERE snapshot_id = ? AND day_key = ?
            ORDER BY mode
            """,
            (snapshot_id, day_key),
        ).fetchall()
        answers[day_key] = {
            str(row["mode"]): json.loads(row["answer_json"])
            for row in answer_rows
        }

    return {
        "exported_at": now_utc_iso(),
        "snapshot": snapshot_record,
        "snapshots": [snapshot_record],
        "days": day_rows,
        "game_days": game_days,
        "pools": pools,
        "answers": answers,
        "summaries": summaries,
        "compare": {
            "actor": _build_actor_compare_map(connection, snapshot_id),
            "malware": _build_malware_compare_map(connection, snapshot_id),
            "technique": _build_technique_compare_map(connection, snapshot_id),
        },
    }


def _patch_game_html_for_static_demo(html: str) -> str:
    marker = '<script src="/js/game.js" type="module"></script>'
    replacement = '<script src="/demo-config.js"></script>\n  <script src="/js/game.js" type="module"></script>'
    if marker not in html:
        raise ValueError("Could not locate game.js script tag in game.html")
    return html.replace(marker, replacement, 1)


def export_static_demo(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    out_dir: Path,
    public_dir: Path,
) -> dict[str, Any]:
    """Copy the public app and write one static demo bundle."""
    bundle = build_static_demo_bundle(connection, snapshot_id)
    out_dir = out_dir.resolve()
    public_dir = public_dir.resolve()

    ensure_directory(out_dir)
    shutil.copytree(public_dir, out_dir, dirs_exist_ok=True)
    ensure_directory(out_dir / "demo-data")
    (out_dir / "demo-data" / "static-demo.json").write_text(
        json.dumps(bundle, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    game_html = (public_dir / "game.html").read_text(encoding="utf-8")
    patched_game_html = _patch_game_html_for_static_demo(game_html)
    (out_dir / "game.html").write_text(patched_game_html, encoding="utf-8")
    (out_dir / "index.html").write_text(patched_game_html, encoding="utf-8")
    (out_dir / "demo-config.js").write_text(
        "window.THREATDLE_STATIC_DEMO_FILE = '/demo-data/static-demo.json';\n",
        encoding="utf-8",
    )
    (out_dir / "_redirects").write_text("/game /game.html 200\n", encoding="utf-8")

    bundle_path = out_dir / "demo-data" / "static-demo.json"
    return {
        "snapshot_id": snapshot_id,
        "out_dir": str(out_dir),
        "bundle_path": str(bundle_path),
        "bundle_size_bytes": bundle_path.stat().st_size,
        "day_count": int(bundle["snapshot"]["day_count"]),
        "row_count": int(bundle["snapshot"]["row_count"]),
    }
