"""Review data export from puzzle_day.

Reads baked puzzle_day rows and formats them for the review viewer.
Does not re-run generation logic — shows exactly what was persisted.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any


def list_review_snapshots(connection: sqlite3.Connection) -> list[dict[str, Any]]:
    """List snapshots that have puzzle_day rows."""
    rows = connection.execute(
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
        GROUP BY pd.snapshot_id
        ORDER BY pd.snapshot_id DESC
        """
    ).fetchall()
    return [
        {
            "snapshot_id": row["snapshot_id"],
            "status": row["status"],
            "ready_at": row["ready_at"],
            "row_count": row["row_count"],
            "day_count": row["day_count"],
            "first_day": row["first_day"],
            "last_day": row["last_day"],
        }
        for row in rows
    ]


def list_review_days(
    connection: sqlite3.Connection,
    snapshot_id: str,
) -> list[dict[str, Any]]:
    """List day_keys for a snapshot."""
    rows = connection.execute(
        """
        SELECT day_key, COUNT(*) AS mode_count
        FROM puzzle_day
        WHERE snapshot_id = ?
        GROUP BY day_key
        ORDER BY day_key
        """,
        (snapshot_id,),
    ).fetchall()
    return [
        {
            "day_key": row["day_key"],
            "mode_count": row["mode_count"],
        }
        for row in rows
    ]


def _infer_theme(
    connection: sqlite3.Connection,
    modes: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Infer theming from baked puzzle_day data.

    Checks whether the actor answer is cross-linked to the other
    published modes by examining answer_json contents and relationship
    tables.
    """
    actor_answer = modes.get("actor", {}).get("answer", {})
    actor_key = actor_answer.get("answer_key")
    actor_label = actor_answer.get("answer_label")
    if actor_answer.get("chain_mode") == "exact":
        return {
            "themed": True,
            "anchor": (
                {"answer_key": actor_key, "answer_label": actor_label}
                if actor_key
                else None
            ),
            "connected_modes": list(modes),
            "fallback_modes": [],
        }

    if not actor_key:
        return {
            "themed": False,
            "anchor": None,
            "connected_modes": [],
            "fallback_modes": ["actor", "malware", "technique"],
        }

    connected: list[str] = ["actor"]
    fallback: list[str] = []

    # Malware: actor label appears in comparison.actor_names
    malware_answer = modes.get("malware", {}).get("answer", {})
    malware_actors = malware_answer.get("comparison", {}).get("actor_names", [])
    if actor_label and actor_label in malware_actors:
        connected.append("malware")
    else:
        fallback.append("malware")

    # Technique: query relationship tables for actor-technique link
    technique_answer = modes.get("technique", {}).get("answer", {})
    technique_key = technique_answer.get("answer_key")
    if technique_key:
        linked = connection.execute(
            """
            SELECT 1
            FROM actor_techniques at_rel
            JOIN actors a ON a.actor_id = at_rel.actor_id
            JOIN techniques t ON t.technique_id = at_rel.technique_id
            WHERE a.attack_group_id = ? AND t.attack_id = ?
            LIMIT 1
            """,
            (actor_key, technique_key),
        ).fetchone()
        if linked:
            connected.append("technique")
        else:
            fallback.append("technique")
    else:
        fallback.append("technique")

    themed = len(connected) >= 3
    return {
        "themed": themed,
        "anchor": (
            {"answer_key": actor_key, "answer_label": actor_label}
            if themed
            else None
        ),
        "connected_modes": connected if themed else [],
        "fallback_modes": (
            fallback
            if themed
            else ["actor", "malware", "technique"]
        ),
    }


def get_review_day(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
) -> dict[str, Any] | None:
    """Get full review data for one day.

    Returns payload (player-visible clues) and answer (hidden) for each
    mode, plus inferred theme status and malware summary tier.
    """
    rows = connection.execute(
        """
        SELECT mode, payload_json, answer_json, created_at
        FROM puzzle_day
        WHERE snapshot_id = ? AND day_key = ?
        ORDER BY mode
        """,
        (snapshot_id, day_key),
    ).fetchall()

    if not rows:
        return None

    modes: dict[str, dict[str, Any]] = {}
    for row in rows:
        modes[row["mode"]] = {
            "payload": json.loads(row["payload_json"]),
            "answer": json.loads(row["answer_json"]),
            "created_at": row["created_at"],
        }

    # Attach summary_tier for malware from candidate table
    malware_answer = modes.get("malware", {}).get("answer", {})
    malware_key = malware_answer.get("answer_key")
    if malware_key:
        tier_row = connection.execute(
            """
            SELECT summary_tier
            FROM malware_candidates_v1
            WHERE snapshot_id = ? AND answer_key = ?
            LIMIT 1
            """,
            (snapshot_id, malware_key),
        ).fetchone()
        if tier_row:
            modes["malware"]["summary_tier"] = tier_row["summary_tier"]

    theme_info = _infer_theme(connection, modes)

    return {
        "snapshot_id": snapshot_id,
        "day_key": day_key,
        "theme": theme_info,
        "modes": modes,
    }
