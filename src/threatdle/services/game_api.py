"""Game API services for serving puzzle data to the player.

Reads from the puzzle_day and candidate tables to serve the player UI.
"""

from __future__ import annotations

from datetime import UTC, datetime
import json
import random
import sqlite3
from typing import Any
from zoneinfo import ZoneInfo

from threatdle.services.puzzle_generator import _parse_day_key
from threatdle.services.game_engine import score_guess
from threatdle.normalize.text import redact_names_from_text


DEFAULT_GAME_TIMEZONE = "America/New_York"


def _day_key_in_timezone(timezone_name: str, *, now: datetime | None = None) -> str:
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    return current.astimezone(ZoneInfo(timezone_name)).date().isoformat()


def _select_game_snapshot(connection: sqlite3.Connection, snapshot_id: str | None) -> sqlite3.Row:
    if snapshot_id:
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
        return row

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
        GROUP BY pd.snapshot_id, s.status, s.ready_at
        ORDER BY
            CASE WHEN s.status = 'ready' THEN 0 ELSE 1 END,
            COALESCE(s.ready_at, '') DESC,
            pd.snapshot_id DESC
        LIMIT 1
        """
    ).fetchone()
    if row is None:
        raise ValueError("No snapshots available")
    return row


def get_game_today(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str | None = None,
    day_key: str | None = None,
    timezone_name: str = DEFAULT_GAME_TIMEZONE,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Resolve the active published game day using server time."""
    snapshot = _select_game_snapshot(connection, snapshot_id)
    resolved_snapshot_id = str(snapshot["snapshot_id"])
    server_day_key = _day_key_in_timezone(timezone_name, now=now)

    day_rows = connection.execute(
        """
        SELECT day_key
        FROM puzzle_day
        WHERE snapshot_id = ?
        GROUP BY day_key
        ORDER BY day_key DESC
        """,
        (resolved_snapshot_id,),
    ).fetchall()
    all_day_keys = [str(row["day_key"]) for row in day_rows]
    if not all_day_keys:
        raise ValueError(f"Snapshot {resolved_snapshot_id} has no puzzle days")

    available_days = [value for value in all_day_keys if value <= server_day_key]
    if not available_days:
        available_days = list(all_day_keys)

    latest_day = available_days[0]
    selected_day = latest_day
    if day_key and day_key in available_days:
        selected_day = day_key

    return {
        "snapshot_id": resolved_snapshot_id,
        "timezone": timezone_name,
        "server_day_key": server_day_key,
        "day_key": selected_day,
        "latest_day": latest_day,
        "available_days": available_days,
    }


def _shuffle_timeline_steps(snapshot_id: str, day_key: str, steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(steps) <= 1:
        return [dict(step) for step in steps]
    shuffled = [dict(step) for step in steps]
    rng = random.Random(f"{snapshot_id}:{day_key}:timeline-scramble")
    rng.shuffle(shuffled)
    if all(
        shuffled[index].get("attack_id") == steps[index].get("attack_id")
        for index in range(len(steps))
    ):
        shuffled = shuffled[1:] + shuffled[:1]
    return shuffled


def _timeline_steps_from_answer(answer: dict[str, Any]) -> list[dict[str, Any]]:
    steps = list(answer.get("comparison", {}).get("steps") or [])
    canonical_steps: list[dict[str, Any]] = []
    for index, step in enumerate(steps, start=1):
        canonical_steps.append(
            {
                "step_index": int(step.get("step_index") or index),
                "attack_id": str(step.get("attack_id") or ""),
                "technique_name": str(step.get("technique_name") or step.get("attack_id") or ""),
            }
        )
    return canonical_steps


def get_game_day(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
) -> dict[str, Any] | None:
    """Get the player-visible puzzle data for one day.
    
    Returns ONLY the payload (clues). Strip all answer_key, answer_json, 
    theme anchors, and other review data.
    """
    rows = connection.execute(
        """
        SELECT mode, payload_json, answer_json
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
        payload = json.loads(row["payload_json"])
        answer = json.loads(row["answer_json"])

        # Redact the malware name and aliases from its capability summary
        if row["mode"] == "malware":
            names_to_redact = []
            if answer.get("answer_label"):
                names_to_redact.append(answer["answer_label"])
            
            aliases = answer.get("comparison", {}).get("aliases", [])
            names_to_redact.extend(aliases)
            
            platforms = answer.get("comparison", {}).get("platforms", [])
            names_to_redact.extend(platforms)
            
            summary = payload.get("clues", {}).get("capability_summary")
            if summary and names_to_redact:
                redacted_summary = redact_names_from_text(summary, names_to_redact, "[CLASSIFIED]")
                payload["clues"]["capability_summary"] = redacted_summary
                
            if "aliases" in payload.get("clues", {}):
                del payload["clues"]["aliases"]

        if row["mode"] == "timeline":
            clues = payload.setdefault("clues", {})
            canonical_steps = _timeline_steps_from_answer(answer)
            if canonical_steps:
                clues["steps"] = canonical_steps
                clues["scrambled_steps"] = _shuffle_timeline_steps(snapshot_id, day_key, canonical_steps)
            clues.setdefault("ordering_basis", "Arrange the techniques in the source-reported execution order.")

        modes[row["mode"]] = {
            "payload": payload,
        }

    return {
        "snapshot_id": snapshot_id,
        "day_key": day_key,
        "modes": modes,
    }


def get_game_pool(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    mode: str,
) -> list[dict[str, Any]]:
    """Get exactly 5 valid choices for the game UI (1 correct, 4 incorrect)."""
    
    # First, get the true answer
    _parse_day_key(day_key)
    puzzle_row = connection.execute(
        """
        SELECT answer_json
        FROM puzzle_day
        WHERE snapshot_id = ? AND day_key = ? AND mode = ?
        """,
        (snapshot_id, day_key, mode),
    ).fetchone()

    if not puzzle_row:
        raise ValueError(f"No puzzle found for {day_key} mode {mode}")

    answer_json = json.loads(puzzle_row["answer_json"])
    true_answer_key = answer_json.get("answer_key")

    if mode == "actor":
        rows = connection.execute(
            """
            SELECT answer_key, answer_label 
            FROM actor_candidates_v1 
            WHERE snapshot_id = ? 
            ORDER BY answer_label
            """,
            (snapshot_id,)
        ).fetchall()
    elif mode == "malware":
        rows = connection.execute(
            """
            SELECT answer_key, answer_label 
            FROM malware_candidates_v1 
            WHERE snapshot_id = ? 
            ORDER BY answer_label
            """,
            (snapshot_id,)
        ).fetchall()
    elif mode == "technique":
        rows = connection.execute(
            """
            SELECT answer_key, answer_label 
            FROM technique_candidates_v1 
            WHERE snapshot_id = ? 
            ORDER BY answer_label
            """,
            (snapshot_id,)
        ).fetchall()
    elif mode == "timeline":
        return []
    else:
        raise ValueError(f"Unknown mode: {mode}")

    all_candidates = [
        {"guess_key": row["answer_key"], "guess_label": row["answer_label"]}
        for row in rows
    ]

    # Find the correct answer
    correct_candidate = next((c for c in all_candidates if c["guess_key"] == true_answer_key), None)
    if not correct_candidate:
        raise ValueError(f"True answer {true_answer_key} not found in pool")

    # Filter out the correct answer to form the decoy pool
    decoy_pool = [c for c in all_candidates if c["guess_key"] != true_answer_key]

    # Deterministically select 4 decoys to ensure they are the same every time the player refreshes the page
    rng = random.Random(f"{snapshot_id}-{day_key}-{mode}")
    selected_decoys = rng.sample(decoy_pool, min(4, len(decoy_pool)))

    # Combine and shuffle
    final_choices = [correct_candidate] + selected_decoys
    rng.shuffle(final_choices)

    return final_choices


def validate_game_guess(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    mode: str,
    guess_key: str | None = None,
    guess_steps: list[str] | None = None,
) -> dict[str, Any]:
    """Validate a player's guess against the hidden answer."""
    _parse_day_key(day_key)
    row = connection.execute(
        """
        SELECT answer_json
        FROM puzzle_day
        WHERE snapshot_id = ? AND day_key = ? AND mode = ?
        """,
        (snapshot_id, day_key, mode),
    ).fetchone()

    if not row:
        raise ValueError(f"No puzzle found for {day_key} mode {mode}")

    answer_json = json.loads(row["answer_json"])
    true_answer_key = answer_json.get("answer_key")
    true_steps = [str(step.get("attack_id")) for step in answer_json.get("comparison", {}).get("steps", [])]

    # Score the guess attributes using the game engine
    feedback = score_guess(connection, snapshot_id, mode, guess_key, answer_json, guess_steps=guess_steps)

    if mode == "timeline":
        normalized_guess_steps = [str(step) for step in (guess_steps or [])]
        return {
            "guess_key": guess_key,
            "solved": normalized_guess_steps == true_steps,
            "feedback": feedback,
        }

    return {
        "guess_key": guess_key,
        "solved": guess_key == true_answer_key,
        "feedback": feedback,
    }


def get_game_summary(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
) -> dict[str, Any]:
    """Get the post-game summary including article links and theme info."""
    from threatdle.services.review_export import _infer_theme
    _parse_day_key(day_key)
    rows = connection.execute(
        """
        SELECT mode, answer_json
        FROM puzzle_day
        WHERE snapshot_id = ? AND day_key = ?
        """,
        (snapshot_id, day_key),
    ).fetchall()

    if not rows:
        raise ValueError(f"No puzzle found for {day_key}")

    modes = {}
    exact_timeline_id = None
    linked_timeline_answer_key = None
    for row in rows:
        answer = json.loads(row["answer_json"])
        modes[row["mode"]] = {"answer": answer}
        if exact_timeline_id is None and answer.get("timeline_id") is not None:
            exact_timeline_id = int(answer["timeline_id"])
        if row["mode"] == "timeline":
            linked_timeline_answer_key = answer.get("answer_key")

    theme_info = _infer_theme(connection, modes)

    provenance = {}
    incident_source: dict[str, Any] | None = None
    if exact_timeline_id is not None:
        incident_row = connection.execute(
            """
            SELECT attack_campaign_id, source_article_url, source_article_title, provenance_json
            FROM incident_candidates_v1
            WHERE snapshot_id = ? AND timeline_id = ?
            LIMIT 1
            """,
            (snapshot_id, exact_timeline_id),
        ).fetchone()
        if incident_row is not None:
            incident_provenance = json.loads(incident_row["provenance_json"])
            source_article_url = incident_row["source_article_url"]
            if source_article_url:
                incident_source = {
                    "url": source_article_url,
                    "title": (
                        incident_row["source_article_title"]
                        or incident_provenance.get("incident_name")
                        or incident_provenance.get("flow_name")
                        or incident_provenance.get("campaign_name")
                        or "Incident source"
                    ),
                    "attack_campaign_id": incident_row["attack_campaign_id"],
                }
        prov_row = connection.execute(
            """
            SELECT provenance_json
            FROM timeline_sequences_v1
            WHERE snapshot_id = ? AND timeline_id = ?
            LIMIT 1
            """,
            (snapshot_id, exact_timeline_id),
        ).fetchone()
        if prov_row:
            provenance = json.loads(prov_row["provenance_json"])
    elif linked_timeline_answer_key:
        prov_row = connection.execute(
            """
            SELECT provenance_json
            FROM timeline_sequences_v1
            WHERE snapshot_id = ? AND answer_key = ? AND answer_type = 'actor'
            LIMIT 1
            """,
            (snapshot_id, linked_timeline_answer_key),
        ).fetchone()
        if prov_row:
            provenance = json.loads(prov_row["provenance_json"])

    return {
        "snapshot_id": snapshot_id,
        "day_key": day_key,
        "theme": theme_info,
        "incident_source": incident_source,
        "timeline_provenance": provenance,
    }
