"""Shared helpers for timeline-oriented source ingest."""

from __future__ import annotations

import sqlite3

from threatdle.normalize.text import normalize_actor_name


def load_actor_name_lookup(connection: sqlite3.Connection) -> tuple[dict[str, str], dict[str, str], dict[str, int]]:
    name_lookup: dict[str, str] = {}
    label_lookup: dict[str, str] = {}
    id_lookup: dict[str, int] = {}
    rows = connection.execute(
        "SELECT actor_id, attack_group_id, name FROM actors ORDER BY attack_group_id"
    ).fetchall()
    for row in rows:
        group_id = str(row["attack_group_id"])
        label_lookup[group_id] = str(row["name"])
        id_lookup[group_id] = int(row["actor_id"])
        normalized = normalize_actor_name(str(row["name"]))
        if normalized:
            name_lookup[normalized] = group_id
    alias_rows = connection.execute(
        """
        SELECT a.attack_group_id, aa.normalized_alias
        FROM actors a
        JOIN actor_aliases aa ON aa.actor_id = a.actor_id
        ORDER BY a.attack_group_id
        """
    ).fetchall()
    for row in alias_rows:
        normalized_alias = str(row["normalized_alias"] or "").strip()
        if normalized_alias:
            name_lookup[normalized_alias] = str(row["attack_group_id"])
    return name_lookup, label_lookup, id_lookup


def load_technique_lookup(connection: sqlite3.Connection) -> dict[str, tuple[int, str]]:
    rows = connection.execute(
        "SELECT technique_id, attack_id, name FROM techniques WHERE revoked = 0 AND deprecated = 0"
    ).fetchall()
    return {str(row["attack_id"]): (int(row["technique_id"]), str(row["name"])) for row in rows}


def clear_timeline_source_rows(connection: sqlite3.Connection, *timeline_source_types: str) -> None:
    if not timeline_source_types:
        return
    placeholders = ", ".join("?" for _ in timeline_source_types)
    with connection:
        connection.execute(
            f"""
            DELETE FROM timeline_steps
            WHERE timeline_id IN (
                SELECT timeline_id
                FROM timelines
                WHERE timeline_source_type IN ({placeholders})
            )
            """,
            timeline_source_types,
        )
        connection.execute(
            f"DELETE FROM timelines WHERE timeline_source_type IN ({placeholders})",
            timeline_source_types,
        )
        connection.execute(
            f"""
            DELETE FROM operation_actors
            WHERE operation_id IN (
                SELECT operation_id
                FROM operations
                WHERE timeline_source_type IN ({placeholders})
            )
            """,
            timeline_source_types,
        )
        connection.execute(
            f"DELETE FROM operations WHERE timeline_source_type IN ({placeholders})",
            timeline_source_types,
        )
