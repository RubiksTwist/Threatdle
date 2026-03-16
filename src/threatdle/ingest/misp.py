"""MISP Galaxy threat actor enrichment."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.db.repositories import (
    clear_unresolved_matches,
    ensure_snapshot_loading,
    finish_ingest_run,
    get_source_artifact,
    record_unresolved_match,
    start_ingest_run,
)
from threatdle.ingest.base import load_json_file
from threatdle.normalize.text import levenshtein_distance, normalize_actor_name


def _normalize_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    return [text] if text else []


def _load_actor_lookup(connection: sqlite3.Connection) -> tuple[dict[str, list[tuple[int, str]]], list[tuple[str, int, str]]]:
    rows = connection.execute(
        """
        SELECT a.actor_id, a.attack_group_id, a.name, aa.alias, aa.normalized_alias
        FROM actors a
        JOIN actor_aliases aa ON aa.actor_id = a.actor_id
        ORDER BY a.actor_id, aa.alias
        """
    ).fetchall()
    by_normalized: dict[str, list[tuple[int, str]]] = {}
    near_candidates: list[tuple[str, int, str]] = []
    for row in rows:
        normalized = row["normalized_alias"]
        if not normalized:
            continue
        by_normalized.setdefault(str(normalized), []).append((int(row["actor_id"]), str(row["attack_group_id"])))
        near_candidates.append((str(normalized), int(row["actor_id"]), str(row["attack_group_id"])))
    return by_normalized, near_candidates


def _load_match_overrides(connection: sqlite3.Connection) -> dict[str, str]:
    rows = connection.execute(
        "SELECT misp_uuid, attack_group_id FROM actor_match_overrides ORDER BY misp_uuid"
    ).fetchall()
    return {str(row["misp_uuid"]): str(row["attack_group_id"]) for row in rows}


def _apply_enrichment(connection: sqlite3.Connection, actor_id: int, meta: dict[str, Any]) -> None:
    actor = connection.execute(
        """
        SELECT
            country_code,
            state_sponsor,
            target_categories_json,
            victim_countries_json,
            motivation_tags_json,
            first_observed_year
        FROM actors
        WHERE actor_id = ?
        """,
        (actor_id,),
    ).fetchone()
    if actor is None:
        raise KeyError(f"Unknown actor id {actor_id}")
    target_categories = json.loads(actor["target_categories_json"]) if actor["target_categories_json"] else []
    victim_countries = json.loads(actor["victim_countries_json"]) if actor["victim_countries_json"] else []
    motivation_tags = json.loads(actor["motivation_tags_json"]) if actor["motivation_tags_json"] else []
    incoming_targets = _normalize_list(meta.get("cfr-target-category"))
    incoming_victims = _normalize_list(meta.get("cfr-suspected-victims"))
    incoming_motivation = _normalize_list(meta.get("cfr-type-of-incident"))
    target_categories = target_categories or incoming_targets
    victim_countries = victim_countries or incoming_victims
    motivation_tags = motivation_tags or incoming_motivation
    with connection:
        connection.execute(
            """
            UPDATE actors
            SET
                country_code = COALESCE(country_code, ?),
                state_sponsor = COALESCE(state_sponsor, ?),
                target_categories_json = CASE WHEN target_categories_json IS NULL THEN ? ELSE target_categories_json END,
                victim_countries_json = CASE WHEN victim_countries_json IS NULL THEN ? ELSE victim_countries_json END,
                motivation_tags_json = CASE WHEN motivation_tags_json IS NULL THEN ? ELSE motivation_tags_json END
            WHERE actor_id = ?
            """,
            (
                str(meta.get("country")).strip().upper() if meta.get("country") else None,
                str(meta.get("cfr-suspected-state-sponsor")).strip() if meta.get("cfr-suspected-state-sponsor") else None,
                json.dumps(target_categories, sort_keys=True) if target_categories else None,
                json.dumps(victim_countries, sort_keys=True) if victim_countries else None,
                json.dumps(motivation_tags, sort_keys=True) if motivation_tags else None,
                actor_id,
            ),
        )


def ingest_misp_actors(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    artifact = get_source_artifact(connection, snapshot_id, "misp_threat_actors")
    if artifact is None:
        raise ValueError(f"Snapshot {snapshot_id} is missing MISP source artifact")
    ingest_run_id = start_ingest_run(connection, snapshot_id, "ingest-misp-actors", "misp_threat_actors")
    payload = load_json_file(Path(artifact["file_path"]))
    values = payload.get("values")
    if not isinstance(values, list):
        raise ValueError("Invalid MISP threat-actor.json payload: missing values list")
    clear_unresolved_matches(connection, snapshot_id, "misp_threat_actors")
    direct_lookup, near_candidates = _load_actor_lookup(connection)
    override_lookup = _load_match_overrides(connection)

    counts = {"matched": 0, "ambiguous": 0, "near_match": 0, "no_match": 0}

    try:
        for item in values:
            if not isinstance(item, dict):
                continue
            misp_uuid = str(item.get("uuid") or "")
            primary_name = str(item.get("value") or item.get("name") or "").strip()
            if not misp_uuid or not primary_name:
                continue
            match_group_id = override_lookup.get(misp_uuid)
            if match_group_id:
                row = connection.execute(
                    "SELECT actor_id FROM actors WHERE attack_group_id = ?",
                    (match_group_id,),
                ).fetchone()
                if row is None:
                    raise ValueError(f"actor_match_overrides.csv references unknown ATT&CK actor {match_group_id}")
                _apply_enrichment(connection, int(row["actor_id"]), dict(item.get("meta") or {}))
                counts["matched"] += 1
                continue

            names = [primary_name, *_normalize_list((item.get("meta") or {}).get("synonyms"))]
            normalized_names = [value for value in (normalize_actor_name(name) for name in names) if value]
            matched_actor_ids: dict[int, str] = {}
            for normalized in normalized_names:
                for actor_id, attack_group_id in direct_lookup.get(normalized, []):
                    matched_actor_ids[actor_id] = attack_group_id

            if len(matched_actor_ids) == 1:
                actor_id = next(iter(matched_actor_ids))
                _apply_enrichment(connection, actor_id, dict(item.get("meta") or {}))
                counts["matched"] += 1
                continue

            external_key = f"{misp_uuid}:{primary_name}"
            if len(matched_actor_ids) > 1:
                record_unresolved_match(
                    connection,
                    snapshot_id=snapshot_id,
                    source_name="misp_threat_actors",
                    external_key=external_key,
                    candidate_key=None,
                    reason="ambiguous",
                    detail={"candidate_group_ids": sorted(matched_actor_ids.values())},
                )
                counts["ambiguous"] += 1
                continue

            best_distance = None
            best_match: tuple[str, int, str] | None = None
            for normalized in normalized_names:
                for candidate_name, actor_id, attack_group_id in near_candidates:
                    distance = levenshtein_distance(normalized, candidate_name)
                    if distance <= 2 and (best_distance is None or distance < best_distance):
                        best_distance = distance
                        best_match = (candidate_name, actor_id, attack_group_id)

            if best_match is not None and best_distance is not None:
                record_unresolved_match(
                    connection,
                    snapshot_id=snapshot_id,
                    source_name="misp_threat_actors",
                    external_key=external_key,
                    candidate_key=best_match[2],
                    reason="near_match",
                    detail={"normalized_names": normalized_names, "candidate_name": best_match[0], "distance": best_distance},
                )
                counts["near_match"] += 1
            else:
                record_unresolved_match(
                    connection,
                    snapshot_id=snapshot_id,
                    source_name="misp_threat_actors",
                    external_key=external_key,
                    candidate_key=None,
                    reason="no_match",
                    detail={"normalized_names": normalized_names},
                )
                counts["no_match"] += 1

        finish_ingest_run(
            connection,
            ingest_run_id,
            status="completed",
            row_count=sum(counts.values()),
        )
    except Exception as exc:
        finish_ingest_run(
            connection,
            ingest_run_id,
            status="failed",
            row_count=0,
            error_message=str(exc),
        )
        raise

    return counts
