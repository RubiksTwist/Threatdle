"""Manual override ingest and application."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3

from threatdle.config import get_paths
from threatdle.db.repositories import (
    ensure_snapshot_loading,
    finish_ingest_run,
    get_snapshot,
    set_snapshot_refs,
    start_ingest_run,
)
from threatdle.ingest.base import compute_sha256_file, ensure_directory, now_utc_iso
from threatdle.normalize.text import split_pipe_list


MATCH_OVERRIDE_FILE = "actor_match_overrides.csv"
ACTOR_OVERRIDE_FILE = "actor_overrides.csv"
MALWARE_OVERRIDE_FILE = "malware_overrides.csv"


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [{str(key): (value or "").strip() for key, value in row.items()} for row in reader]


def _write_empty_if_missing(path: Path, headers: list[str]) -> None:
    if path.exists():
        return
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()


def _validate_required_headers(path: Path, rows: list[dict[str, str]], headers: list[str]) -> None:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        actual_headers = reader.fieldnames or []
    missing = [header for header in headers if header not in actual_headers]
    if missing:
        raise ValueError(f"{path.name} is missing required headers: {', '.join(missing)}")


def ingest_overrides(connection: sqlite3.Connection, snapshot_id: str, *, root_dir: Path | None = None) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    paths = get_paths(root_dir=root_dir)
    ingest_run_id = start_ingest_run(connection, snapshot_id, "ingest-overrides")
    ensure_directory(paths.overrides_dir)

    match_path = paths.overrides_dir / MATCH_OVERRIDE_FILE
    actor_path = paths.overrides_dir / ACTOR_OVERRIDE_FILE
    malware_path = paths.overrides_dir / MALWARE_OVERRIDE_FILE
    _write_empty_if_missing(match_path, ["misp_uuid", "attack_group_id"])
    _write_empty_if_missing(
        actor_path,
        [
            "attack_group_id",
            "display_name",
            "country_code",
            "first_observed_year",
            "target_categories",
            "victim_countries",
            "motivation_tags",
            "notes",
            "reference_url",
        ],
    )
    _write_empty_if_missing(
        malware_path,
        [
            "attack_software_id",
            "display_name",
            "malware_category",
            "platforms",
            "capability_summary",
            "reference_url",
        ],
    )
    match_rows = _load_csv(match_path)
    actor_rows = _load_csv(actor_path)
    malware_rows = _load_csv(malware_path)
    _validate_required_headers(match_path, match_rows, ["misp_uuid", "attack_group_id"])
    _validate_required_headers(
        actor_path,
        actor_rows,
        [
            "attack_group_id",
            "display_name",
            "country_code",
            "first_observed_year",
            "target_categories",
            "victim_countries",
            "motivation_tags",
            "notes",
            "reference_url",
        ],
    )
    _validate_required_headers(
        malware_path,
        malware_rows,
        [
            "attack_software_id",
            "display_name",
            "malware_category",
            "platforms",
            "capability_summary",
            "reference_url",
        ],
    )

    match_hash = compute_sha256_file(match_path)
    actor_hash = compute_sha256_file(actor_path)
    malware_hash = compute_sha256_file(malware_path)
    snapshot = get_snapshot(connection, snapshot_id)
    if snapshot is None:
        raise KeyError(f"Unknown snapshot {snapshot_id}")
    existing_hashes = {
        "actor_match_override_hash": snapshot["actor_match_override_hash"],
        "actor_override_hash": snapshot["actor_override_hash"],
        "malware_override_hash": snapshot["malware_override_hash"],
    }
    for field_name, new_hash in {
        "actor_match_override_hash": match_hash,
        "actor_override_hash": actor_hash,
        "malware_override_hash": malware_hash,
    }.items():
        current_hash = existing_hashes[field_name]
        if current_hash is not None and current_hash != new_hash:
            raise ValueError(f"Snapshot {snapshot_id} override hash changed for {field_name}")
    set_snapshot_refs(
        connection,
        snapshot_id,
        actor_match_override_hash=match_hash,
        actor_override_hash=actor_hash,
        malware_override_hash=malware_hash,
    )

    counts = {"match_overrides": 0, "actor_overrides": 0, "malware_overrides": 0}
    try:
        with connection:
            connection.execute("DELETE FROM actor_match_overrides")
            connection.execute("DELETE FROM actor_override_records")
            connection.execute("DELETE FROM malware_override_records")

            seen_match_keys: set[str] = set()
            for row in match_rows:
                misp_uuid = row.get("misp_uuid", "").strip()
                attack_group_id = row.get("attack_group_id", "").strip()
                if not misp_uuid and not attack_group_id:
                    continue
                if not misp_uuid or not attack_group_id:
                    raise ValueError(f"{MATCH_OVERRIDE_FILE} has incomplete row: {row!r}")
                if misp_uuid in seen_match_keys:
                    raise ValueError(f"{MATCH_OVERRIDE_FILE} has duplicate misp_uuid {misp_uuid}")
                actor = connection.execute(
                    "SELECT actor_id FROM actors WHERE attack_group_id = ?",
                    (attack_group_id,),
                ).fetchone()
                if actor is None:
                    raise ValueError(f"{MATCH_OVERRIDE_FILE} references unknown ATT&CK actor {attack_group_id}")
                connection.execute(
                    """
                    INSERT INTO actor_match_overrides (misp_uuid, attack_group_id, source_name, loaded_at)
                    VALUES (?, ?, 'actor_match_overrides', ?)
                    """,
                    (misp_uuid, attack_group_id, now_utc_iso()),
                )
                seen_match_keys.add(misp_uuid)
                counts["match_overrides"] += 1

            seen_actor_keys: set[str] = set()
            for row in actor_rows:
                attack_group_id = row.get("attack_group_id", "").strip()
                if not attack_group_id:
                    continue
                if attack_group_id in seen_actor_keys:
                    raise ValueError(f"{ACTOR_OVERRIDE_FILE} has duplicate attack_group_id {attack_group_id}")
                actor = connection.execute(
                    "SELECT actor_id FROM actors WHERE attack_group_id = ?",
                    (attack_group_id,),
                ).fetchone()
                if actor is None:
                    raise ValueError(f"{ACTOR_OVERRIDE_FILE} references unknown ATT&CK actor {attack_group_id}")
                year_value = row.get("first_observed_year", "").strip()
                first_observed_year = int(year_value) if year_value else None
                connection.execute(
                    """
                    INSERT INTO actor_override_records (
                        attack_group_id,
                        display_name,
                        country_code,
                        first_observed_year,
                        target_categories_json,
                        victim_countries_json,
                        motivation_tags_json,
                        notes,
                        reference_url,
                        source_name,
                        loaded_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'actor_overrides', ?)
                    """,
                    (
                        attack_group_id,
                        row.get("display_name") or None,
                        (row.get("country_code") or "").upper() or None,
                        first_observed_year,
                        json.dumps(split_pipe_list(row.get("target_categories")), sort_keys=True)
                        if row.get("target_categories")
                        else None,
                        json.dumps(split_pipe_list(row.get("victim_countries")), sort_keys=True)
                        if row.get("victim_countries")
                        else None,
                        json.dumps(split_pipe_list(row.get("motivation_tags")), sort_keys=True)
                        if row.get("motivation_tags")
                        else None,
                        row.get("notes") or None,
                        row.get("reference_url") or None,
                        now_utc_iso(),
                    ),
                )
                seen_actor_keys.add(attack_group_id)
                counts["actor_overrides"] += 1

            seen_malware_keys: set[str] = set()
            for row in malware_rows:
                attack_software_id = row.get("attack_software_id", "").strip()
                if not attack_software_id:
                    continue
                if attack_software_id in seen_malware_keys:
                    raise ValueError(f"{MALWARE_OVERRIDE_FILE} has duplicate attack_software_id {attack_software_id}")
                malware = connection.execute(
                    "SELECT malware_id FROM malware WHERE attack_software_id = ?",
                    (attack_software_id,),
                ).fetchone()
                if malware is None:
                    raise ValueError(f"{MALWARE_OVERRIDE_FILE} references unknown ATT&CK malware {attack_software_id}")
                connection.execute(
                    """
                    INSERT INTO malware_override_records (
                        attack_software_id,
                        display_name,
                        malware_category,
                        platforms_json,
                        capability_summary,
                        reference_url,
                        source_name,
                        loaded_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'malware_overrides', ?)
                    """,
                    (
                        attack_software_id,
                        row.get("display_name") or None,
                        row.get("malware_category") or None,
                        json.dumps(split_pipe_list(row.get("platforms")), sort_keys=True) if row.get("platforms") else None,
                        row.get("capability_summary") or None,
                        row.get("reference_url") or None,
                        now_utc_iso(),
                    ),
                )
                seen_malware_keys.add(attack_software_id)
                counts["malware_overrides"] += 1

            connection.execute(
                """
                UPDATE actors
                SET
                    name = COALESCE((SELECT display_name FROM actor_override_records o WHERE o.attack_group_id = actors.attack_group_id), name),
                    country_code = COALESCE((SELECT country_code FROM actor_override_records o WHERE o.attack_group_id = actors.attack_group_id), country_code),
                    first_observed_year = COALESCE((SELECT first_observed_year FROM actor_override_records o WHERE o.attack_group_id = actors.attack_group_id), first_observed_year),
                    target_categories_json = COALESCE((SELECT target_categories_json FROM actor_override_records o WHERE o.attack_group_id = actors.attack_group_id), target_categories_json),
                    victim_countries_json = COALESCE((SELECT victim_countries_json FROM actor_override_records o WHERE o.attack_group_id = actors.attack_group_id), victim_countries_json),
                    motivation_tags_json = COALESCE((SELECT motivation_tags_json FROM actor_override_records o WHERE o.attack_group_id = actors.attack_group_id), motivation_tags_json)
                """
            )

            connection.execute(
                """
                UPDATE malware
                SET
                    name = COALESCE((SELECT display_name FROM malware_override_records o WHERE o.attack_software_id = malware.attack_software_id), name),
                    malware_category = COALESCE((SELECT malware_category FROM malware_override_records o WHERE o.attack_software_id = malware.attack_software_id), malware_category),
                    platforms_json = COALESCE((SELECT platforms_json FROM malware_override_records o WHERE o.attack_software_id = malware.attack_software_id), platforms_json),
                    capability_summary = COALESCE((SELECT capability_summary FROM malware_override_records o WHERE o.attack_software_id = malware.attack_software_id), capability_summary)
                """
            )

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
