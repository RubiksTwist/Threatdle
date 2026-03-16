"""Incident-level malware override ingest."""

from __future__ import annotations

import csv
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


INCIDENT_OVERRIDE_FILE = "incident_overrides.csv"
INCIDENT_OVERRIDE_HEADERS = [
    "source_flow_id",
    "path_hash",
    "incident_name",
    "attack_group_id",
    "attack_software_ids",
    "attack_campaign_id",
    "reference_url",
    "source_article_url",
    "source_article_title",
    "notes",
    "confidence",
]
REQUIRED_HEADERS = [
    "source_flow_id",
    "path_hash",
    "incident_name",
    "attack_group_id",
    "attack_software_ids",
    "reference_url",
    "notes",
    "confidence",
]
ALLOWED_CONFIDENCE = {"low", "medium", "high"}


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        return [{str(key): (value or "").strip() for key, value in row.items()} for row in reader]


def _write_empty_if_missing(path: Path) -> None:
    if path.exists():
        return
    ensure_directory(path.parent)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=INCIDENT_OVERRIDE_HEADERS)
        writer.writeheader()


def _validate_required_headers(path: Path) -> None:
    if not path.exists():
        return
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        actual_headers = reader.fieldnames or []
    missing = [header for header in REQUIRED_HEADERS if header not in actual_headers]
    if missing:
        raise ValueError(f"{INCIDENT_OVERRIDE_FILE} is missing required headers: {', '.join(missing)}")


def _optional_text(row: dict[str, str], key: str) -> str | None:
    value = (row.get(key) or "").strip()
    return value or None


def ingest_incident_overrides(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    root_dir: Path | None = None,
) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    paths = get_paths(root_dir=root_dir)
    ingest_run_id = start_ingest_run(connection, snapshot_id, "ingest-incident-overrides")
    override_path = paths.overrides_dir / INCIDENT_OVERRIDE_FILE
    _write_empty_if_missing(override_path)
    rows = _load_csv(override_path)
    _validate_required_headers(override_path)

    override_hash = compute_sha256_file(override_path)
    snapshot = get_snapshot(connection, snapshot_id)
    if snapshot is None:
        raise KeyError(f"Unknown snapshot {snapshot_id}")
    current_hash = snapshot["incident_override_hash"]
    has_override_rows = any(
        any(
            (
                (row.get("source_flow_id") or "").strip(),
                (row.get("path_hash") or "").strip(),
                (row.get("attack_group_id") or "").strip(),
                split_pipe_list(row.get("attack_software_ids")),
            )
        )
        for row in rows
    )
    if current_hash is not None and current_hash != override_hash and has_override_rows:
        raise ValueError(f"Snapshot {snapshot_id} override hash changed for incident_override_hash")
    set_snapshot_refs(connection, snapshot_id, incident_override_hash=override_hash)

    counts = {"incident_override_rows": 0, "timeline_malware_links": 0, "timeline_incident_metadata_rows": 0}
    try:
        with connection:
            connection.execute("DELETE FROM timeline_incident_metadata")
            connection.execute("DELETE FROM timeline_malware")

            seen_rows: set[tuple[str, str]] = set()
            for row in rows:
                source_flow_id = row.get("source_flow_id", "").strip()
                path_hash = row.get("path_hash", "").strip()
                attack_group_id = row.get("attack_group_id", "").strip()
                attack_software_ids = split_pipe_list(row.get("attack_software_ids"))
                if not any((source_flow_id, path_hash, attack_group_id, attack_software_ids)):
                    continue
                if not source_flow_id or not path_hash or not attack_group_id or not attack_software_ids:
                    raise ValueError(f"{INCIDENT_OVERRIDE_FILE} has incomplete row: {row!r}")

                key = (source_flow_id, path_hash)
                if key in seen_rows:
                    raise ValueError(
                        f"{INCIDENT_OVERRIDE_FILE} has duplicate source_flow_id/path_hash pair "
                        f"{source_flow_id}/{path_hash}"
                    )

                timeline = connection.execute(
                    """
                    SELECT timeline_id, answer_type, answer_key, flow_name
                    FROM timelines
                    WHERE source_flow_id = ? AND path_hash = ?
                    """,
                    (source_flow_id, path_hash),
                ).fetchone()
                if timeline is None:
                    raise ValueError(
                        f"{INCIDENT_OVERRIDE_FILE} references unknown timeline "
                        f"{source_flow_id}/{path_hash}"
                    )
                if timeline["answer_type"] != "actor":
                    raise ValueError(
                        f"{INCIDENT_OVERRIDE_FILE} timeline {source_flow_id}/{path_hash} is not actor-attributed"
                    )
                if timeline["answer_key"] != attack_group_id:
                    raise ValueError(
                        f"{INCIDENT_OVERRIDE_FILE} actor mismatch for {source_flow_id}/{path_hash}: "
                        f"timeline has {timeline['answer_key']}, override has {attack_group_id}"
                    )

                confidence = (row.get("confidence") or "medium").strip().lower()
                if confidence not in ALLOWED_CONFIDENCE:
                    raise ValueError(
                        f"{INCIDENT_OVERRIDE_FILE} has invalid confidence {confidence!r} "
                        f"for {source_flow_id}/{path_hash}"
                    )
                source_article_url = _optional_text(row, "source_article_url")
                source_article_title = _optional_text(row, "source_article_title")
                if source_article_url is not None and not source_article_url.startswith("https://"):
                    raise ValueError(
                        f"{INCIDENT_OVERRIDE_FILE} has invalid source_article_url {source_article_url!r} "
                        f"for {source_flow_id}/{path_hash}"
                    )
                attack_campaign_id = _optional_text(row, "attack_campaign_id")
                if attack_campaign_id is not None:
                    campaign = connection.execute(
                        """
                        SELECT c.campaign_id, a.attack_group_id
                        FROM campaigns c
                        JOIN campaign_actors ca ON ca.campaign_id = c.campaign_id
                        JOIN actors a ON a.actor_id = ca.actor_id
                        WHERE c.attack_campaign_id = ?
                        """,
                        (attack_campaign_id,),
                    ).fetchall()
                    if not campaign:
                        raise ValueError(
                            f"{INCIDENT_OVERRIDE_FILE} references unknown ATT&CK campaign {attack_campaign_id}"
                        )
                    actor_keys = {str(campaign_row["attack_group_id"]) for campaign_row in campaign}
                    if attack_group_id not in actor_keys:
                        raise ValueError(
                            f"{INCIDENT_OVERRIDE_FILE} campaign actor mismatch for {source_flow_id}/{path_hash}: "
                            f"campaign {attack_campaign_id} is linked to {sorted(actor_keys)}, "
                            f"override has {attack_group_id}"
                        )

                seen_malware_ids: set[int] = set()
                for attack_software_id in attack_software_ids:
                    malware = connection.execute(
                        """
                        SELECT malware_id
                        FROM malware
                        WHERE attack_software_id = ?
                        """,
                        (attack_software_id,),
                    ).fetchone()
                    if malware is None:
                        raise ValueError(
                            f"{INCIDENT_OVERRIDE_FILE} references unknown ATT&CK malware {attack_software_id}"
                        )
                    malware_id = int(malware["malware_id"])
                    if malware_id in seen_malware_ids:
                        raise ValueError(
                            f"{INCIDENT_OVERRIDE_FILE} repeats malware {attack_software_id} "
                            f"for {source_flow_id}/{path_hash}"
                        )
                    connection.execute(
                        """
                        INSERT INTO timeline_malware (
                            timeline_id,
                            malware_id,
                            reference_url,
                            notes,
                            confidence
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            int(timeline["timeline_id"]),
                            malware_id,
                            row.get("reference_url") or None,
                            row.get("notes") or None,
                            confidence,
                        ),
                    )
                    seen_malware_ids.add(malware_id)
                    counts["timeline_malware_links"] += 1

                connection.execute(
                    """
                    INSERT INTO timeline_incident_metadata (
                        timeline_id,
                        incident_name,
                        attack_campaign_id,
                        reference_url,
                        source_article_url,
                        source_article_title,
                        notes,
                        confidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        int(timeline["timeline_id"]),
                        _optional_text(row, "incident_name"),
                        attack_campaign_id,
                        _optional_text(row, "reference_url"),
                        source_article_url,
                        source_article_title,
                        _optional_text(row, "notes"),
                        confidence,
                    ),
                )
                counts["timeline_incident_metadata_rows"] += 1
                seen_rows.add(key)
                counts["incident_override_rows"] += 1

        finish_ingest_run(
            connection,
            ingest_run_id,
            status="completed",
            row_count=counts["timeline_malware_links"],
        )
    except Exception as exc:
        finish_ingest_run(
            connection,
            ingest_run_id,
            status="failed",
            row_count=counts["timeline_malware_links"],
            error_message=str(exc),
        )
        raise

    return counts
