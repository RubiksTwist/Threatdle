"""Repository helpers for snapshot, artifact, and canonical state operations."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.ingest.base import compute_logical_hash, compute_sha256_file, now_utc_iso
from threatdle.db.schema import clear_canonical_tables


REQUIRED_SOURCES = ("attack_stix", "misp_threat_actors", "curated_flows")


def _dumps_json(value: Any) -> str | None:
    if value is None:
        return None
    return json.dumps(value, sort_keys=True)


def get_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> sqlite3.Row | None:
    return connection.execute(
        "SELECT * FROM snapshots WHERE snapshot_id = ?",
        (snapshot_id,),
    ).fetchone()


def get_or_create_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> sqlite3.Row:
    row = get_snapshot(connection, snapshot_id)
    if row is not None:
        return row
    created_at = now_utc_iso()
    with connection:
        connection.execute(
            """
            INSERT INTO snapshots (snapshot_id, created_at, status)
            VALUES (?, ?, 'pending')
            """,
            (snapshot_id, created_at),
        )
    return get_snapshot(connection, snapshot_id)


def require_pending_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> sqlite3.Row:
    snapshot = get_or_create_snapshot(connection, snapshot_id)
    if snapshot["status"] != "pending":
        raise ValueError(f"Snapshot {snapshot_id} is locked with status {snapshot['status']}")
    return snapshot


def set_snapshot_refs(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    attack_version: str | None = None,
    misp_ref: str | None = None,
    attack_flow_ref: str | None = None,
    actor_match_override_hash: str | None = None,
    actor_override_hash: str | None = None,
    malware_override_hash: str | None = None,
    incident_override_hash: str | None = None,
) -> None:
    existing = get_snapshot(connection, snapshot_id)
    if existing is None:
        raise KeyError(f"Unknown snapshot {snapshot_id}")
    payload = {
        "attack_version": attack_version if attack_version is not None else existing["attack_version"],
        "misp_ref": misp_ref if misp_ref is not None else existing["misp_ref"],
        "attack_flow_ref": attack_flow_ref if attack_flow_ref is not None else existing["attack_flow_ref"],
        "actor_match_override_hash": (
            actor_match_override_hash
            if actor_match_override_hash is not None
            else existing["actor_match_override_hash"]
        ),
        "actor_override_hash": actor_override_hash if actor_override_hash is not None else existing["actor_override_hash"],
        "malware_override_hash": (
            malware_override_hash if malware_override_hash is not None else existing["malware_override_hash"]
        ),
        "incident_override_hash": (
            incident_override_hash if incident_override_hash is not None else existing["incident_override_hash"]
        ),
        "snapshot_id": snapshot_id,
    }
    with connection:
        connection.execute(
            """
            UPDATE snapshots
            SET
                attack_version = :attack_version,
                misp_ref = :misp_ref,
                attack_flow_ref = :attack_flow_ref,
                actor_match_override_hash = :actor_match_override_hash,
                actor_override_hash = :actor_override_hash,
                malware_override_hash = :malware_override_hash,
                incident_override_hash = :incident_override_hash
            WHERE snapshot_id = :snapshot_id
            """,
            payload,
        )


def upsert_source_artifact(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    source_name: str,
    url: str,
    resolved_ref: str | None,
    file_path: Path,
    artifact_hash: str,
    extracted_files: list[str] | None,
    status: str,
) -> None:
    fetched_at = now_utc_iso()
    payload = {
        "snapshot_id": snapshot_id,
        "source_name": source_name,
        "url": url,
        "resolved_ref": resolved_ref,
        "file_path": str(file_path),
        "artifact_hash": artifact_hash,
        "fetched_at": fetched_at,
        "extracted_files_json": _dumps_json(extracted_files or []),
        "status": status,
    }
    with connection:
        connection.execute(
            """
            INSERT INTO source_artifacts (
                snapshot_id,
                source_name,
                url,
                resolved_ref,
                file_path,
                artifact_hash,
                fetched_at,
                extracted_files_json,
                status
            )
            VALUES (
                :snapshot_id,
                :source_name,
                :url,
                :resolved_ref,
                :file_path,
                :artifact_hash,
                :fetched_at,
                :extracted_files_json,
                :status
            )
            ON CONFLICT(snapshot_id, source_name) DO UPDATE SET
                url = excluded.url,
                resolved_ref = excluded.resolved_ref,
                file_path = excluded.file_path,
                artifact_hash = excluded.artifact_hash,
                fetched_at = excluded.fetched_at,
                extracted_files_json = excluded.extracted_files_json,
                status = excluded.status;
            """,
            payload,
        )
        connection.execute(
            """
            INSERT INTO snapshot_sources (
                snapshot_id,
                source_name,
                url,
                resolved_ref,
                local_path,
                artifact_hash,
                fetched_at,
                extracted_files_json,
                status
            )
            VALUES (
                :snapshot_id,
                :source_name,
                :url,
                :resolved_ref,
                :file_path,
                :artifact_hash,
                :fetched_at,
                :extracted_files_json,
                :status
            )
            ON CONFLICT(snapshot_id, source_name) DO UPDATE SET
                url = excluded.url,
                resolved_ref = excluded.resolved_ref,
                local_path = excluded.local_path,
                artifact_hash = excluded.artifact_hash,
                fetched_at = excluded.fetched_at,
                extracted_files_json = excluded.extracted_files_json,
                status = excluded.status;
            """,
            payload,
        )


def get_source_artifact(connection: sqlite3.Connection, snapshot_id: str, source_name: str) -> sqlite3.Row | None:
    return connection.execute(
        """
        SELECT *
        FROM source_artifacts
        WHERE snapshot_id = ? AND source_name = ?
        """,
        (snapshot_id, source_name),
    ).fetchone()


def list_source_artifacts(connection: sqlite3.Connection, snapshot_id: str) -> list[sqlite3.Row]:
    rows = connection.execute(
        """
        SELECT *
        FROM source_artifacts
        WHERE snapshot_id = ?
        ORDER BY source_name
        """,
        (snapshot_id,),
    ).fetchall()
    return list(rows)


def verify_snapshot_has_required_sources(connection: sqlite3.Connection, snapshot_id: str) -> None:
    missing = [source_name for source_name in REQUIRED_SOURCES if get_source_artifact(connection, snapshot_id, source_name) is None]
    if missing:
        raise ValueError(f"Snapshot {snapshot_id} is missing required sources: {', '.join(missing)}")


def _current_artifact_hash(row: sqlite3.Row) -> str:
    file_path = Path(row["file_path"])
    if not file_path.exists():
        raise FileNotFoundError(f"Artifact path does not exist: {file_path}")
    extracted_files = json.loads(row["extracted_files_json"] or "[]")
    if extracted_files:
        base_dir = file_path if file_path.is_dir() else file_path.parent
        paths = [base_dir / relative_path for relative_path in extracted_files]
        missing = [str(path) for path in paths if not path.exists()]
        if missing:
            raise FileNotFoundError(f"Extracted files missing for {row['source_name']}: {', '.join(missing)}")
        return compute_logical_hash(paths, base_dir)
    return compute_sha256_file(file_path)


def verify_locked_snapshot_artifacts(connection: sqlite3.Connection, snapshot_id: str) -> None:
    for row in list_source_artifacts(connection, snapshot_id):
        actual_hash = _current_artifact_hash(row)
        if actual_hash != row["artifact_hash"]:
            raise ValueError(
                f"Snapshot {snapshot_id} source {row['source_name']} hash changed after lock: "
                f"expected {row['artifact_hash']}, found {actual_hash}"
            )


def ensure_snapshot_loading(connection: sqlite3.Connection, snapshot_id: str) -> sqlite3.Row:
    snapshot = get_or_create_snapshot(connection, snapshot_id)
    verify_snapshot_has_required_sources(connection, snapshot_id)
    if snapshot["status"] == "pending":
        with connection:
            clear_canonical_tables(connection)
            connection.execute(
                """
                UPDATE snapshots
                SET status = 'ingesting', locked_at = ?
                WHERE snapshot_id = ?
                """,
                (now_utc_iso(), snapshot_id),
            )
            connection.execute(
                """
                UPDATE canonical_state
                SET active_snapshot_id = ?, loaded_at = ?
                WHERE id = 1
                """,
                (snapshot_id, now_utc_iso()),
            )
        snapshot = get_snapshot(connection, snapshot_id)
    elif snapshot["status"] not in {"ingesting", "ready"}:
        raise ValueError(f"Snapshot {snapshot_id} cannot be loaded from status {snapshot['status']}")
    active_snapshot = get_active_snapshot(connection)
    if active_snapshot != snapshot_id:
        raise ValueError(
            f"Canonical tables currently belong to snapshot {active_snapshot}; "
            f"start a new pending snapshot for a reload"
        )
    verify_locked_snapshot_artifacts(connection, snapshot_id)
    return get_snapshot(connection, snapshot_id)


def get_active_snapshot(connection: sqlite3.Connection) -> str | None:
    row = connection.execute("SELECT active_snapshot_id FROM canonical_state WHERE id = 1").fetchone()
    if row is None:
        return None
    return row["active_snapshot_id"]


def mark_snapshot_ready(connection: sqlite3.Connection, snapshot_id: str) -> None:
    with connection:
        connection.execute(
            """
            UPDATE snapshots
            SET status = 'ready', ready_at = ?
            WHERE snapshot_id = ?
            """,
            (now_utc_iso(), snapshot_id),
        )


def mark_snapshot_failed(connection: sqlite3.Connection, snapshot_id: str) -> None:
    with connection:
        connection.execute(
            "UPDATE snapshots SET status = 'failed' WHERE snapshot_id = ?",
            (snapshot_id,),
        )
        active_snapshot = get_active_snapshot(connection)
        if active_snapshot == snapshot_id:
            clear_canonical_tables(connection)
            connection.execute(
                """
                UPDATE canonical_state
                SET active_snapshot_id = NULL, loaded_at = ?
                WHERE id = 1
                """,
                (now_utc_iso(),),
            )


def start_ingest_run(
    connection: sqlite3.Connection,
    snapshot_id: str,
    command_name: str,
    source_name: str | None = None,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO ingest_runs (
            snapshot_id,
            command_name,
            source_name,
            started_at,
            status,
            row_count
        )
        VALUES (?, ?, ?, ?, 'running', 0)
        """,
        (snapshot_id, command_name, source_name, now_utc_iso()),
    )
    connection.commit()
    return int(cursor.lastrowid)


def finish_ingest_run(
    connection: sqlite3.Connection,
    ingest_run_id: int,
    *,
    status: str,
    row_count: int,
    error_message: str | None = None,
) -> None:
    with connection:
        connection.execute(
            """
            UPDATE ingest_runs
            SET completed_at = ?, status = ?, row_count = ?, error_message = ?
            WHERE ingest_run_id = ?
            """,
            (now_utc_iso(), status, row_count, error_message, ingest_run_id),
        )


def clear_unresolved_matches(connection: sqlite3.Connection, snapshot_id: str, source_name: str) -> None:
    with connection:
        connection.execute(
            """
            DELETE FROM unresolved_matches
            WHERE snapshot_id = ? AND source_name = ?
            """,
            (snapshot_id, source_name),
        )


def record_unresolved_match(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    source_name: str,
    external_key: str,
    candidate_key: str | None,
    reason: str,
    detail: dict[str, Any] | None = None,
) -> None:
    with connection:
        connection.execute(
            """
            INSERT INTO unresolved_matches (
                snapshot_id,
                source_name,
                external_key,
                candidate_key,
                reason,
                detail_json,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                source_name,
                external_key,
                candidate_key,
                reason,
                _dumps_json(detail),
                now_utc_iso(),
            ),
        )
