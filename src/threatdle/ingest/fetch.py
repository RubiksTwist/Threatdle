"""Source fetching for Threatdle snapshots."""

from __future__ import annotations

from fnmatch import fnmatch
import json
from pathlib import Path
import shutil
import sqlite3
from typing import Any
from urllib.request import Request, urlopen
import zipfile

from threatdle.config import get_paths, load_sources_config
from threatdle.db.repositories import (
    require_pending_snapshot,
    set_snapshot_refs,
    upsert_source_artifact,
)
from threatdle.ingest.base import compute_logical_hash, compute_sha256_bytes, ensure_directory


USER_AGENT = "threatdle-ingest/0.1"


def fetch_url_bytes(url: str, timeout_seconds: float = 45.0) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout_seconds) as response:
        return response.read()


def _write_bytes(path: Path, payload: bytes) -> None:
    ensure_directory(path.parent)
    path.write_bytes(payload)


def _resolve_attack_bundle(index_payload: dict[str, Any], pinned_version: str) -> tuple[str, str]:
    for collection in index_payload.get("collections", []):
        versions = collection.get("versions", [])
        for version_row in versions:
            if version_row.get("version") == pinned_version:
                url = str(version_row["url"])
                if "/enterprise-attack/" in url:
                    return pinned_version, url
    raise ValueError(f"Unable to resolve ATT&CK enterprise version {pinned_version}")


def _extract_zip_matches(zip_path: Path, destination_dir: Path, pattern: str) -> list[Path]:
    extracted: list[Path] = []
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.namelist():
            if member.endswith("/") or not fnmatch(member, pattern):
                continue
            target_path = destination_dir / member
            ensure_directory(target_path.parent)
            with archive.open(member) as source_handle, target_path.open("wb") as target_handle:
                shutil.copyfileobj(source_handle, target_handle)
            extracted.append(target_path)
    return extracted


def _result_status(previous_hash: str | None, current_hash: str) -> str:
    if previous_hash == current_hash:
        return "no_change"
    return "fetched"


def _copy_local_matches(source_dir: Path, destination_dir: Path, pattern: str) -> list[Path]:
    copied: list[Path] = []
    for path in sorted(source_dir.glob(pattern)):
        if not path.is_file():
            continue
        target_path = destination_dir / path.name
        ensure_directory(target_path.parent)
        shutil.copy2(path, target_path)
        copied.append(target_path)
    return copied


def fetch_sources(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    root_dir: Path | None = None,
    timeout_seconds: float = 45.0,
) -> dict[str, dict[str, Any]]:
    require_pending_snapshot(connection, snapshot_id)
    paths = get_paths(root_dir=root_dir)
    source_config = load_sources_config(root_dir=root_dir)
    snapshot_dir = ensure_directory(paths.snapshots_dir / snapshot_id)
    results: dict[str, dict[str, Any]] = {}

    attack_index_bytes = fetch_url_bytes(source_config["attack_stix"]["index_url"], timeout_seconds=timeout_seconds)
    attack_index = json.loads(attack_index_bytes.decode("utf-8"))
    attack_version, attack_bundle_url = _resolve_attack_bundle(
        attack_index,
        str(source_config["attack_stix"]["pinned_version"]),
    )
    set_snapshot_refs(connection, snapshot_id, attack_version=attack_version)

    for source_name, config in source_config.items():
        source_dir = ensure_directory(snapshot_dir / source_name)
        if source_name == "attack_stix":
            payload = fetch_url_bytes(attack_bundle_url, timeout_seconds=timeout_seconds)
            file_path = source_dir / str(config["filename"])
            _write_bytes(file_path, payload)
            artifact_hash = compute_sha256_bytes(payload)
            previous = connection.execute(
                """
                SELECT artifact_hash
                FROM source_artifacts
                WHERE snapshot_id = ? AND source_name = ?
                """,
                (snapshot_id, source_name),
            ).fetchone()
            status = _result_status(previous["artifact_hash"] if previous else None, artifact_hash)
            upsert_source_artifact(
                connection,
                snapshot_id=snapshot_id,
                source_name=source_name,
                url=attack_bundle_url,
                resolved_ref=attack_version,
                file_path=file_path,
                artifact_hash=artifact_hash,
                extracted_files=[],
                status=status,
            )
            results[source_name] = {"status": status, "artifact_hash": artifact_hash, "file_path": str(file_path)}
            continue

        if source_name == "misp_threat_actors":
            payload = fetch_url_bytes(str(config["url"]), timeout_seconds=timeout_seconds)
            file_path = source_dir / str(config["filename"])
            _write_bytes(file_path, payload)
            artifact_hash = compute_sha256_bytes(payload)
            resolved_ref = str(config.get("ref") or "main")
            previous = connection.execute(
                """
                SELECT artifact_hash
                FROM source_artifacts
                WHERE snapshot_id = ? AND source_name = ?
                """,
                (snapshot_id, source_name),
            ).fetchone()
            status = _result_status(previous["artifact_hash"] if previous else None, artifact_hash)
            set_snapshot_refs(connection, snapshot_id, misp_ref=resolved_ref)
            upsert_source_artifact(
                connection,
                snapshot_id=snapshot_id,
                source_name=source_name,
                url=str(config["url"]),
                resolved_ref=resolved_ref,
                file_path=file_path,
                artifact_hash=artifact_hash,
                extracted_files=[],
                status=status,
            )
            results[source_name] = {"status": status, "artifact_hash": artifact_hash, "file_path": str(file_path)}
            continue

        if "url" in config and "extract_glob" in config:
            payload = fetch_url_bytes(str(config["url"]), timeout_seconds=timeout_seconds)
            archive_path = source_dir / str(config["filename"])
            _write_bytes(archive_path, payload)
            extracted = _extract_zip_matches(archive_path, source_dir, str(config["extract_glob"]))
            previous = connection.execute(
                """
                SELECT artifact_hash
                FROM source_artifacts
                WHERE snapshot_id = ? AND source_name = ?
                """,
                (snapshot_id, source_name),
            ).fetchone()
            artifact_hash = compute_logical_hash(extracted, source_dir) if extracted else compute_sha256_bytes(payload)
            extracted_files = [str(path.relative_to(source_dir)).replace("\\", "/") for path in extracted]
            resolved_ref = str(config.get("ref") or "main")
            status = _result_status(previous["artifact_hash"] if previous else None, artifact_hash)
            if source_name == "attack_flow":
                set_snapshot_refs(connection, snapshot_id, attack_flow_ref=resolved_ref)
            upsert_source_artifact(
                connection,
                snapshot_id=snapshot_id,
                source_name=source_name,
                url=str(config["url"]),
                resolved_ref=resolved_ref,
                file_path=archive_path,
                artifact_hash=artifact_hash,
                extracted_files=extracted_files,
                status=status,
            )
            results[source_name] = {
                "status": status,
                "artifact_hash": artifact_hash,
                "file_path": str(archive_path),
                "extracted_files": extracted_files,
            }
            continue

        if source_name == "curated_flows":
            configured_path = Path(str(config["path"]))
            local_source_dir = configured_path if configured_path.is_absolute() else paths.root_dir / configured_path
            if not local_source_dir.exists():
                raise FileNotFoundError(f"Curated flows directory does not exist: {local_source_dir}")
            copied = _copy_local_matches(local_source_dir, source_dir, str(config["glob"]))
            if not copied:
                raise ValueError(f"No curated flow files matched {config['glob']} in {local_source_dir}")
            previous = connection.execute(
                """
                SELECT artifact_hash
                FROM source_artifacts
                WHERE snapshot_id = ? AND source_name = ?
                """,
                (snapshot_id, source_name),
            ).fetchone()
            artifact_hash = compute_logical_hash(copied, source_dir)
            extracted_files = [path.name for path in copied]
            resolved_ref = str(config.get("ref") or "curated")
            set_snapshot_refs(connection, snapshot_id, attack_flow_ref=resolved_ref)
            upsert_source_artifact(
                connection,
                snapshot_id=snapshot_id,
                source_name=source_name,
                url=str(local_source_dir),
                resolved_ref=resolved_ref,
                file_path=source_dir,
                artifact_hash=artifact_hash,
                extracted_files=extracted_files,
                status=_result_status(previous["artifact_hash"] if previous else None, artifact_hash),
            )
            results[source_name] = {
                "status": _result_status(previous["artifact_hash"] if previous else None, artifact_hash),
                "artifact_hash": artifact_hash,
                "file_path": str(source_dir),
                "extracted_files": extracted_files,
            }
            continue

        raise ValueError(f"Unsupported source configuration: {source_name}")

    return results
