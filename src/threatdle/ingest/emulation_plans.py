"""Ingest structured adversary emulation plans as ordered timelines."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

import yaml

from threatdle.db.repositories import (
    clear_unresolved_matches,
    ensure_snapshot_loading,
    finish_ingest_run,
    get_source_artifact,
    record_unresolved_match,
    start_ingest_run,
)
from threatdle.ingest.timeline_common import clear_timeline_source_rows, load_actor_name_lookup, load_technique_lookup
from threatdle.normalize.text import normalize_actor_name


EMULATION_SOURCE_NAMES = ("ctid_emulation_library", "attackevals_ael")
PROCEDURE_TOKEN_PATTERN = re.compile(r"\d+|[A-Za-z]+")
GROUP_ATTACK_ID_PATTERN = re.compile(r"\bG\d{4}\b", re.IGNORECASE)


def _coerce_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _load_yaml_file(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _alpha_token_value(token: str) -> int:
    value = 0
    for char in token.upper():
        if not char.isalpha():
            continue
        value = (value * 26) + (ord(char) - ord("A") + 1)
    return value


def _procedure_sort_key(value: str | None) -> tuple[tuple[int, int], ...]:
    if not value:
        return tuple()
    parts = PROCEDURE_TOKEN_PATTERN.findall(value)
    key: list[tuple[int, int]] = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, _alpha_token_value(part)))
    return tuple(key)


def _segment_key(value: str | None) -> str | None:
    if not value:
        return None
    parts = [part.upper() for part in PROCEDURE_TOKEN_PATTERN.findall(value)]
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return ".".join(parts[:2])


def _collapse_adjacent_duplicates(values: list[str]) -> list[str]:
    collapsed: list[str] = []
    for value in values:
        if not collapsed or collapsed[-1] != value:
            collapsed.append(value)
    return collapsed


def _canonical_attack_ids(steps: list[dict[str, str]], technique_lookup: dict[str, tuple[int, str]]) -> tuple[list[str], list[str]]:
    mapped_attack_ids: list[str] = []
    missing_attack_ids: list[str] = []
    for step in steps:
        attack_id = step["attack_id"]
        if attack_id in technique_lookup:
            mapped_attack_ids.append(attack_id)
        else:
            missing_attack_ids.append(attack_id)
    unique_ids = list(dict.fromkeys(_collapse_adjacent_duplicates(mapped_attack_ids)))
    return unique_ids, sorted(dict.fromkeys(missing_attack_ids))


def _relative_paths_from_artifact(artifact: sqlite3.Row) -> tuple[Path, list[str]]:
    extracted_files = json.loads(artifact["extracted_files_json"] or "[]")
    source_path = Path(artifact["file_path"])
    source_root = source_path if source_path.is_dir() else source_path.parent
    return source_root, [str(path) for path in extracted_files]


def _resolve_actor_answer_key(
    details: dict[str, Any],
    path: Path,
    actor_lookup: dict[str, str],
) -> str | None:
    candidates = [
        _coerce_string(details.get("adversary_name")),
        path.stem,
    ]
    for parent_name in reversed(path.parts[:-1]):
        candidates.append(parent_name.replace("_", " "))
    for candidate in candidates:
        match = GROUP_ATTACK_ID_PATTERN.search(candidate or "")
        if match is not None:
            return match.group(0).upper()
        normalized = normalize_actor_name(candidate)
        if normalized and normalized in actor_lookup:
            return actor_lookup[normalized]
    return None


def _extract_steps(payload: Any) -> tuple[dict[str, Any], list[dict[str, str]]]:
    details: dict[str, Any] = {}
    steps: list[dict[str, str]] = []
    if not isinstance(payload, list):
        return details, steps
    for item in payload:
        if not isinstance(item, dict):
            continue
        if "emulation_plan_details" in item and isinstance(item["emulation_plan_details"], dict):
            details = dict(item["emulation_plan_details"])
            continue
        technique = item.get("technique")
        if not isinstance(technique, dict):
            continue
        attack_id = _coerce_string(technique.get("attack_id"))
        procedure_step = _coerce_string(item.get("procedure_step"))
        if not attack_id or not procedure_step:
            continue
        steps.append(
            {
                "attack_id": attack_id.upper(),
                "procedure_step": procedure_step,
                "technique_name": _coerce_string(technique.get("name")) or attack_id.upper(),
                "source_url": _coerce_string(item.get("cti_source")),
            }
        )
    steps.sort(key=lambda row: (_procedure_sort_key(row["procedure_step"]), row["attack_id"]))
    return details, steps


def ingest_emulation_plans(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    ingest_run_id = start_ingest_run(connection, snapshot_id, "ingest-emulation-plans", "emulation_plans")
    actor_lookup, actor_labels, actor_ids = load_actor_name_lookup(connection)
    technique_lookup = load_technique_lookup(connection)
    counts = {
        "sources": 0,
        "plans": 0,
        "operations": 0,
        "operation_actors": 0,
        "timelines": 0,
        "timeline_steps": 0,
        "skipped_plans": 0,
        "skipped_segments": 0,
    }

    try:
        clear_timeline_source_rows(connection, *EMULATION_SOURCE_NAMES)
        for source_name in EMULATION_SOURCE_NAMES:
            clear_unresolved_matches(connection, snapshot_id, source_name)
            artifact = get_source_artifact(connection, snapshot_id, source_name)
            if artifact is None:
                continue
            counts["sources"] += 1
            source_root, extracted_files = _relative_paths_from_artifact(artifact)
            for relative_path in extracted_files:
                path = source_root / relative_path
                payload = _load_yaml_file(path)
                details, steps = _extract_steps(payload)
                if not steps:
                    counts["skipped_plans"] += 1
                    continue
                actor_answer_key = _resolve_actor_answer_key(details, Path(relative_path), actor_lookup)
                if actor_answer_key is None or actor_answer_key not in actor_ids:
                    record_unresolved_match(
                        connection,
                        snapshot_id=snapshot_id,
                        source_name=source_name,
                        external_key=relative_path,
                        candidate_key=None,
                        reason="unmapped_actor",
                        detail={"adversary_name": details.get("adversary_name"), "path": relative_path},
                    )
                    counts["skipped_plans"] += 1
                    continue
                counts["plans"] += 1
                plan_name = _coerce_string(details.get("adversary_name")) or Path(relative_path).stem
                plan_description = _coerce_string(details.get("adversary_description"))
                grouped_steps: dict[str, list[dict[str, str]]] = {}
                for step in steps:
                    segment = _segment_key(step["procedure_step"])
                    if not segment:
                        continue
                    grouped_steps.setdefault(segment, []).append(step)
                valid_segments: list[tuple[str, list[str], str | None]] = []
                for segment_key in sorted(grouped_steps, key=_procedure_sort_key):
                    attack_ids, missing_attack_ids = _canonical_attack_ids(grouped_steps[segment_key], technique_lookup)
                    if missing_attack_ids:
                        record_unresolved_match(
                            connection,
                            snapshot_id=snapshot_id,
                            source_name=source_name,
                            external_key=f"{relative_path}:{segment_key}",
                            candidate_key=actor_answer_key,
                            reason="unmapped_technique",
                            detail={"attack_ids": missing_attack_ids},
                        )
                    if not 3 <= len(attack_ids) <= 8:
                        counts["skipped_segments"] += 1
                        continue
                    source_url = next(
                        (step["source_url"] for step in grouped_steps[segment_key] if step.get("source_url")),
                        None,
                    )
                    valid_segments.append((segment_key, attack_ids, source_url))
                if not valid_segments:
                    counts["skipped_plans"] += 1
                    continue
                operation_source_id = f"{source_name}:{relative_path}"
                with connection:
                    cursor = connection.execute(
                        """
                        INSERT INTO operations (
                            source_flow_id,
                            name,
                            description,
                            source_url,
                            timeline_source_type
                        )
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            operation_source_id,
                            plan_name,
                            plan_description,
                            next((source_url for _, _, source_url in valid_segments if source_url), None),
                            source_name,
                        ),
                    )
                    operation_id = int(cursor.lastrowid)
                    connection.execute(
                        """
                        INSERT OR IGNORE INTO operation_actors (operation_id, actor_id)
                        VALUES (?, ?)
                        """,
                        (operation_id, actor_ids[actor_answer_key]),
                    )
                counts["operations"] += 1
                counts["operation_actors"] += 1
                for segment_key, attack_ids, source_url in valid_segments:
                    flow_name = f"{plan_name} {segment_key}"
                    path_hash = hashlib.sha1(
                        f"{source_name}|{relative_path}|{segment_key}|{'|'.join(attack_ids)}".encode("utf-8")
                    ).hexdigest()
                    difficulty = "easy" if len(attack_ids) == 3 else "standard"
                    with connection:
                        cursor = connection.execute(
                            """
                            INSERT INTO timelines (
                                source_flow_id,
                                flow_name,
                                source_url,
                                answer_type,
                                answer_key,
                                answer_label,
                                difficulty,
                                step_count,
                                timeline_source_type,
                                path_hash
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                f"{operation_source_id}:{segment_key}",
                                flow_name,
                                source_url,
                                "actor",
                                actor_answer_key,
                                actor_labels[actor_answer_key],
                                difficulty,
                                len(attack_ids),
                                source_name,
                                path_hash,
                            ),
                        )
                        timeline_id = int(cursor.lastrowid)
                        for step_index, attack_id in enumerate(attack_ids, start=1):
                            technique_id, technique_name = technique_lookup[attack_id]
                            connection.execute(
                                """
                                INSERT INTO timeline_steps (
                                    timeline_id,
                                    step_index,
                                    technique_id,
                                    attack_id,
                                    technique_name
                                )
                                VALUES (?, ?, ?, ?, ?)
                                """,
                                (timeline_id, step_index, technique_id, attack_id, technique_name),
                            )
                            counts["timeline_steps"] += 1
                    counts["timelines"] += 1

        finish_ingest_run(
            connection,
            ingest_run_id,
            status="completed",
            row_count=counts["timelines"] + counts["timeline_steps"],
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
