"""Curated flow timeline ingest."""

from __future__ import annotations

from collections import deque
import hashlib
import json
from pathlib import Path
import re
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
from threatdle.ingest.timeline_common import clear_timeline_source_rows, load_actor_name_lookup, load_technique_lookup
from threatdle.normalize.text import normalize_actor_name


ATTACK_FLOW_OBJECT = "attack-flow"
ATTACK_ACTION_OBJECT = "attack-action"
PASS_THROUGH_OBJECT_TYPES = {"attack-condition", "attack-operator"}
GROUP_OBJECT_TYPES = {"intrusion-set", "threat-actor"}
RELATIONSHIP_OBJECT = "relationship"
FLOW_EDGE_RELATIONSHIP_TYPES = {"effect"}
FLOW_ATTRIBUTION_RELATIONSHIP_TYPES = {"attributed-to", "uses", "related-to"}
ATTACK_ID_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{1,3})?\b", re.IGNORECASE)
GROUP_ATTACK_ID_PATTERN = re.compile(r"\bG\d{4}\b", re.IGNORECASE)


def _coerce_string(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_ref_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if _coerce_string(item)]
    text = _coerce_string(value)
    return [text] if text else []


def _is_relevant_flow_node(obj: dict[str, Any] | None) -> bool:
    if not isinstance(obj, dict):
        return False
    object_type = obj.get("type")
    return object_type in PASS_THROUGH_OBJECT_TYPES | {ATTACK_ACTION_OBJECT}


def _extract_attack_ids_from_value(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, dict):
        candidates: list[str] = []
        for nested_key in ("attack_id", "technique_id", "external_id", "id", "value", "name"):
            if nested_key in value:
                candidates.extend(_extract_attack_ids_from_value(value.get(nested_key)))
        for nested_key, nested_value in value.items():
            if nested_key in {"attack_id", "technique_id", "external_id", "id", "value", "name"}:
                continue
            if isinstance(nested_value, (dict, list, str)):
                candidates.extend(_extract_attack_ids_from_value(nested_value))
        return candidates
    if isinstance(value, list):
        candidates: list[str] = []
        for item in value:
            candidates.extend(_extract_attack_ids_from_value(item))
        return candidates
    text = _coerce_string(value)
    if not text:
        return []
    return [match.group(0).upper() for match in ATTACK_ID_PATTERN.finditer(text)]


def _extract_action_attack_ids(action_object: dict[str, Any]) -> tuple[str, ...]:
    candidates: list[str] = []
    for key in ("technique_id", "attack_id", "technique", "technique_ref"):
        candidates.extend(_extract_attack_ids_from_value(action_object.get(key)))
    for reference in action_object.get("external_references", []):
        candidates.extend(_extract_attack_ids_from_value(reference))
    normalized = [value for value in dict.fromkeys(candidates) if value.startswith("T")]
    return tuple(normalized)


def _extract_group_attack_id(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        for key in ("group_attack_id", "external_id", "attack_group_id"):
            resolved = _extract_group_attack_id(value.get(key))
            if resolved:
                return resolved
        for reference in value.get("external_references", []) if isinstance(value.get("external_references"), list) else []:
            resolved = _extract_group_attack_id(reference)
            if resolved:
                return resolved
        return None
    if isinstance(value, list):
        for item in value:
            resolved = _extract_group_attack_id(item)
            if resolved:
                return resolved
        return None
    text = _coerce_string(value)
    if not text:
        return None
    match = GROUP_ATTACK_ID_PATTERN.search(text)
    return match.group(0).upper() if match is not None else None


def _build_group_ref_map(objects: list[dict[str, Any]], actor_lookup: dict[str, str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") not in GROUP_OBJECT_TYPES:
            continue
        group_attack_id = _extract_group_attack_id(obj)
        if not group_attack_id:
            normalized_name = normalize_actor_name(_coerce_string(obj.get("name")))
            if normalized_name:
                group_attack_id = actor_lookup.get(normalized_name)
        object_id = _coerce_string(obj.get("id"))
        if object_id and group_attack_id:
            mapping[object_id] = group_attack_id
    return mapping


def _extract_source_url(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    direct = _coerce_string(value.get("source_url") or value.get("url"))
    if direct:
        return direct
    for reference in value.get("external_references", []):
        if not isinstance(reference, dict):
            continue
        url = _coerce_string(reference.get("url"))
        if url:
            return url
    return None


def _infer_root_refs(flow_object: dict[str, Any], object_index: dict[str, dict[str, Any]], adjacency: dict[str, tuple[str, ...]]) -> list[str]:
    start_refs = _coerce_ref_list(flow_object.get("start_refs"))
    if start_refs:
        return start_refs
    relevant_ids = {
        object_id
        for object_id, obj in object_index.items()
        if obj.get("type") in PASS_THROUGH_OBJECT_TYPES | {ATTACK_ACTION_OBJECT}
    }
    inbound_counts = {object_id: 0 for object_id in relevant_ids}
    for source_ref, targets in adjacency.items():
        if source_ref not in relevant_ids:
            continue
        for target_ref in targets:
            if target_ref in inbound_counts:
                inbound_counts[target_ref] += 1
    return sorted(object_id for object_id, inbound_count in inbound_counts.items() if inbound_count == 0)


def _relationship_graph(
    flow_id: str,
    object_index: dict[str, dict[str, Any]],
) -> tuple[dict[str, list[str]], list[str], list[str]]:
    adjacency: dict[str, list[str]] = {}
    start_refs: list[str] = []
    group_refs: list[str] = []
    for obj in object_index.values():
        if obj.get("type") != RELATIONSHIP_OBJECT:
            continue
        relationship_type = _coerce_string(obj.get("relationship_type"))
        source_ref = _coerce_string(obj.get("source_ref"))
        target_ref = _coerce_string(obj.get("target_ref"))
        if not relationship_type or not source_ref or not target_ref:
            continue
        if relationship_type in FLOW_EDGE_RELATIONSHIP_TYPES:
            if source_ref == flow_id and object_index.get(target_ref, {}).get("type") == ATTACK_ACTION_OBJECT:
                start_refs.append(target_ref)
                continue
            if (
                object_index.get(source_ref, {}).get("type") == ATTACK_ACTION_OBJECT
                and object_index.get(target_ref, {}).get("type") in PASS_THROUGH_OBJECT_TYPES | {ATTACK_ACTION_OBJECT}
            ):
                adjacency.setdefault(source_ref, []).append(target_ref)
        if relationship_type in FLOW_ATTRIBUTION_RELATIONSHIP_TYPES:
            if source_ref == flow_id and object_index.get(target_ref, {}).get("type") in GROUP_OBJECT_TYPES:
                group_refs.append(target_ref)
            elif target_ref == flow_id and object_index.get(source_ref, {}).get("type") in GROUP_OBJECT_TYPES:
                group_refs.append(source_ref)
    return adjacency, list(dict.fromkeys(start_refs)), list(dict.fromkeys(group_refs))


def _find_first_actions(start_refs: list[str], object_index: dict[str, dict[str, Any]], adjacency: dict[str, tuple[str, ...]]) -> list[str]:
    roots: set[str] = set()
    queue = deque(start_refs)
    visited: set[str] = set()
    while queue:
        ref = queue.popleft()
        if ref in visited:
            continue
        visited.add(ref)
        obj = object_index.get(ref)
        if obj is None:
            continue
        object_type = obj.get("type")
        if object_type == ATTACK_ACTION_OBJECT:
            roots.add(ref)
            continue
        if object_type not in PASS_THROUGH_OBJECT_TYPES:
            continue
        for target_ref in adjacency.get(ref, ()):
            queue.append(target_ref)
    return sorted(roots)


def _find_next_actions(action_ref: str, object_index: dict[str, dict[str, Any]], adjacency: dict[str, tuple[str, ...]]) -> list[str]:
    next_actions: set[str] = set()
    queue = deque(adjacency.get(action_ref, ()))
    visited: set[str] = set()
    while queue:
        ref = queue.popleft()
        if ref in visited or ref == action_ref:
            continue
        visited.add(ref)
        obj = object_index.get(ref)
        if obj is None:
            continue
        object_type = obj.get("type")
        if object_type == ATTACK_ACTION_OBJECT:
            next_actions.add(ref)
            continue
        if object_type not in PASS_THROUGH_OBJECT_TYPES:
            continue
        for target_ref in adjacency.get(ref, ()):
            queue.append(target_ref)
    return sorted(next_actions)


def _collapse_adjacent_duplicates(values: list[str]) -> list[str]:
    collapsed: list[str] = []
    for value in values:
        if not collapsed or collapsed[-1] != value:
            collapsed.append(value)
    return collapsed


def _derive_paths_for_flow(flow_object: dict[str, Any], object_index: dict[str, dict[str, Any]]) -> list[list[str]]:
    adjacency: dict[str, tuple[str, ...]] = {
        object_id: tuple(_coerce_ref_list(obj.get("effect_refs")))
        for object_id, obj in object_index.items()
    }
    relationship_adjacency, relationship_start_refs, _ = _relationship_graph(str(flow_object["id"]), object_index)
    for source_ref, target_refs in relationship_adjacency.items():
        merged = list(adjacency.get(source_ref, ()))
        for target_ref in target_refs:
            if target_ref not in merged:
                merged.append(target_ref)
        adjacency[source_ref] = tuple(merged)
    start_refs = _coerce_ref_list(flow_object.get("start_refs")) or relationship_start_refs
    if not start_refs:
        start_refs = _infer_root_refs(flow_object, object_index, adjacency)
    root_actions = _find_first_actions(start_refs, object_index, adjacency)
    paths: list[list[str]] = []

    def visit(action_ref: str, current_path: list[str], seen_refs: set[str]) -> None:
        if action_ref in seen_refs:
            return
        action_object = object_index.get(action_ref)
        if action_object is None:
            return
        attack_ids = list(_extract_action_attack_ids(action_object))
        if attack_ids:
            expanded_paths = [current_path + [attack_id] for attack_id in attack_ids]
        else:
            expanded_paths = [current_path]
        next_actions = _find_next_actions(action_ref, object_index, adjacency)
        if not next_actions:
            for path in expanded_paths:
                collapsed = _collapse_adjacent_duplicates(path)
                if collapsed:
                    paths.append(collapsed)
            return
        for path in expanded_paths:
            for next_ref in next_actions:
                visit(next_ref, path, seen_refs | {action_ref})

    for root_action in root_actions:
        visit(root_action, [], set())
    unique_paths: list[list[str]] = []
    seen: set[tuple[str, ...]] = set()
    for path in paths:
        path_key = tuple(path)
        if path_key not in seen:
            seen.add(path_key)
            unique_paths.append(path)
    return unique_paths


def _resolve_group_ids(flow_object: dict[str, Any], object_index: dict[str, dict[str, Any]], group_ref_map: dict[str, str]) -> list[str]:
    candidates: set[str] = set()
    direct_group_attack_id = _extract_group_attack_id(flow_object)
    if direct_group_attack_id:
        candidates.add(direct_group_attack_id)
    _, _, relationship_group_refs = _relationship_graph(str(flow_object["id"]), object_index)
    for ref in relationship_group_refs:
        attack_group_id = group_ref_map.get(ref)
        if attack_group_id:
            candidates.add(attack_group_id)
    for ref_key, ref_value in flow_object.items():
        if not ref_key.endswith("_ref") and not ref_key.endswith("_refs"):
            continue
        for ref in _coerce_ref_list(ref_value):
            attack_group_id = group_ref_map.get(ref)
            if attack_group_id:
                candidates.add(attack_group_id)
    if candidates:
        return sorted(candidates)
    unique_groups = sorted(set(group_ref_map.values()))
    if len(unique_groups) == 1:
        return unique_groups
    return []


def ingest_attack_flow(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    artifact = get_source_artifact(connection, snapshot_id, "curated_flows")
    if artifact is None:
        raise ValueError(f"Snapshot {snapshot_id} is missing curated flow source artifact")
    ingest_run_id = start_ingest_run(connection, snapshot_id, "ingest-attack-flow", "curated_flows")
    clear_unresolved_matches(connection, snapshot_id, "curated_flows")
    actor_lookup, actor_labels, actor_ids = load_actor_name_lookup(connection)
    technique_lookup = load_technique_lookup(connection)
    extracted_files = json.loads(artifact["extracted_files_json"] or "[]")
    source_path = Path(artifact["file_path"])
    source_root = source_path if source_path.is_dir() else source_path.parent
    counts = {"operations": 0, "operation_actors": 0, "timelines": 0, "timeline_steps": 0, "skipped_paths": 0}

    try:
        clear_timeline_source_rows(connection, "curated_flows")

        for relative_path in extracted_files:
            path = source_root / relative_path
            payload = load_json_file(path)
            if not isinstance(payload, dict):
                continue
            object_index = {
                str(obj["id"]): obj
                for obj in payload.get("objects", [])
                if isinstance(obj, dict) and obj.get("id")
            }
            flow_objects = [obj for obj in object_index.values() if obj.get("type") == ATTACK_FLOW_OBJECT]
            if not flow_objects:
                continue
            group_ref_map = _build_group_ref_map(list(object_index.values()), actor_lookup)
            for flow_object in flow_objects:
                flow_name = _coerce_string(flow_object.get("name")) or path.stem
                source_url = _extract_source_url(flow_object)
                group_attack_ids = _resolve_group_ids(flow_object, object_index, group_ref_map)
                raw_paths = _derive_paths_for_flow(flow_object, object_index)
                valid_paths: list[list[str]] = []
                for raw_path in raw_paths:
                    unique_ids = list(dict.fromkeys(raw_path))
                    if not 3 <= len(unique_ids) <= 8:
                        counts["skipped_paths"] += 1
                        continue
                    missing = [attack_id for attack_id in unique_ids if attack_id not in technique_lookup]
                    if missing:
                        record_unresolved_match(
                            connection,
                            snapshot_id=snapshot_id,
                            source_name="curated_flows",
                            external_key=f"{flow_name}:{'|'.join(unique_ids)}",
                            candidate_key=None,
                            reason="unmapped_technique",
                            detail={"attack_ids": missing},
                        )
                        counts["skipped_paths"] += 1
                        continue
                    valid_paths.append(unique_ids)
                if not valid_paths:
                    continue
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
                            str(flow_object["id"]),
                            flow_name,
                            _coerce_string(flow_object.get("description")),
                            source_url,
                            "curated_flows",
                        ),
                    )
                    operation_id = int(cursor.lastrowid)
                    for group_attack_id in group_attack_ids:
                        actor_id = actor_ids.get(group_attack_id)
                        if actor_id is None:
                            continue
                        connection.execute(
                            """
                            INSERT OR IGNORE INTO operation_actors (operation_id, actor_id)
                            VALUES (?, ?)
                            """,
                            (operation_id, actor_id),
                        )
                        counts["operation_actors"] += 1
                counts["operations"] += 1
                for unique_ids in valid_paths:
                    path_hash = hashlib.sha1("|".join(unique_ids).encode("utf-8")).hexdigest()
                    answer_type = "incident"
                    answer_key = f"{flow_object['id']}:{path_hash}"
                    answer_label = flow_name
                    if len(group_attack_ids) == 1 and group_attack_ids[0] in actor_labels:
                        answer_type = "actor"
                        answer_key = group_attack_ids[0]
                        answer_label = actor_labels[group_attack_ids[0]]
                    difficulty = "easy" if len(unique_ids) == 3 else "standard"
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
                                str(flow_object["id"]),
                                flow_name,
                                source_url,
                                answer_type,
                                answer_key,
                                answer_label,
                                difficulty,
                                len(unique_ids),
                                "curated_flows",
                                path_hash,
                            ),
                        )
                        timeline_id = int(cursor.lastrowid)
                        for step_index, attack_id in enumerate(unique_ids, start=1):
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
