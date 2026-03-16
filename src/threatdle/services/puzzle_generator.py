"""Daily puzzle generation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
import json
import random
import sqlite3
from typing import Any

from threatdle.db.repositories import get_snapshot
from threatdle.ingest.base import now_utc_iso


CHAIN_MODES = {"linked", "exact"}
THEME_MODES = {"off", "prefer", "strict"}
MODE_ORDER = ("actor", "malware", "technique")
EXACT_INCIDENT_REPEAT_WINDOW_DAYS = 21
REPEAT_WINDOWS = {
    "actor": 14,
    "timeline": 21,
    "malware": 21,
    "technique": 10,
}


@dataclass(frozen=True)
class CandidateRow:
    mode: str
    answer_key: str
    answer_label: str
    payload: dict[str, Any]
    provenance: dict[str, Any]
    row_id: int
    difficulty: str | None = None
    clue_score: int | None = None
    summary_tier: int | None = None
    answer_type: str | None = None
    linked_actor_ids: tuple[str, ...] = ()
    repeat_key: str | None = None


@dataclass(frozen=True)
class IncidentCandidateRow:
    timeline_id: int
    actor_answer_key: str
    actor_answer_label: str
    malware_answer_keys: tuple[str, ...]
    technique_attack_ids: tuple[str, ...]
    difficulty: str
    repeat_key: str
    provenance: dict[str, Any]
    attack_campaign_id: str | None = None
    source_article_url: str | None = None
    source_article_title: str | None = None


def _loads_json(value: str | None, *, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


def _parse_day_key(day_key: str) -> date:
    return date.fromisoformat(day_key)


def _day_rng(snapshot_id: str, day_key: str) -> random.Random:
    payload = hashlib.sha256(f"{snapshot_id}:{day_key}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(payload, "big"))


def _mode_rng(snapshot_id: str, day_key: str, mode: str) -> random.Random:
    payload = hashlib.sha256(f"{snapshot_id}:{day_key}:{mode}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(payload, "big"))


def _stable_sort_key(candidate: CandidateRow) -> tuple[Any, ...]:
    return (
        candidate.answer_key,
        candidate.answer_label,
        candidate.row_id,
    )


def _candidate_repeat_key(candidate: CandidateRow) -> str:
    return str(candidate.repeat_key or candidate.answer_key)


def _pick_candidate(candidates: list[CandidateRow], rng: random.Random) -> CandidateRow:
    ordered = sorted(candidates, key=_stable_sort_key)
    return ordered[rng.randrange(len(ordered))]


def _repeat_answer_keys(connection: sqlite3.Connection, mode: str, day_key: str) -> set[str]:
    window_days = REPEAT_WINDOWS[mode]
    start_day = (_parse_day_key(day_key) - timedelta(days=window_days)).isoformat()
    rows = connection.execute(
        """
        SELECT COALESCE(
            json_extract(answer_json, '$.repeat_key'),
            json_extract(answer_json, '$.answer_key')
        ) AS repeat_key
        FROM puzzle_day
        WHERE mode = ?
          AND day_key >= ?
          AND day_key < ?
        """,
        (mode, start_day, day_key),
    ).fetchall()
    return {str(row["repeat_key"]) for row in rows if row["repeat_key"] is not None}


def _delete_existing_day(connection: sqlite3.Connection, day_key: str) -> int:
    with connection:
        cursor = connection.execute("DELETE FROM puzzle_day WHERE day_key = ?", (day_key,))
    return int(cursor.rowcount)


def _existing_day_modes(connection: sqlite3.Connection, day_key: str) -> list[str]:
    rows = connection.execute(
        "SELECT mode FROM puzzle_day WHERE day_key = ? ORDER BY mode",
        (day_key,),
    ).fetchall()
    return [str(row["mode"]) for row in rows]


def _require_ready_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> None:
    snapshot = get_snapshot(connection, snapshot_id)
    if snapshot is None:
        raise ValueError(f"Unknown snapshot {snapshot_id}")
    if snapshot["status"] != "ready":
        raise ValueError(f"Snapshot {snapshot_id} is not ready; current status is {snapshot['status']}")


def _load_actor_candidates(connection: sqlite3.Connection, snapshot_id: str) -> list[CandidateRow]:
    rows = connection.execute(
        """
        SELECT
            ac.actor_id,
            ac.answer_key,
            ac.answer_label,
            ac.difficulty,
            ac.clue_score,
            ap.clue_payload_json,
            ap.provenance_json
        FROM actor_candidates_v1 ac
        JOIN actor_profiles_v1 ap
          ON ap.snapshot_id = ac.snapshot_id AND ap.actor_id = ac.actor_id
        WHERE ac.snapshot_id = ?
        ORDER BY ac.answer_label
        """,
        (snapshot_id,),
    ).fetchall()
    return [
        CandidateRow(
            mode="actor",
            answer_key=str(row["answer_key"]),
            answer_label=str(row["answer_label"]),
            payload=_loads_json(row["clue_payload_json"], default={}),
            provenance=_loads_json(row["provenance_json"], default={}),
            row_id=int(row["actor_id"]),
            difficulty=str(row["difficulty"]),
            clue_score=int(row["clue_score"]),
            linked_actor_ids=(str(row["answer_key"]),),
            repeat_key=str(row["answer_key"]),
        )
        for row in rows
    ]


def _load_malware_candidates(connection: sqlite3.Connection, snapshot_id: str) -> list[CandidateRow]:
    rows = connection.execute(
        """
        SELECT
            mc.malware_id,
            mc.answer_key,
            mc.answer_label,
            mc.summary_tier,
            mp.clue_payload_json,
            mp.provenance_json
        FROM malware_candidates_v1 mc
        JOIN malware_profiles_v1 mp
          ON mp.snapshot_id = mc.snapshot_id AND mp.malware_id = mc.malware_id
        WHERE mc.snapshot_id = ?
        ORDER BY mc.answer_label
        """,
        (snapshot_id,),
    ).fetchall()
    candidates: list[CandidateRow] = []
    for row in rows:
        linked_rows = connection.execute(
            """
            SELECT DISTINCT a.attack_group_id
            FROM actor_malware am
            JOIN actors a ON a.actor_id = am.actor_id
            WHERE am.malware_id = ?
            ORDER BY a.attack_group_id
            """,
            (row["malware_id"],),
        ).fetchall()
        candidates.append(
            CandidateRow(
                mode="malware",
                answer_key=str(row["answer_key"]),
                answer_label=str(row["answer_label"]),
                payload=_loads_json(row["clue_payload_json"], default={}),
                provenance=_loads_json(row["provenance_json"], default={}),
                row_id=int(row["malware_id"]),
                summary_tier=int(row["summary_tier"]),
                linked_actor_ids=tuple(str(linked["attack_group_id"]) for linked in linked_rows),
                repeat_key=str(row["answer_key"]),
            )
        )
    return candidates


def _load_technique_candidates(connection: sqlite3.Connection, snapshot_id: str) -> list[CandidateRow]:
    rows = connection.execute(
        """
        SELECT
            tc.technique_id,
            tc.answer_key,
            tc.answer_label,
            tp.clue_payload_json,
            tp.provenance_json
        FROM technique_candidates_v1 tc
        JOIN technique_profiles_v1 tp
          ON tp.snapshot_id = tc.snapshot_id AND tp.technique_id = tc.technique_id
        WHERE tc.snapshot_id = ?
        ORDER BY tc.answer_key
        """,
        (snapshot_id,),
    ).fetchall()
    candidates: list[CandidateRow] = []
    for row in rows:
        linked_rows = connection.execute(
            """
            SELECT DISTINCT a.attack_group_id
            FROM actor_techniques at
            JOIN actors a ON a.actor_id = at.actor_id
            WHERE at.technique_id = ?
            ORDER BY a.attack_group_id
            """,
            (row["technique_id"],),
        ).fetchall()
        candidates.append(
            CandidateRow(
                mode="technique",
                answer_key=str(row["answer_key"]),
                answer_label=str(row["answer_label"]),
                payload=_loads_json(row["clue_payload_json"], default={}),
                provenance=_loads_json(row["provenance_json"], default={}),
                row_id=int(row["technique_id"]),
                linked_actor_ids=tuple(str(linked["attack_group_id"]) for linked in linked_rows),
                repeat_key=str(row["answer_key"]),
            )
        )
    return candidates


def _load_timeline_candidates(connection: sqlite3.Connection, snapshot_id: str) -> list[CandidateRow]:
    rows = connection.execute(
        """
        SELECT
            tc.timeline_id,
            tc.answer_type,
            tc.answer_key,
            tc.answer_label,
            tc.difficulty,
            ts.steps_json,
            ts.provenance_json
        FROM timeline_candidates_v1 tc
        JOIN timeline_sequences_v1 ts
          ON ts.snapshot_id = tc.snapshot_id AND ts.timeline_id = tc.timeline_id
        WHERE tc.snapshot_id = ?
        ORDER BY tc.timeline_id
        """,
        (snapshot_id,),
    ).fetchall()
    return [
        CandidateRow(
            mode="timeline",
            answer_key=str(row["answer_key"]),
            answer_label=str(row["answer_label"]),
            payload={"steps": _loads_json(row["steps_json"], default=[])},
            provenance=_loads_json(row["provenance_json"], default={}),
            row_id=int(row["timeline_id"]),
            difficulty=str(row["difficulty"]),
            answer_type=str(row["answer_type"]),
            linked_actor_ids=((str(row["answer_key"]),) if str(row["answer_type"]) == "actor" else ()),
            repeat_key=_timeline_repeat_key(
                int(row["timeline_id"]),
                _loads_json(row["steps_json"], default=[]),
                _loads_json(row["provenance_json"], default={}),
            ),
        )
        for row in rows
    ]


def _load_incident_candidates(connection: sqlite3.Connection, snapshot_id: str) -> list[IncidentCandidateRow]:
    rows = connection.execute(
        """
        SELECT
            timeline_id,
            actor_answer_key,
            actor_answer_label,
            malware_answer_keys_json,
            technique_attack_ids_json,
            difficulty,
            repeat_key,
            attack_campaign_id,
            source_article_url,
            source_article_title,
            provenance_json
        FROM incident_candidates_v1
        WHERE snapshot_id = ?
        ORDER BY timeline_id
        """,
        (snapshot_id,),
    ).fetchall()
    return [
        IncidentCandidateRow(
            timeline_id=int(row["timeline_id"]),
            actor_answer_key=str(row["actor_answer_key"]),
            actor_answer_label=str(row["actor_answer_label"]),
            malware_answer_keys=tuple(str(value) for value in _loads_json(row["malware_answer_keys_json"], default=[])),
            technique_attack_ids=tuple(str(value) for value in _loads_json(row["technique_attack_ids_json"], default=[])),
            difficulty=str(row["difficulty"]),
            repeat_key=str(row["repeat_key"]),
            attack_campaign_id=(str(row["attack_campaign_id"]) if row["attack_campaign_id"] else None),
            source_article_url=(str(row["source_article_url"]) if row["source_article_url"] else None),
            source_article_title=(str(row["source_article_title"]) if row["source_article_title"] else None),
            provenance=_loads_json(row["provenance_json"], default={}),
        )
        for row in rows
    ]


def _timeline_repeat_key(timeline_id: int, steps: list[dict[str, Any]], provenance: dict[str, Any]) -> str:
    step_attack_ids = "|".join(str(step.get("attack_id") or "") for step in steps)
    path_hash = hashlib.sha1(step_attack_ids.encode("utf-8")).hexdigest()
    source_flow_id = provenance.get("source_flow_id")
    if source_flow_id:
        return f"{source_flow_id}:{path_hash}"
    return f"timeline:{timeline_id}:{path_hash}"


def _timeline_attack_ids(candidate: CandidateRow) -> set[str]:
    return {
        str(step.get("attack_id"))
        for step in list(candidate.payload.get("steps") or [])
        if step.get("attack_id")
    }


def load_candidate_pools(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, list[CandidateRow]]:
    _require_ready_snapshot(connection, snapshot_id)
    pools = {
        "actor": _load_actor_candidates(connection, snapshot_id),
        "malware": _load_malware_candidates(connection, snapshot_id),
        "technique": _load_technique_candidates(connection, snapshot_id),
        "timeline": _load_timeline_candidates(connection, snapshot_id),
    }
    missing = [mode for mode in MODE_ORDER if not pools[mode]]
    if missing:
        raise ValueError(f"Snapshot {snapshot_id} has no candidates for modes: {', '.join(sorted(missing))}")
    return pools


def _repeat_exact_incident_keys(connection: sqlite3.Connection, day_key: str) -> set[str]:
    start_day = (_parse_day_key(day_key) - timedelta(days=EXACT_INCIDENT_REPEAT_WINDOW_DAYS)).isoformat()
    rows = connection.execute(
        """
        SELECT DISTINCT json_extract(answer_json, '$.repeat_key') AS repeat_key
        FROM puzzle_day
        WHERE mode = 'actor'
          AND day_key >= ?
          AND day_key < ?
          AND json_extract(answer_json, '$.chain_mode') = 'exact'
          AND json_extract(answer_json, '$.repeat_key') IS NOT NULL
        """,
        (start_day, day_key),
    ).fetchall()
    return {str(row["repeat_key"]) for row in rows if row["repeat_key"] is not None}


def _select_exact_incident_day(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    pools: dict[str, list[CandidateRow]],
) -> tuple[dict[str, CandidateRow], IncidentCandidateRow]:
    incidents = _load_incident_candidates(connection, snapshot_id)
    if not incidents:
        raise ValueError(f"Snapshot {snapshot_id} has no incident candidates for exact generation")

    actor_candidates = {
        candidate.answer_key: candidate
        for candidate in _apply_quality_gate("actor", pools["actor"])
    }
    malware_candidates = {
        candidate.answer_key: candidate
        for candidate in _apply_quality_gate("malware", pools["malware"])
    }
    technique_candidates = {
        candidate.answer_key: candidate
        for candidate in _apply_quality_gate("technique", pools["technique"])
    }
    repeated_incident_keys = _repeat_exact_incident_keys(connection, day_key)
    available: list[tuple[IncidentCandidateRow, dict[str, CandidateRow]]] = []
    for incident in incidents:
        if incident.repeat_key in repeated_incident_keys:
            continue
        actor_candidate = actor_candidates.get(incident.actor_answer_key)
        if actor_candidate is None:
            continue
        malware_options = [
            malware_candidates[key]
            for key in incident.malware_answer_keys
            if key in malware_candidates
        ]
        if not malware_options:
            continue
        tier_one_malware = [candidate for candidate in malware_options if candidate.summary_tier == 1]
        malware_pool = tier_one_malware or malware_options
        malware_candidate = _pick_candidate(
            malware_pool,
            _mode_rng(snapshot_id, day_key, "malware"),
        )
        technique_options = [
            technique_candidates[key]
            for key in incident.technique_attack_ids
            if key in technique_candidates
        ]
        if not technique_options:
            continue
        technique_candidate = _pick_candidate(
            technique_options,
            _mode_rng(snapshot_id, day_key, "technique"),
        )
        available.append(
            (
                incident,
                {
                    "actor": actor_candidate,
                    "malware": malware_candidate,
                    "technique": technique_candidate,
                },
            )
        )
    if not available:
        raise ValueError(f"Exact incident generation failed for {day_key}: no unused exact incidents available")
    available.sort(key=lambda item: item[0].repeat_key)
    selected_incident, selected_rows = available[_day_rng(snapshot_id, day_key).randrange(len(available))]
    return selected_rows, selected_incident


def _passes_actor_quality(candidate: CandidateRow) -> bool:
    payload = candidate.payload
    return (
        bool(payload.get("country_code"))
        and payload.get("first_observed_year") is not None
        and bool(payload.get("target_categories"))
        and bool(payload.get("motivation_tags"))
    )


def _passes_malware_quality(candidate: CandidateRow) -> bool:
    summary = str(candidate.payload.get("capability_summary") or "").strip()
    return len(summary) >= 20


def _passes_technique_quality(candidate: CandidateRow) -> bool:
    platforms = list(candidate.payload.get("platforms") or [])
    tactics = list(candidate.payload.get("tactics") or [])
    if len(platforms) >= 2:
        return True
    if candidate.payload.get("is_subtechnique") and len(platforms) >= 1 and len(tactics) >= 2:
        return True
    return False


def _apply_quality_gate(mode: str, candidates: list[CandidateRow]) -> list[CandidateRow]:
    if mode == "actor":
        return [candidate for candidate in candidates if _passes_actor_quality(candidate)]
    if mode == "malware":
        return [candidate for candidate in candidates if _passes_malware_quality(candidate)]
    if mode == "technique":
        return [candidate for candidate in candidates if _passes_technique_quality(candidate)]
    return list(candidates)


def _select_with_repeat_fallback(
    candidates: list[CandidateRow],
    *,
    rng: random.Random,
    repeated_answer_keys: set[str],
) -> CandidateRow:
    filtered = [candidate for candidate in candidates if _candidate_repeat_key(candidate) not in repeated_answer_keys]
    pool = filtered or candidates
    if not pool:
        raise ValueError("No candidates available for selection")
    return _pick_candidate(pool, rng)


def _select_independent_malware(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    pools: dict[str, list[CandidateRow]],
    *,
    allowed_summary_tiers: set[int] | None = None,
) -> CandidateRow | None:
    candidates = _apply_quality_gate("malware", pools["malware"])
    if allowed_summary_tiers is not None:
        candidates = [candidate for candidate in candidates if candidate.summary_tier in allowed_summary_tiers]
        if not candidates:
            return None
    return _select_with_repeat_fallback(
        candidates,
        rng=_mode_rng(snapshot_id, day_key, "malware"),
        repeated_answer_keys=_repeat_answer_keys(connection, "malware", day_key),
    )


def _actor_payload(candidate: CandidateRow) -> dict[str, Any]:
    counts = candidate.payload.get("counts") or {}
    return {
        "mode": "actor",
        "clues": {
            "country_code": candidate.payload.get("country_code"),
            "first_observed_year": candidate.payload.get("first_observed_year"),
            "target_categories": list(candidate.payload.get("target_categories") or []),
            "motivation_tags": list(candidate.payload.get("motivation_tags") or []),
            "malware_count": int(counts.get("malware_count") or 0),
            "technique_count": int(counts.get("technique_count") or 0),
        },
    }


def _actor_answer(
    candidate: CandidateRow,
    *,
    timeline_id: int | None = None,
    repeat_key: str | None = None,
    chain_mode: str = "linked",
) -> dict[str, Any]:
    counts = candidate.payload.get("counts") or {}
    answer = {
        "answer_key": candidate.answer_key,
        "answer_label": candidate.answer_label,
        "chain_mode": chain_mode,
        "comparison": {
            "country_code": candidate.payload.get("country_code"),
            "first_observed_year": candidate.payload.get("first_observed_year"),
            "target_categories": list(candidate.payload.get("target_categories") or []),
            "motivation_tags": list(candidate.payload.get("motivation_tags") or []),
            "malware_count": int(counts.get("malware_count") or 0),
            "technique_count": int(counts.get("technique_count") or 0),
        },
    }
    if timeline_id is not None:
        answer["timeline_id"] = timeline_id
    if repeat_key is not None:
        answer["repeat_key"] = repeat_key
    return answer


def _malware_payload(candidate: CandidateRow) -> dict[str, Any]:
    actor_names = list(candidate.payload.get("actor_names") or [])
    return {
        "mode": "malware",
        "clues": {
            "platforms": list(candidate.payload.get("platforms") or []),
            "capability_summary": candidate.payload.get("capability_summary"),
            "aliases": list(candidate.payload.get("aliases") or []),
            "actor_count": len(actor_names),
        },
    }


def _malware_answer(
    candidate: CandidateRow,
    *,
    timeline_id: int | None = None,
    repeat_key: str | None = None,
    chain_mode: str = "linked",
) -> dict[str, Any]:
    answer = {
        "answer_key": candidate.answer_key,
        "answer_label": candidate.answer_label,
        "chain_mode": chain_mode,
        "comparison": {
            "platforms": list(candidate.payload.get("platforms") or []),
            "aliases": list(candidate.payload.get("aliases") or []),
            "actor_names": list(candidate.payload.get("actor_names") or []),
        },
    }
    if timeline_id is not None:
        answer["timeline_id"] = timeline_id
    if repeat_key is not None:
        answer["repeat_key"] = repeat_key
    return answer


def _technique_payload(candidate: CandidateRow) -> dict[str, Any]:
    return {
        "mode": "technique",
        "clues": {
            "tactics": list(candidate.payload.get("tactics") or []),
            "platforms": list(candidate.payload.get("platforms") or []),
            "is_subtechnique": bool(candidate.payload.get("is_subtechnique")),
            "parent_name": candidate.payload.get("parent_name"),
        },
    }


def _technique_answer(
    candidate: CandidateRow,
    *,
    timeline_id: int | None = None,
    repeat_key: str | None = None,
    chain_mode: str = "linked",
) -> dict[str, Any]:
    answer = {
        "answer_key": candidate.answer_key,
        "answer_label": candidate.answer_label,
        "chain_mode": chain_mode,
        "comparison": {
            "tactics": list(candidate.payload.get("tactics") or []),
            "platforms": list(candidate.payload.get("platforms") or []),
            "is_subtechnique": bool(candidate.payload.get("is_subtechnique")),
            "parent_attack_id": candidate.payload.get("parent_attack_id"),
            "parent_name": candidate.payload.get("parent_name"),
        },
    }
    if timeline_id is not None:
        answer["timeline_id"] = timeline_id
    if repeat_key is not None:
        answer["repeat_key"] = repeat_key
    return answer


def _timeline_payload(candidate: CandidateRow) -> dict[str, Any]:
    steps = list(candidate.payload.get("steps") or [])
    return {
        "mode": "timeline",
        "clues": {
            "step_count": len(steps),
            "ordering_basis": "Arrange the techniques in the source-reported execution order.",
            "steps": [
                {
                    "step_index": int(step["step_index"]),
                    "attack_id": step["attack_id"],
                    "technique_name": step["technique_name"],
                }
                for step in steps
            ],
        },
    }


def _timeline_answer(
    candidate: CandidateRow,
    *,
    chain_mode: str = "linked",
    repeat_key: str | None = None,
) -> dict[str, Any]:
    steps = list(candidate.payload.get("steps") or [])
    return {
        "answer_key": candidate.answer_key,
        "answer_label": candidate.answer_label,
        "answer_type": candidate.answer_type,
        "timeline_id": candidate.row_id,
        "repeat_key": repeat_key or _candidate_repeat_key(candidate),
        "chain_mode": chain_mode,
        "comparison": {
            "steps": [
                {
                    "step_index": int(step["step_index"]),
                    "attack_id": step["attack_id"],
                    "technique_name": step["technique_name"],
                }
                for step in steps
            ],
        },
    }


def _build_row(
    mode: str,
    candidate: CandidateRow,
    *,
    chain_mode: str = "linked",
    timeline_id: int | None = None,
    repeat_key: str | None = None,
) -> dict[str, Any]:
    if mode == "actor":
        payload = _actor_payload(candidate)
        answer = _actor_answer(candidate, timeline_id=timeline_id, repeat_key=repeat_key, chain_mode=chain_mode)
    elif mode == "malware":
        payload = _malware_payload(candidate)
        answer = _malware_answer(candidate, timeline_id=timeline_id, repeat_key=repeat_key, chain_mode=chain_mode)
    elif mode == "technique":
        payload = _technique_payload(candidate)
        answer = _technique_answer(candidate, timeline_id=timeline_id, repeat_key=repeat_key, chain_mode=chain_mode)
    elif mode == "timeline":
        payload = _timeline_payload(candidate)
        answer = _timeline_answer(candidate, chain_mode=chain_mode, repeat_key=repeat_key)
    else:
        raise ValueError(f"Unsupported mode {mode}")
    return {
        "mode": mode,
        "answer_key": candidate.answer_key,
        "answer_label": candidate.answer_label,
        "payload_json": payload,
        "answer_json": answer,
        "provenance": candidate.provenance,
    }


def _select_independent_mode(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    mode: str,
    pools: dict[str, list[CandidateRow]],
) -> CandidateRow:
    candidates = _apply_quality_gate(mode, pools[mode])
    if mode == "malware":
        selected = _select_independent_malware(connection, snapshot_id, day_key, pools)
        if selected is None:
            raise ValueError("No malware candidates available for independent selection")
        return selected
    if mode == "timeline":
        repeated = _repeat_answer_keys(connection, mode, day_key)
        actor_candidates = [candidate for candidate in candidates if candidate.answer_type == "actor"]
        filtered_actor_candidates = [
            candidate for candidate in actor_candidates if _candidate_repeat_key(candidate) not in repeated
        ]
        if filtered_actor_candidates:
            return _pick_candidate(filtered_actor_candidates, _mode_rng(snapshot_id, day_key, mode))
        if actor_candidates:
            return _pick_candidate(actor_candidates, _mode_rng(snapshot_id, day_key, mode))
        return _select_with_repeat_fallback(
            candidates,
            rng=_mode_rng(snapshot_id, day_key, mode),
            repeated_answer_keys=repeated,
        )
    return _select_with_repeat_fallback(
        candidates,
        rng=_mode_rng(snapshot_id, day_key, mode),
        repeated_answer_keys=_repeat_answer_keys(connection, mode, day_key),
    )


def _cross_linkable_actors(connection: sqlite3.Connection, day_key: str, pools: dict[str, list[CandidateRow]]) -> list[CandidateRow]:
    repeated_actor_keys = _repeat_answer_keys(connection, "actor", day_key)
    actor_candidates = {
        candidate.answer_key: candidate
        for candidate in _apply_quality_gate("actor", pools["actor"])
        if candidate.answer_key not in repeated_actor_keys
    }
    malware_actor_keys: set[str] = set()
    for candidate in _apply_quality_gate("malware", pools["malware"]):
        malware_actor_keys.update(candidate.linked_actor_ids)
    technique_actor_keys: set[str] = set()
    for candidate in _apply_quality_gate("technique", pools["technique"]):
        technique_actor_keys.update(candidate.linked_actor_ids)
    cross_linkable_keys = set(actor_candidates) & malware_actor_keys & technique_actor_keys
    return [actor_candidates[key] for key in sorted(cross_linkable_keys)]


def _count_anchor_connections(anchor: CandidateRow, selected: dict[str, CandidateRow]) -> int:
    connected = 0
    actor_candidate = selected["actor"]
    if actor_candidate.answer_key == anchor.answer_key:
        connected += 1
    malware_candidate = selected["malware"]
    if anchor.answer_key in malware_candidate.linked_actor_ids:
        connected += 1
    technique_candidate = selected["technique"]
    if anchor.answer_key in technique_candidate.linked_actor_ids:
        connected += 1
    return connected


def _select_themed_mode(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    mode: str,
    anchor: CandidateRow,
    pools: dict[str, list[CandidateRow]],
    *,
    selected: dict[str, CandidateRow] | None = None,
) -> CandidateRow | None:
    if mode == "actor":
        return anchor
    if mode == "malware":
        candidates = [candidate for candidate in pools["malware"] if anchor.answer_key in candidate.linked_actor_ids]
        candidates = _apply_quality_gate(mode, candidates)
        tier_one = [candidate for candidate in candidates if candidate.summary_tier == 1]
        if tier_one:
            candidates = tier_one
    elif mode == "technique":
        candidates = [candidate for candidate in pools["technique"] if anchor.answer_key in candidate.linked_actor_ids]
        candidates = _apply_quality_gate(mode, candidates)
    else:
        raise ValueError(f"Unsupported themed mode {mode}")
    repeated_keys = _repeat_answer_keys(connection, mode, day_key)
    filtered = [candidate for candidate in candidates if _candidate_repeat_key(candidate) not in repeated_keys]
    if not filtered:
        return None
    return _pick_candidate(filtered, _mode_rng(snapshot_id, day_key, mode))


def _select_day_candidates(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    theme_mode: str,
    pools: dict[str, list[CandidateRow]],
) -> tuple[dict[str, CandidateRow], CandidateRow | None, list[str]]:
    if theme_mode not in THEME_MODES:
        raise ValueError(f"Unsupported theme mode {theme_mode}")
    if theme_mode == "off":
        selected = {
            mode: _select_independent_mode(connection, snapshot_id, day_key, mode, pools)
            for mode in MODE_ORDER
        }
        return selected, None, []

    cross_linkable_actors = _cross_linkable_actors(connection, day_key, pools)
    if not cross_linkable_actors:
        if theme_mode == "strict":
            raise ValueError("No cross-linkable actors available for strict themed generation")
        selected = {
            mode: _select_independent_mode(connection, snapshot_id, day_key, mode, pools)
            for mode in MODE_ORDER
        }
        return selected, None, list(MODE_ORDER)

    anchor = _pick_candidate(cross_linkable_actors, _day_rng(snapshot_id, day_key))
    selected: dict[str, CandidateRow] = {"actor": anchor}
    fallback_modes: list[str] = []
    for mode in ("malware", "technique"):
        themed_candidate = _select_themed_mode(
            connection,
            snapshot_id,
            day_key,
            mode,
            anchor,
            pools,
            selected=selected,
        )
        if themed_candidate is not None:
            selected[mode] = themed_candidate
            continue
        if theme_mode == "strict":
            raise ValueError(
                f"Strict themed generation failed for {day_key}: no {mode} candidate linked to {anchor.answer_key}"
            )
        selected[mode] = _select_independent_mode(connection, snapshot_id, day_key, mode, pools)
        fallback_modes.append(mode)

    if theme_mode == "prefer" and _count_anchor_connections(anchor, selected) < len(MODE_ORDER):
        selected = {
            mode: _select_independent_mode(connection, snapshot_id, day_key, mode, pools)
            for mode in MODE_ORDER
        }
        return selected, None, list(MODE_ORDER)
    return selected, anchor, fallback_modes


def _persist_day_rows(
    connection: sqlite3.Connection,
    *,
    snapshot_id: str,
    day_key: str,
    rows: list[dict[str, Any]],
) -> int:
    created_at = now_utc_iso()
    with connection:
        for row in rows:
            connection.execute(
                """
                INSERT INTO puzzle_day (day_key, snapshot_id, mode, payload_json, answer_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    day_key,
                    snapshot_id,
                    row["mode"],
                    json.dumps(row["payload_json"], sort_keys=True),
                    json.dumps(row["answer_json"], sort_keys=True),
                    created_at,
                ),
            )
    return len(rows)


def generate_puzzle_day(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    *,
    theme_mode: str = "prefer",
    chain_mode: str = "linked",
    force: bool = False,
    dry_run: bool = False,
    pools: dict[str, list[CandidateRow]] | None = None,
) -> dict[str, Any]:
    _parse_day_key(day_key)
    _require_ready_snapshot(connection, snapshot_id)
    if chain_mode not in CHAIN_MODES:
        raise ValueError(f"Unsupported chain mode {chain_mode}")
    if not dry_run:
        existing_modes = _existing_day_modes(connection, day_key)
        if existing_modes and not force:
            raise ValueError(f"Puzzle rows already exist for {day_key}: {', '.join(existing_modes)}")
        deleted = _delete_existing_day(connection, day_key) if existing_modes and force else 0
    else:
        deleted = 0
    loaded_pools = pools or load_candidate_pools(connection, snapshot_id)
    exact_incident: IncidentCandidateRow | None = None
    if chain_mode == "exact":
        selected, exact_incident = _select_exact_incident_day(connection, snapshot_id, day_key, loaded_pools)
        anchor = selected["actor"]
        fallback_modes: list[str] = []
    else:
        selected, anchor, fallback_modes = _select_day_candidates(
            connection,
            snapshot_id,
            day_key,
            theme_mode,
            loaded_pools,
        )
    row_payloads = []
    for mode in MODE_ORDER:
        built_row = _build_row(
            mode,
            selected[mode],
            chain_mode=chain_mode,
            timeline_id=(exact_incident.timeline_id if exact_incident is not None else None),
            repeat_key=(exact_incident.repeat_key if exact_incident is not None else None),
        )
        row_payloads.append(
            {
                "mode": mode,
                "answer_key": built_row["answer_key"],
                "answer_label": built_row["answer_label"],
                "payload_json": built_row["payload_json"],
                "answer_json": built_row["answer_json"],
                "provenance": built_row["provenance"],
            }
        )
    rows_written = 0
    if not dry_run:
        rows_written = _persist_day_rows(connection, snapshot_id=snapshot_id, day_key=day_key, rows=row_payloads)
    return {
        "day_key": day_key,
        "snapshot_id": snapshot_id,
        "theme_mode": theme_mode,
        "chain_mode": chain_mode,
        "theme_anchor": (
            {"answer_key": anchor.answer_key, "answer_label": anchor.answer_label}
            if anchor is not None
            else None
        ),
        "exact_timeline_id": (exact_incident.timeline_id if exact_incident is not None else None),
        "fallback_modes": fallback_modes,
        "deleted_rows": deleted,
        "rows_written": rows_written,
        "rows": row_payloads,
    }


def preview_puzzle_day(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
    *,
    theme_mode: str = "prefer",
    chain_mode: str = "linked",
) -> dict[str, Any]:
    return generate_puzzle_day(
        connection,
        snapshot_id,
        day_key,
        theme_mode=theme_mode,
        chain_mode=chain_mode,
        force=False,
        dry_run=True,
    )


def generate_puzzle_range(
    connection: sqlite3.Connection,
    snapshot_id: str,
    start_day: str,
    days: int,
    *,
    theme_mode: str = "prefer",
    chain_mode: str = "linked",
    force: bool = False,
) -> dict[str, Any]:
    if days <= 0:
        raise ValueError("--days must be positive")
    start_date = _parse_day_key(start_day)
    loaded_pools = load_candidate_pools(connection, snapshot_id)
    results = []
    for offset in range(days):
        day_key = (start_date + timedelta(days=offset)).isoformat()
        results.append(
            generate_puzzle_day(
                connection,
                snapshot_id,
                day_key,
                theme_mode=theme_mode,
                chain_mode=chain_mode,
                force=force,
                dry_run=False,
                pools=loaded_pools,
            )
        )
    return {
        "snapshot_id": snapshot_id,
        "start_day": start_day,
        "days": days,
        "theme_mode": theme_mode,
        "chain_mode": chain_mode,
        "generated_days": results,
    }
