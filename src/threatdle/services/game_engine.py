"""Game engine scoring logic for the Threatdle deduction grids.

Provides the `score_guess` function to compare a player's guess against 
the stored hidden `answer_json` attributes.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Any, Dict, List


def _compare_string(guess_val: str | None, true_val: str | None) -> str:
    if not true_val and not guess_val:
        return "match"
    if not true_val or not guess_val:
        return "mismatch"
    if str(guess_val).strip().lower() == str(true_val).strip().lower():
        return "match"
    return "mismatch"


def _compare_numeric(guess_val: int | float | None, true_val: int | float | None) -> str:
    if true_val is None and guess_val is None:
        return "match"
    if true_val is None or guess_val is None:
        return "mismatch"
    try:
        g = float(guess_val)
        t = float(true_val)
    except ValueError:
        return "mismatch"

    if g == t:
        return "match"
    if g < t:
        return "higher"
    return "lower"


def _compare_list(guess_list: List[str] | None, true_list: List[str] | None) -> str:
    if not guess_list and not true_list:
        return "match"
    
    g_set = set(str(x).lower().strip() for x in (guess_list or []))
    t_set = set(str(x).lower().strip() for x in (true_list or []))

    if not g_set or not t_set:
        return "mismatch"

    if g_set == t_set:
        return "match"
    
    if g_set.intersection(t_set):
        return "partial"
        
    return "mismatch"


def _score_actor(guess_attrs: dict[str, Any], true_attrs: dict[str, Any]) -> dict[str, Any]:
    return {
        "country": {"status": _compare_string(guess_attrs.get("country_code"), true_attrs.get("country_code")), "value": guess_attrs.get("country_code")},
        "year": {"status": _compare_numeric(guess_attrs.get("first_observed_year"), true_attrs.get("first_observed_year")), "value": guess_attrs.get("first_observed_year")},
        "targets": {"status": _compare_list(guess_attrs.get("target_categories"), true_attrs.get("target_categories")), "value": guess_attrs.get("target_categories")},
        "motivation": {"status": _compare_list(guess_attrs.get("motivation_tags"), true_attrs.get("motivation_tags")), "value": guess_attrs.get("motivation_tags")},
        "malware": {"status": _compare_numeric(guess_attrs.get("malware_count"), true_attrs.get("malware_count")), "value": guess_attrs.get("malware_count")},
        "techniques": {"status": _compare_numeric(guess_attrs.get("technique_count"), true_attrs.get("technique_count")), "value": guess_attrs.get("technique_count")},
    }


def _score_malware(guess_attrs: dict[str, Any], true_attrs: dict[str, Any]) -> dict[str, Any]:
    return {
        "platforms": {"status": _compare_list(guess_attrs.get("platforms"), true_attrs.get("platforms")), "value": guess_attrs.get("platforms")},
        "aliases": {"status": _compare_list(guess_attrs.get("aliases"), true_attrs.get("aliases")), "value": guess_attrs.get("aliases")},
        "actors": {"status": _compare_list(guess_attrs.get("actor_names"), true_attrs.get("actor_names")), "value": guess_attrs.get("actor_names")},
    }


def _score_technique(guess_attrs: dict[str, Any], true_attrs: dict[str, Any]) -> dict[str, Any]:
    return {
        "tactics": {"status": _compare_list(guess_attrs.get("tactics"), true_attrs.get("tactics")), "value": guess_attrs.get("tactics")},
        "platforms": {"status": _compare_list(guess_attrs.get("platforms"), true_attrs.get("platforms")), "value": guess_attrs.get("platforms")},
        "subtechnique": {"status": _compare_string(str(guess_attrs.get("is_subtechnique")), str(true_attrs.get("is_subtechnique"))), "value": guess_attrs.get("is_subtechnique")},
        "parent": {"status": _compare_string(guess_attrs.get("parent_name"), true_attrs.get("parent_name")), "value": guess_attrs.get("parent_name")},
    }


def _score_timeline(guess_attrs: dict[str, Any], true_attrs: dict[str, Any]) -> dict[str, Any]:
    true_steps = list(true_attrs.get("steps") or [])
    guess_steps = list(guess_attrs.get("steps") or [])
    true_attack_ids = {str(step.get("attack_id")) for step in true_steps}
    feedback: dict[str, Any] = {}

    for index, true_step in enumerate(true_steps, start=1):
        guessed_step = guess_steps[index - 1] if index - 1 < len(guess_steps) else {}
        guessed_attack_id = str(guessed_step.get("attack_id") or "")
        if guessed_attack_id == str(true_step.get("attack_id") or ""):
            status = "match"
        elif guessed_attack_id in true_attack_ids:
            status = "partial"
        else:
            status = "mismatch"
        feedback[f"step_{index}"] = {
            "status": status,
            "value": guessed_step.get("technique_name") or guessed_step.get("attack_id"),
        }
    return feedback


def score_guess(
    connection: sqlite3.Connection,
    snapshot_id: str,
    mode: str,
    guess_key: str | None,
    true_answer: dict[str, Any],
    *,
    guess_steps: list[str] | None = None,
) -> dict[str, Any]:
    """Score a guess against the true answer, returning attribute matches."""
    
    true_attrs = true_answer.get("comparison", {})

    # 1. Fetch the attributes for the user's *guess* from the candidate tables.
    #    We need to retrieve what the guess's attributes actually are so we can compare them.
    guess_attrs: dict[str, Any] = {}
    
    if mode == "actor":
        row = connection.execute(
            """
            SELECT ap.clue_payload_json 
            FROM actor_candidates_v1 ac
            JOIN actor_profiles_v1 ap ON ap.snapshot_id = ac.snapshot_id AND ap.actor_id = ac.actor_id
            WHERE ac.snapshot_id = ? AND ac.answer_key = ?
            """,
            (snapshot_id, guess_key)
        ).fetchone()
        if row:
            guess_payload = json.loads(row["clue_payload_json"])
            counts = guess_payload.get("counts", {})
            guess_attrs = {
                "country_code": guess_payload.get("country_code"),
                "first_observed_year": guess_payload.get("first_observed_year"),
                "target_categories": guess_payload.get("target_categories", []),
                "motivation_tags": guess_payload.get("motivation_tags", []),
                "malware_count": counts.get("malware_count", 0),
                "technique_count": counts.get("technique_count", 0),
            }
        else:
            raise ValueError(f"Guess actor {guess_key} not found in pool")
            
        feedback = _score_actor(guess_attrs, true_attrs)

    elif mode == "malware":
        row = connection.execute(
            """
            SELECT mp.clue_payload_json 
            FROM malware_candidates_v1 mc
            JOIN malware_profiles_v1 mp ON mp.snapshot_id = mc.snapshot_id AND mp.malware_id = mc.malware_id
            WHERE mc.snapshot_id = ? AND mc.answer_key = ?
            """,
            (snapshot_id, guess_key)
        ).fetchone()
        if row:
            guess_payload = json.loads(row["clue_payload_json"])
            guess_attrs = {
                "platforms": guess_payload.get("platforms", []),
                "aliases": guess_payload.get("aliases", []),
                "actor_names": guess_payload.get("actor_names", []),
            }
        else:
            raise ValueError(f"Guess malware {guess_key} not found in pool")
            
        feedback = _score_malware(guess_attrs, true_attrs)

    elif mode == "technique":
        row = connection.execute(
            """
            SELECT tp.clue_payload_json 
            FROM technique_candidates_v1 tc
            JOIN technique_profiles_v1 tp ON tp.snapshot_id = tc.snapshot_id AND tp.technique_id = tc.technique_id
            WHERE tc.snapshot_id = ? AND tc.answer_key = ?
            """,
            (snapshot_id, guess_key)
        ).fetchone()
        if row:
            guess_payload = json.loads(row["clue_payload_json"])
            guess_attrs = {
                "tactics": guess_payload.get("tactics", []),
                "platforms": guess_payload.get("platforms", []),
                "is_subtechnique": guess_payload.get("is_subtechnique", False),
                "parent_name": guess_payload.get("parent_name"),
            }
        else:
            raise ValueError(f"Guess technique {guess_key} not found in pool")
            
        feedback = _score_technique(guess_attrs, true_attrs)
        
    elif mode == "timeline":
        true_steps = list(true_attrs.get("steps") or [])
        step_name_lookup = {
            str(step.get("attack_id") or ""): step.get("technique_name") or step.get("attack_id")
            for step in true_steps
        }
        guess_attrs = {
            "steps": [
                {
                    "attack_id": str(attack_id),
                    "technique_name": step_name_lookup.get(str(attack_id), str(attack_id)),
                }
                for attack_id in (guess_steps or [])
            ]
        }
        feedback = _score_timeline(guess_attrs, true_attrs)
        
    else:
        raise ValueError(f"Unsupported scoring mode {mode}")

    return feedback
