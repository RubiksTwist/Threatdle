"""Automated validation for baked review data."""

from __future__ import annotations

import re
import sqlite3
from typing import Any

from threatdle.services.review_export import get_review_day, list_review_days


MARKDOWN_LINK_PATTERN = re.compile(r"\[[^\]]+\]\([^)]+\)")
CITATION_PATTERN = re.compile(r"\(Citation:[^)]+\)")


def _iter_strings(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, dict):
        results: list[tuple[str, str]] = []
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            results.extend(_iter_strings(child, child_path))
        return results
    if isinstance(value, list):
        results = []
        for index, child in enumerate(value):
            child_path = f"{path}[{index}]"
            results.extend(_iter_strings(child, child_path))
        return results
    if isinstance(value, str) and value.strip():
        return [(path, value)]
    return []


def _answer_label_pattern(answer_label: str | None) -> re.Pattern[str] | None:
    if not answer_label:
        return None
    tokens = re.findall(r"[A-Za-z0-9]+", answer_label)
    if not tokens:
        return None
    joined = r"[\W_]*".join(re.escape(token) for token in tokens)
    return re.compile(rf"(?<![A-Za-z0-9]){joined}(?![A-Za-z0-9])", re.IGNORECASE)


def _build_issue(
    *,
    snapshot_id: str,
    day_key: str,
    severity: str,
    check: str,
    mode: str,
    path: str,
    message: str,
) -> dict[str, str]:
    return {
        "snapshot_id": snapshot_id,
        "day_key": day_key,
        "severity": severity,
        "check": check,
        "mode": mode,
        "path": path,
        "message": message,
    }


def validate_review_day(
    connection: sqlite3.Connection,
    snapshot_id: str,
    day_key: str,
) -> dict[str, Any]:
    payload = get_review_day(connection, snapshot_id, day_key)
    if payload is None:
        raise ValueError(f"No puzzle data for snapshot {snapshot_id} day {day_key}")

    issues: list[dict[str, str]] = []
    theme = payload["theme"]
    anchor = theme.get("anchor") or {}
    anchor_pattern = _answer_label_pattern(anchor.get("answer_label"))

    for mode, mode_payload in payload["modes"].items():
        for path, string_value in _iter_strings(mode_payload.get("payload", {}), f"modes.{mode}.payload"):
            if MARKDOWN_LINK_PATTERN.search(string_value):
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="error",
                        check="raw_markdown_artifact",
                        mode=mode,
                        path=path,
                        message="Player-visible clue text contains raw markdown links.",
                    )
                )
            if CITATION_PATTERN.search(string_value):
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="error",
                        check="citation_artifact",
                        mode=mode,
                        path=path,
                        message="Player-visible clue text contains ATT&CK citation markup.",
                    )
                )
            if theme.get("themed") and mode != "actor" and anchor_pattern and anchor_pattern.search(string_value):
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="error",
                        check="themed_actor_leak",
                        mode=mode,
                        path=path,
                        message=(
                            f"Player-visible clue text references themed actor "
                            f"{anchor['answer_label']} ({anchor['answer_key']})."
                        ),
                    )
                )

    actor_clues = payload["modes"].get("actor", {}).get("payload", {}).get("clues", {})
    required_actor_clues = (
        (
            "country_code",
            "error",
            "missing_actor_country_code",
            "Actor clue is missing country_code; exclude this actor from gameplay or add an override.",
        ),
        (
            "first_observed_year",
            "error",
            "missing_actor_first_observed_year",
            "Actor clue is missing first_observed_year; exclude this actor from gameplay or add an override.",
        ),
        (
            "target_categories",
            "error",
            "missing_actor_target_categories",
            "Actor clue is missing target_categories; exclude this actor from gameplay or add an override.",
        ),
        (
            "motivation_tags",
            "error",
            "missing_actor_motivation_tags",
            "Actor clue is missing motivation_tags; exclude this actor from gameplay or add an override.",
        ),
    )
    for clue_key, severity, check, message in required_actor_clues:
        clue_value = actor_clues.get(clue_key)
        is_missing = clue_value is None or clue_value == "" or clue_value == []
        if is_missing:
            issues.append(
                _build_issue(
                    snapshot_id=snapshot_id,
                    day_key=day_key,
                    severity=severity,
                    check=check,
                    mode="actor",
                    path=f"modes.actor.payload.clues.{clue_key}",
                    message=message,
                )
            )

    answer_rows = {
        mode: mode_payload.get("answer", {})
        for mode, mode_payload in payload["modes"].items()
    }
    chain_modes = {
        str(answer.get("chain_mode"))
        for answer in answer_rows.values()
        if answer.get("chain_mode")
    }
    if chain_modes == {"exact"}:
        present_timeline_ids = [
            int(answer["timeline_id"])
            for answer in answer_rows.values()
            if answer.get("timeline_id") is not None
        ]
        timeline_ids = set(present_timeline_ids)
        incident_row = None
        exact_timeline_id = next(iter(timeline_ids), None)
        if exact_timeline_id is not None:
            incident_row = connection.execute(
                """
                SELECT malware_answer_keys_json, technique_attack_ids_json, source_article_url, source_article_title
                FROM incident_candidates_v1
                WHERE snapshot_id = ? AND timeline_id = ?
                LIMIT 1
                """,
                (snapshot_id, exact_timeline_id),
            ).fetchone()
        if len(present_timeline_ids) != len(answer_rows):
            issues.append(
                _build_issue(
                    snapshot_id=snapshot_id,
                    day_key=day_key,
                    severity="error",
                    check="exact_chain_missing_timeline_id",
                    mode="all",
                    path="modes.*.answer.timeline_id",
                    message="Exact-chain day is missing timeline_id on one or more mode answers.",
                )
            )
        elif len(timeline_ids) != 1:
            issues.append(
                _build_issue(
                    snapshot_id=snapshot_id,
                    day_key=day_key,
                    severity="error",
                    check="exact_chain_mismatch",
                    mode="all",
                    path="modes.*.answer.timeline_id",
                    message="Exact-chain day has mismatched timeline_id values across modes.",
                )
            )
        elif incident_row is None:
            issues.append(
                _build_issue(
                    snapshot_id=snapshot_id,
                    day_key=day_key,
                    severity="error",
                    check="missing_exact_incident_candidate",
                    mode="all",
                    path="incident_candidates_v1",
                    message="Exact-chain day is missing its incident candidate record.",
                )
            )
        else:
            malware_keys = set(json.loads(incident_row["malware_answer_keys_json"]))
            technique_keys = set(json.loads(incident_row["technique_attack_ids_json"]))
            malware_answer_key = answer_rows.get("malware", {}).get("answer_key")
            if malware_answer_key and malware_answer_key not in malware_keys:
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="error",
                        check="exact_chain_malware_mismatch",
                        mode="malware",
                        path="modes.malware.answer.answer_key",
                        message="Exact-chain malware answer is not part of the incident malware set.",
                    )
                )
            technique_answer_key = answer_rows.get("technique", {}).get("answer_key")
            if technique_answer_key and technique_answer_key not in technique_keys:
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="error",
                        check="exact_chain_technique_mismatch",
                        mode="technique",
                        path="modes.technique.answer.answer_key",
                        message="Exact-chain technique answer is not part of the incident timeline steps.",
                    )
                )
        if incident_row is not None:
            source_article_url = incident_row["source_article_url"]
            source_article_title = incident_row["source_article_title"]
            if source_article_url and not str(source_article_url).startswith("https://"):
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="error",
                        check="invalid_source_article_url",
                        mode="all",
                        path="incident_candidates_v1.source_article_url",
                        message="Incident source article URL must use HTTPS.",
                    )
                )
            if source_article_title and not source_article_url:
                issues.append(
                    _build_issue(
                        snapshot_id=snapshot_id,
                        day_key=day_key,
                        severity="warning",
                        check="source_article_title_without_url",
                        mode="all",
                        path="incident_candidates_v1.source_article_title",
                        message="Incident source article title is present without a URL and will not be shown.",
                    )
                )

    return {
        "snapshot_id": snapshot_id,
        "day_key": day_key,
        "theme": theme,
        "issue_count": len(issues),
        "issues": issues,
    }


def validate_review_snapshot(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    day_key: str | None = None,
) -> dict[str, Any]:
    if day_key is not None:
        day_keys = [day_key]
    else:
        day_keys = [row["day_key"] for row in list_review_days(connection, snapshot_id)]

    if not day_keys:
        raise ValueError(f"Snapshot {snapshot_id} has no puzzle_day rows to validate")

    day_results = [
        validate_review_day(connection, snapshot_id, current_day_key)
        for current_day_key in day_keys
    ]
    issues = [
        issue
        for day_result in day_results
        for issue in day_result["issues"]
    ]
    issue_counts = {
        "error": sum(1 for issue in issues if issue["severity"] == "error"),
        "warning": sum(1 for issue in issues if issue["severity"] == "warning"),
    }
    checks: dict[str, int] = {}
    for issue in issues:
        checks[issue["check"]] = checks.get(issue["check"], 0) + 1

    return {
        "snapshot_id": snapshot_id,
        "validated_day_count": len(day_keys),
        "validated_days": day_keys,
        "issue_count": len(issues),
        "issue_counts": issue_counts,
        "issue_counts_by_check": dict(sorted(checks.items())),
        "days_with_issues": [day_result for day_result in day_results if day_result["issues"]],
    }
