"""Export actor metadata backfill candidates for manual curation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.config import get_paths
from threatdle.ingest.base import ensure_directory, now_utc_iso
from threatdle.normalize.text import normalize_actor_name


THEMATIC_AREA_TO_COUNTRY_CODE = {
    "China": "CN",
    "India": "IN",
    "Iran": "IR",
    "North Korea": "KP",
    "Pakistan": "PK",
    "Palestine": "PS",
    "Russia": "RU",
    "South Korea": "KR",
    "United States": "US",
    "Vietnam": "VN",
}


def _report_paths(root_dir: Path | None, snapshot_id: str) -> tuple[Path, Path]:
    paths = get_paths(root_dir=root_dir)
    report_dir = ensure_directory(paths.snapshots_dir / snapshot_id / "reports")
    return (
        report_dir / "actor_backfill_report.json",
        report_dir / "actor_backfill_report.csv",
    )


def _loads_json(value: str | None, *, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


def _load_profile_json(path: Path | None) -> list[dict[str, Any]]:
    if path is None or not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    profiles = payload.get("profiles", [])
    if not isinstance(profiles, list):
        return []
    return [dict(row) for row in profiles if isinstance(row, dict)]


def _profile_match_index(profiles: list[dict[str, Any]]) -> list[tuple[dict[str, Any], set[str]]]:
    index: list[tuple[dict[str, Any], set[str]]] = []
    for profile in profiles:
        keys: set[str] = set()
        for value in [profile.get("name"), *list(profile.get("aliases") or [])]:
            normalized = normalize_actor_name(value)
            if normalized:
                keys.add(normalized)
        index.append((profile, keys))
    return index


def _actor_aliases(connection: sqlite3.Connection) -> dict[str, set[str]]:
    aliases: dict[str, set[str]] = {}
    rows = connection.execute(
        """
        SELECT a.attack_group_id, a.name, aa.alias
        FROM actors a
        LEFT JOIN actor_aliases aa ON aa.actor_id = a.actor_id
        ORDER BY a.attack_group_id
        """
    ).fetchall()
    for row in rows:
        group_id = str(row["attack_group_id"])
        aliases.setdefault(group_id, set()).add(str(row["name"]))
        if row["alias"]:
            aliases[group_id].add(str(row["alias"]))
    return aliases


def build_actor_backfill_report(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    root_dir: Path | None = None,
    profile_json_path: Path | None = None,
) -> dict[str, Any]:
    profiles = _load_profile_json(profile_json_path)
    profile_index = _profile_match_index(profiles)
    actor_aliases = _actor_aliases(connection)
    rows = connection.execute(
        """
        SELECT
            a.actor_id,
            a.attack_group_id,
            a.name,
            ap.clue_payload_json
        FROM actor_profiles_v1 ap
        JOIN actors a ON a.actor_id = ap.actor_id
        WHERE ap.snapshot_id = ?
        ORDER BY a.name
        """,
        (snapshot_id,),
    ).fetchall()

    candidates: list[dict[str, Any]] = []
    summary = {
        "snapshot_id": snapshot_id,
        "generated_at": now_utc_iso(),
        "profile_json_path": str(profile_json_path) if profile_json_path is not None else None,
        "total_actor_profiles": len(rows),
        "software_ttp_ready": 0,
        "publishable_now": 0,
        "one_field_away": 0,
        "one_field_away_by_missing_field": {"country": 0, "year": 0, "targets": 0, "motivation": 0},
        "one_field_away_with_profile_match": 0,
    }

    for row in rows:
        clue = _loads_json(row["clue_payload_json"], default={})
        counts = clue.get("counts", {})
        if not (int(counts.get("malware_count", 0)) >= 1 and int(counts.get("technique_count", 0)) >= 3):
            continue
        summary["software_ttp_ready"] += 1
        fields = {
            "country": bool(clue.get("country_code")),
            "year": clue.get("first_observed_year") is not None,
            "targets": bool(clue.get("target_categories")),
            "motivation": bool(clue.get("motivation_tags")),
        }
        missing_fields = [field_name for field_name, present in fields.items() if not present]
        if not missing_fields:
            summary["publishable_now"] += 1
            continue

        actor_keys = {
            normalize_actor_name(value)
            for value in actor_aliases.get(str(row["attack_group_id"]), set())
            if normalize_actor_name(value)
        }
        matched_profiles: list[dict[str, Any]] = []
        for profile, profile_keys in profile_index:
            if actor_keys.intersection(profile_keys):
                thematic_area = str(profile.get("thematic_area") or "").strip()
                matched_profiles.append(
                    {
                        "profile_name": str(profile.get("name") or ""),
                        "thematic_area": thematic_area,
                        "suggested_country_code": THEMATIC_AREA_TO_COUNTRY_CODE.get(thematic_area),
                        "objectives": list(profile.get("objectives") or []),
                        "aliases": list(profile.get("aliases") or []),
                        "tools": list(profile.get("tools") or []),
                    }
                )
        if len(missing_fields) == 1:
            missing_field = missing_fields[0]
            summary["one_field_away"] += 1
            summary["one_field_away_by_missing_field"][missing_field] += 1
            if matched_profiles:
                summary["one_field_away_with_profile_match"] += 1
            candidates.append(
                {
                    "attack_group_id": row["attack_group_id"],
                    "actor_name": row["name"],
                    "missing_field": missing_field,
                    "country_code": clue.get("country_code"),
                    "first_observed_year": clue.get("first_observed_year"),
                    "target_categories": list(clue.get("target_categories") or []),
                    "motivation_tags": list(clue.get("motivation_tags") or []),
                    "malware_count": int(counts.get("malware_count", 0)),
                    "technique_count": int(counts.get("technique_count", 0)),
                    "matched_profiles": matched_profiles,
                }
            )

    json_path, csv_path = _report_paths(root_dir, snapshot_id)
    json_path.write_text(json.dumps({"summary": summary, "candidates": candidates}, indent=2, sort_keys=True), encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "attack_group_id",
                "actor_name",
                "missing_field",
                "country_code",
                "first_observed_year",
                "target_categories",
                "motivation_tags",
                "malware_count",
                "technique_count",
                "matched_profile_names",
                "suggested_country_codes",
                "suggested_objectives",
            ],
        )
        writer.writeheader()
        for candidate in candidates:
            matched_profiles = list(candidate["matched_profiles"])
            writer.writerow(
                {
                    "attack_group_id": candidate["attack_group_id"],
                    "actor_name": candidate["actor_name"],
                    "missing_field": candidate["missing_field"],
                    "country_code": candidate["country_code"] or "",
                    "first_observed_year": candidate["first_observed_year"] or "",
                    "target_categories": "|".join(candidate["target_categories"]),
                    "motivation_tags": "|".join(candidate["motivation_tags"]),
                    "malware_count": candidate["malware_count"],
                    "technique_count": candidate["technique_count"],
                    "matched_profile_names": "|".join(
                        str(profile["profile_name"]) for profile in matched_profiles if profile.get("profile_name")
                    ),
                    "suggested_country_codes": "|".join(
                        str(profile["suggested_country_code"])
                        for profile in matched_profiles
                        if profile.get("suggested_country_code")
                    ),
                    "suggested_objectives": "|".join(
                        objective
                        for profile in matched_profiles
                        for objective in list(profile.get("objectives") or [])
                        if objective
                    ),
                }
            )

    return {**summary, "json_report_path": str(json_path), "csv_report_path": str(csv_path)}
