"""Build snapshot-keyed puzzle materializations."""

from __future__ import annotations

import json
import re
import sqlite3

from threatdle.db.repositories import ensure_snapshot_loading
from threatdle.db.schema import clear_puzzle_tables_for_snapshot
from threatdle.normalize.text import clean_attack_text, contains_any_name_reference, normalize_actor_name


TOKEN_PATTERN = re.compile(r"[A-Za-z0-9]+")


def _loads_list(value: str | None) -> list[str]:
    if not value:
        return []
    return list(json.loads(value))


def _difficulty_from_score(clue_score: int) -> str:
    return "easy" if clue_score >= 5 else "standard"


def _has_complete_actor_phase_one_clues(
    *,
    country_code: str | None,
    first_observed_year: int | None,
    target_categories: list[str],
    motivation_tags: list[str],
) -> bool:
    return bool(country_code) and first_observed_year is not None and bool(target_categories) and bool(motivation_tags)


def _has_publishable_actor_three_phase_coverage(*, malware_count: int, technique_count: int) -> bool:
    return malware_count >= 1 and technique_count >= 3


def _name_tokens(values: list[str]) -> set[str]:
    tokens: set[str] = set()
    for value in values:
        for token in TOKEN_PATTERN.findall(value or ""):
            normalized = token.casefold()
            if len(normalized) >= 4:
                tokens.add(normalized)
    return tokens


def _name_boost(campaign_names: list[str], flow_identifiers: list[str]) -> int:
    campaign_tokens = _name_tokens(campaign_names)
    flow_tokens = _name_tokens(flow_identifiers)
    if campaign_tokens.intersection(flow_tokens):
        return 1
    normalized_campaigns = {normalize_actor_name(value) for value in campaign_names if value}
    normalized_flows = {normalize_actor_name(value) for value in flow_identifiers if value}
    normalized_campaigns.discard(None)
    normalized_flows.discard(None)
    for campaign_name in normalized_campaigns:
        for flow_name in normalized_flows:
            if campaign_name == flow_name or campaign_name in flow_name or flow_name in campaign_name:
                return 1
    return 0


def _materialize_campaign_incidents(connection: sqlite3.Connection, snapshot_id: str) -> tuple[int, dict[int, dict[str, object]]]:
    count = 0
    incidents: dict[int, dict[str, object]] = {}
    campaign_rows = connection.execute(
        """
        SELECT campaign_id, attack_campaign_id, name, aliases_json
        FROM campaigns
        WHERE revoked = 0 AND deprecated = 0
        ORDER BY name
        """
    ).fetchall()
    for row in campaign_rows:
        actor_rows = connection.execute(
            """
            SELECT a.attack_group_id, a.name
            FROM campaign_actors ca
            JOIN actors a ON a.actor_id = ca.actor_id
            WHERE ca.campaign_id = ? AND a.revoked = 0 AND a.deprecated = 0
            ORDER BY a.name
            """,
            (row["campaign_id"],),
        ).fetchall()
        if len(actor_rows) != 1:
            continue
        malware_rows = connection.execute(
            """
            SELECT m.attack_software_id, m.name
            FROM campaign_malware cm
            JOIN malware m ON m.malware_id = cm.malware_id
            WHERE cm.campaign_id = ? AND m.revoked = 0 AND m.deprecated = 0
            ORDER BY m.name
            """,
            (row["campaign_id"],),
        ).fetchall()
        technique_rows = connection.execute(
            """
            SELECT t.attack_id
            FROM campaign_techniques ct
            JOIN techniques t ON t.technique_id = ct.technique_id
            WHERE ct.campaign_id = ? AND t.revoked = 0 AND t.deprecated = 0
            ORDER BY t.attack_id
            """,
            (row["campaign_id"],),
        ).fetchall()
        if not malware_rows or len(technique_rows) < 3:
            continue
        actor_row = actor_rows[0]
        malware_keys = [str(malware_row["attack_software_id"]) for malware_row in malware_rows]
        malware_labels = [str(malware_row["name"]) for malware_row in malware_rows]
        technique_ids = [str(technique_row["attack_id"]) for technique_row in technique_rows]
        aliases = _loads_list(row["aliases_json"])
        provenance = {
            "identity": "attack_stix",
            "attack_campaign_id": row["attack_campaign_id"],
            "campaign_name": row["name"],
            "campaign_aliases": aliases,
            "relationship_source": "attack_stix",
        }
        with connection:
            connection.execute(
                """
                INSERT INTO campaign_incidents_v1 (
                    snapshot_id,
                    campaign_id,
                    attack_campaign_id,
                    campaign_name,
                    actor_answer_key,
                    actor_answer_label,
                    malware_answer_keys_json,
                    malware_answer_labels_json,
                    technique_attack_ids_json,
                    technique_count,
                    provenance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    row["campaign_id"],
                    row["attack_campaign_id"],
                    row["name"],
                    actor_row["attack_group_id"],
                    actor_row["name"],
                    json.dumps(malware_keys, sort_keys=True),
                    json.dumps(malware_labels, sort_keys=True),
                    json.dumps(technique_ids, sort_keys=True),
                    len(technique_ids),
                    json.dumps(provenance, sort_keys=True),
                ),
            )
        incidents[int(row["campaign_id"])] = {
            "campaign_id": int(row["campaign_id"]),
            "attack_campaign_id": row["attack_campaign_id"],
            "campaign_name": row["name"],
            "campaign_names": [str(row["name"]), *aliases],
            "actor_answer_key": actor_row["attack_group_id"],
            "actor_answer_label": actor_row["name"],
            "malware_answer_keys": malware_keys,
            "malware_answer_labels": malware_labels,
            "technique_attack_ids": set(technique_ids),
        }
        count += 1
    return count, incidents


def _materialize_campaign_timeline_matches(
    connection: sqlite3.Connection,
    snapshot_id: str,
    campaign_incidents: dict[int, dict[str, object]],
    timelines: list[dict[str, object]],
) -> int:
    match_count = 0
    for campaign in campaign_incidents.values():
        matches: list[dict[str, object]] = []
        for timeline in timelines:
            if timeline["answer_key"] != campaign["actor_answer_key"]:
                continue
            overlap_attack_ids = sorted(campaign["technique_attack_ids"].intersection(timeline["attack_ids"]))
            overlap_count = len(overlap_attack_ids)
            if overlap_count < 2:
                continue
            timeline_precision = overlap_count / len(timeline["attack_ids"])
            if timeline_precision < 0.5:
                continue
            name_boost = _name_boost(
                list(campaign["campaign_names"]),
                [str(timeline["flow_name"] or ""), str(timeline["source_flow_id"] or "")],
            )
            matches.append(
                {
                    "timeline_id": int(timeline["timeline_id"]),
                    "flow_name": timeline["flow_name"],
                    "source_flow_id": timeline["source_flow_id"],
                    "overlap_attack_ids": overlap_attack_ids,
                    "technique_overlap_count": overlap_count,
                    "timeline_precision": timeline_precision,
                    "name_boost": name_boost,
                }
            )
        matches.sort(
            key=lambda row: (
                -int(row["technique_overlap_count"]),
                -float(row["timeline_precision"]),
                -int(row["name_boost"]),
                int(row["timeline_id"]),
            )
        )
        for index, match in enumerate(matches, start=1):
            with connection:
                connection.execute(
                    """
                    INSERT INTO campaign_timeline_matches_v1 (
                        snapshot_id,
                        campaign_id,
                        timeline_id,
                        match_rank,
                        attack_campaign_id,
                        campaign_name,
                        actor_answer_key,
                        actor_answer_label,
                        malware_answer_keys_json,
                        malware_answer_labels_json,
                        overlap_attack_ids_json,
                        technique_overlap_count,
                        timeline_precision,
                        name_boost,
                        flow_name,
                        source_flow_id
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        campaign["campaign_id"],
                        match["timeline_id"],
                        index,
                        campaign["attack_campaign_id"],
                        campaign["campaign_name"],
                        campaign["actor_answer_key"],
                        campaign["actor_answer_label"],
                        json.dumps(campaign["malware_answer_keys"], sort_keys=True),
                        json.dumps(campaign["malware_answer_labels"], sort_keys=True),
                        json.dumps(match["overlap_attack_ids"], sort_keys=True),
                        match["technique_overlap_count"],
                        match["timeline_precision"],
                        match["name_boost"],
                        match["flow_name"],
                        match["source_flow_id"],
                    ),
                )
            match_count += 1
    return match_count


def build_puzzle_tables(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    clear_puzzle_tables_for_snapshot(connection, snapshot_id)
    counts = {
        "actor_profiles": 0,
        "actor_candidates": 0,
        "malware_profiles": 0,
        "malware_candidates": 0,
        "technique_profiles": 0,
        "technique_candidates": 0,
        "timeline_sequences": 0,
        "timeline_candidates": 0,
        "incident_candidates": 0,
        "campaign_incidents": 0,
        "campaign_timeline_matches": 0,
    }

    actor_rows = connection.execute(
        """
        SELECT
            a.actor_id,
            a.attack_group_id,
            a.name,
            a.country_code,
            a.first_observed_year,
            a.target_categories_json,
            a.victim_countries_json,
            a.motivation_tags_json,
            COUNT(DISTINCT am.malware_id) AS malware_count,
            COUNT(DISTINCT oa.operation_id) AS operations_count,
            COUNT(DISTINCT ca.campaign_id) AS campaign_count,
            COUNT(DISTINCT at.technique_id) AS technique_count
        FROM actors a
        LEFT JOIN actor_malware am ON am.actor_id = a.actor_id
        LEFT JOIN operation_actors oa ON oa.actor_id = a.actor_id
        LEFT JOIN campaign_actors ca ON ca.actor_id = a.actor_id
        LEFT JOIN actor_techniques at ON at.actor_id = a.actor_id
        WHERE a.revoked = 0 AND a.deprecated = 0
        GROUP BY
            a.actor_id,
            a.attack_group_id,
            a.name,
            a.country_code,
            a.first_observed_year,
            a.target_categories_json,
            a.victim_countries_json,
            a.motivation_tags_json
        ORDER BY a.name
        """
    ).fetchall()
    for row in actor_rows:
        malware_names = [
            value["name"]
            for value in connection.execute(
                """
                SELECT m.name
                FROM actor_malware am
                JOIN malware m ON m.malware_id = am.malware_id
                WHERE am.actor_id = ?
                ORDER BY m.name
                """,
                (row["actor_id"],),
            )
        ]
        campaign_names = [
            value["name"]
            for value in connection.execute(
                """
                SELECT c.name
                FROM campaign_actors ca
                JOIN campaigns c ON c.campaign_id = ca.campaign_id
                WHERE ca.actor_id = ?
                ORDER BY c.name
                """,
                (row["actor_id"],),
            )
        ]
        operation_names = [
            value["name"]
            for value in connection.execute(
                """
                SELECT o.name
                FROM operation_actors oa
                JOIN operations o ON o.operation_id = oa.operation_id
                WHERE oa.actor_id = ?
                ORDER BY o.name
                """,
                (row["actor_id"],),
            )
        ]
        technique_names = [
            value["name"]
            for value in connection.execute(
                """
                SELECT t.name
                FROM actor_techniques at
                JOIN techniques t ON t.technique_id = at.technique_id
                WHERE at.actor_id = ?
                ORDER BY t.attack_id
                LIMIT 10
                """,
                (row["actor_id"],),
            )
        ]
        profile_clues = [
            int(bool(row["country_code"])),
            int(row["first_observed_year"] is not None),
            int(bool(_loads_list(row["target_categories_json"]))),
            int(bool(_loads_list(row["motivation_tags_json"]))),
        ]
        relationship_clues = [
            int(int(row["malware_count"]) >= 1),
            int(int(row["operations_count"]) >= 1 or int(row["campaign_count"]) >= 1),
            int(int(row["technique_count"]) >= 3),
        ]
        clue_score = sum(profile_clues) + sum(relationship_clues)
        target_categories = _loads_list(row["target_categories_json"])
        victim_countries = _loads_list(row["victim_countries_json"])
        motivation_tags = _loads_list(row["motivation_tags_json"])
        has_complete_phase_one_clues = _has_complete_actor_phase_one_clues(
            country_code=row["country_code"],
            first_observed_year=row["first_observed_year"],
            target_categories=target_categories,
            motivation_tags=motivation_tags,
        )
        has_publishable_three_phase_coverage = _has_publishable_actor_three_phase_coverage(
            malware_count=int(row["malware_count"]),
            technique_count=int(row["technique_count"]),
        )
        clue_payload = {
            "attack_group_id": row["attack_group_id"],
            "display_name": row["name"],
            "country_code": row["country_code"],
            "first_observed_year": row["first_observed_year"],
            "target_categories": target_categories,
            "victim_countries": victim_countries,
            "motivation_tags": motivation_tags,
            "malware_names": malware_names,
            "operation_names": operation_names,
            "campaign_names": campaign_names,
            "technique_names": technique_names,
            "counts": {
                "malware_count": int(row["malware_count"]),
                "operations_count": int(row["operations_count"]),
                "campaign_count": int(row["campaign_count"]),
                "technique_count": int(row["technique_count"]),
            },
        }
        provenance = {
            "identity": "attack_stix",
            "profile": ["misp_threat_actors", "actor_overrides"],
            "relationships": "attack_stix",
        }
        with connection:
            connection.execute(
                """
                INSERT INTO actor_profiles_v1 (
                    snapshot_id,
                    actor_id,
                    clue_payload_json,
                    provenance_json,
                    clue_score
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    row["actor_id"],
                    json.dumps(clue_payload, sort_keys=True),
                    json.dumps(provenance, sort_keys=True),
                    clue_score,
                ),
            )
        counts["actor_profiles"] += 1
        if (
            has_complete_phase_one_clues
            and
            has_publishable_three_phase_coverage
        ):
            with connection:
                connection.execute(
                    """
                    INSERT INTO actor_candidates_v1 (
                        snapshot_id,
                        actor_id,
                        answer_key,
                        answer_label,
                        difficulty,
                        clue_score
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        row["actor_id"],
                        row["attack_group_id"],
                        row["name"],
                        _difficulty_from_score(clue_score),
                        clue_score,
                    ),
                )
            counts["actor_candidates"] += 1

    malware_rows = connection.execute(
        """
        SELECT malware_id, attack_software_id, name, description, aliases_json, platforms_json, malware_category, capability_summary
        FROM malware
        WHERE revoked = 0 AND deprecated = 0
        ORDER BY name
        """
    ).fetchall()
    for row in malware_rows:
        platforms = _loads_list(row["platforms_json"])
        actor_names = [
            value["name"]
            for value in connection.execute(
                """
                SELECT a.name
                FROM actor_malware am
                JOIN actors a ON a.actor_id = am.actor_id
                WHERE am.malware_id = ?
                ORDER BY a.name
                """,
                (row["malware_id"],),
            )
        ]
        technique_names = [
            value["name"]
            for value in connection.execute(
                """
                SELECT DISTINCT t.name
                FROM actor_malware am
                JOIN actor_techniques at ON at.actor_id = am.actor_id
                JOIN techniques t ON t.technique_id = at.technique_id
                WHERE am.malware_id = ?
                ORDER BY t.name
                LIMIT 10
                """,
                (row["malware_id"],),
            )
        ]
        cleaned_capability_summary = clean_attack_text(row["capability_summary"])
        cleaned_description = clean_attack_text(row["description"])
        payload = {
            "attack_software_id": row["attack_software_id"],
            "display_name": row["name"],
            "aliases": _loads_list(row["aliases_json"]),
            "platforms": platforms,
            "malware_category": row["malware_category"],
            "capability_summary": cleaned_capability_summary or cleaned_description,
            "actor_names": actor_names,
            "technique_names": technique_names,
        }
        provenance = {"identity": "attack_stix", "profile": ["malware_overrides"], "relationships": "attack_stix"}
        with connection:
            connection.execute(
                """
                INSERT INTO malware_profiles_v1 (snapshot_id, malware_id, clue_payload_json, provenance_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    row["malware_id"],
                    json.dumps(payload, sort_keys=True),
                    json.dumps(provenance, sort_keys=True),
                ),
            )
        counts["malware_profiles"] += 1
        summary_tier = None
        if platforms and actor_names:
            if cleaned_capability_summary:
                summary_tier = 1
            elif (
                cleaned_description
                and 50 <= len(cleaned_description) <= 300
                and not contains_any_name_reference(cleaned_description, actor_names)
            ):
                summary_tier = 2
        if summary_tier is not None:
            with connection:
                connection.execute(
                    """
                    INSERT INTO malware_candidates_v1 (
                        snapshot_id,
                        malware_id,
                        answer_key,
                        answer_label,
                        summary_tier
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        row["malware_id"],
                        row["attack_software_id"],
                        row["name"],
                        summary_tier,
                    ),
                )
            counts["malware_candidates"] += 1

    technique_rows = connection.execute(
        """
        SELECT technique_id, attack_id, name, description, tactics_json, platforms_json, is_subtechnique, parent_attack_id
        FROM techniques
        WHERE revoked = 0 AND deprecated = 0
        ORDER BY attack_id
        """
    ).fetchall()
    for row in technique_rows:
        tactics = _loads_list(row["tactics_json"])
        platforms = _loads_list(row["platforms_json"])
        parent_name = None
        if row["parent_attack_id"]:
            parent_row = connection.execute(
                "SELECT name FROM techniques WHERE attack_id = ?",
                (row["parent_attack_id"],),
            ).fetchone()
            if parent_row is not None:
                parent_name = parent_row["name"]
        payload = {
            "attack_id": row["attack_id"],
            "display_name": row["name"],
            "description": row["description"],
            "tactics": tactics,
            "platforms": platforms,
            "is_subtechnique": bool(row["is_subtechnique"]),
            "parent_attack_id": row["parent_attack_id"],
            "parent_name": parent_name,
        }
        provenance = {"identity": "attack_stix"}
        with connection:
            connection.execute(
                """
                INSERT INTO technique_profiles_v1 (snapshot_id, technique_id, clue_payload_json, provenance_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    row["technique_id"],
                    json.dumps(payload, sort_keys=True),
                    json.dumps(provenance, sort_keys=True),
                ),
            )
        counts["technique_profiles"] += 1
        if tactics and platforms:
            with connection:
                connection.execute(
                    """
                    INSERT INTO technique_candidates_v1 (
                        snapshot_id,
                        technique_id,
                        answer_key,
                        answer_label
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        row["technique_id"],
                        row["attack_id"],
                        row["name"],
                    ),
                )
            counts["technique_candidates"] += 1

    campaign_incident_count, campaign_incidents = _materialize_campaign_incidents(connection, snapshot_id)
    counts["campaign_incidents"] = campaign_incident_count

    timeline_rows = connection.execute(
        """
        SELECT
            timeline_id,
            source_flow_id,
            flow_name,
            source_url,
            answer_type,
            answer_key,
            answer_label,
            step_count,
            difficulty,
            timeline_source_type,
            path_hash
        FROM timelines
        ORDER BY timeline_id
        """
    ).fetchall()
    incident_metadata_rows = connection.execute(
        """
        SELECT
            timeline_id,
            incident_name,
            attack_campaign_id,
            reference_url,
            source_article_url,
            source_article_title,
            notes,
            confidence
        FROM timeline_incident_metadata
        """
    ).fetchall()
    incident_metadata_by_timeline = {
        int(row["timeline_id"]): row
        for row in incident_metadata_rows
    }
    timeline_match_inputs: list[dict[str, object]] = []
    for row in timeline_rows:
        steps = [
            {"step_index": step["step_index"], "attack_id": step["attack_id"], "technique_name": step["technique_name"]}
            for step in connection.execute(
                """
                SELECT step_index, attack_id, technique_name
                FROM timeline_steps
                WHERE timeline_id = ?
                ORDER BY step_index
                """,
                (row["timeline_id"],),
            )
        ]
        linked_malware = [
            {
                "answer_key": malware_row["attack_software_id"],
                "answer_label": malware_row["name"],
                "reference_url": malware_row["reference_url"],
                "notes": malware_row["notes"],
                "confidence": malware_row["confidence"],
            }
            for malware_row in connection.execute(
                """
                SELECT
                    m.attack_software_id,
                    m.name,
                    tm.reference_url,
                    tm.notes,
                    tm.confidence
                FROM timeline_malware tm
                JOIN malware m ON m.malware_id = tm.malware_id
                WHERE tm.timeline_id = ?
                ORDER BY m.name
                """,
                (row["timeline_id"],),
            )
        ]
        incident_metadata = incident_metadata_by_timeline.get(int(row["timeline_id"]))
        timeline_provenance = {
            "timeline_source_type": row["timeline_source_type"],
            "source_flow_id": row["source_flow_id"],
            "flow_name": row["flow_name"],
            "source_url": row["source_url"],
        }
        if incident_metadata is not None:
            timeline_provenance.update(
                {
                    "incident_name": incident_metadata["incident_name"],
                    "attack_campaign_id": incident_metadata["attack_campaign_id"],
                    "reference_url": incident_metadata["reference_url"],
                    "source_article_url": incident_metadata["source_article_url"],
                    "source_article_title": incident_metadata["source_article_title"],
                    "notes": incident_metadata["notes"],
                    "confidence": incident_metadata["confidence"],
                }
            )
        with connection:
            connection.execute(
                """
                INSERT INTO timeline_sequences_v1 (
                    snapshot_id,
                    timeline_id,
                    answer_type,
                    answer_key,
                    answer_label,
                    step_count,
                    difficulty,
                    steps_json,
                    provenance_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    row["timeline_id"],
                    row["answer_type"],
                    row["answer_key"],
                    row["answer_label"],
                    row["step_count"],
                    row["difficulty"],
                    json.dumps(steps, sort_keys=True),
                    json.dumps(timeline_provenance, sort_keys=True),
                ),
            )
            connection.execute(
                """
                INSERT INTO timeline_candidates_v1 (
                    snapshot_id,
                    timeline_id,
                    answer_type,
                    answer_key,
                    answer_label,
                    step_count,
                    difficulty
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    row["timeline_id"],
                    row["answer_type"],
                    row["answer_key"],
                    row["answer_label"],
                    row["step_count"],
                    row["difficulty"],
                ),
            )
        counts["timeline_sequences"] += 1
        counts["timeline_candidates"] += 1
        if row["answer_type"] == "actor" and steps:
            timeline_match_inputs.append(
                {
                    "timeline_id": int(row["timeline_id"]),
                    "answer_key": str(row["answer_key"]),
                    "flow_name": row["flow_name"],
                    "source_flow_id": row["source_flow_id"],
                    "attack_ids": {str(step["attack_id"]) for step in steps},
                }
            )
        if row["answer_type"] == "actor" and linked_malware and len(steps) >= 3:
            provenance = {
                **timeline_provenance,
                "reference_urls": sorted(
                    {
                        entry["reference_url"]
                        for entry in linked_malware
                        if entry["reference_url"]
                    }
                ),
                "malware_evidence": linked_malware,
            }
            with connection:
                connection.execute(
                    """
                    INSERT INTO incident_candidates_v1 (
                        snapshot_id,
                        timeline_id,
                        actor_answer_key,
                        actor_answer_label,
                        malware_answer_keys_json,
                        malware_answer_labels_json,
                        technique_attack_ids_json,
                        step_count,
                        difficulty,
                        repeat_key,
                        attack_campaign_id,
                        source_article_url,
                        source_article_title,
                        provenance_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        snapshot_id,
                        row["timeline_id"],
                        row["answer_key"],
                        row["answer_label"],
                        json.dumps([entry["answer_key"] for entry in linked_malware], sort_keys=True),
                        json.dumps([entry["answer_label"] for entry in linked_malware], sort_keys=True),
                        json.dumps([step["attack_id"] for step in steps], sort_keys=True),
                        row["step_count"],
                        row["difficulty"],
                        f"{row['source_flow_id']}:{row['path_hash']}",
                        incident_metadata["attack_campaign_id"] if incident_metadata is not None else None,
                        incident_metadata["source_article_url"] if incident_metadata is not None else None,
                        incident_metadata["source_article_title"] if incident_metadata is not None else None,
                        json.dumps(provenance, sort_keys=True),
                    ),
                )
            counts["incident_candidates"] += 1

    counts["campaign_timeline_matches"] = _materialize_campaign_timeline_matches(
        connection,
        snapshot_id,
        campaign_incidents,
        timeline_match_inputs,
    )

    if counts["timeline_sequences"] < 20:
        counts["timeline_warning_total_sequences_below_target"] = counts["timeline_sequences"]
    standard_timelines = connection.execute(
        """
        SELECT COUNT(*)
        FROM timeline_sequences_v1
        WHERE snapshot_id = ? AND difficulty = 'standard'
        """,
        (snapshot_id,),
    ).fetchone()[0]
    if standard_timelines < 10:
        counts["timeline_warning_standard_sequences_below_target"] = int(standard_timelines)

    return counts
