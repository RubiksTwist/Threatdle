from __future__ import annotations

import json

from threatdle.ingest.base import now_utc_iso
from threatdle.services.puzzle_generator import generate_puzzle_day
from threatdle.services.review_validation import validate_review_snapshot


def _seed_review_snapshot(
    db_connection,
    snapshot_id: str,
    *,
    actor_name: str = "Turla",
    actor_key: str = "G0010",
    first_observed_year: int | None = 2004,
    capability_summary: str,
    summary_tier: int,
) -> None:
    actor_payload = {
        "attack_group_id": actor_key,
        "display_name": actor_name,
        "country_code": "RU",
        "first_observed_year": first_observed_year,
        "target_categories": ["Government", "Military"],
        "victim_countries": ["UA"],
        "motivation_tags": ["Espionage"],
        "malware_names": ["Crutch"],
        "campaign_names": [],
        "technique_names": ["Obfuscated Files or Information"],
        "counts": {
            "malware_count": 1,
            "operations_count": 1,
            "campaign_count": 0,
            "technique_count": 1,
        },
    }
    malware_payload = {
        "attack_software_id": "S0538",
        "display_name": "Crutch",
        "aliases": ["Crutch"],
        "platforms": ["Windows"],
        "malware_category": None,
        "capability_summary": capability_summary,
        "actor_names": [actor_name],
        "technique_names": ["Obfuscated Files or Information"],
    }
    technique_payload = {
        "attack_id": "T1027",
        "display_name": "Obfuscated Files or Information",
        "description": "Example technique description",
        "tactics": ["defense-evasion"],
        "platforms": ["Windows", "Linux"],
        "is_subtechnique": False,
        "parent_attack_id": None,
        "parent_name": None,
    }
    steps = [
        {"step_index": 1, "attack_id": "T1566.002", "technique_name": "Spearphishing Link"},
        {"step_index": 2, "attack_id": "T1204.002", "technique_name": "Malicious File"},
        {"step_index": 3, "attack_id": "T1027", "technique_name": "Obfuscated Files or Information"},
    ]

    with db_connection:
        db_connection.execute(
            """
            INSERT INTO snapshots (snapshot_id, created_at, status, ready_at)
            VALUES (?, ?, 'ready', ?)
            """,
            (snapshot_id, now_utc_iso(), now_utc_iso()),
        )
        db_connection.execute(
            """
            INSERT INTO actors (
                actor_id,
                attack_group_id,
                name,
                country_code,
                target_categories_json,
                victim_countries_json,
                motivation_tags_json,
                first_observed_year,
                revoked,
                deprecated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (
                1,
                actor_key,
                actor_name,
                actor_payload["country_code"],
                json.dumps(actor_payload["target_categories"]),
                json.dumps(actor_payload["victim_countries"]),
                json.dumps(actor_payload["motivation_tags"]),
                actor_payload["first_observed_year"],
            ),
        )
        db_connection.execute(
            """
            INSERT INTO malware (
                malware_id,
                stix_id,
                attack_software_id,
                name,
                description,
                aliases_json,
                platforms_json,
                malware_category,
                capability_summary,
                revoked,
                deprecated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0)
            """,
            (
                2,
                "malware--crutch",
                "S0538",
                "Crutch",
                capability_summary,
                json.dumps(malware_payload["aliases"]),
                json.dumps(malware_payload["platforms"]),
                malware_payload["malware_category"],
                capability_summary,
            ),
        )
        db_connection.execute(
            """
            INSERT INTO techniques (
                technique_id,
                stix_id,
                attack_id,
                name,
                description,
                tactics_json,
                platforms_json,
                is_subtechnique,
                parent_attack_id,
                revoked,
                deprecated
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, 0, 0)
            """,
            (
                3,
                "attack-pattern--t1027",
                technique_payload["attack_id"],
                technique_payload["display_name"],
                technique_payload["description"],
                json.dumps(technique_payload["tactics"]),
                json.dumps(technique_payload["platforms"]),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO timelines (
                timeline_id,
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
            VALUES (?, ?, ?, ?, 'actor', ?, ?, 'easy', 3, 'synthetic', ?)
            """,
            (
                4,
                "attack-flow--turla-crutch",
                "Turla Crutch Flow",
                "https://example.test/turla-crutch",
                actor_key,
                actor_name,
                "path-hash-turla",
            ),
        )
        db_connection.execute("INSERT INTO actor_malware (actor_id, malware_id) VALUES (1, 2)")
        db_connection.execute("INSERT INTO actor_techniques (actor_id, technique_id) VALUES (1, 3)")
        db_connection.execute(
            """
            INSERT INTO actor_profiles_v1 (snapshot_id, actor_id, clue_payload_json, provenance_json, clue_score)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                snapshot_id,
                1,
                json.dumps(actor_payload, sort_keys=True),
                json.dumps({"identity": "synthetic"}, sort_keys=True),
                5,
            ),
        )
        db_connection.execute(
            """
            INSERT INTO actor_candidates_v1 (
                snapshot_id, actor_id, answer_key, answer_label, difficulty, clue_score
            )
            VALUES (?, ?, ?, ?, 'easy', 5)
            """,
            (snapshot_id, 1, actor_key, actor_name),
        )
        db_connection.execute(
            """
            INSERT INTO malware_profiles_v1 (snapshot_id, malware_id, clue_payload_json, provenance_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                snapshot_id,
                2,
                json.dumps(malware_payload, sort_keys=True),
                json.dumps({"identity": "synthetic"}, sort_keys=True),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO malware_candidates_v1 (
                snapshot_id, malware_id, answer_key, answer_label, summary_tier
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (snapshot_id, 2, "S0538", "Crutch", summary_tier),
        )
        db_connection.execute(
            """
            INSERT INTO technique_profiles_v1 (snapshot_id, technique_id, clue_payload_json, provenance_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                snapshot_id,
                3,
                json.dumps(technique_payload, sort_keys=True),
                json.dumps({"identity": "synthetic"}, sort_keys=True),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO technique_candidates_v1 (snapshot_id, technique_id, answer_key, answer_label)
            VALUES (?, ?, ?, ?)
            """,
            (snapshot_id, 3, "T1027", technique_payload["display_name"]),
        )
        db_connection.execute(
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
            VALUES (?, ?, 'actor', ?, ?, 3, 'easy', ?, ?)
            """,
            (
                snapshot_id,
                4,
                actor_key,
                actor_name,
                json.dumps(steps, sort_keys=True),
                json.dumps({"timeline_source_type": "synthetic"}, sort_keys=True),
            ),
        )
        db_connection.execute(
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
            VALUES (?, ?, 'actor', ?, ?, 3, 'easy')
            """,
            (snapshot_id, 4, actor_key, actor_name),
        )


def _insert_exact_incident_candidate(
    db_connection,
    snapshot_id: str,
    *,
    source_article_url: str | None = None,
    source_article_title: str | None = None,
) -> None:
    with db_connection:
        db_connection.execute(
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
            VALUES (?, 4, 'G0010', 'Turla', ?, ?, ?, 3, 'easy', 'attack-flow--turla-crutch:path-hash-turla', 'C0001', ?, ?, ?)
            """,
            (
                snapshot_id,
                json.dumps(["S0538"], sort_keys=True),
                json.dumps(["Crutch"], sort_keys=True),
                json.dumps(["T1566.002", "T1204.002", "T1027"], sort_keys=True),
                source_article_url,
                source_article_title,
                json.dumps(
                    {
                        "source_article_url": source_article_url,
                        "source_article_title": source_article_title,
                    },
                    sort_keys=True,
                ),
            ),
        )


def test_validate_review_snapshot_flags_frontend_review_issues(db_connection):
    snapshot_id = "snap-review-issues"
    _seed_review_snapshot(
        db_connection,
        snapshot_id,
        first_observed_year=2004,
        capability_summary="Document theft backdoor that targets Windows hosts and removable storage.",
        summary_tier=1,
    )

    generate_puzzle_day(
        db_connection,
        snapshot_id,
        "2026-03-16",
        theme_mode="strict",
        force=False,
    )
    actor_row = db_connection.execute(
        """
        SELECT payload_json
        FROM puzzle_day
        WHERE snapshot_id = ? AND day_key = ? AND mode = 'actor'
        """,
        (snapshot_id, "2026-03-16"),
    ).fetchone()
    actor_payload = json.loads(actor_row["payload_json"])
    actor_payload["clues"]["first_observed_year"] = None
    malware_row = db_connection.execute(
        """
        SELECT payload_json
        FROM puzzle_day
        WHERE snapshot_id = ? AND day_key = ? AND mode = 'malware'
        """,
        (snapshot_id, "2026-03-16"),
    ).fetchone()
    malware_payload = json.loads(malware_row["payload_json"])
    malware_payload["clues"]["capability_summary"] = (
        "[Crutch](https://attack.mitre.org/software/S0538) is a backdoor designed for "
        "document theft that has been used by Turla since at least 2015."
        "(Citation: ESET Crutch December 2020)"
    )
    with db_connection:
        db_connection.execute(
            """
            UPDATE puzzle_day
            SET payload_json = ?
            WHERE snapshot_id = ? AND day_key = ? AND mode = 'actor'
            """,
            (
                json.dumps(actor_payload, sort_keys=True),
                snapshot_id,
                "2026-03-16",
            ),
        )
        db_connection.execute(
            """
            UPDATE puzzle_day
            SET payload_json = ?
            WHERE snapshot_id = ? AND day_key = ? AND mode = 'malware'
            """,
            (
                json.dumps(malware_payload, sort_keys=True),
                snapshot_id,
                "2026-03-16",
            ),
        )
        db_connection.execute(
            """
            UPDATE malware_candidates_v1
            SET summary_tier = 2
            WHERE snapshot_id = ? AND malware_id = 2
            """,
            (snapshot_id,),
        )

    result = validate_review_snapshot(db_connection, snapshot_id)

    assert result["issue_counts"] == {"error": 4, "warning": 0}
    assert result["issue_counts_by_check"] == {
        "citation_artifact": 1,
        "missing_actor_first_observed_year": 1,
        "raw_markdown_artifact": 1,
        "themed_actor_leak": 1,
    }


def test_validate_review_snapshot_passes_clean_day(db_connection):
    snapshot_id = "snap-review-clean"
    _seed_review_snapshot(
        db_connection,
        snapshot_id,
        first_observed_year=2004,
        capability_summary="Document theft backdoor that targets Windows hosts and removable storage.",
        summary_tier=1,
    )

    generate_puzzle_day(
        db_connection,
        snapshot_id,
        "2026-03-16",
        theme_mode="strict",
        force=False,
    )

    result = validate_review_snapshot(db_connection, snapshot_id)

    assert result["issue_count"] == 0
    assert result["issue_counts"] == {"error": 0, "warning": 0}
    assert result["days_with_issues"] == []


def test_validate_review_snapshot_flags_exact_chain_mismatches_and_source_article_warning(db_connection):
    snapshot_id = "snap-review-exact"
    _seed_review_snapshot(
        db_connection,
        snapshot_id,
        first_observed_year=2004,
        capability_summary="Document theft backdoor that targets Windows hosts and removable storage.",
        summary_tier=1,
    )
    _insert_exact_incident_candidate(
        db_connection,
        snapshot_id,
        source_article_url=None,
        source_article_title="Orphaned title",
    )

    generate_puzzle_day(
        db_connection,
        snapshot_id,
        "2026-03-16",
        chain_mode="exact",
        force=False,
    )
    with db_connection:
        db_connection.execute(
            """
            UPDATE puzzle_day
            SET answer_json = json_set(answer_json, '$.timeline_id', 999)
            WHERE snapshot_id = ? AND day_key = ? AND mode = 'malware'
            """,
            (snapshot_id, "2026-03-16"),
        )

    result = validate_review_snapshot(db_connection, snapshot_id)

    assert result["issue_counts"] == {"error": 1, "warning": 1}
    assert result["issue_counts_by_check"] == {
        "exact_chain_mismatch": 1,
        "source_article_title_without_url": 1,
    }
