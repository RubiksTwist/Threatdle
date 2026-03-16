from __future__ import annotations

import json
from datetime import UTC, datetime

from threatdle.ingest.base import now_utc_iso
from threatdle.services.game_api import get_game_day, get_game_summary, get_game_today, validate_game_guess


SNAPSHOT_ID = "snap-game"
DAY_KEY = "2026-03-16"


def _insert_snapshot(db_connection) -> None:
    with db_connection:
        db_connection.execute(
            """
            INSERT INTO snapshots (snapshot_id, created_at, status, ready_at)
            VALUES (?, ?, 'ready', ?)
            """,
            (SNAPSHOT_ID, now_utc_iso(), now_utc_iso()),
        )


def _insert_timeline_day(db_connection) -> None:
    _insert_snapshot(db_connection)
    steps = [
        {"step_index": 1, "attack_id": "T1566.001", "technique_name": "Spearphishing Attachment"},
        {"step_index": 2, "attack_id": "T1059.001", "technique_name": "PowerShell"},
        {"step_index": 3, "attack_id": "T1003", "technique_name": "OS Credential Dumping"},
    ]
    with db_connection:
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
            VALUES (?, ?, ?, ?, 'actor', 'G0016', 'APT29', 'easy', 3, 'curated_flows', ?)
            """,
            (
                901,
                "flow--timeline-test",
                "Timeline Test Flow",
                "https://example.test/timeline-flow",
                "timeline-test-path-hash",
            ),
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
            VALUES (?, ?, 'actor', 'G0016', 'APT29', 3, 'easy', ?, ?)
            """,
            (
                SNAPSHOT_ID,
                901,
                json.dumps(steps, sort_keys=True),
                json.dumps(
                    {
                        "source_flow_id": "flow--timeline-test",
                        "flow_name": "Timeline Test Flow",
                        "source_url": "https://example.test/timeline-flow",
                        "timeline_source_type": "curated_flows",
                    },
                    sort_keys=True,
                ),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO puzzle_day (
                day_key,
                snapshot_id,
                mode,
                payload_json,
                answer_json,
                created_at
            )
            VALUES (?, ?, 'timeline', ?, ?, ?)
            """,
            (
                DAY_KEY,
                SNAPSHOT_ID,
                json.dumps({"mode": "timeline", "clues": {"step_count": 3}}, sort_keys=True),
                json.dumps(
                    {
                        "answer_key": "G0016",
                        "answer_label": "APT29",
                        "answer_type": "actor",
                        "timeline_id": 901,
                        "repeat_key": "flow--timeline-test:abc123",
                        "comparison": {"steps": steps},
                    },
                    sort_keys=True,
                ),
                now_utc_iso(),
            ),
        )


def _insert_incident_candidate(
    db_connection,
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
            VALUES (?, ?, 'G0016', 'APT29', ?, ?, ?, 3, 'easy', ?, 'C0001', ?, ?, ?)
            """,
            (
                SNAPSHOT_ID,
                901,
                json.dumps(["S0559"], sort_keys=True),
                json.dumps(["SUNBURST"], sort_keys=True),
                json.dumps(["T1566.001", "T1059.001", "T1003"], sort_keys=True),
                "flow--timeline-test:abc123",
                source_article_url,
                source_article_title,
                json.dumps(
                    {
                        "flow_name": "Timeline Test Flow",
                        "source_article_url": source_article_url,
                        "source_article_title": source_article_title,
                    },
                    sort_keys=True,
                ),
            ),
        )


def _insert_exact_three_phase_day(db_connection) -> None:
    _insert_timeline_day(db_connection)
    with db_connection:
        db_connection.execute(
            """
            DELETE FROM puzzle_day
            WHERE snapshot_id = ? AND day_key = ? AND mode = 'timeline'
            """,
            (SNAPSHOT_ID, DAY_KEY),
        )
        rows = [
            (
                "actor",
                {"mode": "actor", "clues": {"country_code": "RU", "first_observed_year": 2008}},
                {
                    "answer_key": "G0016",
                    "answer_label": "APT29",
                    "chain_mode": "exact",
                    "timeline_id": 901,
                    "repeat_key": "flow--timeline-test:abc123",
                    "comparison": {
                        "country_code": "RU",
                        "first_observed_year": 2008,
                        "target_categories": ["Government"],
                        "motivation_tags": ["Espionage"],
                        "malware_count": 1,
                        "technique_count": 3,
                    },
                },
            ),
            (
                "malware",
                {"mode": "malware", "clues": {"platforms": ["Windows"], "actor_count": 1}},
                {
                    "answer_key": "S0559",
                    "answer_label": "SUNBURST",
                    "chain_mode": "exact",
                    "timeline_id": 901,
                    "repeat_key": "flow--timeline-test:abc123",
                    "comparison": {
                        "platforms": ["Windows"],
                        "malware_category": "Backdoor",
                        "aliases": ["Solorigate"],
                        "actor_names": ["APT29"],
                    },
                },
            ),
            (
                "technique",
                {"mode": "technique", "clues": {"tactics": ["execution"], "platforms": ["Windows"]}},
                {
                    "answer_key": "T1566.001",
                    "answer_label": "Spearphishing Attachment",
                    "chain_mode": "exact",
                    "timeline_id": 901,
                    "repeat_key": "flow--timeline-test:abc123",
                    "comparison": {
                        "tactics": ["execution"],
                        "platforms": ["Windows"],
                        "is_subtechnique": True,
                        "parent_attack_id": "T1566",
                        "parent_name": "Phishing",
                    },
                },
            ),
        ]
        for mode, payload_json, answer_json in rows:
            db_connection.execute(
                """
                INSERT INTO puzzle_day (
                    day_key,
                    snapshot_id,
                    mode,
                    payload_json,
                    answer_json,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    DAY_KEY,
                    SNAPSHOT_ID,
                    mode,
                    json.dumps(payload_json, sort_keys=True),
                    json.dumps(answer_json, sort_keys=True),
                    now_utc_iso(),
                ),
            )


def test_get_game_day_exposes_deterministic_scrambled_timeline_steps(db_connection):
    _insert_timeline_day(db_connection)

    first = get_game_day(db_connection, SNAPSHOT_ID, DAY_KEY)
    second = get_game_day(db_connection, SNAPSHOT_ID, DAY_KEY)

    first_clues = first["modes"]["timeline"]["payload"]["clues"]
    second_clues = second["modes"]["timeline"]["payload"]["clues"]

    canonical_ids = [step["attack_id"] for step in first_clues["steps"]]
    scrambled_ids = [step["attack_id"] for step in first_clues["scrambled_steps"]]

    assert canonical_ids == ["T1566.001", "T1059.001", "T1003"]
    assert scrambled_ids != canonical_ids
    assert scrambled_ids == [step["attack_id"] for step in second_clues["scrambled_steps"]]
    assert first_clues["ordering_basis"] == "Arrange the techniques in the source-reported execution order."


def test_validate_game_guess_scores_timeline_order(db_connection):
    _insert_timeline_day(db_connection)

    incorrect = validate_game_guess(
        db_connection,
        SNAPSHOT_ID,
        DAY_KEY,
        "timeline",
        guess_steps=["T1059.001", "T1566.001", "T1003"],
    )
    assert incorrect["solved"] is False
    assert incorrect["feedback"]["step_1"]["status"] == "partial"
    assert incorrect["feedback"]["step_2"]["status"] == "partial"
    assert incorrect["feedback"]["step_3"]["status"] == "match"

    correct = validate_game_guess(
        db_connection,
        SNAPSHOT_ID,
        DAY_KEY,
        "timeline",
        guess_steps=["T1566.001", "T1059.001", "T1003"],
    )
    assert correct["solved"] is True
    assert all(cell["status"] == "match" for cell in correct["feedback"].values())


def test_get_game_summary_uses_exact_timeline_id_for_provenance(db_connection):
    _insert_timeline_day(db_connection)

    summary = get_game_summary(db_connection, SNAPSHOT_ID, DAY_KEY)

    assert summary["timeline_provenance"]["flow_name"] == "Timeline Test Flow"
    assert summary["timeline_provenance"]["source_url"] == "https://example.test/timeline-flow"


def test_get_game_summary_exposes_incident_source_only_for_exact_days(db_connection):
    _insert_exact_three_phase_day(db_connection)
    _insert_incident_candidate(
        db_connection,
        source_article_url="https://example.test/article",
        source_article_title="Canonical Incident Article",
    )

    summary = get_game_summary(db_connection, SNAPSHOT_ID, DAY_KEY)

    assert summary["incident_source"] == {
        "attack_campaign_id": "C0001",
        "title": "Canonical Incident Article",
        "url": "https://example.test/article",
    }
    assert summary["timeline_provenance"]["flow_name"] == "Timeline Test Flow"


def test_get_game_today_uses_server_timezone_and_returns_archive_days(db_connection):
    _insert_exact_three_phase_day(db_connection)
    with db_connection:
        db_connection.execute(
            """
            INSERT INTO puzzle_day (
                day_key,
                snapshot_id,
                mode,
                payload_json,
                answer_json,
                created_at
            )
            VALUES (?, ?, 'actor', ?, ?, ?)
            """,
            (
                "2026-03-17",
                SNAPSHOT_ID,
                json.dumps({"mode": "actor", "clues": {"country_code": "RU"}}, sort_keys=True),
                json.dumps(
                    {
                        "answer_key": "G0016",
                        "answer_label": "APT29",
                        "comparison": {"country_code": "RU"},
                    },
                    sort_keys=True,
                ),
                now_utc_iso(),
            ),
        )

    payload = get_game_today(
        db_connection,
        snapshot_id=SNAPSHOT_ID,
        timezone_name="America/New_York",
        now=datetime(2026, 3, 16, 12, 0, tzinfo=UTC),
    )

    assert payload["snapshot_id"] == SNAPSHOT_ID
    assert payload["server_day_key"] == "2026-03-16"
    assert payload["day_key"] == DAY_KEY
    assert payload["latest_day"] == DAY_KEY
    assert payload["available_days"] == [DAY_KEY]
    assert payload["timezone"] == "America/New_York"


def test_get_game_today_allows_valid_archive_override(db_connection):
    _insert_exact_three_phase_day(db_connection)

    payload = get_game_today(
        db_connection,
        snapshot_id=SNAPSHOT_ID,
        day_key=DAY_KEY,
        timezone_name="America/New_York",
        now=datetime(2026, 3, 16, 12, 0, tzinfo=UTC),
    )

    assert payload["day_key"] == DAY_KEY
