from __future__ import annotations

import io
import json
from pathlib import Path
import zipfile

import pytest

from threatdle.ingest.attack_flow import ingest_attack_flow
from threatdle.ingest.attack_stix import ingest_attack_stix
from threatdle.ingest.fetch import fetch_sources
from threatdle.ingest.misp import ingest_misp_actors
from threatdle.ingest.overrides import ingest_overrides
from threatdle.ingest.base import now_utc_iso
from threatdle.services.puzzle_generator import (
    CandidateRow,
    _actor_answer,
    _actor_payload,
    _malware_answer,
    _malware_payload,
    generate_puzzle_day,
    generate_puzzle_range,
    preview_puzzle_day,
    _passes_actor_quality,
    _passes_technique_quality,
    _repeat_answer_keys,
)
from threatdle.services.puzzle_views import build_puzzle_tables


def _fixture_bytes(fixture_dir: Path, file_name: str) -> bytes:
    return (fixture_dir / file_name).read_bytes()


def _empty_zip_bytes() -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w"):
        pass
    return payload.getvalue()


def _fake_fetch_factory(fixture_dir: Path):
    empty_zip = _empty_zip_bytes()

    def _fake_fetch(url: str, timeout_seconds: float = 45.0) -> bytes:
        mapping = {
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json": _fixture_bytes(
                fixture_dir,
                "attack_index.json",
            ),
            "https://example.test/enterprise-attack/enterprise-attack-18.1.json": _fixture_bytes(
                fixture_dir,
                "enterprise-attack-18.1.json",
            ),
            "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json": _fixture_bytes(
                fixture_dir,
                "threat-actor.json",
            ),
            "https://github.com/center-for-threat-informed-defense/adversary_emulation_library/archive/refs/heads/master.zip": empty_zip,
            "https://github.com/attackevals/ael/archive/refs/heads/main.zip": empty_zip,
        }
        return mapping[url]

    return _fake_fetch


def _write_override_files(app_root: Path) -> None:
    overrides_dir = app_root / "data" / "overrides"
    overrides_dir.mkdir(parents=True, exist_ok=True)
    (overrides_dir / "actor_match_overrides.csv").write_text(
        "\n".join(
            [
                "misp_uuid,attack_group_id",
                "uuid-override,G0016",
            ]
        ),
        encoding="utf-8",
    )
    (overrides_dir / "actor_overrides.csv").write_text(
        "\n".join(
            [
                "attack_group_id,display_name,country_code,first_observed_year,target_categories,victim_countries,motivation_tags,notes,reference_url",
                "G0016,APT29,CN,2014,,,,manual note,https://example.test/actor",
            ]
        ),
        encoding="utf-8",
    )
    (overrides_dir / "malware_overrides.csv").write_text(
        "\n".join(
            [
                "attack_software_id,display_name,malware_category,platforms,capability_summary,reference_url",
                "S0559,SUNBURST,Supply Chain,Windows,Supply chain backdoor,https://example.test/malware",
            ]
        ),
        encoding="utf-8",
    )


def _write_curated_flows(app_root: Path, curated_flow_payload: dict) -> None:
    curated_dir = app_root / "data" / "curated-flows"
    curated_dir.mkdir(parents=True, exist_ok=True)
    (curated_dir / "solarwinds.json").write_text(json.dumps(curated_flow_payload), encoding="utf-8")


def _build_ready_snapshot(monkeypatch, fixture_dir: Path, curated_flow_payload: dict, db_connection, app_root: Path, snapshot_id: str) -> None:
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    monkeypatch.setattr(
        "threatdle.ingest.fetch.fetch_url_bytes",
        _fake_fetch_factory(fixture_dir),
    )
    fetch_sources(db_connection, snapshot_id, root_dir=app_root)
    ingest_attack_stix(db_connection, snapshot_id)
    ingest_overrides(db_connection, snapshot_id, root_dir=app_root)
    ingest_misp_actors(db_connection, snapshot_id)
    ingest_overrides(db_connection, snapshot_id, root_dir=app_root)
    ingest_attack_flow(db_connection, snapshot_id)
    build_puzzle_tables(db_connection, snapshot_id)
    with db_connection:
        db_connection.execute(
            "UPDATE snapshots SET status = 'ready', ready_at = ? WHERE snapshot_id = ?",
            (now_utc_iso(), snapshot_id),
        )


def _seed_synthetic_snapshot(db_connection, snapshot_id: str, *, count: int) -> None:
    with db_connection:
        db_connection.execute(
            """
            INSERT INTO snapshots (snapshot_id, created_at, status, ready_at)
            VALUES (?, ?, 'ready', ?)
            """,
            (snapshot_id, now_utc_iso(), now_utc_iso()),
        )
        for index in range(1, count + 1):
            actor_id = 1000 + index
            malware_id = 2000 + index
            technique_id = 3000 + index
            timeline_id = 4000 + index
            attack_group_id = f"G{9000 + index:04d}"
            attack_software_id = f"S{9000 + index:04d}"
            attack_id = f"T{9000 + index:04d}"
            actor_name = f"Actor {index}"
            malware_name = f"Malware {index}"
            technique_name = f"Technique {index}"
            payload_actor = {
                "attack_group_id": attack_group_id,
                "display_name": actor_name,
                "country_code": "US" if index % 2 else "CN",
                "first_observed_year": 2010 + index,
                "target_categories": ["Government"],
                "victim_countries": ["US"],
                "motivation_tags": ["Espionage"],
                "malware_names": [malware_name],
                "campaign_names": [],
                "technique_names": [technique_name],
                "counts": {
                    "malware_count": 1,
                    "operations_count": 1,
                    "campaign_count": 0,
                    "technique_count": 1,
                },
            }
            payload_malware = {
                "attack_software_id": attack_software_id,
                "display_name": malware_name,
                "aliases": [f"M{index}"],
                "platforms": ["Windows", "Linux"],
                "malware_category": "Backdoor",
                "capability_summary": f"Synthetic malware summary for candidate {index} that is long enough.",
                "actor_names": [actor_name],
                "technique_names": [technique_name],
            }
            payload_technique = {
                "attack_id": attack_id,
                "display_name": technique_name,
                "description": f"Synthetic technique description {index}",
                "tactics": ["execution", "persistence"],
                "platforms": ["Windows", "Linux"],
                "is_subtechnique": False,
                "parent_attack_id": None,
                "parent_name": None,
            }
            steps = [
                {"step_index": 1, "attack_id": attack_id, "technique_name": technique_name},
                {"step_index": 2, "attack_id": f"T{9100 + index:04d}", "technique_name": f"Step {index}B"},
                {"step_index": 3, "attack_id": f"T{9200 + index:04d}", "technique_name": f"Step {index}C"},
            ]
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
                    actor_id,
                    attack_group_id,
                    actor_name,
                    payload_actor["country_code"],
                    json.dumps(payload_actor["target_categories"]),
                    json.dumps(payload_actor["victim_countries"]),
                    json.dumps(payload_actor["motivation_tags"]),
                    payload_actor["first_observed_year"],
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
                    malware_id,
                    f"malware--{attack_software_id.lower()}",
                    attack_software_id,
                    malware_name,
                    payload_malware["capability_summary"],
                    json.dumps(payload_malware["aliases"]),
                    json.dumps(payload_malware["platforms"]),
                    payload_malware["malware_category"],
                    payload_malware["capability_summary"],
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
                    technique_id,
                    f"attack-pattern--{attack_id.lower()}",
                    attack_id,
                    technique_name,
                    payload_technique["description"],
                    json.dumps(payload_technique["tactics"]),
                    json.dumps(payload_technique["platforms"]),
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
                    timeline_id,
                    f"attack-flow--synthetic-{index}",
                    f"Synthetic Timeline {index}",
                    f"https://example.test/timeline/{index}",
                    attack_group_id,
                    actor_name,
                    f"path-{index}",
                ),
            )
            db_connection.execute(
                "INSERT INTO actor_malware (actor_id, malware_id) VALUES (?, ?)",
                (actor_id, malware_id),
            )
            db_connection.execute(
                "INSERT INTO actor_techniques (actor_id, technique_id) VALUES (?, ?)",
                (actor_id, technique_id),
            )
            db_connection.execute(
                """
                INSERT INTO actor_profiles_v1 (snapshot_id, actor_id, clue_payload_json, provenance_json, clue_score)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    actor_id,
                    json.dumps(payload_actor, sort_keys=True),
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
                (snapshot_id, actor_id, attack_group_id, actor_name),
            )
            db_connection.execute(
                """
                INSERT INTO malware_profiles_v1 (snapshot_id, malware_id, clue_payload_json, provenance_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    malware_id,
                    json.dumps(payload_malware, sort_keys=True),
                    json.dumps({"identity": "synthetic"}, sort_keys=True),
                ),
            )
            db_connection.execute(
                """
                INSERT INTO malware_candidates_v1 (
                    snapshot_id, malware_id, answer_key, answer_label, summary_tier
                )
                VALUES (?, ?, ?, ?, 1)
                """,
                (snapshot_id, malware_id, attack_software_id, malware_name),
            )
            db_connection.execute(
                """
                INSERT INTO technique_profiles_v1 (snapshot_id, technique_id, clue_payload_json, provenance_json)
                VALUES (?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    technique_id,
                    json.dumps(payload_technique, sort_keys=True),
                    json.dumps({"identity": "synthetic"}, sort_keys=True),
                ),
            )
            db_connection.execute(
                """
                INSERT INTO technique_candidates_v1 (snapshot_id, technique_id, answer_key, answer_label)
                VALUES (?, ?, ?, ?)
                """,
                (snapshot_id, technique_id, attack_id, technique_name),
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
                    timeline_id,
                    attack_group_id,
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
                (snapshot_id, timeline_id, attack_group_id, actor_name),
            )


def _seed_exact_incident_candidate(
    db_connection,
    snapshot_id: str,
    *,
    index: int = 1,
    source_article_url: str | None = None,
    source_article_title: str | None = None,
) -> None:
    attack_group_id = f"G{9000 + index:04d}"
    attack_software_id = f"S{9000 + index:04d}"
    attack_id = f"T{9000 + index:04d}"
    timeline_id = 4000 + index
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
            VALUES (?, ?, ?, ?, ?, ?, ?, 3, 'easy', ?, 'C0001', ?, ?, ?)
            """,
            (
                snapshot_id,
                timeline_id,
                attack_group_id,
                f"Actor {index}",
                json.dumps([attack_software_id], sort_keys=True),
                json.dumps([f"Malware {index}"], sort_keys=True),
                json.dumps([attack_id], sort_keys=True),
                f"attack-flow--synthetic-{index}:path-{index}",
                source_article_url,
                source_article_title,
                json.dumps(
                    {
                        "flow_name": f"Synthetic Timeline {index}",
                        "source_article_url": source_article_url,
                        "source_article_title": source_article_title,
                    },
                    sort_keys=True,
                ),
            ),
        )


def test_determinism_for_same_snapshot_and_day(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-determinism", count=20)

    first = preview_puzzle_day(db_connection, "snap-determinism", "2026-03-16", theme_mode="prefer")
    second = preview_puzzle_day(db_connection, "snap-determinism", "2026-03-16", theme_mode="prefer")

    assert first["theme_anchor"] == second["theme_anchor"]
    assert first["fallback_modes"] == second["fallback_modes"]
    assert first["rows"] == second["rows"]


def test_exact_chain_technique_comes_from_incident_technique_set(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-timeline-technique", count=1)
    _seed_exact_incident_candidate(db_connection, "snap-timeline-technique")

    preview = preview_puzzle_day(
        db_connection,
        "snap-timeline-technique",
        "2026-03-16",
        chain_mode="exact",
    )

    technique_row = next(row for row in preview["rows"] if row["mode"] == "technique")

    assert technique_row["answer_key"] == "T9001"


def test_actor_rows_omit_operations_from_player_payloads():
    candidate = CandidateRow(
        row_id=1,
        mode="actor",
        answer_key="G0001",
        answer_label="Actor Example",
        payload={
            "country_code": "IR",
            "first_observed_year": 2014,
            "target_categories": ["Government"],
            "motivation_tags": ["Espionage"],
            "counts": {
                "malware_count": 2,
                "operations_count": 0,
                "campaign_count": 0,
                "technique_count": 6,
            },
        },
        provenance={},
    )

    actor_payload = _actor_payload(candidate)
    actor_answer = _actor_answer(candidate)

    assert "operations_count" not in actor_payload["clues"]
    assert "campaign_count" not in actor_payload["clues"]
    assert "operations_count" not in actor_answer["comparison"]
    assert "campaign_count" not in actor_answer["comparison"]


def test_malware_rows_omit_category_from_player_payloads():
    candidate = CandidateRow(
        row_id=2,
        mode="malware",
        answer_key="S0001",
        answer_label="Malware Example",
        payload={
            "platforms": ["Windows", "Linux"],
            "malware_category": "Backdoor",
            "capability_summary": "Long enough capability summary for the malware clue panel.",
            "aliases": ["Alias Example"],
            "actor_names": ["Actor Example"],
        },
        provenance={},
    )

    malware_payload = _malware_payload(candidate)
    malware_answer = _malware_answer(candidate)

    assert "malware_category" not in malware_payload["clues"]
    assert "malware_category" not in malware_answer["comparison"]


def test_repeat_window_prevents_same_actor_on_day_one_and_day_fifteen(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-repeat", count=20)

    result = generate_puzzle_range(
        db_connection,
        "snap-repeat",
        "2026-03-01",
        15,
        theme_mode="off",
        force=False,
    )

    day_one_actor = next(row for row in result["generated_days"][0]["rows"] if row["mode"] == "actor")
    day_fifteen_actor = next(row for row in result["generated_days"][14]["rows"] if row["mode"] == "actor")
    assert day_one_actor["answer_key"] != day_fifteen_actor["answer_key"]


def test_timeline_repeat_window_uses_repeat_key_when_present(db_connection):
    with db_connection:
        db_connection.execute(
            """
            INSERT INTO snapshots (snapshot_id, created_at, status, ready_at)
            VALUES ('snap-repeat-key', ?, 'ready', ?)
            """,
            (now_utc_iso(), now_utc_iso()),
        )
        db_connection.execute(
            """
            INSERT INTO puzzle_day (day_key, snapshot_id, mode, payload_json, answer_json, created_at)
            VALUES ('2026-03-16', 'snap-repeat-key', 'timeline', '{}', ?, ?)
            """,
            (
                json.dumps(
                    {
                        "answer_key": "G0016",
                        "repeat_key": "flow--repeat-key:path-a",
                    },
                    sort_keys=True,
                ),
                now_utc_iso(),
            ),
        )

    assert _repeat_answer_keys(db_connection, "timeline", "2026-03-20") == {"flow--repeat-key:path-a"}


def test_theme_mode_strict_fails_when_single_anchor_is_in_repeat_window(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-strict", count=1)

    generate_puzzle_day(
        db_connection,
        "snap-strict",
        "2026-03-16",
        theme_mode="strict",
        force=False,
    )

    with pytest.raises(ValueError, match="No cross-linkable actors available for strict themed generation"):
        generate_puzzle_day(
            db_connection,
            "snap-strict",
            "2026-03-17",
            theme_mode="strict",
            force=False,
        )


def test_exact_chain_mode_uses_one_timeline_for_all_modes(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-exact", count=1)
    _seed_exact_incident_candidate(
        db_connection,
        "snap-exact",
        source_article_url="https://example.test/article",
        source_article_title="Synthetic Incident Article",
    )

    result = generate_puzzle_day(
        db_connection,
        "snap-exact",
        "2026-03-16",
        chain_mode="exact",
        force=False,
    )

    assert result["chain_mode"] == "exact"
    assert result["fallback_modes"] == []
    assert len(result["rows"]) == 3
    timeline_ids = {row["answer_json"]["timeline_id"] for row in result["rows"]}
    assert timeline_ids == {4001}
    assert all(row["answer_json"]["chain_mode"] == "exact" for row in result["rows"])


def test_exact_chain_mode_fails_without_incident_candidates(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-exact-empty", count=1)

    with pytest.raises(ValueError, match="no incident candidates for exact generation"):
        preview_puzzle_day(
            db_connection,
            "snap-exact-empty",
            "2026-03-16",
            chain_mode="exact",
        )


def test_malware_candidate_tiering(monkeypatch, fixture_dir: Path, curated_flow_payload: dict, db_connection, app_root: Path):
    _build_ready_snapshot(monkeypatch, fixture_dir, curated_flow_payload, db_connection, app_root, "snap-malware-tier")

    actor_id = db_connection.execute(
        "SELECT actor_id FROM actors WHERE attack_group_id = 'G0016'"
    ).fetchone()["actor_id"]
    with db_connection:
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
                9001,
                "malware--tier-two",
                "S9001",
                "Tier Two Malware",
                "This synthetic fallback description is concise enough to be usable in a puzzle without an override summary.",
                json.dumps(["TierTwo"]),
                json.dumps(["Windows"]),
                "Backdoor",
                None,
            ),
        )
        db_connection.execute("INSERT INTO actor_malware (actor_id, malware_id) VALUES (?, ?)", (actor_id, 9001))
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
                9002,
                "malware--too-long",
                "S9002",
                "Too Long Malware",
                "L" * 301,
                json.dumps(["TooLong"]),
                json.dumps(["Windows"]),
                "Backdoor",
                None,
            ),
        )
        db_connection.execute("INSERT INTO actor_malware (actor_id, malware_id) VALUES (?, ?)", (actor_id, 9002))

    counts = build_puzzle_tables(db_connection, "snap-malware-tier")
    assert counts["malware_candidates"] == 2

    candidate_rows = db_connection.execute(
        """
        SELECT answer_key, summary_tier
        FROM malware_candidates_v1
        WHERE snapshot_id = 'snap-malware-tier'
        ORDER BY answer_key
        """
    ).fetchall()
    assert [(row["answer_key"], row["summary_tier"]) for row in candidate_rows] == [("S0559", 1), ("S9001", 2)]


def test_build_puzzle_tables_sanitizes_malware_summaries_and_rejects_actor_leaking_tier_two(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _build_ready_snapshot(monkeypatch, fixture_dir, curated_flow_payload, db_connection, app_root, "snap-malware-clean")

    actor_id = db_connection.execute(
        "SELECT actor_id FROM actors WHERE attack_group_id = 'G0016'"
    ).fetchone()["actor_id"]
    with db_connection:
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
                9003,
                "malware--leaky-tier-two",
                "S9003",
                "Leaky Tier Two Malware",
                "[Leak](https://example.test) is malware used by APT29 for exfiltration. (Citation: Example Source)",
                json.dumps(["Leak"]),
                json.dumps(["Windows"]),
                "Backdoor",
                None,
            ),
        )
        db_connection.execute("INSERT INTO actor_malware (actor_id, malware_id) VALUES (?, ?)", (actor_id, 9003))

    build_puzzle_tables(db_connection, "snap-malware-clean")

    payload = json.loads(
        db_connection.execute(
            """
            SELECT clue_payload_json
            FROM malware_profiles_v1
            WHERE snapshot_id = 'snap-malware-clean' AND malware_id = 9003
            """
        ).fetchone()["clue_payload_json"]
    )
    assert payload["capability_summary"] == "Leak is malware used by APT29 for exfiltration."

    candidate_row = db_connection.execute(
        """
        SELECT summary_tier
        FROM malware_candidates_v1
        WHERE snapshot_id = 'snap-malware-clean' AND malware_id = 9003
        """
    ).fetchone()
    assert candidate_row is None


def test_preview_puzzle_day_does_not_write(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-preview", count=5)

    preview = preview_puzzle_day(db_connection, "snap-preview", "2026-03-16", theme_mode="prefer")

    assert len(preview["rows"]) == 3
    written = db_connection.execute("SELECT COUNT(*) FROM puzzle_day").fetchone()[0]
    assert written == 0


def test_technique_quality_gate_rejects_single_platform_single_tactic():
    weak = CandidateRow(
        mode="technique",
        answer_key="T9999",
        answer_label="Weak Technique",
        payload={
            "attack_id": "T9999",
            "display_name": "Weak Technique",
            "description": "weak",
            "tactics": ["execution"],
            "platforms": ["Windows"],
            "is_subtechnique": False,
            "parent_attack_id": None,
            "parent_name": None,
        },
        provenance={},
        row_id=1,
    )
    assert _passes_technique_quality(weak) is False


def test_actor_quality_gate_requires_first_observed_year():
    weak = CandidateRow(
        mode="actor",
        answer_key="G9999",
        answer_label="Actor Without Year",
        payload={
            "attack_group_id": "G9999",
            "display_name": "Actor Without Year",
            "country_code": "RU",
            "first_observed_year": None,
            "target_categories": ["Government"],
            "victim_countries": ["UA"],
            "motivation_tags": ["Espionage"],
            "malware_names": ["Test Malware"],
            "campaign_names": [],
            "technique_names": ["Test Technique"],
            "counts": {
                "malware_count": 1,
                "operations_count": 0,
                "campaign_count": 0,
                "technique_count": 5,
            },
        },
        provenance={},
        row_id=1,
    )
    assert _passes_actor_quality(weak) is False


def test_actor_quality_gate_requires_targets_and_motivation():
    weak = CandidateRow(
        mode="actor",
        answer_key="G9998",
        answer_label="Actor Without Profile Lists",
        payload={
            "attack_group_id": "G9998",
            "display_name": "Actor Without Profile Lists",
            "country_code": "RU",
            "first_observed_year": 2016,
            "target_categories": [],
            "victim_countries": ["UA"],
            "motivation_tags": [],
            "malware_names": ["Test Malware"],
            "operation_names": ["Test Operation"],
            "campaign_names": [],
            "technique_names": ["Test Technique"],
            "counts": {
                "malware_count": 1,
                "operations_count": 1,
                "campaign_count": 0,
                "technique_count": 5,
            },
        },
        provenance={},
        row_id=1,
    )
    assert _passes_actor_quality(weak) is False


def test_prefer_theme_can_use_safe_tier_two_malware_when_no_tier_one_is_linked(db_connection):
    _seed_synthetic_snapshot(db_connection, "snap-themed-tier-fallback", count=1)

    with db_connection:
        db_connection.execute(
            """
            UPDATE malware_candidates_v1
            SET summary_tier = 2
            WHERE snapshot_id = 'snap-themed-tier-fallback' AND malware_id = 2001
            """
        )
        db_connection.execute(
            """
            UPDATE malware_profiles_v1
            SET clue_payload_json = ?
            WHERE snapshot_id = 'snap-themed-tier-fallback' AND malware_id = 2001
            """,
            (
                json.dumps(
                    {
                        "actor_names": ["Actor 1"],
                        "aliases": ["M1"],
                        "attack_software_id": "S9001",
                        "capability_summary": "Fallback summary that is long enough to be a tier-two clue.",
                        "display_name": "Malware 1",
                        "malware_category": "Backdoor",
                        "platforms": ["Windows", "Linux"],
                        "technique_names": ["Technique 1"],
                    },
                    sort_keys=True,
                ),
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
                9009,
                "malware--independent-tier-one",
                "S9009",
                "Independent Malware",
                "Independent malware override summary",
                json.dumps(["Indie"]),
                json.dumps(["Windows"]),
                "Backdoor",
                "Independent malware override summary",
            ),
        )
        db_connection.execute(
            """
            INSERT INTO malware_profiles_v1 (snapshot_id, malware_id, clue_payload_json, provenance_json)
            VALUES (?, ?, ?, ?)
            """,
            (
                "snap-themed-tier-fallback",
                9009,
                json.dumps(
                    {
                        "attack_software_id": "S9009",
                        "display_name": "Independent Malware",
                        "aliases": ["Indie"],
                        "platforms": ["Windows"],
                        "malware_category": "Backdoor",
                        "capability_summary": "Independent malware override summary",
                        "actor_names": [],
                        "technique_names": [],
                    },
                    sort_keys=True,
                ),
                json.dumps({"identity": "synthetic"}, sort_keys=True),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO malware_candidates_v1 (
                snapshot_id, malware_id, answer_key, answer_label, summary_tier
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            ("snap-themed-tier-fallback", 9009, "S9009", "Independent Malware"),
        )

    result = generate_puzzle_day(
        db_connection,
        "snap-themed-tier-fallback",
        "2026-03-16",
        theme_mode="prefer",
        force=False,
    )

    assert result["theme_anchor"] == {"answer_key": "G9001", "answer_label": "Actor 1"}
    malware_row = next(row for row in result["rows"] if row["mode"] == "malware")
    assert malware_row["answer_key"] == "S9001"
    assert result["fallback_modes"] == []
