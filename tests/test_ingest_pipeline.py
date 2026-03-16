from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import zipfile

from threatdle.db.repositories import get_snapshot, mark_snapshot_ready
from threatdle.ingest.attack_flow import ingest_attack_flow
from threatdle.ingest.attack_stix import ingest_attack_stix
from threatdle.ingest.emulation_plans import ingest_emulation_plans
from threatdle.ingest.fetch import fetch_sources
from threatdle.ingest.incident_overrides import ingest_incident_overrides
from threatdle.ingest.misp import ingest_misp_actors
from threatdle.ingest.overrides import ingest_overrides
from threatdle.normalize.text import normalize_actor_name
from threatdle.services.actor_backfill_report import build_actor_backfill_report
from threatdle.services.campaign_report import build_campaign_match_report
from threatdle.services.puzzle_views import build_puzzle_tables


def _fixture_bytes(fixture_dir: Path, file_name: str) -> bytes:
    return (fixture_dir / file_name).read_bytes()


def _campaign_ready_attack_bundle_bytes(fixture_dir: Path) -> bytes:
    bundle = json.loads((fixture_dir / "enterprise-attack-18.1.json").read_text(encoding="utf-8"))
    bundle["objects"].extend(
        [
            {
                "type": "relationship",
                "id": "relationship--campaign-tech-3",
                "relationship_type": "uses",
                "source_ref": "campaign--solarwinds",
                "target_ref": "attack-pattern--credential-dumping",
            },
            {
                "type": "relationship",
                "id": "relationship--campaign-malware-1",
                "relationship_type": "uses",
                "source_ref": "campaign--solarwinds",
                "target_ref": "malware--sunburst",
            },
        ]
    )
    return json.dumps(bundle).encode("utf-8")


def _zip_bytes(file_map: dict[str, str]) -> bytes:
    payload = io.BytesIO()
    with zipfile.ZipFile(payload, "w") as archive:
        for path, contents in file_map.items():
            archive.writestr(path, contents)
    return payload.getvalue()


def _sample_emulation_plan_yaml(actor_name: str = "APT29") -> str:
    return "\n".join(
        [
            "- emulation_plan_details:",
            f"    adversary_name: {actor_name}",
            "    adversary_description: Example plan",
            "- id: step-1",
            "  procedure_step: '1.A.1'",
            "  cti_source: https://example.test/report/one",
            "  technique:",
            "    attack_id: T1566.001",
            "    name: Spearphishing Attachment",
            "- id: step-2",
            "  procedure_step: '1.A.2'",
            "  cti_source: https://example.test/report/one",
            "  technique:",
            "    attack_id: T1059.001",
            "    name: PowerShell",
            "- id: step-3",
            "  procedure_step: '1.A.3'",
            "  cti_source: https://example.test/report/one",
            "  technique:",
            "    attack_id: T1003",
            "    name: Credential Dumping",
            "- id: step-4",
            "  procedure_step: '2.A.1'",
            "  cti_source: https://example.test/report/two",
            "  technique:",
            "    attack_id: T1566.001",
            "    name: Spearphishing Attachment",
            "- id: step-5",
            "  procedure_step: '2.A.2'",
            "  cti_source: https://example.test/report/two",
            "  technique:",
            "    attack_id: T1059.001",
            "    name: PowerShell",
            "- id: step-6",
            "  procedure_step: '2.A.3'",
            "  cti_source: https://example.test/report/two",
            "  technique:",
            "    attack_id: T1021",
            "    name: Remote Services",
            "",
        ]
    )


def _fake_fetch_factory(
    fixture_dir: Path,
    *,
    enterprise_attack_bytes: bytes | None = None,
    ctid_zip_bytes: bytes | None = None,
    attackevals_zip_bytes: bytes | None = None,
):
    empty_zip = _zip_bytes({})

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
        if enterprise_attack_bytes is not None:
            mapping["https://example.test/enterprise-attack/enterprise-attack-18.1.json"] = enterprise_attack_bytes
        if ctid_zip_bytes is not None:
            mapping["https://github.com/center-for-threat-informed-defense/adversary_emulation_library/archive/refs/heads/master.zip"] = ctid_zip_bytes
        if attackevals_zip_bytes is not None:
            mapping["https://github.com/attackevals/ael/archive/refs/heads/main.zip"] = attackevals_zip_bytes
        try:
            return mapping[url]
        except KeyError as exc:
            raise AssertionError(f"Unexpected fetch URL: {url}") from exc

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


def _path_hash(*attack_ids: str) -> str:
    return hashlib.sha1("|".join(attack_ids).encode("utf-8")).hexdigest()


def _write_incident_override_file(app_root: Path, rows: list[list[str]]) -> None:
    overrides_dir = app_root / "data" / "overrides"
    overrides_dir.mkdir(parents=True, exist_ok=True)
    payload = [
        (
            "source_flow_id,path_hash,incident_name,attack_group_id,attack_software_ids,"
            "attack_campaign_id,reference_url,source_article_url,source_article_title,notes,confidence"
        ),
        *[",".join(row) for row in rows],
    ]
    (overrides_dir / "incident_overrides.csv").write_text("\n".join(payload), encoding="utf-8")


def _fetch_snapshot(
    monkeypatch,
    fixture_dir: Path,
    db_connection,
    app_root: Path,
    snapshot_id: str,
    *,
    enterprise_attack_bytes: bytes | None = None,
    ctid_zip_bytes: bytes | None = None,
    attackevals_zip_bytes: bytes | None = None,
):
    monkeypatch.setattr(
        "threatdle.ingest.fetch.fetch_url_bytes",
        _fake_fetch_factory(
            fixture_dir,
            enterprise_attack_bytes=enterprise_attack_bytes,
            ctid_zip_bytes=ctid_zip_bytes,
            attackevals_zip_bytes=attackevals_zip_bytes,
        ),
    )
    return fetch_sources(db_connection, snapshot_id, root_dir=app_root)


def test_fetch_sources_resolves_bundle_extracts_json_and_skips_unchanged(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_curated_flows(app_root, curated_flow_payload)
    first = _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-1")
    second = _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-1")

    assert first["attack_stix"]["status"] == "fetched"
    assert second["attack_stix"]["status"] == "no_change"
    assert first["misp_threat_actors"]["status"] == "fetched"
    assert second["misp_threat_actors"]["status"] == "no_change"
    assert first["curated_flows"]["status"] == "fetched"
    assert second["curated_flows"]["status"] == "no_change"
    assert first["curated_flows"]["extracted_files"] == ["solarwinds.json"]
    assert first["ctid_emulation_library"]["status"] == "fetched"
    assert first["attackevals_ael"]["status"] == "fetched"

    snapshot = get_snapshot(db_connection, "snap-1")
    assert snapshot is not None
    assert snapshot["attack_version"] == "18.1"
    assert snapshot["misp_ref"] == "main"
    assert snapshot["attack_flow_ref"] == "curated-v1"


def test_snapshot_rejects_artifact_changes_after_lock(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-immutability")
    ingest_attack_stix(db_connection, "snap-immutability")

    artifact_path = app_root / "data" / "snapshots" / "snap-immutability" / "attack_stix" / "enterprise-attack.json"
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    payload["objects"][0]["name"] = "Mutated tactic"
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    try:
        ingest_attack_stix(db_connection, "snap-immutability")
    except ValueError as exc:
        assert "hash changed after lock" in str(exc)
    else:
        raise AssertionError("expected snapshot hash validation failure")


def test_misp_matching_normalization_and_override_precedence(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-misp")
    ingest_attack_stix(db_connection, "snap-misp")
    ingest_overrides(db_connection, "snap-misp", root_dir=app_root)
    counts = ingest_misp_actors(db_connection, "snap-misp")
    ingest_overrides(db_connection, "snap-misp", root_dir=app_root)

    assert normalize_actor_name("APT29") == normalize_actor_name("APT 29") == normalize_actor_name("APT-29")
    assert normalize_actor_name("Cozy Bear") == normalize_actor_name("CozyBear")
    assert counts == {"matched": 2, "ambiguous": 1, "near_match": 1, "no_match": 1}

    actor = db_connection.execute(
        """
        SELECT country_code, first_observed_year, target_categories_json
        FROM actors
        WHERE attack_group_id = 'G0016'
        """
    ).fetchone()
    assert actor is not None
    assert actor["country_code"] == "CN"
    assert actor["first_observed_year"] == 2014
    assert json.loads(actor["target_categories_json"]) == ["Government"]

    unresolved = db_connection.execute(
        """
        SELECT reason, candidate_key
        FROM unresolved_matches
        WHERE snapshot_id = 'snap-misp' AND source_name = 'misp_threat_actors'
        ORDER BY reason
        """
    ).fetchall()
    assert [row["reason"] for row in unresolved] == ["ambiguous", "near_match", "no_match"]
    assert unresolved[1]["candidate_key"] == "G0016"


def test_attack_flow_extracts_easy_timelines_and_logs_unmapped_techniques(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-flow")
    ingest_attack_stix(db_connection, "snap-flow")
    counts = ingest_attack_flow(db_connection, "snap-flow")

    assert counts["operations"] == 1
    assert counts["operation_actors"] == 1
    assert counts["timelines"] == 2
    assert counts["timeline_steps"] == 6
    assert counts["skipped_paths"] == 1

    timelines = db_connection.execute(
        """
        SELECT answer_type, answer_key, difficulty, step_count
        FROM timelines
        ORDER BY answer_key
        """
    ).fetchall()
    assert len(timelines) == 2
    assert all(row["answer_type"] == "actor" for row in timelines)
    assert all(row["answer_key"] == "G0016" for row in timelines)
    assert all(row["difficulty"] == "easy" for row in timelines)
    assert all(row["step_count"] == 3 for row in timelines)

    step_sets = [
        [
            row["attack_id"]
            for row in db_connection.execute(
                """
                SELECT attack_id
                FROM timeline_steps
                WHERE timeline_id = ?
                ORDER BY step_index
                """,
                (timeline_id,),
            )
        ]
        for (timeline_id,) in db_connection.execute("SELECT timeline_id FROM timelines ORDER BY timeline_id")
    ]
    assert ["T1566.001", "T1059.001", "T1003"] in step_sets
    assert ["T1566.001", "T1059.001", "T1021"] in step_sets

    unresolved = db_connection.execute(
        """
        SELECT reason, detail_json
        FROM unresolved_matches
        WHERE snapshot_id = 'snap-flow' AND source_name = 'curated_flows'
        """
    ).fetchall()
    assert len(unresolved) == 1
    assert unresolved[0]["reason"] == "unmapped_technique"
    assert json.loads(unresolved[0]["detail_json"]) == {"attack_ids": ["T9999"]}


def test_attack_campaign_malware_materializes_campaign_incidents_and_match_report(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(
        monkeypatch,
        fixture_dir,
        db_connection,
        app_root,
        "snap-campaign-report",
        enterprise_attack_bytes=_campaign_ready_attack_bundle_bytes(fixture_dir),
    )
    attack_stix_counts = ingest_attack_stix(db_connection, "snap-campaign-report")
    ingest_overrides(db_connection, "snap-campaign-report", root_dir=app_root)
    ingest_misp_actors(db_connection, "snap-campaign-report")
    ingest_overrides(db_connection, "snap-campaign-report", root_dir=app_root)
    ingest_attack_flow(db_connection, "snap-campaign-report")

    puzzle_counts = build_puzzle_tables(db_connection, "snap-campaign-report")
    report = build_campaign_match_report(db_connection, "snap-campaign-report", root_dir=app_root)

    assert attack_stix_counts["campaign_malware"] == 1
    campaign_link = db_connection.execute(
        """
        SELECT c.attack_campaign_id, m.attack_software_id
        FROM campaign_malware cm
        JOIN campaigns c ON c.campaign_id = cm.campaign_id
        JOIN malware m ON m.malware_id = cm.malware_id
        """
    ).fetchone()
    assert dict(campaign_link) == {"attack_campaign_id": "C0001", "attack_software_id": "S0559"}
    assert puzzle_counts["campaign_incidents"] == 1
    assert puzzle_counts["campaign_timeline_matches"] == 2

    match_row = db_connection.execute(
        """
        SELECT attack_campaign_id, campaign_name, technique_overlap_count, timeline_precision, name_boost, flow_name
        FROM campaign_timeline_matches_v1
        WHERE snapshot_id = 'snap-campaign-report'
        ORDER BY match_rank, timeline_id
        LIMIT 1
        """
    ).fetchone()
    assert dict(match_row) == {
        "attack_campaign_id": "C0001",
        "campaign_name": "SolarWinds Compromise",
        "technique_overlap_count": 3,
        "timeline_precision": 1.0,
        "name_boost": 1,
        "flow_name": "SolarWinds Flow",
    }
    assert report["eligible_campaigns"] == 1
    assert report["matched_campaigns"] == 1
    assert report["dropped_campaigns"] == 0
    assert report["reported_match_rows"] == 2
    assert Path(report["json_report_path"]).exists()
    assert Path(report["csv_report_path"]).exists()


def test_emulation_plan_ingest_materializes_timeline_segments(
    monkeypatch,
    fixture_dir: Path,
    db_connection,
    app_root: Path,
):
    ctid_zip_bytes = _zip_bytes(
        {
            "adversary_emulation_library-master/apt29/Emulation_Plan/yaml/APT29.yaml": _sample_emulation_plan_yaml(),
        }
    )
    attackevals_zip_bytes = _zip_bytes(
        {
            "ael-main/Enterprise/apt29/Emulation_Plan/yaml/APT29.yaml": _sample_emulation_plan_yaml(),
        }
    )
    _write_curated_flows(app_root, {"objects": []})
    _fetch_snapshot(
        monkeypatch,
        fixture_dir,
        db_connection,
        app_root,
        "snap-emulation",
        ctid_zip_bytes=ctid_zip_bytes,
        attackevals_zip_bytes=attackevals_zip_bytes,
    )
    ingest_attack_stix(db_connection, "snap-emulation")

    counts = ingest_emulation_plans(db_connection, "snap-emulation")

    assert counts == {
        "sources": 2,
        "plans": 2,
        "operations": 2,
        "operation_actors": 2,
        "timelines": 4,
        "timeline_steps": 12,
        "skipped_plans": 0,
        "skipped_segments": 0,
    }
    source_counts = db_connection.execute(
        """
        SELECT timeline_source_type, COUNT(*) AS timeline_count
        FROM timelines
        GROUP BY timeline_source_type
        ORDER BY timeline_source_type
        """
    ).fetchall()
    assert [dict(row) for row in source_counts] == [
        {"timeline_source_type": "attackevals_ael", "timeline_count": 2},
        {"timeline_source_type": "ctid_emulation_library", "timeline_count": 2},
    ]
    step_sequences = [
        [row["attack_id"] for row in db_connection.execute(
            """
            SELECT attack_id
            FROM timeline_steps
            WHERE timeline_id = ?
            ORDER BY step_index
            """,
            (timeline_id,),
        )]
        for (timeline_id,) in db_connection.execute("SELECT timeline_id FROM timelines ORDER BY timeline_id")
    ]
    assert step_sequences == [
        ["T1566.001", "T1059.001", "T1003"],
        ["T1566.001", "T1059.001", "T1021"],
        ["T1566.001", "T1059.001", "T1003"],
        ["T1566.001", "T1059.001", "T1021"],
    ]


def test_incident_overrides_link_timeline_malware_and_materialize_incident_candidates(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-incident")
    ingest_attack_stix(db_connection, "snap-incident")
    ingest_overrides(db_connection, "snap-incident", root_dir=app_root)
    ingest_misp_actors(db_connection, "snap-incident")
    ingest_overrides(db_connection, "snap-incident", root_dir=app_root)
    ingest_attack_flow(db_connection, "snap-incident")
    _write_incident_override_file(
        app_root,
        [
            [
                "attack-flow--solarwinds",
                _path_hash("T1566.001", "T1059.001", "T1003"),
                "SolarWinds Flow",
                "G0016",
                "S0559",
                "C0001",
                "https://example.test/solarwinds-malware",
                "https://example.test/solarwinds-report",
                "SolarWinds incident report",
                "Primary malware observed in this incident",
                "high",
            ]
        ],
    )

    counts = ingest_incident_overrides(db_connection, "snap-incident", root_dir=app_root)
    puzzle_counts = build_puzzle_tables(db_connection, "snap-incident")

    assert counts == {"incident_override_rows": 1, "timeline_malware_links": 1, "timeline_incident_metadata_rows": 1}
    snapshot = get_snapshot(db_connection, "snap-incident")
    assert snapshot is not None
    assert snapshot["incident_override_hash"] is not None

    linked = db_connection.execute(
        """
        SELECT t.source_flow_id, m.attack_software_id, tm.reference_url, tm.confidence
        FROM timeline_malware tm
        JOIN timelines t ON t.timeline_id = tm.timeline_id
        JOIN malware m ON m.malware_id = tm.malware_id
        ORDER BY t.timeline_id
        """
    ).fetchall()
    assert [dict(row) for row in linked] == [
        {
            "source_flow_id": "attack-flow--solarwinds",
            "attack_software_id": "S0559",
            "reference_url": "https://example.test/solarwinds-malware",
            "confidence": "high",
        }
    ]

    incident_candidate = db_connection.execute(
        """
        SELECT actor_answer_key, actor_answer_label, malware_answer_keys_json, technique_attack_ids_json, repeat_key
        , attack_campaign_id, source_article_url, source_article_title
        FROM incident_candidates_v1
        WHERE snapshot_id = 'snap-incident'
        """
    ).fetchone()
    assert incident_candidate is not None
    assert incident_candidate["actor_answer_key"] == "G0016"
    assert incident_candidate["actor_answer_label"] == "APT29"
    assert json.loads(incident_candidate["malware_answer_keys_json"]) == ["S0559"]
    assert json.loads(incident_candidate["technique_attack_ids_json"]) == ["T1566.001", "T1059.001", "T1003"]
    assert incident_candidate["repeat_key"].startswith("attack-flow--solarwinds:")
    assert incident_candidate["attack_campaign_id"] == "C0001"
    assert incident_candidate["source_article_url"] == "https://example.test/solarwinds-report"
    assert incident_candidate["source_article_title"] == "SolarWinds incident report"


def test_actor_backfill_report_surfaces_one_field_away_candidates(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-backfill")
    ingest_attack_stix(db_connection, "snap-backfill")
    ingest_overrides(db_connection, "snap-backfill", root_dir=app_root)
    ingest_misp_actors(db_connection, "snap-backfill")
    ingest_overrides(db_connection, "snap-backfill", root_dir=app_root)
    ingest_attack_flow(db_connection, "snap-backfill")
    with db_connection:
        db_connection.execute(
            """
            UPDATE actors
            SET motivation_tags_json = NULL
            WHERE attack_group_id = 'G0016'
            """
        )

    build_puzzle_tables(db_connection, "snap-backfill")
    profile_json_path = app_root / "profiles.json"
    profile_json_path.write_text(
        json.dumps(
            {
                "count": 1,
                "profiles": [
                        {
                            "name": "SILVER FISH",
                            "description": "Example profile",
                            "thematic_area": "Russia",
                            "objectives": ["Espionage"],
                            "aliases": ["APT29"],
                            "tools": ["ExampleTool"],
                            "download_timestamp": "2026-03-16T00:02:07.876Z",
                        }
                ],
            }
        ),
        encoding="utf-8",
    )

    report = build_actor_backfill_report(
        db_connection,
        "snap-backfill",
        root_dir=app_root,
        profile_json_path=profile_json_path,
    )

    assert report["software_ttp_ready"] == 1
    assert report["publishable_now"] == 0
    assert report["one_field_away"] == 1
    assert report["one_field_away_by_missing_field"] == {
        "country": 0,
        "year": 0,
        "targets": 0,
        "motivation": 1,
    }
    payload = json.loads(Path(report["json_report_path"]).read_text(encoding="utf-8"))
    assert payload["candidates"][0]["actor_name"] == "APT29"
    assert payload["candidates"][0]["missing_field"] == "motivation"
    assert payload["candidates"][0]["matched_profiles"][0]["suggested_country_code"] == "RU"
    assert payload["candidates"][0]["matched_profiles"][0]["objectives"] == ["Espionage"]


def test_end_to_end_pipeline_builds_puzzle_tables(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-end")
    ingest_attack_stix(db_connection, "snap-end")
    ingest_overrides(db_connection, "snap-end", root_dir=app_root)
    ingest_misp_actors(db_connection, "snap-end")
    ingest_overrides(db_connection, "snap-end", root_dir=app_root)
    ingest_attack_flow(db_connection, "snap-end")
    _write_incident_override_file(
        app_root,
        [
            [
                "attack-flow--solarwinds",
                _path_hash("T1566.001", "T1059.001", "T1003"),
                "SolarWinds Flow",
                "G0016",
                "S0559",
                "C0001",
                "https://example.test/solarwinds-malware",
                "https://example.test/solarwinds-report",
                "SolarWinds incident report",
                "Primary malware observed in this incident",
                "high",
            ]
        ],
    )
    ingest_incident_overrides(db_connection, "snap-end", root_dir=app_root)
    counts = build_puzzle_tables(db_connection, "snap-end")
    mark_snapshot_ready(db_connection, "snap-end")

    assert counts["actor_profiles"] >= 1
    assert counts["actor_candidates"] >= 1
    assert counts["malware_profiles"] == 1
    assert counts["malware_candidates"] == 1
    assert counts["technique_profiles"] == 5
    assert counts["technique_candidates"] == 5
    assert counts["timeline_sequences"] == 2
    assert counts["timeline_candidates"] == 2
    assert counts["incident_candidates"] == 1
    assert counts["campaign_incidents"] == 0
    assert counts["campaign_timeline_matches"] == 0
    assert counts["timeline_warning_total_sequences_below_target"] == 2
    assert counts["timeline_warning_standard_sequences_below_target"] == 0

    actor_candidate = db_connection.execute(
        """
        SELECT answer_key, answer_label, clue_score
        FROM actor_candidates_v1
        WHERE snapshot_id = 'snap-end'
        """
    ).fetchone()
    assert actor_candidate is not None
    assert actor_candidate["answer_key"] == "G0016"
    assert actor_candidate["answer_label"] == "APT29"
    assert actor_candidate["clue_score"] >= 4
    actor_payload = json.loads(
        db_connection.execute(
            """
            SELECT clue_payload_json
            FROM actor_profiles_v1
            WHERE snapshot_id = 'snap-end'
            """
        ).fetchone()["clue_payload_json"]
    )
    assert actor_payload["counts"]["operations_count"] == 1

    malware_payload = json.loads(
        db_connection.execute(
            """
            SELECT clue_payload_json
            FROM malware_profiles_v1
            WHERE snapshot_id = 'snap-end'
            """
        ).fetchone()["clue_payload_json"]
    )
    assert malware_payload["malware_category"] == "Supply Chain"
    assert malware_payload["capability_summary"] == "Supply chain backdoor"
    malware_candidate = db_connection.execute(
        """
        SELECT answer_key, answer_label, summary_tier
        FROM malware_candidates_v1
        WHERE snapshot_id = 'snap-end'
        """
    ).fetchone()
    assert malware_candidate is not None
    assert malware_candidate["answer_key"] == "S0559"
    assert malware_candidate["answer_label"] == "SUNBURST"
    assert malware_candidate["summary_tier"] == 1

    timeline_payload = json.loads(
        db_connection.execute(
            """
            SELECT steps_json
            FROM timeline_sequences_v1
            WHERE snapshot_id = 'snap-end'
            ORDER BY timeline_id
            LIMIT 1
            """
        ).fetchone()["steps_json"]
    )
    assert len(timeline_payload) == 3
    technique_candidates = db_connection.execute(
        """
        SELECT COUNT(*)
        FROM technique_candidates_v1
        WHERE snapshot_id = 'snap-end'
        """
    ).fetchone()[0]
    assert technique_candidates == 5


def test_actor_candidates_require_publishable_three_phase_coverage(
    monkeypatch,
    fixture_dir: Path,
    curated_flow_payload: dict,
    db_connection,
    app_root: Path,
):
    _write_override_files(app_root)
    _write_curated_flows(app_root, curated_flow_payload)
    _fetch_snapshot(monkeypatch, fixture_dir, db_connection, app_root, "snap-strict-actor-candidates")
    ingest_attack_stix(db_connection, "snap-strict-actor-candidates")
    ingest_overrides(db_connection, "snap-strict-actor-candidates", root_dir=app_root)
    ingest_misp_actors(db_connection, "snap-strict-actor-candidates")
    ingest_overrides(db_connection, "snap-strict-actor-candidates", root_dir=app_root)
    ingest_attack_flow(db_connection, "snap-strict-actor-candidates")

    with db_connection:
        db_connection.execute("DELETE FROM actor_malware")

    counts = build_puzzle_tables(db_connection, "snap-strict-actor-candidates")

    assert counts["actor_profiles"] >= 1
    assert counts["actor_candidates"] == 0
