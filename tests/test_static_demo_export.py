from __future__ import annotations

import json
from pathlib import Path

from threatdle.ingest.base import now_utc_iso
from threatdle.services.static_demo_export import build_static_demo_bundle, export_static_demo


def _seed_static_demo_snapshot(db_connection, snapshot_id: str) -> None:
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
                actor_id, attack_group_id, name, country_code, target_categories_json,
                victim_countries_json, motivation_tags_json, first_observed_year, revoked, deprecated
            )
            VALUES (1, 'G0001', 'Actor Demo', 'US', '["Government"]', '["US"]', '["Espionage"]', 2014, 0, 0)
            """
        )
        db_connection.execute(
            """
            INSERT INTO malware (
                malware_id, stix_id, attack_software_id, name, description, aliases_json, platforms_json,
                malware_category, capability_summary, revoked, deprecated
            )
            VALUES (
                2, 'malware--demo', 'S0001', 'Malware Demo', 'Malware demo description',
                '["DemoAlias"]', '["Windows"]', 'Backdoor', 'Demo malware capability summary', 0, 0
            )
            """
        )
        db_connection.execute(
            """
            INSERT INTO techniques (
                technique_id, stix_id, attack_id, name, description, tactics_json, platforms_json,
                is_subtechnique, parent_attack_id, revoked, deprecated
            )
            VALUES (
                3, 'attack-pattern--demo', 'T1001', 'Technique Demo', 'Technique demo description',
                '["persistence"]', '["Windows"]', 1, 'T1000', 0, 0
            )
            """
        )
        db_connection.execute("INSERT INTO actor_malware (actor_id, malware_id) VALUES (1, 2)")
        db_connection.execute("INSERT INTO actor_techniques (actor_id, technique_id) VALUES (1, 3)")

        db_connection.execute(
            """
            INSERT INTO actor_profiles_v1 (snapshot_id, actor_id, clue_payload_json, provenance_json, clue_score)
            VALUES (?, 1, ?, '{"identity":"synthetic"}', 6)
            """,
            (
                snapshot_id,
                json.dumps(
                    {
                        "country_code": "US",
                        "first_observed_year": 2014,
                        "target_categories": ["Government"],
                        "motivation_tags": ["Espionage"],
                        "counts": {
                            "malware_count": 1,
                            "technique_count": 5,
                        },
                    },
                    sort_keys=True,
                ),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO actor_candidates_v1 (snapshot_id, actor_id, answer_key, answer_label, difficulty, clue_score)
            VALUES (?, 1, 'G0001', 'Actor Demo', 'easy', 6)
            """,
            (snapshot_id,),
        )

        db_connection.execute(
            """
            INSERT INTO malware_profiles_v1 (snapshot_id, malware_id, clue_payload_json, provenance_json)
            VALUES (?, 2, ?, '{"identity":"synthetic"}')
            """,
            (
                snapshot_id,
                json.dumps(
                    {
                        "platforms": ["Windows"],
                        "aliases": ["DemoAlias"],
                        "capability_summary": "Demo malware capability summary",
                        "actor_names": ["Actor Demo"],
                    },
                    sort_keys=True,
                ),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO malware_candidates_v1 (snapshot_id, malware_id, answer_key, answer_label, summary_tier)
            VALUES (?, 2, 'S0001', 'Malware Demo', 1)
            """,
            (snapshot_id,),
        )

        db_connection.execute(
            """
            INSERT INTO technique_profiles_v1 (snapshot_id, technique_id, clue_payload_json, provenance_json)
            VALUES (?, 3, ?, '{"identity":"synthetic"}')
            """,
            (
                snapshot_id,
                json.dumps(
                    {
                        "tactics": ["persistence"],
                        "platforms": ["Windows"],
                        "is_subtechnique": True,
                        "parent_name": "Parent Demo",
                    },
                    sort_keys=True,
                ),
            ),
        )
        db_connection.execute(
            """
            INSERT INTO technique_candidates_v1 (snapshot_id, technique_id, answer_key, answer_label)
            VALUES (?, 3, 'T1001', 'Technique Demo')
            """,
            (snapshot_id,),
        )

        puzzle_rows = [
            (
                "actor",
                {"mode": "actor", "clues": {"country_code": "US", "first_observed_year": 2014, "target_categories": ["Government"], "motivation_tags": ["Espionage"], "malware_count": 1, "technique_count": 5}},
                {"answer_key": "G0001", "answer_label": "Actor Demo", "chain_mode": "linked", "comparison": {"country_code": "US", "first_observed_year": 2014, "target_categories": ["Government"], "motivation_tags": ["Espionage"], "malware_count": 1, "technique_count": 5}},
            ),
            (
                "malware",
                {"mode": "malware", "clues": {"platforms": ["Windows"], "capability_summary": "Demo malware capability summary", "actor_count": 1, "aliases": ["DemoAlias"]}},
                {"answer_key": "S0001", "answer_label": "Malware Demo", "chain_mode": "linked", "comparison": {"platforms": ["Windows"], "aliases": ["DemoAlias"], "actor_names": ["Actor Demo"]}},
            ),
            (
                "technique",
                {"mode": "technique", "clues": {"tactics": ["persistence"], "platforms": ["Windows"], "is_subtechnique": True, "parent_name": "Parent Demo"}},
                {"answer_key": "T1001", "answer_label": "Technique Demo", "chain_mode": "linked", "comparison": {"tactics": ["persistence"], "platforms": ["Windows"], "is_subtechnique": True, "parent_name": "Parent Demo"}},
            ),
        ]
        for mode, payload_json, answer_json in puzzle_rows:
            db_connection.execute(
                """
                INSERT INTO puzzle_day (day_key, snapshot_id, mode, payload_json, answer_json, created_at)
                VALUES ('2026-03-15', ?, ?, ?, ?, ?)
                """,
                (
                    snapshot_id,
                    mode,
                    json.dumps(payload_json, sort_keys=True),
                    json.dumps(answer_json, sort_keys=True),
                    now_utc_iso(),
                ),
            )


def test_build_static_demo_bundle_includes_scoring_maps(db_connection):
    _seed_static_demo_snapshot(db_connection, "snap-static-demo")

    bundle = build_static_demo_bundle(db_connection, "snap-static-demo")

    assert bundle["snapshot"]["snapshot_id"] == "snap-static-demo"
    assert bundle["days"] == [{"day_key": "2026-03-15", "mode_count": 3}]
    assert bundle["game_days"]["2026-03-15"]["modes"]["actor"]["payload"]["clues"]["country_code"] == "US"
    assert bundle["answers"]["2026-03-15"]["malware"]["comparison"]["actor_names"] == ["Actor Demo"]
    assert bundle["compare"]["actor"]["G0001"]["technique_count"] == 5
    assert bundle["compare"]["malware"]["S0001"]["aliases"] == ["DemoAlias"]
    assert bundle["compare"]["technique"]["T1001"]["parent_name"] == "Parent Demo"


def test_export_static_demo_writes_bundle_and_patched_html(db_connection, app_root: Path):
    _seed_static_demo_snapshot(db_connection, "snap-static-export")

    public_dir = app_root / "public"
    (public_dir / "js").mkdir(parents=True)
    (public_dir / "css").mkdir(parents=True)
    (public_dir / "images").mkdir(parents=True)
    (public_dir / "game.html").write_text(
        "<!doctype html><html><body><script src=\"/js/game.js\" type=\"module\"></script></body></html>",
        encoding="utf-8",
    )
    (public_dir / "sources.html").write_text("<!doctype html><html><body>Sources</body></html>", encoding="utf-8")
    (public_dir / "js" / "game.js").write_text("console.log('demo');", encoding="utf-8")
    (public_dir / "css" / "game.css").write_text("body{}", encoding="utf-8")
    (public_dir / "images" / "logo.png").write_bytes(b"png")

    out_dir = app_root / "dist" / "static-demo"
    result = export_static_demo(
        db_connection,
        "snap-static-export",
        out_dir=out_dir,
        public_dir=public_dir,
    )

    assert result["snapshot_id"] == "snap-static-export"
    assert (out_dir / "demo-data" / "static-demo.json").is_file()
    assert (out_dir / "demo-config.js").read_text(encoding="utf-8").strip() == "window.THREATDLE_STATIC_DEMO_FILE = '/demo-data/static-demo.json';"
    assert '<script src="/demo-config.js"></script>' in (out_dir / "game.html").read_text(encoding="utf-8")
    assert (out_dir / "index.html").is_file()
    assert (out_dir / "_redirects").read_text(encoding="utf-8").strip() == "/game /game.html 200"
