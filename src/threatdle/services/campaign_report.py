"""Export ATT&CK campaign to timeline match reports for curation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.config import get_paths
from threatdle.ingest.base import ensure_directory, now_utc_iso
from threatdle.services.puzzle_views import build_puzzle_tables


def _report_paths(root_dir: Path | None, snapshot_id: str) -> tuple[Path, Path]:
    paths = get_paths(root_dir=root_dir)
    report_dir = ensure_directory(paths.snapshots_dir / snapshot_id / "reports")
    return (
        report_dir / "campaign_timeline_matches.json",
        report_dir / "campaign_timeline_matches.csv",
    )


def build_campaign_match_report(
    connection: sqlite3.Connection,
    snapshot_id: str,
    *,
    root_dir: Path | None = None,
) -> dict[str, Any]:
    puzzle_counts = build_puzzle_tables(connection, snapshot_id)

    rows = connection.execute(
        """
        SELECT
            attack_campaign_id,
            campaign_name,
            actor_answer_key,
            actor_answer_label,
            malware_answer_keys_json,
            malware_answer_labels_json,
            timeline_id,
            flow_name,
            source_flow_id,
            technique_overlap_count,
            timeline_precision,
            name_boost,
            overlap_attack_ids_json,
            match_rank
        FROM campaign_timeline_matches_v1
        WHERE snapshot_id = ?
        ORDER BY campaign_name, match_rank, timeline_id
        """,
        (snapshot_id,),
    ).fetchall()
    exported_matches = [
        {
            "attack_campaign_id": row["attack_campaign_id"],
            "campaign_name": row["campaign_name"],
            "actor_answer_key": row["actor_answer_key"],
            "actor_answer_label": row["actor_answer_label"],
            "malware_answer_keys": json.loads(row["malware_answer_keys_json"]),
            "malware_answer_labels": json.loads(row["malware_answer_labels_json"]),
            "timeline_id": int(row["timeline_id"]),
            "flow_name": row["flow_name"],
            "source_flow_id": row["source_flow_id"],
            "technique_overlap_count": int(row["technique_overlap_count"]),
            "timeline_precision": float(row["timeline_precision"]),
            "name_boost": int(row["name_boost"]),
            "overlap_attack_ids": json.loads(row["overlap_attack_ids_json"]),
            "match_rank": int(row["match_rank"]),
        }
        for row in rows
    ]
    eligible_campaign_count = int(
        connection.execute(
            """
            SELECT COUNT(*)
            FROM campaign_incidents_v1
            WHERE snapshot_id = ?
            """,
            (snapshot_id,),
        ).fetchone()[0]
    )
    matched_campaign_count = len({row["attack_campaign_id"] or row["campaign_name"] for row in exported_matches})
    summary = {
        "snapshot_id": snapshot_id,
        "generated_at": now_utc_iso(),
        "eligible_campaigns": eligible_campaign_count,
        "matched_campaigns": matched_campaign_count,
        "dropped_campaigns": max(eligible_campaign_count - matched_campaign_count, 0),
        "reported_match_rows": len(exported_matches),
        "thresholds": {
            "technique_overlap_count": 2,
            "timeline_precision": 0.5,
        },
        "puzzle_counts": puzzle_counts,
    }
    json_path, csv_path = _report_paths(root_dir, snapshot_id)
    json_path.write_text(
        json.dumps(
            {
                "summary": summary,
                "matches": exported_matches,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "attack_campaign_id",
                "campaign_name",
                "actor_answer_key",
                "actor_answer_label",
                "malware_answer_keys",
                "malware_answer_labels",
                "timeline_id",
                "flow_name",
                "source_flow_id",
                "technique_overlap_count",
                "timeline_precision",
                "name_boost",
                "overlap_attack_ids",
                "match_rank",
            ],
        )
        writer.writeheader()
        for row in exported_matches:
            writer.writerow(
                {
                    **row,
                    "malware_answer_keys": "|".join(row["malware_answer_keys"]),
                    "malware_answer_labels": "|".join(row["malware_answer_labels"]),
                    "overlap_attack_ids": "|".join(row["overlap_attack_ids"]),
                }
            )

    return {
        **summary,
        "json_report_path": str(json_path),
        "csv_report_path": str(csv_path),
    }
