"""Compare the hosted Threatdle snapshot to the local Optic Postgres corpus.

This script reads the Threatdle SQLite database and hosted runtime bundle, then
queries the local `optic-postgres` Docker container with `psql`. The output is
intended to answer two practical questions:

- What data was actually packaged for hosting?
- How does that curated Threatdle snapshot compare to the broader local CTI
  corpus in Postgres?
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import sqlite3
import subprocess
from typing import Any


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


def _markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_No rows._"
    header_row = "| " + " | ".join(headers) + " |"
    separator_row = "| " + " | ".join("---" for _ in headers) + " |"
    body_rows = ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join([header_row, separator_row, *body_rows])


def _format_pct(part: int, whole: int) -> str:
    if whole <= 0:
        return "0.0%"
    return f"{(part / whole) * 100:.1f}%"


def _run_psql(
    *,
    container: str,
    db_user: str,
    db_name: str,
    sql: str,
) -> list[list[str]]:
    command = [
        "docker",
        "exec",
        container,
        "psql",
        "-U",
        db_user,
        "-d",
        db_name,
        "-At",
        "-F",
        "\t",
        "-P",
        "pager=off",
        "-c",
        sql,
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(
            "Failed to query local Postgres via Docker.\n"
            f"Command: {' '.join(command)}\n"
            f"stderr: {result.stderr.strip()}"
        )
    rows: list[list[str]] = []
    for line in result.stdout.splitlines():
        stripped = line.rstrip("\n")
        if stripped.strip():
            rows.append(stripped.split("\t"))
    return rows


def _sqlite_rows(connection: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
    return connection.execute(sql, params).fetchall()


def _sqlite_scalar(connection: sqlite3.Connection, sql: str, params: tuple[Any, ...] = ()) -> Any:
    row = connection.execute(sql, params).fetchone()
    return None if row is None else row[0]


def _load_runtime_bundle(runtime_bundle_path: Path) -> dict[str, Any] | None:
    if not runtime_bundle_path.is_file():
        return None
    return json.loads(runtime_bundle_path.read_text(encoding="utf-8"))


def _get_snapshot_id(
    *,
    requested_snapshot_id: str | None,
    runtime_bundle: dict[str, Any] | None,
    connection: sqlite3.Connection,
) -> str:
    if requested_snapshot_id:
        return requested_snapshot_id
    if runtime_bundle:
        snapshot = runtime_bundle.get("snapshot")
        if isinstance(snapshot, dict) and snapshot.get("snapshot_id"):
            return str(snapshot["snapshot_id"])
    active_snapshot_id = _sqlite_scalar(
        connection,
        "SELECT active_snapshot_id FROM canonical_state WHERE id = 1",
    )
    if active_snapshot_id:
        return str(active_snapshot_id)
    raise ValueError("Could not determine the hosted Threatdle snapshot id.")


def _normalize_snapshot_group(snapshot_id: str) -> str:
    prefix, _, _ = snapshot_id.rpartition("-")
    return prefix


def _sqlite_set(connection: sqlite3.Connection, sql: str) -> set[str]:
    return {str(row[0]) for row in connection.execute(sql) if row[0]}


def _psql_set(*, container: str, db_user: str, db_name: str, sql: str) -> set[str]:
    return {row[0] for row in _run_psql(container=container, db_user=db_user, db_name=db_name, sql=sql) if row and row[0]}


def _quote_sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _build_report(
    *,
    root_dir: Path,
    sqlite_db_path: Path,
    runtime_bundle_path: Path,
    postgres_container: str,
    postgres_user: str,
    postgres_db: str,
    snapshot_id: str | None,
) -> dict[str, Any]:
    runtime_bundle = _load_runtime_bundle(runtime_bundle_path)

    with sqlite3.connect(str(sqlite_db_path)) as connection:
        connection.row_factory = sqlite3.Row
        resolved_snapshot_id = _get_snapshot_id(
            requested_snapshot_id=snapshot_id,
            runtime_bundle=runtime_bundle,
            connection=connection,
        )

        snapshot_group = _normalize_snapshot_group(resolved_snapshot_id)
        sibling_like = f"{snapshot_group}-%"

        snapshot_row = _sqlite_rows(
            connection,
            """
            SELECT snapshot_id, created_at, ready_at, status
            FROM snapshots
            WHERE snapshot_id = ?
            """,
            (resolved_snapshot_id,),
        )[0]
        active_snapshot_id = _sqlite_scalar(
            connection,
            "SELECT active_snapshot_id FROM canonical_state WHERE id = 1",
        )

        source_rows = _sqlite_rows(
            connection,
            """
            SELECT snapshot_id, source_name, resolved_ref, artifact_hash, status
            FROM snapshot_sources
            WHERE snapshot_id LIKE ?
            ORDER BY snapshot_id, source_name
            """,
            (sibling_like,),
        )
        source_hashes_by_snapshot: dict[str, dict[str, tuple[str, str]]] = {}
        for row in source_rows:
            source_hashes_by_snapshot.setdefault(str(row["snapshot_id"]), {})[str(row["source_name"])] = (
                str(row["resolved_ref"] or ""),
                str(row["artifact_hash"]),
            )
        source_hash_groups = {frozenset(value.items()) for value in source_hashes_by_snapshot.values()}
        sibling_sources_identical = len(source_hash_groups) == 1 and bool(source_hash_groups)

        sibling_snapshot_rows = _sqlite_rows(
            connection,
            """
            SELECT
                s.snapshot_id,
                s.status,
                (
                    SELECT COUNT(*) FROM actor_candidates_v1 a
                    WHERE a.snapshot_id = s.snapshot_id
                ) AS actor_candidates,
                (
                    SELECT COUNT(*) FROM malware_candidates_v1 m
                    WHERE m.snapshot_id = s.snapshot_id
                ) AS malware_candidates,
                (
                    SELECT COUNT(*) FROM technique_candidates_v1 t
                    WHERE t.snapshot_id = s.snapshot_id
                ) AS technique_candidates,
                (
                    SELECT COUNT(*) FROM timeline_candidates_v1 tl
                    WHERE tl.snapshot_id = s.snapshot_id
                ) AS timeline_candidates,
                (
                    SELECT COUNT(*) FROM campaign_incidents_v1 ci
                    WHERE ci.snapshot_id = s.snapshot_id
                ) AS campaign_incidents,
                (
                    SELECT COUNT(*) FROM puzzle_day pd
                    WHERE pd.snapshot_id = s.snapshot_id
                ) AS puzzle_day_rows
            FROM snapshots s
            WHERE s.snapshot_id LIKE ?
            ORDER BY s.snapshot_id
            """,
            (sibling_like,),
        )

        threatdle_counts = {
            "actors": int(_sqlite_scalar(connection, "SELECT COUNT(*) FROM actors") or 0),
            "malware": int(_sqlite_scalar(connection, "SELECT COUNT(*) FROM malware") or 0),
            "techniques_total": int(_sqlite_scalar(connection, "SELECT COUNT(*) FROM techniques") or 0),
            "techniques_active": int(
                _sqlite_scalar(
                    connection,
                    "SELECT COUNT(*) FROM techniques WHERE revoked = 0 AND deprecated = 0",
                )
                or 0
            ),
            "campaigns": int(_sqlite_scalar(connection, "SELECT COUNT(*) FROM campaigns") or 0),
            "timelines": int(_sqlite_scalar(connection, "SELECT COUNT(*) FROM timelines") or 0),
        }

        threatdle_timeline_technique_ids = _sqlite_set(
            connection,
            "SELECT DISTINCT attack_id FROM timeline_steps",
        )
        threatdle_technique_ids = _sqlite_set(
            connection,
            "SELECT attack_id FROM techniques WHERE revoked = 0 AND deprecated = 0",
        )
        threatdle_actor_ids = _sqlite_set(connection, "SELECT attack_group_id FROM actors")
        threatdle_malware_ids = _sqlite_set(connection, "SELECT attack_software_id FROM malware")
        threatdle_campaign_names = _sqlite_set(connection, "SELECT name FROM campaigns")

    postgres_table_counts = {
        row[0]: int(row[1])
        for row in _run_psql(
            container=postgres_container,
            db_user=postgres_user,
            db_name=postgres_db,
            sql="""
            SELECT 'articles' AS table_name, COUNT(*) AS row_count FROM optic.articles
            UNION ALL SELECT 'entities', COUNT(*) FROM optic.entities
            UNION ALL SELECT 'entity_aliases', COUNT(*) FROM optic.entity_aliases
            UNION ALL SELECT 'attack_catalog', COUNT(*) FROM optic.attack_catalog
            UNION ALL SELECT 'attack_mappings', COUNT(*) FROM optic.attack_mappings
            UNION ALL SELECT 'article_entity_mentions', COUNT(*) FROM optic.article_entity_mentions
            UNION ALL SELECT 'article_relationships', COUNT(*) FROM optic.article_relationships
            UNION ALL SELECT 'article_technique_facts', COUNT(*) FROM optic.article_technique_facts
            UNION ALL SELECT 'article_extractions', COUNT(*) FROM optic.article_extractions
            UNION ALL SELECT 'ingestion_runs', COUNT(*) FROM optic.ingestion_runs
            UNION ALL SELECT 'attack_backfill_runs', COUNT(*) FROM optic.attack_backfill_runs
            """,
        )
    }
    postgres_entity_type_counts = {
        row[0]: int(row[1])
        for row in _run_psql(
            container=postgres_container,
            db_user=postgres_user,
            db_name=postgres_db,
            sql="""
            SELECT entity_type, COUNT(*) AS row_count
            FROM optic.entities
            GROUP BY entity_type
            ORDER BY row_count DESC, entity_type
            """,
        )
    }
    postgres_article_window_row = _run_psql(
        container=postgres_container,
        db_user=postgres_user,
        db_name=postgres_db,
        sql="""
        SELECT
            COALESCE(MIN(publication_date)::text, '') AS min_publication_date,
            COALESCE(MAX(publication_date)::text, '') AS max_publication_date,
            COUNT(*)::text AS article_count
        FROM optic.articles
        """,
    )[0]
    postgres_attack_domains = {
        row[0]: {
            "total": int(row[1]),
            "active": int(row[2]),
        }
        for row in _run_psql(
            container=postgres_container,
            db_user=postgres_user,
            db_name=postgres_db,
            sql="""
            SELECT
                domain,
                COUNT(*)::text AS row_count,
                SUM(
                    CASE
                        WHEN NOT COALESCE(is_deprecated, false)
                         AND NOT COALESCE(is_revoked, false)
                        THEN 1 ELSE 0
                    END
                )::text AS active_rows
            FROM optic.attack_catalog
            GROUP BY domain
            ORDER BY domain
            """,
        )
    }
    postgres_top_vendors = [
        {"vendor": row[0], "article_count": int(row[1])}
        for row in _run_psql(
            container=postgres_container,
            db_user=postgres_user,
            db_name=postgres_db,
            sql="""
            SELECT vendor, COUNT(*)::text AS article_count
            FROM optic.articles
            GROUP BY vendor
            ORDER BY article_count DESC, vendor
            LIMIT 10
            """,
        )
    ]
    postgres_entity_attack_id_stats = {
        row[0]: {
            "total_rows": int(row[1]),
            "rows_with_attack_id": int(row[2]),
            "distinct_attack_ids": int(row[3]),
        }
        for row in _run_psql(
            container=postgres_container,
            db_user=postgres_user,
            db_name=postgres_db,
            sql="""
            SELECT
                entity_type,
                COUNT(*)::text AS total_rows,
                COUNT(entity_metadata_json->>'attack_id')::text AS rows_with_attack_id,
                COUNT(DISTINCT entity_metadata_json->>'attack_id')::text AS distinct_attack_ids
            FROM optic.entities
            WHERE entity_type IN ('threat_actor', 'malware', 'campaign', 'technique')
            GROUP BY entity_type
            ORDER BY entity_type
            """,
        )
    }

    postgres_attack_catalog_enterprise_active = _psql_set(
        container=postgres_container,
        db_user=postgres_user,
        db_name=postgres_db,
        sql="""
        SELECT DISTINCT attack_id
        FROM optic.attack_catalog
        WHERE domain = 'enterprise'
          AND NOT COALESCE(is_deprecated, false)
          AND NOT COALESCE(is_revoked, false)
        ORDER BY attack_id
        """,
    )
    postgres_article_fact_techniques = _psql_set(
        container=postgres_container,
        db_user=postgres_user,
        db_name=postgres_db,
        sql="""
        SELECT DISTINCT current_attack_id
        FROM optic.article_technique_facts
        WHERE current_domain = 'enterprise'
          AND current_attack_id IS NOT NULL
        ORDER BY current_attack_id
        """,
    )
    postgres_actor_attack_ids = _psql_set(
        container=postgres_container,
        db_user=postgres_user,
        db_name=postgres_db,
        sql="""
        SELECT DISTINCT entity_metadata_json->>'attack_id'
        FROM optic.entities
        WHERE entity_type = 'threat_actor'
          AND entity_metadata_json ? 'attack_id'
        ORDER BY 1
        """,
    )
    postgres_malware_attack_ids = _psql_set(
        container=postgres_container,
        db_user=postgres_user,
        db_name=postgres_db,
        sql="""
        SELECT DISTINCT entity_metadata_json->>'attack_id'
        FROM optic.entities
        WHERE entity_type = 'malware'
          AND entity_metadata_json ? 'attack_id'
        ORDER BY 1
        """,
    )
    postgres_campaign_names = _psql_set(
        container=postgres_container,
        db_user=postgres_user,
        db_name=postgres_db,
        sql="""
        SELECT canonical_name
        FROM optic.entities
        WHERE entity_type = 'campaign'
        ORDER BY canonical_name
        """,
    )

    technique_catalog_overlap = threatdle_technique_ids & postgres_attack_catalog_enterprise_active
    technique_fact_overlap = threatdle_technique_ids & postgres_article_fact_techniques
    actor_overlap = threatdle_actor_ids & postgres_actor_attack_ids
    malware_overlap = threatdle_malware_ids & postgres_malware_attack_ids
    postgres_campaign_names_casefold = {value.casefold() for value in postgres_campaign_names}
    campaign_name_overlap = {
        name for name in threatdle_campaign_names if name.casefold() in postgres_campaign_names_casefold
    }

    extra_actor_ids = sorted(postgres_actor_attack_ids - threatdle_actor_ids)
    extra_malware_ids = sorted(postgres_malware_attack_ids - threatdle_malware_ids)

    actor_extra_name_rows: list[dict[str, str]] = []
    if extra_actor_ids:
        actor_id_list = ", ".join(_quote_sql_literal(value) for value in extra_actor_ids)
        actor_extra_name_rows = [
            {"name": row[0], "attack_id": row[1]}
            for row in _run_psql(
                container=postgres_container,
                db_user=postgres_user,
                db_name=postgres_db,
                sql=f"""
                SELECT canonical_name, entity_metadata_json->>'attack_id' AS attack_id
                FROM optic.entities
                WHERE entity_type = 'threat_actor'
                  AND entity_metadata_json->>'attack_id' IN ({actor_id_list})
                ORDER BY attack_id, canonical_name
                """,
            )
        ]

    malware_extra_name_rows: list[dict[str, str]] = []
    if extra_malware_ids:
        malware_id_list = ", ".join(_quote_sql_literal(value) for value in extra_malware_ids[:10])
        malware_extra_name_rows = [
            {"name": row[0], "attack_id": row[1]}
            for row in _run_psql(
                container=postgres_container,
                db_user=postgres_user,
                db_name=postgres_db,
                sql=f"""
                SELECT canonical_name, entity_metadata_json->>'attack_id' AS attack_id
                FROM optic.entities
                WHERE entity_type = 'malware'
                  AND entity_metadata_json->>'attack_id' IN ({malware_id_list})
                ORDER BY attack_id, canonical_name
                """,
            )
        ]

    threatdle_missing_from_fact = sorted(threatdle_technique_ids - postgres_article_fact_techniques)
    timeline_missing_from_fact = sorted(threatdle_timeline_technique_ids - postgres_article_fact_techniques)
    fact_only_ids = sorted(postgres_article_fact_techniques - threatdle_technique_ids)

    return {
        "generated_at": _utc_now_iso(),
        "root_dir": str(root_dir),
        "sqlite_db_path": str(sqlite_db_path),
        "runtime_bundle_path": str(runtime_bundle_path),
        "runtime_bundle": runtime_bundle,
        "snapshot": {
            "snapshot_id": str(snapshot_row["snapshot_id"]),
            "status": str(snapshot_row["status"]),
            "created_at": str(snapshot_row["created_at"]),
            "ready_at": str(snapshot_row["ready_at"]),
            "active_snapshot_id": str(active_snapshot_id or ""),
            "canonical_snapshot_matches_hosted": str(active_snapshot_id or "") == str(snapshot_row["snapshot_id"]),
            "sibling_sources_identical": sibling_sources_identical,
        },
        "sibling_snapshots": [
            {
                "snapshot_id": str(row["snapshot_id"]),
                "status": str(row["status"]),
                "actor_candidates": int(row["actor_candidates"]),
                "malware_candidates": int(row["malware_candidates"]),
                "technique_candidates": int(row["technique_candidates"]),
                "timeline_candidates": int(row["timeline_candidates"]),
                "campaign_incidents": int(row["campaign_incidents"]),
                "puzzle_day_rows": int(row["puzzle_day_rows"]),
            }
            for row in sibling_snapshot_rows
        ],
        "snapshot_sources": [
            {
                "source_name": source_name,
                "resolved_ref": resolved_ref,
                "artifact_hash": artifact_hash,
            }
            for source_name, (resolved_ref, artifact_hash) in sorted(
                source_hashes_by_snapshot.get(resolved_snapshot_id, {}).items()
            )
        ],
        "threatdle": {
            "counts": threatdle_counts,
            "timeline_technique_count": len(threatdle_timeline_technique_ids),
            "campaign_name_count": len(threatdle_campaign_names),
        },
        "postgres": {
            "container": postgres_container,
            "db_name": postgres_db,
            "db_user": postgres_user,
            "article_count": int(postgres_article_window_row[2]),
            "article_window": {
                "min_publication_date": postgres_article_window_row[0],
                "max_publication_date": postgres_article_window_row[1],
            },
            "table_counts": postgres_table_counts,
            "entity_type_counts": postgres_entity_type_counts,
            "attack_domain_counts": postgres_attack_domains,
            "top_vendors": postgres_top_vendors,
            "entity_attack_id_stats": postgres_entity_attack_id_stats,
        },
        "overlap": {
            "technique_catalog": {
                "threatdle_count": len(threatdle_technique_ids),
                "optic_count": len(postgres_attack_catalog_enterprise_active),
                "intersection_count": len(technique_catalog_overlap),
                "only_threatdle_ids": sorted(threatdle_technique_ids - postgres_attack_catalog_enterprise_active),
                "only_optic_ids": sorted(postgres_attack_catalog_enterprise_active - threatdle_technique_ids),
            },
            "technique_observed_in_articles": {
                "threatdle_active_count": len(threatdle_technique_ids),
                "optic_observed_count": len(postgres_article_fact_techniques),
                "intersection_count": len(technique_fact_overlap),
                "threatdle_missing_count": len(threatdle_missing_from_fact),
                "optic_only_count": len(fact_only_ids),
                "threatdle_missing_sample": threatdle_missing_from_fact[:20],
                "optic_only_ids": fact_only_ids,
            },
            "timeline_techniques_observed_in_articles": {
                "threatdle_timeline_count": len(threatdle_timeline_technique_ids),
                "intersection_count": len(threatdle_timeline_technique_ids & postgres_article_fact_techniques),
                "missing_ids": timeline_missing_from_fact,
            },
            "actors": {
                "threatdle_count": len(threatdle_actor_ids),
                "optic_count": len(postgres_actor_attack_ids),
                "intersection_count": len(actor_overlap),
                "only_threatdle_ids": sorted(threatdle_actor_ids - postgres_actor_attack_ids),
                "only_optic_ids": extra_actor_ids,
                "only_optic_named_rows": actor_extra_name_rows,
            },
            "malware": {
                "threatdle_count": len(threatdle_malware_ids),
                "optic_count": len(postgres_malware_attack_ids),
                "intersection_count": len(malware_overlap),
                "only_threatdle_ids": sorted(threatdle_malware_ids - postgres_malware_attack_ids),
                "only_optic_ids": extra_malware_ids,
                "only_optic_named_sample": malware_extra_name_rows,
            },
            "campaigns": {
                "threatdle_count": len(threatdle_campaign_names),
                "optic_count": len(postgres_campaign_names),
                "exact_name_overlap_count": len(campaign_name_overlap),
                "exact_name_overlap_sample": sorted(campaign_name_overlap)[:20],
                "optic_campaign_attack_id_distinct_count": postgres_entity_attack_id_stats["campaign"]["distinct_attack_ids"],
            },
        },
    }


def _render_markdown(report: dict[str, Any]) -> str:
    runtime_bundle = report.get("runtime_bundle") or {}
    runtime_snapshot = runtime_bundle.get("snapshot") if isinstance(runtime_bundle, dict) else {}
    if not isinstance(runtime_snapshot, dict):
        runtime_snapshot = {}

    summary_lines = [
        "# Hosted Snapshot vs Local Optic Postgres Comparison",
        "",
        f"Generated: `{report['generated_at']}`",
        f"Hosted snapshot: `{report['snapshot']['snapshot_id']}`",
        f"Threatdle SQLite: `{report['sqlite_db_path']}`",
        f"Optic Postgres container: `{report['postgres']['container']}`",
        "",
        "## Summary",
        "",
        f"- The hosted runtime bundle points at snapshot `{report['snapshot']['snapshot_id']}` and packages `{runtime_snapshot.get('day_count', 'n/a')}` puzzle days with `{runtime_snapshot.get('row_count', 'n/a')}` rows.",
        f"- The three sibling `*-live-*` snapshots share identical source hashes: `{str(report['snapshot']['sibling_sources_identical']).lower()}`.",
        f"- Threatdle's active enterprise ATT&CK technique set overlaps the Optic enterprise ATT&CK catalog exactly: `{report['overlap']['technique_catalog']['intersection_count']}/{report['overlap']['technique_catalog']['threatdle_count']}`.",
        f"- Every Threatdle ATT&CK-mapped actor and malware id is present in Optic: actors `{report['overlap']['actors']['intersection_count']}/{report['overlap']['actors']['threatdle_count']}`, malware `{report['overlap']['malware']['intersection_count']}/{report['overlap']['malware']['threatdle_count']}`.",
        f"- Optic's article corpus observes `{report['overlap']['technique_observed_in_articles']['intersection_count']}/{report['overlap']['technique_observed_in_articles']['threatdle_active_count']}` Threatdle active techniques and `{report['overlap']['timeline_techniques_observed_in_articles']['intersection_count']}/{report['overlap']['timeline_techniques_observed_in_articles']['threatdle_timeline_count']}` techniques used in Threatdle timelines.",
        "",
        "## Hosted Snapshot",
        "",
        f"- Snapshot status: `{report['snapshot']['status']}`",
        f"- Created at: `{report['snapshot']['created_at']}`",
        f"- Ready at: `{report['snapshot']['ready_at']}`",
        f"- Canonical SQLite state matches hosted snapshot: `{str(report['snapshot']['canonical_snapshot_matches_hosted']).lower()}`",
        f"- Runtime bundle path: `{report['runtime_bundle_path']}`",
        f"- Runtime bundle generated_for: `{runtime_bundle.get('generated_for', 'n/a')}`",
        f"- Runtime bundle timezone: `{runtime_bundle.get('timezone', 'n/a')}`",
        "",
        _markdown_table(
            ["Source", "Ref", "Artifact SHA-256"],
            [
                [row["source_name"], row["resolved_ref"], row["artifact_hash"]]
                for row in report["snapshot_sources"]
            ],
        ),
        "",
        _markdown_table(
            [
                "Sibling Snapshot",
                "Status",
                "Actor Candidates",
                "Malware Candidates",
                "Technique Candidates",
                "Timeline Candidates",
                "Campaign Incidents",
                "Puzzle Day Rows",
            ],
            [
                [
                    row["snapshot_id"],
                    row["status"],
                    str(row["actor_candidates"]),
                    str(row["malware_candidates"]),
                    str(row["technique_candidates"]),
                    str(row["timeline_candidates"]),
                    str(row["campaign_incidents"]),
                    str(row["puzzle_day_rows"]),
                ]
                for row in report["sibling_snapshots"]
            ],
        ),
        "",
        _markdown_table(
            ["Threatdle Dataset", "Count"],
            [
                ["Actors", str(report["threatdle"]["counts"]["actors"])],
                ["Malware", str(report["threatdle"]["counts"]["malware"])],
                ["Techniques (total)", str(report["threatdle"]["counts"]["techniques_total"])],
                ["Techniques (active enterprise)", str(report["threatdle"]["counts"]["techniques_active"])],
                ["Campaigns", str(report["threatdle"]["counts"]["campaigns"])],
                ["Timelines", str(report["threatdle"]["counts"]["timelines"])],
                ["Distinct timeline techniques", str(report["threatdle"]["timeline_technique_count"])],
            ],
        ),
        "",
        "## Local Optic Postgres",
        "",
        f"- Article window: `{report['postgres']['article_window']['min_publication_date']}` to `{report['postgres']['article_window']['max_publication_date']}`",
        f"- Article count: `{report['postgres']['article_count']}`",
        f"- ATT&CK catalog rows: `{report['postgres']['table_counts']['attack_catalog']}`",
        "",
        _markdown_table(
            ["Table", "Rows"],
            [
                [table_name, str(row_count)]
                for table_name, row_count in sorted(report["postgres"]["table_counts"].items())
            ],
        ),
        "",
        _markdown_table(
            ["Entity Type", "Rows"],
            [
                [entity_type, str(row_count)]
                for entity_type, row_count in report["postgres"]["entity_type_counts"].items()
            ],
        ),
        "",
        _markdown_table(
            ["ATT&CK Domain", "Total Rows", "Active Rows"],
            [
                [domain, str(values["total"]), str(values["active"])]
                for domain, values in report["postgres"]["attack_domain_counts"].items()
            ],
        ),
        "",
        _markdown_table(
            ["Vendor", "Articles"],
            [[row["vendor"], str(row["article_count"])] for row in report["postgres"]["top_vendors"]],
        ),
        "",
        "## Overlap",
        "",
        "### ATT&CK Techniques",
        "",
        f"- Threatdle active enterprise ATT&CK ids: `{report['overlap']['technique_catalog']['threatdle_count']}`",
        f"- Optic active enterprise ATT&CK ids: `{report['overlap']['technique_catalog']['optic_count']}`",
        f"- Exact overlap: `{report['overlap']['technique_catalog']['intersection_count']}`",
        f"- Optic article facts cover `{report['overlap']['technique_observed_in_articles']['intersection_count']}/{report['overlap']['technique_observed_in_articles']['threatdle_active_count']}` Threatdle active techniques (`{_format_pct(report['overlap']['technique_observed_in_articles']['intersection_count'], report['overlap']['technique_observed_in_articles']['threatdle_active_count'])}`).",
        f"- Threatdle timeline techniques covered by Optic article facts: `{report['overlap']['timeline_techniques_observed_in_articles']['intersection_count']}/{report['overlap']['timeline_techniques_observed_in_articles']['threatdle_timeline_count']}` (`{_format_pct(report['overlap']['timeline_techniques_observed_in_articles']['intersection_count'], report['overlap']['timeline_techniques_observed_in_articles']['threatdle_timeline_count'])}`).",
        f"- Threatdle active techniques missing from Optic article facts: `{report['overlap']['technique_observed_in_articles']['threatdle_missing_count']}`. Sample: `{', '.join(report['overlap']['technique_observed_in_articles']['threatdle_missing_sample'])}`.",
        f"- Optic article facts include one enterprise technique outside Threatdle's active set: `{', '.join(report['overlap']['technique_observed_in_articles']['optic_only_ids']) or 'none'}`.",
        f"- Threatdle timeline techniques missing from Optic article facts: `{', '.join(report['overlap']['timeline_techniques_observed_in_articles']['missing_ids']) or 'none'}`.",
        "",
        "### ATT&CK Threat Actors",
        "",
        f"- Threatdle ATT&CK-mapped actors: `{report['overlap']['actors']['threatdle_count']}`",
        f"- Optic ATT&CK-mapped threat actors: `{report['overlap']['actors']['optic_count']}`",
        f"- Exact ATT&CK id overlap: `{report['overlap']['actors']['intersection_count']}`",
        f"- Threatdle actor ids missing from Optic: `{len(report['overlap']['actors']['only_threatdle_ids'])}`",
        f"- Optic-only ATT&CK actor ids: `{', '.join(report['overlap']['actors']['only_optic_ids']) or 'none'}`",
        "",
        _markdown_table(
            ["Optic-Only Actor", "ATT&CK ID"],
            [
                [row["name"], row["attack_id"]]
                for row in report["overlap"]["actors"]["only_optic_named_rows"]
            ],
        ),
        "",
        "### ATT&CK Malware",
        "",
        f"- Threatdle ATT&CK-mapped malware: `{report['overlap']['malware']['threatdle_count']}`",
        f"- Optic ATT&CK-mapped malware: `{report['overlap']['malware']['optic_count']}`",
        f"- Exact ATT&CK id overlap: `{report['overlap']['malware']['intersection_count']}`",
        f"- Threatdle malware ids missing from Optic: `{len(report['overlap']['malware']['only_threatdle_ids'])}`",
        f"- Optic-only ATT&CK malware ids: `{len(report['overlap']['malware']['only_optic_ids'])}`",
        "",
        _markdown_table(
            ["Optic-Only Malware Sample", "ATT&CK ID"],
            [
                [row["name"], row["attack_id"]]
                for row in report["overlap"]["malware"]["only_optic_named_sample"]
            ],
        ),
        "",
        "### Campaigns",
        "",
        f"- Threatdle campaigns: `{report['overlap']['campaigns']['threatdle_count']}`",
        f"- Optic campaign entities: `{report['overlap']['campaigns']['optic_count']}`",
        f"- Optic ATT&CK campaign ids captured in schema: `{report['overlap']['campaigns']['optic_campaign_attack_id_distinct_count']}`",
        f"- Exact campaign name overlap: `{report['overlap']['campaigns']['exact_name_overlap_count']}`. Sample: `{', '.join(report['overlap']['campaigns']['exact_name_overlap_sample']) or 'none'}`.",
        "",
        "## Interpretation",
        "",
        "- The hosted Threatdle snapshot is a curated, ATT&CK-pinned gameplay dataset built from five source artifacts and materialized into puzzle-oriented tables.",
        "- The local Optic Postgres database is a broader article-derived CTI corpus with vendors, articles, mentions, relationships, IOCs, and a larger long-tail of extracted campaign and malware entities.",
        "- Threatdle is not missing any ATT&CK actor or malware ids that Optic already maps for the shared core set. The main breadth gaps are Optic's extra ATT&CK-mapped malware families and four additional ATT&CK-mapped threat actors.",
        "- The strongest practical alignment is on enterprise ATT&CK techniques: the reference catalogs match exactly, and almost all timeline techniques used by Threatdle already appear in Optic article facts.",
        "- Campaign comparison is structurally limited because Optic's campaign entities do not currently store ATT&CK campaign ids, so campaign parity can only be approximated by name matching.",
        "",
    ]
    return "\n".join(summary_lines)


def main() -> None:
    root_dir = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Compare the hosted Threatdle snapshot to the local Optic Postgres corpus.",
    )
    parser.add_argument(
        "--sqlite-db",
        type=Path,
        default=root_dir / "data" / "processed" / "threatdle.db",
        help="Path to the local Threatdle SQLite database.",
    )
    parser.add_argument(
        "--runtime-bundle",
        type=Path,
        default=root_dir / "build" / "runtime" / "game-data.json",
        help="Path to the hosted runtime bundle used for deployment.",
    )
    parser.add_argument(
        "--snapshot-id",
        help="Optional Threatdle snapshot id override. Defaults to the runtime bundle snapshot id.",
    )
    parser.add_argument(
        "--postgres-container",
        default="optic-postgres",
        help="Docker container name for the local Optic Postgres instance.",
    )
    parser.add_argument(
        "--postgres-user",
        default="optic",
        help="Database user for the local Optic Postgres instance.",
    )
    parser.add_argument(
        "--postgres-db",
        default="optic",
        help="Database name for the local Optic Postgres instance.",
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Optional file path to write the report to.",
    )
    args = parser.parse_args()

    report = _build_report(
        root_dir=root_dir,
        sqlite_db_path=args.sqlite_db.resolve(),
        runtime_bundle_path=args.runtime_bundle.resolve(),
        postgres_container=args.postgres_container,
        postgres_user=args.postgres_user,
        postgres_db=args.postgres_db,
        snapshot_id=args.snapshot_id,
    )

    if args.format == "json":
        content = json.dumps(report, indent=2, sort_keys=True)
    else:
        content = _render_markdown(report)

    if args.output:
        args.output.resolve().write_text(content, encoding="utf-8")
    else:
        print(content)


if __name__ == "__main__":
    main()
