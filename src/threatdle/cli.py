"""Command-line entrypoints for Threatdle ingest."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from threatdle.config import get_paths
from threatdle.db.connection import get_connection
from threatdle.db.repositories import mark_snapshot_failed, mark_snapshot_ready
from threatdle.db.schema import create_schema
from threatdle.ingest.attack_flow import ingest_attack_flow
from threatdle.ingest.attack_stix import ingest_attack_stix
from threatdle.ingest.emulation_plans import ingest_emulation_plans
from threatdle.ingest.fetch import fetch_sources
from threatdle.ingest.base import ensure_directory
from threatdle.ingest.incident_overrides import ingest_incident_overrides
from threatdle.ingest.misp import ingest_misp_actors
from threatdle.ingest.overrides import ingest_overrides
from threatdle.services.campaign_report import build_campaign_match_report
from threatdle.services.actor_backfill_report import build_actor_backfill_report
from threatdle.services.live_runtime_export import export_live_runtime
from threatdle.services.live_runtime_build import build_live_runtime_from_sources, default_live_snapshot_id
from threatdle.services.puzzle_generator import generate_puzzle_day, generate_puzzle_range, preview_puzzle_day
from threatdle.services.review_validation import validate_review_snapshot
from threatdle.services.puzzle_views import build_puzzle_tables
from threatdle.services.static_demo_export import export_static_demo
from threatdle.review_server import serve_review


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="threatdle")
    parser.add_argument("--root-dir", type=Path, default=None, help="Project root override")
    parser.add_argument("--db-path", type=Path, default=None, help="SQLite file override")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="Initialize the SQLite database")

    fetch_parser = subparsers.add_parser("fetch-sources", help="Download snapshot source artifacts")
    fetch_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")

    for command_name, help_text in (
        ("ingest-attack-stix", "Load ATT&CK STIX into canonical tables"),
        ("ingest-misp-actors", "Load MISP actor enrichment into canonical tables"),
        ("ingest-attack-flow", "Load Attack Flow timelines into canonical tables"),
        ("ingest-emulation-plans", "Load CTID and ATT&CK Evaluations emulation timelines into canonical tables"),
        ("ingest-overrides", "Load override CSVs and apply explicit precedence rules"),
        ("ingest-incident-overrides", "Load incident-level malware overrides for exact-chain incidents"),
        ("build-puzzle-tables", "Materialize snapshot-keyed puzzle tables"),
        ("build-campaign-match-report", "Export ATT&CK campaign to timeline match candidates"),
        ("build-actor-backfill-report", "Export actor metadata backfill candidates"),
        ("ingest-all", "Run the complete ingest and puzzle build pipeline"),
    ):
        command_parser = subparsers.add_parser(command_name, help=help_text)
        command_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
        if command_name == "build-actor-backfill-report":
            command_parser.add_argument(
                "--profile-json",
                type=Path,
                default=None,
                help="Optional actor profile export JSON for advisory matching",
            )

    generate_day_parser = subparsers.add_parser("generate-puzzle-day", help="Generate one day of puzzles")
    generate_day_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
    generate_day_parser.add_argument("--day-key", required=True, help="Day key in YYYY-MM-DD format")
    generate_day_parser.add_argument(
        "--theme-mode",
        choices=("off", "prefer", "strict"),
        default="prefer",
        help="Theme selection mode",
    )
    generate_day_parser.add_argument(
        "--chain-mode",
        choices=("linked", "exact"),
        default="linked",
        help="Puzzle chaining mode",
    )
    generate_day_parser.add_argument("--force", action="store_true", help="Overwrite any existing puzzle rows for the day")

    generate_range_parser = subparsers.add_parser("generate-puzzle-range", help="Generate a range of daily puzzles")
    generate_range_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
    generate_range_parser.add_argument("--start-day", required=True, help="Start day in YYYY-MM-DD format")
    generate_range_parser.add_argument("--days", required=True, type=int, help="Number of days to generate")
    generate_range_parser.add_argument(
        "--theme-mode",
        choices=("off", "prefer", "strict"),
        default="prefer",
        help="Theme selection mode",
    )
    generate_range_parser.add_argument(
        "--chain-mode",
        choices=("linked", "exact"),
        default="linked",
        help="Puzzle chaining mode",
    )
    generate_range_parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite any existing puzzle rows in the generated date range",
    )

    preview_parser = subparsers.add_parser("preview-puzzle-day", help="Preview one day of puzzles without writing")
    preview_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
    preview_parser.add_argument("--day-key", required=True, help="Day key in YYYY-MM-DD format")
    preview_parser.add_argument(
        "--theme-mode",
        choices=("off", "prefer", "strict"),
        default="prefer",
        help="Theme selection mode",
    )
    preview_parser.add_argument(
        "--chain-mode",
        choices=("linked", "exact"),
        default="linked",
        help="Puzzle chaining mode",
    )

    review_parser = subparsers.add_parser("serve-review", help="Start the puzzle review server")
    review_parser.add_argument("--port", type=int, default=8000, help="Server port (default: 8000)")

    validate_parser = subparsers.add_parser("validate-review", help="Validate baked review data for clue leaks")
    validate_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
    validate_parser.add_argument("--day-key", help="Optional day key in YYYY-MM-DD format")
    validate_parser.add_argument(
        "--fail-on",
        choices=("none", "warning", "error"),
        default="error",
        help="Exit non-zero when issues at or above this severity are found",
    )

    static_export_parser = subparsers.add_parser("export-static-demo", help="Export a static demo bundle for one baked snapshot")
    static_export_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
    static_export_parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for the static site bundle (default: <root>/dist/static-demo)",
    )

    live_runtime_parser = subparsers.add_parser("export-live-runtime", help="Export a private runtime bundle for live server functions")
    live_runtime_parser.add_argument("--snapshot-id", required=True, help="Snapshot identifier")
    live_runtime_parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for the private runtime bundle (default: <root>/build/runtime)",
    )
    live_runtime_parser.add_argument(
        "--timezone",
        default="America/New_York",
        help="Authoritative game timezone for server-owned day selection",
    )

    build_live_runtime_parser = subparsers.add_parser(
        "build-live-runtime",
        help="Fetch sources, ingest, bake puzzle days, and export a private live runtime bundle",
    )
    build_live_runtime_parser.add_argument("--snapshot-id", help="Optional snapshot identifier override")
    build_live_runtime_parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for the private runtime bundle (default: <root>/build/runtime)",
    )
    build_live_runtime_parser.add_argument(
        "--timezone",
        default="America/New_York",
        help="Authoritative game timezone for server-owned day selection",
    )
    build_live_runtime_parser.add_argument(
        "--start-day",
        help="Optional first puzzle day in YYYY-MM-DD format (default: current day in the game timezone)",
    )
    build_live_runtime_parser.add_argument(
        "--days",
        type=int,
        default=365,
        help="Number of days to bake into the runtime bundle",
    )
    build_live_runtime_parser.add_argument(
        "--theme-mode",
        choices=("off", "prefer", "strict"),
        default="prefer",
        help="Theme selection mode",
    )
    build_live_runtime_parser.add_argument(
        "--chain-mode",
        choices=("linked", "exact"),
        default="linked",
        help="Puzzle chaining mode",
    )

    return parser


def _resolve_db_path(root_dir: Path | None, db_path: Path | None) -> Path:
    paths = get_paths(root_dir=root_dir)
    return db_path or paths.db_path


def run_init_db(root_dir: Path | None, db_path: Path | None) -> Path:
    target_path = _resolve_db_path(root_dir, db_path)
    ensure_directory(target_path.parent)
    connection = get_connection(target_path)
    try:
        create_schema(connection)
    finally:
        connection.close()
    return target_path


def run_with_connection(root_dir: Path | None, db_path: Path | None, callback) -> object:
    target_path = run_init_db(root_dir, db_path)
    connection = get_connection(target_path)
    try:
        return callback(connection)
    finally:
        connection.close()


def _validation_failed(result: dict[str, object], fail_on: str) -> bool:
    issue_counts = result.get("issue_counts", {})
    if not isinstance(issue_counts, dict):
        return False
    warning_count = int(issue_counts.get("warning", 0) or 0)
    error_count = int(issue_counts.get("error", 0) or 0)
    if fail_on == "warning":
        return warning_count > 0 or error_count > 0
    if fail_on == "error":
        return error_count > 0
    return False


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.root_dir is not None:
        os.environ["THREATDLE_ROOT"] = str(args.root_dir.resolve())

    if args.command == "init-db":
        target_path = run_init_db(args.root_dir, args.db_path)
        print(f"Initialized database at {target_path}")
        return

    if args.command == "fetch-sources":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: fetch_sources(connection, args.snapshot_id, root_dir=args.root_dir),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-attack-stix":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: ingest_attack_stix(connection, args.snapshot_id),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-misp-actors":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: ingest_misp_actors(connection, args.snapshot_id),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-attack-flow":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: ingest_attack_flow(connection, args.snapshot_id),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-emulation-plans":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: ingest_emulation_plans(connection, args.snapshot_id),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-overrides":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: ingest_overrides(connection, args.snapshot_id, root_dir=args.root_dir),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-incident-overrides":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: ingest_incident_overrides(connection, args.snapshot_id, root_dir=args.root_dir),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "build-puzzle-tables":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: build_puzzle_tables(connection, args.snapshot_id),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "build-campaign-match-report":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: build_campaign_match_report(connection, args.snapshot_id, root_dir=args.root_dir),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "build-actor-backfill-report":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: build_actor_backfill_report(
                connection,
                args.snapshot_id,
                root_dir=args.root_dir,
                profile_json_path=args.profile_json,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "ingest-all":
        def _run_all(connection):
            try:
                results = {
                    "attack_stix": ingest_attack_stix(connection, args.snapshot_id),
                    "overrides_initial": ingest_overrides(connection, args.snapshot_id, root_dir=args.root_dir),
                    "misp": ingest_misp_actors(connection, args.snapshot_id),
                    "overrides_final": ingest_overrides(connection, args.snapshot_id, root_dir=args.root_dir),
                    "attack_flow": ingest_attack_flow(connection, args.snapshot_id),
                    "emulation_plans": ingest_emulation_plans(connection, args.snapshot_id),
                    "incident_overrides": ingest_incident_overrides(connection, args.snapshot_id, root_dir=args.root_dir),
                    "puzzle_tables": build_puzzle_tables(connection, args.snapshot_id),
                }
                mark_snapshot_ready(connection, args.snapshot_id)
                return results
            except Exception:
                mark_snapshot_failed(connection, args.snapshot_id)
                raise

        result = run_with_connection(args.root_dir, args.db_path, _run_all)
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "generate-puzzle-day":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: generate_puzzle_day(
                connection,
                args.snapshot_id,
                args.day_key,
                theme_mode=args.theme_mode,
                chain_mode=args.chain_mode,
                force=args.force,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "generate-puzzle-range":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: generate_puzzle_range(
                connection,
                args.snapshot_id,
                args.start_day,
                args.days,
                theme_mode=args.theme_mode,
                chain_mode=args.chain_mode,
                force=args.force,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "preview-puzzle-day":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: preview_puzzle_day(
                connection,
                args.snapshot_id,
                args.day_key,
                theme_mode=args.theme_mode,
                chain_mode=args.chain_mode,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "validate-review":
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: validate_review_snapshot(
                connection,
                args.snapshot_id,
                day_key=args.day_key,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        if _validation_failed(result, args.fail_on):
            raise SystemExit(1)
        return

    if args.command == "export-static-demo":
        paths = get_paths(root_dir=args.root_dir)
        out_dir = args.out_dir or (paths.root_dir / "dist" / "static-demo")
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: export_static_demo(
                connection,
                args.snapshot_id,
                out_dir=out_dir,
                public_dir=paths.root_dir / "public",
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "export-live-runtime":
        paths = get_paths(root_dir=args.root_dir)
        out_dir = args.out_dir or (paths.root_dir / "build" / "runtime")
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: export_live_runtime(
                connection,
                args.snapshot_id,
                out_dir=out_dir,
                timezone_name=args.timezone,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "build-live-runtime":
        paths = get_paths(root_dir=args.root_dir)
        out_dir = args.out_dir or (paths.root_dir / "build" / "runtime")
        snapshot_id = args.snapshot_id or default_live_snapshot_id(
            args.timezone,
            commit_ref=os.environ.get("COMMIT_REF") or os.environ.get("GITHUB_SHA"),
        )
        result = run_with_connection(
            args.root_dir,
            args.db_path,
            lambda connection: build_live_runtime_from_sources(
                connection,
                snapshot_id,
                root_dir=args.root_dir,
                out_dir=out_dir,
                timezone_name=args.timezone,
                start_day=args.start_day,
                days=args.days,
                theme_mode=args.theme_mode,
                chain_mode=args.chain_mode,
            ),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return

    if args.command == "serve-review":
        paths = get_paths(root_dir=args.root_dir)
        db_path = args.db_path or paths.db_path
        review_dir = paths.root_dir / "review"
        if not review_dir.is_dir():
            parser.error(f"Review assets not found at {review_dir}")
        public_dir = paths.root_dir / "public"
        serve_review(db_path, review_dir, public_dir, port=args.port)
        return

    parser.error(f"Unknown command {args.command}")
