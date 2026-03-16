"""SQLite schema for Threatdle snapshots, canonical tables, and puzzle tables."""

from __future__ import annotations

import sqlite3


SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS snapshots (
        snapshot_id TEXT PRIMARY KEY,
        created_at TEXT NOT NULL,
        status TEXT NOT NULL,
        locked_at TEXT,
        ready_at TEXT,
        attack_version TEXT,
        misp_ref TEXT,
        attack_flow_ref TEXT,
        actor_match_override_hash TEXT,
        actor_override_hash TEXT,
        malware_override_hash TEXT,
        incident_override_hash TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS snapshot_sources (
        snapshot_id TEXT NOT NULL,
        source_name TEXT NOT NULL,
        url TEXT NOT NULL,
        resolved_ref TEXT,
        local_path TEXT NOT NULL,
        artifact_hash TEXT NOT NULL,
        fetched_at TEXT NOT NULL,
        extracted_files_json TEXT,
        status TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, source_name),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS ingest_runs (
        ingest_run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id TEXT NOT NULL,
        command_name TEXT NOT NULL,
        source_name TEXT,
        started_at TEXT NOT NULL,
        completed_at TEXT,
        status TEXT NOT NULL,
        row_count INTEGER NOT NULL DEFAULT 0,
        error_message TEXT,
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS source_artifacts (
        artifact_id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id TEXT NOT NULL,
        source_name TEXT NOT NULL,
        url TEXT NOT NULL,
        resolved_ref TEXT,
        file_path TEXT NOT NULL,
        artifact_hash TEXT NOT NULL,
        fetched_at TEXT NOT NULL,
        extracted_files_json TEXT,
        status TEXT NOT NULL,
        UNIQUE (snapshot_id, source_name),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS unresolved_matches (
        unresolved_match_id INTEGER PRIMARY KEY AUTOINCREMENT,
        snapshot_id TEXT NOT NULL,
        source_name TEXT NOT NULL,
        external_key TEXT NOT NULL,
        candidate_key TEXT,
        reason TEXT NOT NULL,
        detail_json TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS canonical_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        active_snapshot_id TEXT,
        loaded_at TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_match_overrides (
        misp_uuid TEXT PRIMARY KEY,
        attack_group_id TEXT NOT NULL,
        source_name TEXT NOT NULL,
        loaded_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_override_records (
        attack_group_id TEXT PRIMARY KEY,
        display_name TEXT,
        country_code TEXT,
        first_observed_year INTEGER,
        target_categories_json TEXT,
        victim_countries_json TEXT,
        motivation_tags_json TEXT,
        notes TEXT,
        reference_url TEXT,
        source_name TEXT NOT NULL,
        loaded_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS malware_override_records (
        attack_software_id TEXT PRIMARY KEY,
        display_name TEXT,
        malware_category TEXT,
        platforms_json TEXT,
        capability_summary TEXT,
        reference_url TEXT,
        source_name TEXT NOT NULL,
        loaded_at TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actors (
        actor_id INTEGER PRIMARY KEY AUTOINCREMENT,
        attack_group_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        country_code TEXT,
        state_sponsor TEXT,
        target_categories_json TEXT,
        victim_countries_json TEXT,
        motivation_tags_json TEXT,
        first_observed_year INTEGER,
        revoked INTEGER NOT NULL DEFAULT 0,
        deprecated INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_aliases (
        actor_alias_id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_id INTEGER NOT NULL,
        alias TEXT NOT NULL,
        normalized_alias TEXT NOT NULL,
        UNIQUE (actor_id, alias),
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS tactics (
        tactic_id INTEGER PRIMARY KEY AUTOINCREMENT,
        stix_id TEXT NOT NULL UNIQUE,
        short_name TEXT UNIQUE,
        name TEXT NOT NULL,
        description TEXT
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS techniques (
        technique_id INTEGER PRIMARY KEY AUTOINCREMENT,
        stix_id TEXT NOT NULL UNIQUE,
        attack_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        tactics_json TEXT,
        platforms_json TEXT,
        is_subtechnique INTEGER NOT NULL DEFAULT 0,
        parent_attack_id TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        deprecated INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS malware (
        malware_id INTEGER PRIMARY KEY AUTOINCREMENT,
        stix_id TEXT NOT NULL UNIQUE,
        attack_software_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        aliases_json TEXT,
        platforms_json TEXT,
        malware_category TEXT,
        capability_summary TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        deprecated INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS campaigns (
        campaign_id INTEGER PRIMARY KEY AUTOINCREMENT,
        stix_id TEXT NOT NULL UNIQUE,
        attack_campaign_id TEXT UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        aliases_json TEXT,
        revoked INTEGER NOT NULL DEFAULT 0,
        deprecated INTEGER NOT NULL DEFAULT 0
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS operations (
        operation_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_flow_id TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT,
        source_url TEXT,
        timeline_source_type TEXT NOT NULL
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS operation_actors (
        operation_id INTEGER NOT NULL,
        actor_id INTEGER NOT NULL,
        PRIMARY KEY (operation_id, actor_id),
        FOREIGN KEY (operation_id) REFERENCES operations(operation_id) ON DELETE CASCADE,
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_techniques (
        actor_id INTEGER NOT NULL,
        technique_id INTEGER NOT NULL,
        PRIMARY KEY (actor_id, technique_id),
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE,
        FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_malware (
        actor_id INTEGER NOT NULL,
        malware_id INTEGER NOT NULL,
        PRIMARY KEY (actor_id, malware_id),
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE,
        FOREIGN KEY (malware_id) REFERENCES malware(malware_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_actors (
        campaign_id INTEGER NOT NULL,
        actor_id INTEGER NOT NULL,
        PRIMARY KEY (campaign_id, actor_id),
        FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_techniques (
        campaign_id INTEGER NOT NULL,
        technique_id INTEGER NOT NULL,
        PRIMARY KEY (campaign_id, technique_id),
        FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
        FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_malware (
        campaign_id INTEGER NOT NULL,
        malware_id INTEGER NOT NULL,
        PRIMARY KEY (campaign_id, malware_id),
        FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
        FOREIGN KEY (malware_id) REFERENCES malware(malware_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timelines (
        timeline_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_flow_id TEXT NOT NULL,
        flow_name TEXT,
        source_url TEXT,
        answer_type TEXT NOT NULL,
        answer_key TEXT NOT NULL,
        answer_label TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        step_count INTEGER NOT NULL,
        timeline_source_type TEXT NOT NULL,
        path_hash TEXT NOT NULL UNIQUE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_steps (
        timeline_step_id INTEGER PRIMARY KEY AUTOINCREMENT,
        timeline_id INTEGER NOT NULL,
        step_index INTEGER NOT NULL,
        technique_id INTEGER NOT NULL,
        attack_id TEXT NOT NULL,
        technique_name TEXT NOT NULL,
        UNIQUE (timeline_id, step_index),
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE,
        FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_malware (
        timeline_id INTEGER NOT NULL,
        malware_id INTEGER NOT NULL,
        reference_url TEXT,
        notes TEXT,
        confidence TEXT NOT NULL DEFAULT 'medium',
        PRIMARY KEY (timeline_id, malware_id),
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE,
        FOREIGN KEY (malware_id) REFERENCES malware(malware_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_incident_metadata (
        timeline_id INTEGER PRIMARY KEY,
        incident_name TEXT,
        attack_campaign_id TEXT,
        reference_url TEXT,
        source_article_url TEXT,
        source_article_title TEXT,
        notes TEXT,
        confidence TEXT NOT NULL DEFAULT 'medium',
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_profiles_v1 (
        snapshot_id TEXT NOT NULL,
        actor_id INTEGER NOT NULL,
        clue_payload_json TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        clue_score INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, actor_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS actor_candidates_v1 (
        snapshot_id TEXT NOT NULL,
        actor_id INTEGER NOT NULL,
        answer_key TEXT NOT NULL,
        answer_label TEXT NOT NULL,
        difficulty TEXT NOT NULL,
        clue_score INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, actor_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (actor_id) REFERENCES actors(actor_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS malware_profiles_v1 (
        snapshot_id TEXT NOT NULL,
        malware_id INTEGER NOT NULL,
        clue_payload_json TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, malware_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (malware_id) REFERENCES malware(malware_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS malware_candidates_v1 (
        snapshot_id TEXT NOT NULL,
        malware_id INTEGER NOT NULL,
        answer_key TEXT NOT NULL,
        answer_label TEXT NOT NULL,
        summary_tier INTEGER NOT NULL,
        PRIMARY KEY (snapshot_id, malware_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (malware_id) REFERENCES malware(malware_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS technique_profiles_v1 (
        snapshot_id TEXT NOT NULL,
        technique_id INTEGER NOT NULL,
        clue_payload_json TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, technique_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS technique_candidates_v1 (
        snapshot_id TEXT NOT NULL,
        technique_id INTEGER NOT NULL,
        answer_key TEXT NOT NULL,
        answer_label TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, technique_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_sequences_v1 (
        snapshot_id TEXT NOT NULL,
        timeline_id INTEGER NOT NULL,
        answer_type TEXT NOT NULL,
        answer_key TEXT NOT NULL,
        answer_label TEXT NOT NULL,
        step_count INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        steps_json TEXT NOT NULL,
        provenance_json TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, timeline_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS timeline_candidates_v1 (
        snapshot_id TEXT NOT NULL,
        timeline_id INTEGER NOT NULL,
        answer_type TEXT NOT NULL,
        answer_key TEXT NOT NULL,
        answer_label TEXT NOT NULL,
        step_count INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, timeline_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS incident_candidates_v1 (
        snapshot_id TEXT NOT NULL,
        timeline_id INTEGER NOT NULL,
        actor_answer_key TEXT NOT NULL,
        actor_answer_label TEXT NOT NULL,
        malware_answer_keys_json TEXT NOT NULL,
        malware_answer_labels_json TEXT NOT NULL,
        technique_attack_ids_json TEXT NOT NULL,
        step_count INTEGER NOT NULL,
        difficulty TEXT NOT NULL,
        repeat_key TEXT NOT NULL,
        attack_campaign_id TEXT,
        source_article_url TEXT,
        source_article_title TEXT,
        provenance_json TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, timeline_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_incidents_v1 (
        snapshot_id TEXT NOT NULL,
        campaign_id INTEGER NOT NULL,
        attack_campaign_id TEXT,
        campaign_name TEXT NOT NULL,
        actor_answer_key TEXT NOT NULL,
        actor_answer_label TEXT NOT NULL,
        malware_answer_keys_json TEXT NOT NULL,
        malware_answer_labels_json TEXT NOT NULL,
        technique_attack_ids_json TEXT NOT NULL,
        technique_count INTEGER NOT NULL,
        provenance_json TEXT NOT NULL,
        PRIMARY KEY (snapshot_id, campaign_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_timeline_matches_v1 (
        snapshot_id TEXT NOT NULL,
        campaign_id INTEGER NOT NULL,
        timeline_id INTEGER NOT NULL,
        match_rank INTEGER NOT NULL,
        attack_campaign_id TEXT,
        campaign_name TEXT NOT NULL,
        actor_answer_key TEXT NOT NULL,
        actor_answer_label TEXT NOT NULL,
        malware_answer_keys_json TEXT NOT NULL,
        malware_answer_labels_json TEXT NOT NULL,
        overlap_attack_ids_json TEXT NOT NULL,
        technique_overlap_count INTEGER NOT NULL,
        timeline_precision REAL NOT NULL,
        name_boost INTEGER NOT NULL DEFAULT 0,
        flow_name TEXT,
        source_flow_id TEXT,
        PRIMARY KEY (snapshot_id, campaign_id, timeline_id),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
        FOREIGN KEY (campaign_id) REFERENCES campaigns(campaign_id) ON DELETE CASCADE,
        FOREIGN KEY (timeline_id) REFERENCES timelines(timeline_id) ON DELETE CASCADE
    );
    """,
    """
    CREATE TABLE IF NOT EXISTS puzzle_day (
        day_key TEXT NOT NULL,
        snapshot_id TEXT NOT NULL,
        mode TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        answer_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (day_key, mode),
        FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id)
    );
    """,
]


CANONICAL_CLEAR_ORDER = [
    "timeline_incident_metadata",
    "timeline_malware",
    "timeline_steps",
    "timelines",
    "operation_actors",
    "operations",
    "campaign_malware",
    "campaign_techniques",
    "campaign_actors",
    "actor_malware",
    "actor_techniques",
    "campaigns",
    "malware",
    "techniques",
    "tactics",
    "actor_aliases",
    "actors",
]


PUZZLE_TABLES = [
    "actor_profiles_v1",
    "actor_candidates_v1",
    "malware_profiles_v1",
    "malware_candidates_v1",
    "technique_profiles_v1",
    "technique_candidates_v1",
    "timeline_sequences_v1",
    "timeline_candidates_v1",
    "incident_candidates_v1",
    "campaign_incidents_v1",
    "campaign_timeline_matches_v1",
]


def create_schema(connection: sqlite3.Connection) -> None:
    with connection:
        for statement in SCHEMA_STATEMENTS:
            connection.execute(statement)
        snapshot_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(snapshots)").fetchall()
        }
        if "incident_override_hash" not in snapshot_columns:
            connection.execute("ALTER TABLE snapshots ADD COLUMN incident_override_hash TEXT")
        incident_candidate_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(incident_candidates_v1)").fetchall()
        }
        if incident_candidate_columns and "attack_campaign_id" not in incident_candidate_columns:
            connection.execute("ALTER TABLE incident_candidates_v1 ADD COLUMN attack_campaign_id TEXT")
        if incident_candidate_columns and "source_article_url" not in incident_candidate_columns:
            connection.execute("ALTER TABLE incident_candidates_v1 ADD COLUMN source_article_url TEXT")
        if incident_candidate_columns and "source_article_title" not in incident_candidate_columns:
            connection.execute("ALTER TABLE incident_candidates_v1 ADD COLUMN source_article_title TEXT")
        connection.execute(
            """
            INSERT INTO canonical_state (id, active_snapshot_id, loaded_at)
            VALUES (1, NULL, NULL)
            ON CONFLICT(id) DO NOTHING;
            """
        )


def clear_canonical_tables(connection: sqlite3.Connection) -> None:
    with connection:
        for table_name in CANONICAL_CLEAR_ORDER:
            connection.execute(f"DELETE FROM {table_name}")


def clear_puzzle_tables_for_snapshot(connection: sqlite3.Connection, snapshot_id: str) -> None:
    with connection:
        for table_name in PUZZLE_TABLES:
            connection.execute(f"DELETE FROM {table_name} WHERE snapshot_id = ?", (snapshot_id,))
