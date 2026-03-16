"""ATT&CK STIX ingest for Threatdle."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
from typing import Any

from threatdle.db.repositories import (
    ensure_snapshot_loading,
    finish_ingest_run,
    get_source_artifact,
    start_ingest_run,
)
from threatdle.ingest.base import load_json_file
from threatdle.normalize.text import extract_first_observed_year, normalize_actor_name


ATTACK_PATTERN = "attack-pattern"
INTRUSION_SET = "intrusion-set"
CAMPAIGN = "campaign"
RELATIONSHIP = "relationship"
TACTIC = "x-mitre-tactic"
SOFTWARE_TYPES = {"malware", "tool"}


def _dump_list(value: list[str]) -> str:
    return json.dumps(value, sort_keys=True)


def _coerce_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _extract_external_id(obj: dict[str, Any]) -> str | None:
    for reference in obj.get("external_references", []):
        source_name = str(reference.get("source_name", ""))
        if "mitre" not in source_name:
            continue
        external_id = reference.get("external_id")
        if external_id:
            return str(external_id)
    return None


def _extract_aliases(obj: dict[str, Any]) -> list[str]:
    aliases: list[str] = []
    for key in ("aliases", "x_mitre_aliases"):
        value = obj.get(key)
        if isinstance(value, list):
            aliases.extend(str(item) for item in value if item)
    return list(dict.fromkeys(aliases))


def _extract_tactics(obj: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name"):
            values.append(str(phase["phase_name"]))
    return values


def _stix_type(stix_id: str) -> str:
    return stix_id.split("--", 1)[0]


def ingest_attack_stix(connection: sqlite3.Connection, snapshot_id: str) -> dict[str, int]:
    ensure_snapshot_loading(connection, snapshot_id)
    artifact = get_source_artifact(connection, snapshot_id, "attack_stix")
    if artifact is None:
        raise ValueError(f"Snapshot {snapshot_id} is missing ATT&CK source artifact")
    ingest_run_id = start_ingest_run(connection, snapshot_id, "ingest-attack-stix", "attack_stix")
    bundle = load_json_file(Path(artifact["file_path"]))
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("Invalid ATT&CK STIX bundle: missing objects list")

    object_index = {str(obj["id"]): obj for obj in objects if isinstance(obj, dict) and obj.get("id")}
    parent_map: dict[str, str] = {}
    for obj in objects:
        if not isinstance(obj, dict) or obj.get("type") != RELATIONSHIP or obj.get("relationship_type") != "subtechnique-of":
            continue
        parent = object_index.get(str(obj.get("target_ref")))
        if parent is None:
            continue
        parent_attack_id = _extract_external_id(parent)
        if parent_attack_id:
            parent_map[str(obj.get("source_ref"))] = parent_attack_id

    counts = {
        "actors": 0,
        "actor_aliases": 0,
        "tactics": 0,
        "techniques": 0,
        "malware": 0,
        "campaigns": 0,
        "actor_techniques": 0,
        "actor_malware": 0,
        "campaign_actors": 0,
        "campaign_techniques": 0,
        "campaign_malware": 0,
    }

    try:
        with connection:
            connection.execute("DELETE FROM campaign_malware")
            connection.execute("DELETE FROM campaign_techniques")
            connection.execute("DELETE FROM campaign_actors")
            connection.execute("DELETE FROM actor_malware")
            connection.execute("DELETE FROM actor_techniques")
            connection.execute("DELETE FROM campaigns")
            connection.execute("DELETE FROM malware")
            connection.execute("DELETE FROM techniques")
            connection.execute("DELETE FROM tactics")
            connection.execute("DELETE FROM actor_aliases")
            connection.execute("DELETE FROM actors")

            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != TACTIC:
                    continue
                connection.execute(
                    """
                    INSERT INTO tactics (stix_id, short_name, name, description)
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        str(obj["id"]),
                        _coerce_text(obj.get("x_mitre_shortname")),
                        str(obj.get("name") or "Unknown tactic"),
                        _coerce_text(obj.get("description")),
                    ),
                )
                counts["tactics"] += 1

            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != ATTACK_PATTERN:
                    continue
                attack_id = _extract_external_id(obj)
                if not attack_id:
                    continue
                connection.execute(
                    """
                    INSERT INTO techniques (
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(obj["id"]),
                        attack_id,
                        str(obj.get("name") or "Unknown technique"),
                        _coerce_text(obj.get("description")),
                        _dump_list(_extract_tactics(obj)),
                        _dump_list([str(item) for item in obj.get("x_mitre_platforms", []) if item]),
                        int(bool(obj.get("x_mitre_is_subtechnique", False))),
                        parent_map.get(str(obj["id"])),
                        int(bool(obj.get("revoked", False))),
                        int(bool(obj.get("x_mitre_deprecated", False))),
                    ),
                )
                counts["techniques"] += 1

            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != INTRUSION_SET:
                    continue
                attack_group_id = _extract_external_id(obj)
                if not attack_group_id:
                    continue
                cursor = connection.execute(
                    """
                    INSERT INTO actors (
                        attack_group_id,
                        name,
                        description,
                        country_code,
                        state_sponsor,
                        target_categories_json,
                        victim_countries_json,
                        motivation_tags_json,
                        first_observed_year,
                        revoked,
                        deprecated
                    )
                    VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?, ?, ?)
                    """,
                    (
                        attack_group_id,
                        str(obj.get("name") or attack_group_id),
                        _coerce_text(obj.get("description")),
                        extract_first_observed_year(_coerce_text(obj.get("description"))),
                        int(bool(obj.get("revoked", False))),
                        int(bool(obj.get("x_mitre_deprecated", False))),
                    ),
                )
                actor_id = int(cursor.lastrowid)
                counts["actors"] += 1
                alias_values = [str(obj.get("name") or attack_group_id), *_extract_aliases(obj), attack_group_id]
                for alias in list(dict.fromkeys(alias_values)):
                    normalized_alias = normalize_actor_name(alias)
                    if not normalized_alias:
                        continue
                    connection.execute(
                        """
                        INSERT INTO actor_aliases (actor_id, alias, normalized_alias)
                        VALUES (?, ?, ?)
                        """,
                        (actor_id, alias, normalized_alias),
                    )
                    counts["actor_aliases"] += 1

            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != "malware":
                    continue
                attack_software_id = _extract_external_id(obj)
                if not attack_software_id:
                    continue
                connection.execute(
                    """
                    INSERT INTO malware (
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
                    VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?)
                    """,
                    (
                        str(obj["id"]),
                        attack_software_id,
                        str(obj.get("name") or attack_software_id),
                        _coerce_text(obj.get("description")),
                        _dump_list(_extract_aliases(obj)),
                        _dump_list([str(item) for item in obj.get("x_mitre_platforms", []) if item]),
                        int(bool(obj.get("revoked", False))),
                        int(bool(obj.get("x_mitre_deprecated", False))),
                    ),
                )
                counts["malware"] += 1

            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != CAMPAIGN:
                    continue
                connection.execute(
                    """
                    INSERT INTO campaigns (
                        stix_id,
                        attack_campaign_id,
                        name,
                        description,
                        aliases_json,
                        revoked,
                        deprecated
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(obj["id"]),
                        _extract_external_id(obj),
                        str(obj.get("name") or "Unknown campaign"),
                        _coerce_text(obj.get("description")),
                        _dump_list(_extract_aliases(obj)),
                        int(bool(obj.get("revoked", False))),
                        int(bool(obj.get("x_mitre_deprecated", False))),
                    ),
                )
                counts["campaigns"] += 1

            actor_id_by_stix: dict[str, int] = {}
            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != INTRUSION_SET:
                    continue
                attack_group_id = _extract_external_id(obj)
                if not attack_group_id:
                    continue
                row = connection.execute(
                    "SELECT actor_id FROM actors WHERE attack_group_id = ?",
                    (attack_group_id,),
                ).fetchone()
                if row is not None:
                    actor_id_by_stix[str(obj["id"])] = int(row["actor_id"])

            technique_id_by_stix = {
                row["stix_id"]: row["technique_id"]
                for row in connection.execute("SELECT stix_id, technique_id FROM techniques")
            }
            malware_id_by_stix = {
                row["stix_id"]: row["malware_id"]
                for row in connection.execute("SELECT stix_id, malware_id FROM malware")
            }
            campaign_id_by_stix = {
                row["stix_id"]: row["campaign_id"]
                for row in connection.execute("SELECT stix_id, campaign_id FROM campaigns")
            }

            for obj in objects:
                if not isinstance(obj, dict) or obj.get("type") != RELATIONSHIP:
                    continue
                source_ref = _coerce_text(obj.get("source_ref"))
                target_ref = _coerce_text(obj.get("target_ref"))
                relationship_type = _coerce_text(obj.get("relationship_type"))
                if not source_ref or not target_ref or not relationship_type:
                    continue

                source_type = _stix_type(source_ref)
                target_type = _stix_type(target_ref)

                if relationship_type == "uses" and source_type == INTRUSION_SET and target_type == ATTACK_PATTERN:
                    actor_id = actor_id_by_stix.get(source_ref)
                    technique_id = technique_id_by_stix.get(target_ref)
                    if actor_id and technique_id:
                        connection.execute(
                            "INSERT OR IGNORE INTO actor_techniques (actor_id, technique_id) VALUES (?, ?)",
                            (actor_id, technique_id),
                        )
                        counts["actor_techniques"] += 1
                elif relationship_type == "uses" and source_type == INTRUSION_SET and target_type == "malware":
                    actor_id = actor_id_by_stix.get(source_ref)
                    malware_id = malware_id_by_stix.get(target_ref)
                    if actor_id and malware_id:
                        connection.execute(
                            "INSERT OR IGNORE INTO actor_malware (actor_id, malware_id) VALUES (?, ?)",
                            (actor_id, malware_id),
                        )
                        counts["actor_malware"] += 1
                elif relationship_type == "uses" and source_type == CAMPAIGN and target_type == ATTACK_PATTERN:
                    campaign_id = campaign_id_by_stix.get(source_ref)
                    technique_id = technique_id_by_stix.get(target_ref)
                    if campaign_id and technique_id:
                        connection.execute(
                            "INSERT OR IGNORE INTO campaign_techniques (campaign_id, technique_id) VALUES (?, ?)",
                            (campaign_id, technique_id),
                        )
                        counts["campaign_techniques"] += 1
                elif relationship_type == "uses" and source_type == CAMPAIGN and target_type == "malware":
                    campaign_id = campaign_id_by_stix.get(source_ref)
                    malware_id = malware_id_by_stix.get(target_ref)
                    if campaign_id and malware_id:
                        connection.execute(
                            "INSERT OR IGNORE INTO campaign_malware (campaign_id, malware_id) VALUES (?, ?)",
                            (campaign_id, malware_id),
                        )
                        counts["campaign_malware"] += 1
                elif relationship_type == "attributed-to" and source_type == CAMPAIGN and target_type == INTRUSION_SET:
                    campaign_id = campaign_id_by_stix.get(source_ref)
                    actor_id = actor_id_by_stix.get(target_ref)
                    if campaign_id and actor_id:
                        connection.execute(
                            "INSERT OR IGNORE INTO campaign_actors (campaign_id, actor_id) VALUES (?, ?)",
                            (campaign_id, actor_id),
                        )
                        counts["campaign_actors"] += 1

        finish_ingest_run(
            connection,
            ingest_run_id,
            status="completed",
            row_count=sum(counts.values()),
        )
    except Exception as exc:
        finish_ingest_run(
            connection,
            ingest_run_id,
            status="failed",
            row_count=0,
            error_message=str(exc),
        )
        raise

    return counts
