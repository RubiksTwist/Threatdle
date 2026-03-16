# Threatdle — Architecture & Developer Reference

_Last updated: 2026-03-15_

---

## 1. What Is Threatdle?

Threatdle is a daily cybersecurity puzzle game. Every day a player works through four short challenges built around a single real-world incident theme:

| Puzzle | Player task | Underlying skill |
|---|---|---|
| APT Guess | Identify the threat actor from attribute-based feedback | Threat actor attribution |
| Campaign Timeline | Reconstruct an ordered attack chain | Attack chain analysis |
| Malware Guess | Identify the malware family from clue reveals | Malware identification |
| TTP Wordle | Guess a MITRE ATT&CK technique from attribute feedback | ATT&CK familiarity |

The core design principle is **deduction, not trivia**. All four puzzles in a daily set share a single incident theme so the player feels like they are investigating a real intrusion rather than answering isolated quiz questions.

Target session length is 5–7 minutes. The primary audience is cybersecurity students, SOC analysts, threat intel analysts, and ATT&CK learners.

Full product reasoning is in `docs/threatle-product-brief.md`.

---

## 2. Repository Layout

```
Threatdle/
├── data/
│   ├── curated-flows/          # Hand-authored STIX attack flow JSON files
│   │   ├── README.md           # Flow contract (format rules)
│   │   ├── _manifests/         # Per-batch provenance manifests
│   │   └── *.json              # One file per incident
│   ├── overrides/              # Manual enrichment CSVs
│   │   ├── actor_match_overrides.csv
│   │   ├── actor_overrides.csv
│   │   └── malware_overrides.csv
│   ├── processed/
│   │   └── threatdle.db        # SQLite product database (generated)
│   └── snapshots/              # Per-run downloaded artifacts (generated)
│       └── <snapshot-id>/
│           ├── attack_stix/    # MITRE ATT&CK STIX bundle
│           ├── misp_threat_actors/
│           └── curated_flows/  # Copied from data/curated-flows/
├── docs/                       # Design docs and this file
├── src/
│   └── threatdle/
│       ├── cli.py              # CLI entrypoints (argparse)
│       ├── config.py           # Path resolution, sources.toml loading
│       ├── db/
│       │   ├── connection.py   # SQLite connection factory
│       │   ├── repositories.py # Snapshot and artifact helpers
│       │   └── schema.py       # DDL + clear helpers
│       ├── ingest/
│       │   ├── base.py         # Shared utilities (hashing, timestamps)
│       │   ├── fetch.py        # Source download and artifact registration
│       │   ├── attack_stix.py  # ATT&CK STIX → canonical tables
│       │   ├── misp.py         # MISP Galaxy → actor enrichment
│       │   ├── attack_flow.py  # Curated flows → timelines
│       │   └── overrides.py    # Override CSVs → canonical tables
│       ├── normalize/
│       │   └── text.py         # Name normalization, Levenshtein distance
│       ├── services/
│       │   ├── puzzle_views.py    # Canonical tables → puzzle materialization
│       │   ├── puzzle_generator.py # Daily puzzle selection and baking
│       │   └── review_export.py   # Review data queries from puzzle_day
│       └── review_server.py       # Local HTTP server for puzzle review
├── review/
│   └── index.html              # Single-page puzzle review viewer
├── tests/
│   ├── conftest.py
│   ├── fixtures/               # Minimal test STIX bundles and index
│   ├── test_ingest_pipeline.py
│   └── test_puzzle_generator.py # Generator determinism, repeat, quality tests
├── pyproject.toml
└── sources.toml                # Data source URLs and config
```

---

## 3. Data Sources

Defined in `sources.toml`. Three sources are required for every snapshot:

| Source key | What it provides | Origin |
|---|---|---|
| `attack_stix` | Canonical actors, techniques, malware, campaigns, relationships | MITRE ATT&CK STIX data repo (pinned to v18.1) |
| `misp_threat_actors` | Actor enrichment: country, target categories, motivation tags | MISP Galaxy threat-actor cluster |
| `curated_flows` | Ordered attack chains for the Campaign Timeline puzzle | Hand-authored files in `data/curated-flows/` |

The ATT&CK STIX source is resolved via an index JSON that maps version labels to download URLs. `sources.toml` pins the version at `18.1`.

---

## 4. Snapshot Model

The ingest pipeline is **snapshot-keyed**. A snapshot is a named, immutable unit of work that ties together:

- a set of downloaded source artifacts
- a complete load of canonical entity tables
- a set of snapshot-keyed puzzle materialization tables

### Snapshot lifecycle states

```
pending → ingesting → ready
                    ↘ failed
```

| State | Meaning |
|---|---|
| `pending` | Created; sources not yet fetched |
| `ingesting` | At least one ingest command has started; canonical tables locked to this snapshot |
| `ready` | Full pipeline completed successfully |
| `failed` | A pipeline step failed; canonical tables cleared |

A snapshot can only be loaded into the canonical tables while no other snapshot has claimed them. To re-run the pipeline you must create a new snapshot with a new ID.

### Artifact immutability

Once a source artifact is fetched and a snapshot moves to `ingesting`, every subsequent ingest step re-validates artifact hashes. If any file on disk has changed since the fetch, the run fails with a `hash changed after lock` error.

---

## 5. CLI Commands

The `threatdle` CLI is defined in `src/threatdle/cli.py`. All commands accept `--root-dir` and `--db-path` overrides.

```
threatdle init-db
    Initialize the SQLite schema (idempotent; safe to re-run).

threatdle fetch-sources --snapshot-id <id>
    Download ATT&CK STIX, MISP Galaxy, and copy curated flows
    into data/snapshots/<id>/. Registers artifacts in the DB.
    Snapshot must be in 'pending' state.

threatdle ingest-attack-stix --snapshot-id <id>
    Parse the ATT&CK STIX bundle. Clears and repopulates all
    canonical tables: actors, actor_aliases, tactics, techniques,
    malware, campaigns, and all join tables.

threatdle ingest-overrides --snapshot-id <id>
    Load actor_match_overrides.csv, actor_overrides.csv, and
    malware_overrides.csv. Applies explicit field values to
    canonical actors and malware rows.

threatdle ingest-misp-actors --snapshot-id <id>
    Match MISP Galaxy entries to ATT&CK actors by normalized name.
    Enriches matched actors with country, target categories, and
    motivation tags. Unmatched and ambiguous entries are logged to
    unresolved_matches.

threatdle ingest-attack-flow --snapshot-id <id>
    Parse curated STIX flow bundles. Extracts ordered ATT&CK
    technique chains and writes them to timelines and
    timeline_steps tables.

threatdle build-puzzle-tables --snapshot-id <id>
    Materialize snapshot-keyed puzzle tables: actor_profiles_v1,
    actor_candidates_v1, malware_profiles_v1, malware_candidates_v1,
    technique_profiles_v1, technique_candidates_v1,
    timeline_sequences_v1, timeline_candidates_v1.

threatdle ingest-all --snapshot-id <id>
    Runs the full pipeline in order:
      1. ingest-attack-stix
      2. ingest-overrides (initial — loads match overrides before MISP)
      3. ingest-misp-actors
      4. ingest-overrides (final — applies actor/malware field values)
      5. ingest-attack-flow
      6. build-puzzle-tables
    Marks the snapshot 'ready' on success, 'failed' on any error.

threatdle serve-review [--port 8000]
    Start a local HTTP server for reviewing generated puzzles.
    Serves the review viewer at http://127.0.0.1:8000 and a small
    JSON API that reads directly from puzzle_day.
```

### Standard run workflow

```powershell
# Set PYTHONPATH if running from repo root
$env:PYTHONPATH = 'C:\path\to\Threatdle\src'

python -m threatdle fetch-sources --snapshot-id 2026-03-15-batch-03
python -m threatdle ingest-all --snapshot-id 2026-03-15-batch-03
```

---

## 6. Ingest Pipeline — Stage by Stage

### Stage 1: fetch-sources

Downloads artifacts from `sources.toml` URLs and copies curated flows from `data/curated-flows/`. Each artifact is SHA-256 hashed, stored under `data/snapshots/<id>/`, and registered in `source_artifacts`. A no-change status is returned on subsequent calls if the hash matches.

### Stage 2: ingest-attack-stix

Parses the ATT&CK STIX bundle and fully replaces the canonical tables. The ingest loop runs in five passes over the STIX objects array:

1. **Tactics** (`x-mitre-tactic`) → `tactics`
2. **Techniques** (`attack-pattern`) → `techniques` (includes subtechnique parent resolution)
3. **Actors** (`intrusion-set`) → `actors`, `actor_aliases`
4. **Malware** (`malware`) → `malware`
5. **Campaigns** (`campaign`) → `campaigns`
6. **Relationships** → `actor_techniques`, `actor_malware`, `campaign_actors`, `campaign_techniques`

### Stage 3: ingest-overrides (initial pass)

Loads `actor_match_overrides.csv` into `actor_match_overrides`. This table is read by the MISP ingest to force UUID-to-ATT&CK-ID mappings before fuzzy name matching runs.

### Stage 4: ingest-misp-actors

For each entry in the MISP Galaxy threat-actor cluster:

1. Check `actor_match_overrides` for a forced UUID mapping.
2. If no override: normalize all names and synonyms, then exact-match against `actor_aliases.normalized_alias`.
3. If exactly one match: apply enrichment (country, target categories, motivation tags) to the `actors` row using `COALESCE` so existing values are never overwritten.
4. If zero matches: try Levenshtein distance ≤ 2 fuzzy match and log to `unresolved_matches` with reason `near_match`.
5. If still no match or ambiguous: log to `unresolved_matches` with reason `no_match` or `ambiguous`.

### Stage 5: ingest-overrides (final pass)

Loads `actor_overrides.csv` and `malware_overrides.csv` into their staging tables, then runs `UPDATE … SET col = COALESCE(override, col)` on `actors` and `malware`. This is the highest-precedence layer and can set display names, country codes, malware categories, and capability summaries.

### Stage 6: ingest-attack-flow

Parses each curated STIX flow file. For each `attack-flow` object:

1. Build an adjacency graph from `effect` relationships.
2. Resolve `intrusion-set` references to `attack_group_id` values using the normalized actor lookup.
3. Walk all paths through the graph, collecting `technique_id` values from each `attack-action`.
4. Validate: 3–8 unique technique IDs per path; every ID must exist in the `techniques` table.
5. Write valid paths to `timelines` and `timeline_steps`. Paths with unmapped technique IDs are logged to `unresolved_matches`.
6. `answer_type` is set to `"actor"` when exactly one group is resolved; otherwise `"incident"`.
7. `difficulty` is `"easy"` for 3-step paths, `"standard"` for 4–8.

### Stage 7: build-puzzle-tables

Materializes eight snapshot-keyed puzzle tables from canonical data:

| Table | Contents |
|---|---|
| `actor_profiles_v1` | Full clue payload per actor: country, year, targets, motivation, malware/campaign/technique lists |
| `actor_candidates_v1` | Actors with enough clues (score ≥ 4) to be used in puzzles |
| `malware_profiles_v1` | Name, aliases, platforms, category, capability summary, linked actors |
| `malware_candidates_v1` | Malware eligible for puzzles, with `summary_tier` indicating override-backed or description-backed summary quality |
| `technique_profiles_v1` | ATT&CK ID, name, tactics, platforms, subtechnique metadata |
| `technique_candidates_v1` | Techniques eligible for TTP puzzle selection |
| `timeline_sequences_v1` | Full step-by-step ordered chains with answer attribution |
| `timeline_candidates_v1` | Lightweight index of available timelines for puzzle selection |

Actor clue score is computed as: 1 point each for country, first-observed year, target categories, motivation tags, at least one linked malware, at least one campaign, at least three techniques. Maximum 7. Score ≥ 4 with at least one profile clue and one relationship clue qualifies as a candidate.

---

## 7. Curated Flow Format

Curated flows are STIX 2.1 bundles stored in `data/curated-flows/*.json`. The contract is defined in `data/curated-flows/README.md`.

**Required objects:**
- Exactly one `attack-flow` object with a stable `id` and `name`
- Exactly one `intrusion-set` object with a MITRE Enterprise ATT&CK group ID (`Gxxxx`) in `external_references`
- 3–8 `attack-action` objects, each with a `technique_id` field containing a valid ATT&CK v18.1 ID

**Required relationships:**
- One `attributed-to` relationship: `attack-flow → intrusion-set`
- One `effect` relationship: `attack-flow → first attack-action`
- One `effect` relationship between each adjacent pair of actions (linear chain)

**Do not use:** `technique_ref`, branching graphs, `attack-condition`, `attack-operator`, or `.afb` project files.

### Overlap rule

Before authoring a new flow, compute the longest common subsequence (LCS) overlap against all existing curated flows:

```
ordered_overlap = LCS(candidate_ids, existing_ids) / min(len(candidate), len(existing))
```

Skip if `ordered_overlap > 0.60` unless the incident is clearly distinct and the overlap is justified in the manifest.

### Current live corpus (5 flows)

| File | Actor | Chain |
|---|---|---|
| `solarwinds_apt29.json` | APT29 (G0016) | T1195.002 → T1059.001 → T1003 → T1021 |
| `notpetya_sandworm.json` | Sandworm (G0034) | T1195.002 → T1105 → T1210 → T1486 |
| `wannacry_lazarus.json` | Lazarus (G0032) | T1210 → T1105 → T1490 → T1486 |
| `hafnium_exchange.json` | HAFNIUM (G0125) | T1190 → T1505.003 → T1059.001 → T1003 |
| `apt28_dnc.json` | APT28 (G0007) | T1566.001 → T1047 → T1055 → T1105 |

### Batch manifest contract

Each batch has a manifest in `data/curated-flows/_manifests/batch-NN.json`. Required fields per entry: `filename`, `incident_name`, `actor_attack_id`, `actor_name`, `primary_sources`, `technique_chain_source`, `expected_attack_ids`, `expected_step_count`, `author_notes`, `status` (`accepted` or `skipped`).

---

## 8. Override CSVs

All three files live in `data/overrides/`. They are created as empty stubs if missing when `ingest-overrides` runs.

### actor_match_overrides.csv

Forces UUID-to-ATT&CK mapping for MISP entries that fail name matching.

| Column | Description |
|---|---|
| `misp_uuid` | UUID from MISP Galaxy entry |
| `attack_group_id` | ATT&CK group ID (e.g. `G0016`) |

### actor_overrides.csv

Sets or overrides actor clue fields at highest precedence.

| Column | Description |
|---|---|
| `attack_group_id` | ATT&CK group ID |
| `display_name` | Preferred display name |
| `country_code` | 2-letter country code |
| `first_observed_year` | Integer year |
| `target_categories` | Pipe-separated list |
| `victim_countries` | Pipe-separated list |
| `motivation_tags` | Pipe-separated list |
| `notes` | Free text for internal use |
| `reference_url` | Source link |

### malware_overrides.csv

Sets malware display metadata not present in ATT&CK STIX.

| Column | Description |
|---|---|
| `attack_software_id` | ATT&CK software ID (e.g. `S0559`) |
| `display_name` | Preferred display name |
| `malware_category` | e.g. `Supply Chain`, `Ransomware` |
| `platforms` | Pipe-separated list |
| `capability_summary` | Short human-readable description |
| `reference_url` | Source link |

---

## 9. Database Schema Summary

The SQLite database (`data/processed/threatdle.db`) has three logical groups of tables:

### Infrastructure tables

| Table | Purpose |
|---|---|
| `snapshots` | One row per snapshot; tracks lifecycle state and version refs |
| `snapshot_sources` | Per-snapshot source artifact metadata (legacy mirror of source_artifacts) |
| `source_artifacts` | Authoritative per-snapshot artifact tracking with hash and path |
| `ingest_runs` | One row per ingest command run; tracks start/end time, row count, and errors |
| `unresolved_matches` | MISP and flow items that could not be automatically matched |
| `canonical_state` | Single row tracking which snapshot currently owns canonical tables |

### Canonical tables (replaced on each snapshot load)

| Table | Primary contents |
|---|---|
| `actors` | ATT&CK intrusion sets with enriched clue fields |
| `actor_aliases` | Normalized aliases for fuzzy name matching |
| `tactics` | ATT&CK tactics |
| `techniques` | ATT&CK techniques and subtechniques |
| `malware` | ATT&CK malware with override-enriched metadata |
| `campaigns` | ATT&CK campaigns |
| `actor_techniques` | Many-to-many: actor ↔ technique |
| `actor_malware` | Many-to-many: actor ↔ malware |
| `campaign_actors` | Many-to-many: campaign ↔ actor |
| `campaign_techniques` | Many-to-many: campaign ↔ technique |
| `timelines` | One row per extracted attack chain (path through a flow) |
| `timeline_steps` | Ordered technique steps for each timeline |

### Override staging tables

| Table | Purpose |
|---|---|
| `actor_match_overrides` | UUID→ATT&CK ID forced mappings for MISP matching |
| `actor_override_records` | Staged actor field values; applied via COALESCE update |
| `malware_override_records` | Staged malware field values; applied via COALESCE update |

### Puzzle tables (keyed by snapshot_id)

| Table | Purpose |
|---|---|
| `actor_profiles_v1` | Full clue payload for each actor in a snapshot |
| `actor_candidates_v1` | Actors eligible for the APT Guess puzzle |
| `malware_profiles_v1` | Clue payload for each malware in a snapshot |
| `malware_candidates_v1` | Malware eligible for the Malware Guess puzzle (with `summary_tier` 1 or 2) |
| `technique_profiles_v1` | Clue payload for each technique in a snapshot |
| `technique_candidates_v1` | Techniques eligible for the TTP Wordle puzzle |
| `timeline_sequences_v1` | Full step-by-step sequences for the Campaign Timeline puzzle |
| `timeline_candidates_v1` | Lightweight index of available timeline puzzles |
| `puzzle_day` | Baked daily puzzle output (4 rows per day: actor, malware, technique, timeline) |

---

## 10. Batch Backlog Status

Three batches have been authored and ingested. A fourth batch is pending.

| Batch | Flows | Status |
|---|---|---|
| batch-01 | sony_lazarus, bangladesh_bank_lazarus, shamoon_apt33, singhealth_whitefly | Ingested |
| batch-02 | cloud_hopper_menupass, cobalt_kitty_apt32, turla_carbon, turla_snake | Ingested |
| batch-03 | fin7_hospitality, fin6_pos_intrusion, carbanak_bank_intrusion, cobalt_group_bank_intrusion | Ingested |
| batch-04 | oilrig_campaign, apt41_supply_chain, apt1_economic_espionage, whispergate_sandworm | Not yet authored |

The curated flow handoff prompt for authoring new batches is in `docs/curated-flow-handoff-prompt.md`.

---

## 11. Validation Checklist (After Each Batch)

After running `fetch-sources` and `ingest-all` on a new batch snapshot, confirm:

- Snapshot status is `ready`
- `timeline_sequences_v1` row count increased by the number of `accepted` entries in the manifest
- No rows in `unresolved_matches` with `source_name = 'curated_flows'`
- Spot-check a few `timeline_steps` sequences against the manifest's `expected_attack_ids`
- `actor_candidates_v1` count is non-zero

---

## 12. Puzzle Generator

The puzzle generator (`src/threatdle/services/puzzle_generator.py`) writes 4 `puzzle_day` rows per calendar day — one per mode: `actor`, `malware`, `technique`, `timeline`. The design spec is in `PUZZLE_GENERATOR_SPEC.md` at the repo root. The authoritative implementation reference is `docs/puzzle-generator-implementation.md`.

Key design points: selection is deterministic from `(snapshot_id, day_key)` using a two-level seed model. Themed days (`theme_mode=prefer`) pick an anchor actor and select all four answers from that actor's linked set when possible, falling back to independent selection per mode when not. Repeat windows (14/21/21/10 days) prevent answer reuse. Repeat avoidance is soft — if the filtered pool is empty, the full pool is used rather than failing.

### Generator CLI commands

```
threatdle generate-puzzle-day --snapshot-id <id> --day-key YYYY-MM-DD [--theme-mode prefer] [--force]
threatdle generate-puzzle-range --snapshot-id <id> --start-day YYYY-MM-DD --days N [--theme-mode prefer] [--force]
threatdle preview-puzzle-day --snapshot-id <id> --day-key YYYY-MM-DD [--theme-mode prefer]
```

### Candidate tables

`malware_candidates_v1` and `technique_candidates_v1` were added to close the gap between profile materialization and generator input. Both are populated in `build_puzzle_tables` and cleared on snapshot re-run. Malware candidates use a tiered model: Tier 1 (override-backed `capability_summary`) and Tier 2 (ATT&CK `description` between 50–300 characters).

### Test coverage

`tests/test_puzzle_generator.py` covers: determinism, repeat-window enforcement, strict-theme failure, malware candidate tiering, preview no-write, and technique quality gating (11 tests passing). `tests/test_ingest_pipeline.py` also asserts on the new candidate table counts.

### Live snapshot results

Against `2026-03-15-batch-03`: 56 actor candidates, 235 malware candidates, 691 technique candidates, 17 timeline candidates. A 30-day range generation produced 120 `puzzle_day` rows with zero actor repeat-window violations. Early days were fully themed; later days fell back to independent selection as the small cross-linkable pool was exhausted by repeat windows.

---

## 13. What Is Not Yet Implemented

The following areas are designed but not yet built:

- **Manual review of first 7 generated days** — The 30-day preview has been run (120 `puzzle_day` rows for `2026-03-16` through `2026-04-14`). A review viewer exists at `review/index.html` served via `threatdle serve-review`. Manual inspection of early-day clue quality has not been done yet.
- **Game frontend** — No web or app layer exists. The database is the sole output so far.
- **TTP Wordle guess comparison** — `technique_profiles_v1` is materialized and `puzzle_day` rows can be generated, but no attribute-comparison judging logic for player guesses is built.
- **APT Guess deduction grid** — Same: generation works, but guess judging is not built.
- **Malware Guess clue reveal** — Same.
- **batch-04 flows** — Four incidents remain to be authored: oilrig_campaign, apt41_supply_chain, apt1_economic_espionage, whispergate_sandworm.
- **Reserve batch flows** — Four reserve incidents exist as a fallback if any batch-04 item must be skipped.
