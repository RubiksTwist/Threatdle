# Puzzle Generator Implementation

Status: implemented in the repository as of 2026-03-15.

This document describes the puzzle generator that now exists in Threatdle. It is implementation documentation, not a planning note. Everything here is based on the current code and the live SQLite database behavior.

## Purpose

The generator produces one daily puzzle set across four modes:

- `actor`
- `malware`
- `technique`
- `timeline`

For a given `snapshot_id` and `day_key`, it selects deterministic answers from snapshot-pinned candidate tables, applies repeat-window rules, optionally tries to keep the four modes thematically linked through the same actor, and writes baked payloads into `puzzle_day`.

The generator does not derive answers from raw ATT&CK or MISP tables directly. It only works from the materialized puzzle tables built by `build-puzzle-tables`.

## Code Locations

Main implementation files:

- [puzzle_generator.py](C:/Users/Home/Threatdle/src/threatdle/services/puzzle_generator.py)
- [puzzle_views.py](C:/Users/Home/Threatdle/src/threatdle/services/puzzle_views.py)
- [schema.py](C:/Users/Home/Threatdle/src/threatdle/db/schema.py)
- [cli.py](C:/Users/Home/Threatdle/src/threatdle/cli.py)
- [test_puzzle_generator.py](C:/Users/Home/Threatdle/tests/test_puzzle_generator.py)
- [test_ingest_pipeline.py](C:/Users/Home/Threatdle/tests/test_ingest_pipeline.py)

## Data Flow

The full data path is:

1. `fetch-sources`
2. `ingest-attack-stix`
3. `ingest-overrides`
4. `ingest-misp-actors`
5. `ingest-overrides` again
6. `ingest-attack-flow`
7. `build-puzzle-tables`
8. `generate-puzzle-day` or `generate-puzzle-range`

The key separation is:

- Canonical tables store the current snapshot's normalized entities and relationships.
- Puzzle tables store snapshot-keyed, game-oriented materializations.
- `puzzle_day` stores baked daily output for one calendar day and one mode.

The generator only runs against a snapshot whose status is `ready`.

## Schema Additions For The Generator

Two candidate tables were added:

### `malware_candidates_v1`

Columns:

- `snapshot_id`
- `malware_id`
- `answer_key`
- `answer_label`
- `summary_tier`

`summary_tier` is:

- `1` when the candidate has an override-backed `malware.capability_summary`
- `2` when it falls back to a usable `malware.description`

### `technique_candidates_v1`

Columns:

- `snapshot_id`
- `technique_id`
- `answer_key`
- `answer_label`

Both are cleared by `clear_puzzle_tables_for_snapshot`.

The existing `puzzle_day` table is used unchanged:

```sql
puzzle_day (
  day_key TEXT,
  snapshot_id TEXT,
  mode TEXT,
  payload_json TEXT,
  answer_json TEXT,
  created_at TEXT,
  PRIMARY KEY (day_key, mode)
)
```

## Puzzle Materialization Layer

`build_puzzle_tables` now produces these snapshot-keyed tables:

- `actor_profiles_v1`
- `actor_candidates_v1`
- `malware_profiles_v1`
- `malware_candidates_v1`
- `technique_profiles_v1`
- `technique_candidates_v1`
- `timeline_sequences_v1`
- `timeline_candidates_v1`

### Actor candidate rule

An actor enters `actor_candidates_v1` when:

- `clue_score >= 4`
- at least one profile clue exists
- at least one relationship clue exists

Profile clues come from:

- `country_code`
- `first_observed_year`
- `target_categories`
- `motivation_tags`

Relationship clues come from:

- linked malware
- linked campaigns
- linked techniques

### Malware candidate rule

Shared baseline:

- at least one platform
- at least one linked actor

Tier rules:

- Tier 1: non-empty `malware.capability_summary`
- Tier 2: `capability_summary` missing, but `description` length is between 50 and 300 characters

This rule exists because the live snapshot had zero override-backed malware summaries, and an override-only rule would have produced no malware candidate pool at all.

### Technique candidate rule

A technique enters `technique_candidates_v1` when:

- it has at least one tactic
- it has at least one platform
- it is not revoked
- it is not deprecated

Subtechniques are allowed.

## Generator Service

The generator lives in [puzzle_generator.py](C:/Users/Home/Threatdle/src/threatdle/services/puzzle_generator.py).

Public entrypoints:

- `load_candidate_pools(...)`
- `generate_puzzle_day(...)`
- `preview_puzzle_day(...)`
- `generate_puzzle_range(...)`

### Candidate loading

The service loads four pools:

- actor candidates joined to `actor_profiles_v1`
- malware candidates joined to `malware_profiles_v1`
- technique candidates joined to `technique_profiles_v1`
- timeline candidates joined to `timeline_sequences_v1`

Each loaded row becomes a `CandidateRow` dataclass with:

- answer identity
- clue payload
- provenance payload
- row id
- mode-specific metadata such as `summary_tier`, `difficulty`, `answer_type`, and linked actor ids

### Determinism

Determinism uses two seeds:

- Day seed: `sha256(f"{snapshot_id}:{day_key}")`
- Mode seed: `sha256(f"{snapshot_id}:{day_key}:{mode}")`

Why two seeds:

- the day seed coordinates themed selection by picking one shared anchor actor
- the mode seed picks the actual answer within each mode's filtered pool

No global random state is used.

### Repeat windows

Repeat windows are enforced by reading prior baked rows from `puzzle_day`.

Windows:

- actor: 14 days
- timeline: 21 days
- malware: 21 days
- technique: 10 days

The service extracts `answer_key` from `answer_json` using SQLite JSON1:

```sql
json_extract(answer_json, '$.answer_key')
```

It excludes repeated keys within the window when possible. If the filtered pool becomes empty, it falls back to the full pool instead of hard failing.

## Theme Modes

Supported theme modes:

- `off`
- `prefer`
- `strict`

### `off`

All four modes are selected independently.

### `prefer`

The generator tries to build a themed set around one anchor actor.

Cross-linkable actors are actors that have:

- an actor candidate
- at least one actor-attributed timeline candidate
- at least one malware candidate linked to that actor
- at least one technique candidate linked to that actor

If a cross-linkable actor exists outside the actor repeat window:

1. select one anchor actor from that pool using the day seed
2. select an actor-linked timeline if available
3. select an actor-linked malware if available
4. select an actor-linked technique if available

Fallback behavior:

- if a specific mode cannot be filled from the anchor actor, that mode falls back to independent selection
- if fewer than 3 of the 4 final answers remain connected to the anchor actor, the whole day falls back to fully independent selection

### `strict`

Same as `prefer`, except any failure to fill all four modes from the anchor actor raises an error instead of falling back.

This is intended for testing or debugging, not normal production generation.

## Quality Gates

Quality gates are applied during selection, not during materialization.

### Actor quality gate

The actor must have at least 2 of:

- `country_code`
- `first_observed_year`
- non-empty `target_categories`
- non-empty `motivation_tags`

### Malware quality gate

The displayed summary must be at least 20 characters after stripping whitespace.

This applies to:

- override `capability_summary` for tier 1
- fallback `description` for tier 2

During themed selection, tier 1 malware is preferred if the anchor actor has any. If not, tier 2 is accepted.

### Technique quality gate

Valid if either:

- platform count is at least 2

or:

- it is a subtechnique
- platform count is at least 1
- tactic count is at least 2

### Timeline handling

Timeline mode does not add a separate quality gate. It already inherits constraints from curated flow authoring and timeline materialization.

When selecting independently, the service prefers actor-attributed timelines over incident-attributed timelines.

## `puzzle_day` Output Shape

The generator writes exactly 4 rows per day:

- one row for `actor`
- one row for `malware`
- one row for `technique`
- one row for `timeline`

### `payload_json`

This is the UI-facing clue payload.

It never includes the answer key.

Mode payloads:

- actor: profile clues plus relationship counts
- malware: platforms, category, summary, aliases, actor count
- technique: tactics, platforms, subtechnique flag, parent name
- timeline: step count and ordered technique names only

### `answer_json`

This is the hidden answer payload used for evaluation and post-solve reveal.

It includes:

- `answer_key`
- `answer_label`
- mode-specific comparison fields

Timeline answers include step `attack_id` values. Payloads do not.

Step indexing is preserved as 1-based because the ingest pipeline stores timeline steps that way.

## CLI Commands

New CLI commands are wired in [cli.py](C:/Users/Home/Threatdle/src/threatdle/cli.py).

### Preview one day without writing

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle preview-puzzle-day --snapshot-id 2026-03-15-batch-03 --day-key 2026-03-16 --theme-mode prefer
```

Behavior:

- loads candidates
- runs full selection logic
- does not insert rows into `puzzle_day`

### Generate one day

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle generate-puzzle-day --snapshot-id 2026-03-15-batch-03 --day-key 2026-03-16 --theme-mode prefer
```

Options:

- `--theme-mode off|prefer|strict`
- `--force` to overwrite existing rows for that day

### Generate a range

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle generate-puzzle-range --snapshot-id 2026-03-15-batch-03 --start-day 2026-03-16 --days 30 --theme-mode prefer
```

Behavior:

- writes `4 * days` rows
- shares the same candidate pools across the range call
- still applies repeat-window checks against already-written `puzzle_day` rows

## Force And Overwrite Behavior

`generate-puzzle-day`:

- without `--force`, generation fails if any row already exists for that day
- with `--force`, all rows for that day are deleted and regenerated

`generate-puzzle-range`:

- applies the same overwrite rule to each day in the range

`preview-puzzle-day` never writes and never deletes.

## Testing

Tests currently cover:

- deterministic selection for the same snapshot and day
- actor repeat-window behavior across a 15-day range
- strict themed failure when only one cross-linkable actor exists and is exhausted by repeat history
- malware candidate tiering behavior
- preview no-write behavior
- technique quality-gate rejection
- ingest-pipeline assertions for the new candidate tables

Test files:

- [test_puzzle_generator.py](C:/Users/Home/Threatdle/tests/test_puzzle_generator.py)
- [test_ingest_pipeline.py](C:/Users/Home/Threatdle/tests/test_ingest_pipeline.py)

Last confirmed test run:

```text
11 passed
```

## Live Snapshot Results

The implementation was exercised against live snapshot `2026-03-15-batch-03`.

After rebuilding puzzle tables:

- `actor_candidates_v1`: 56
- `malware_candidates_v1`: 235
- `technique_candidates_v1`: 691
- `timeline_candidates_v1`: 17

After running:

```powershell
python -m threatdle generate-puzzle-range --snapshot-id 2026-03-15-batch-03 --start-day 2026-03-16 --days 30 --theme-mode prefer
```

Results:

- `puzzle_day`: 120 rows
- generated date range: `2026-03-16` through `2026-04-14`
- actor repeat-window violations: `0`

Observed behavior:

- early days were fully themed because the cross-linkable actor pool was still available
- later days fell back to independent mode selection as repeat windows exhausted the small themed pool

This is expected given the current timeline corpus and the relatively small number of fully cross-linkable actors.

## Operational Notes

### When to rerun `build-puzzle-tables`

Rerun it whenever:

- a new snapshot becomes ready
- curated flows change
- override files change
- candidate eligibility logic changes

The generator assumes candidate tables are current for the target snapshot.

### Snapshot discipline

Always generate from an explicit `snapshot_id`.

The generator is not tied to "latest" implicitly. That is intentional. Daily puzzle output should be reproducible against the exact source snapshot used to generate it.

### Preview vs production

Use `preview-puzzle-day` first when checking clue quality or theme coherence.

Use `generate-puzzle-day` or `generate-puzzle-range` only when you actually want rows written into `puzzle_day`.

## Known Limitations

### Themed pool is still small

Themed generation is constrained by the number of actors that currently have:

- a valid actor candidate
- a timeline candidate
- at least one malware candidate
- at least one technique candidate

That pool is enough for prototyping, but not enough for endless fully themed daily generation.

### Malware clue quality varies

Most malware candidates are tier 2, meaning they rely on ATT&CK description fallback instead of a hand-authored override summary. They are usable, but not as clean as curated one-line summaries.

### Timeline pool is still shallow

Timeline mode works, but the total actor-attributed timeline pool is still modest. Additional curated flows will improve themed-day durability and timeline replayability.

### The generator writes data, not gameplay logic

This implementation does not handle:

- guess validation APIs
- scoring
- share-string generation
- frontend rendering

It only bakes the daily answer and clue payloads.

## Recommended Next Steps

1. Review the first 7 generated days manually for clue quality.
2. Add malware overrides for the most visible answers so more tier 1 summaries exist.
3. Expand curated timelines with Batch 04 and reserve incidents.
4. Build the runtime puzzle-evaluation layer that compares guesses against `answer_json`.

## Quick Reference

Rebuild candidate tables for the active snapshot:

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle build-puzzle-tables --snapshot-id 2026-03-15-batch-03
```

Preview one day:

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle preview-puzzle-day --snapshot-id 2026-03-15-batch-03 --day-key 2026-03-16 --theme-mode prefer
```

Generate one day:

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle generate-puzzle-day --snapshot-id 2026-03-15-batch-03 --day-key 2026-03-16 --theme-mode prefer
```

Generate 30 days:

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle generate-puzzle-range --snapshot-id 2026-03-15-batch-03 --start-day 2026-03-16 --days 30 --theme-mode prefer
```
