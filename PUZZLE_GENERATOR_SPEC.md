# Threatdle — Puzzle Generator Spec

_Status: Implemented. Last revised: 2026-03-15. Rev 4 — synced to match implemented state._

This document is the design spec for the puzzle generation engine. For the authoritative implementation reference, see `docs/puzzle-generator-implementation.md`. This spec preserves the original design decisions and rationale; `docs/puzzle-generator-implementation.md` describes the code as built.

---

## 0. Context and Constraints

Before designing anything, understand the current state of the codebase:

**What exists and works:**
- Full ingest pipeline through `build-puzzle-tables` (all 7 steps documented in `docs/architecture.md`)
- All eight puzzle materialization tables are populated: `actor_profiles_v1`, `actor_candidates_v1`, `malware_profiles_v1`, `malware_candidates_v1`, `technique_profiles_v1`, `technique_candidates_v1`, `timeline_sequences_v1`, `timeline_candidates_v1`
- `puzzle_day` is populated by the generator (4 rows per day)

**Implementation status:** All steps in Section 9 are complete. `schema.py`, `puzzle_views.py`, `puzzle_generator.py`, and `cli.py` have been implemented. `test_ingest_pipeline.py` covers candidate table changes. `tests/test_puzzle_generator.py` has 11 passing tests covering determinism, repeat windows, strict-theme failure, malware tiering, preview no-write, and technique quality gating. The 30-day preview run (Step 9) has been executed against `2026-03-15-batch-03` producing 120 `puzzle_day` rows. Manual review (Step 10) is pending.

**Corpus reality:** With the current batch-03 snapshot, full cross-mode linkage (actor has a timeline, a malware, and a technique) exists for approximately 7 actors: APT28, APT29, APT32, APT33, Sandworm Team, Turla, and menuPass. This is the **themed-day eligible pool**. It is enough for prototype generation but not for strict daily theming across a long horizon. The default must be `prefer`, not `strict`.

---

## 1. Schema Changes

Two new tables were added to `schema.py`.

### 1.1 `malware_candidates_v1`

```sql
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
```

`summary_tier` is `1` when the candidate has an override-backed `capability_summary`, `2` when it qualifies via the description fallback. The generator uses this to prefer Tier 1 answers.

### 1.2 `technique_candidates_v1`

```sql
CREATE TABLE IF NOT EXISTS technique_candidates_v1 (
    snapshot_id TEXT NOT NULL,
    technique_id INTEGER NOT NULL,
    answer_key TEXT NOT NULL,
    answer_label TEXT NOT NULL,
    PRIMARY KEY (snapshot_id, technique_id),
    FOREIGN KEY (snapshot_id) REFERENCES snapshots(snapshot_id),
    FOREIGN KEY (technique_id) REFERENCES techniques(technique_id) ON DELETE CASCADE
);
```

Both tables must be added to the `PUZZLE_TABLES` list in `schema.py` so `clear_puzzle_tables_for_snapshot` clears them on a re-run.

**Design rationale:** These tables mirror `actor_candidates_v1` and `timeline_candidates_v1`. Keeping them in the same pattern means the generator can query all four candidate tables with the same join style. They do not need a `clue_score` column because eligibility for malware and technique is binary (pass/fail a set of rules), not a numeric threshold.

---

## 2. Candidate Eligibility Rules

These rules are applied inside `build_puzzle_tables` in `puzzle_views.py`, immediately after the profile tables are populated. They define which rows from each profile table graduate to the candidate table.

### 2.1 Malware eligibility

Malware eligibility uses a **tiered model**. A malware row must meet a shared baseline, then qualify through either Tier 1 or Tier 2.

**Shared baseline (all required):**
1. At least one platform in `platforms_json`.
2. At least one linked actor in `actor_malware`.

**Tier 1 — override-backed (preferred):**
3a. `malware.capability_summary` is not null and not empty. This is the column set by `malware_overrides.csv`, not the ATT&CK `description` fallback.

**Tier 2 — description fallback (acceptable):**
3b. `malware.capability_summary` is null, **but** `malware.description` is between 50 and 300 characters (inclusive, after `trim()`).

Rows that fail both tiers (no override and description is either missing, too short, or too verbose) are excluded.

The candidate table must store a `summary_tier` column (`INTEGER NOT NULL`, value `1` or `2`) so the generator can prefer Tier 1 answers when both are available during selection.

**Design rationale:** The live snapshot currently has 0 malware rows with an override-backed `capability_summary`. A strict override-only rule would produce an empty candidate pool and block generator rollout entirely. The tiered approach gives us ~200+ usable candidates immediately (Tier 2) while preserving the signal that override-curated summaries are higher quality. During themed selection, the generator should prefer Tier 1 candidates when they exist for the anchor actor, falling back to Tier 2 within the same actor's pool before falling back to independent selection.

**Important:** The `malware_profiles_v1` payload already stores `capability_summary or description`. The candidate eligibility check must read the raw `malware.capability_summary` and `malware.description` columns separately to distinguish tiers — do not rely on the profile payload for this check.

### 2.2 Technique eligibility

A technique row is eligible if **all** of the following are true:

1. At least one tactic in `tactics_json`.
2. At least one platform in `platforms_json`.
3. Not revoked, not deprecated (already filtered in the profile query).

**No subtechnique exclusion.** The plan mentioned "keep subtechniques allowed" — this is correct. Subtechniques are often the interesting, specific answer. Excluding them would reduce pool quality.

**Design rationale:** The technique pool across all of ATT&CK is very large (hundreds of rows). The eligibility bar is intentionally low because the quality gate at generation time (described in Section 6) does the heavier filtering. The candidate table just ensures no obviously broken rows (no tactic, no platform) enter the pool.

---

## 3. `puzzle_day` Row Shape

The existing schema is:

```sql
puzzle_day (day_key TEXT, snapshot_id TEXT, mode TEXT, payload_json TEXT, answer_json TEXT, created_at TEXT)
PRIMARY KEY (day_key, mode)
```

Each generate run writes exactly **4 rows** per `day_key`, one per mode: `actor`, `malware`, `technique`, `timeline`.

### 3.1 `payload_json` — what the UI receives

`payload_json` contains only what is needed to render the puzzle. It must never contain the answer.

**Actor mode:**
```json
{
  "mode": "actor",
  "clues": {
    "country_code": "RU",
    "first_observed_year": 2014,
    "target_categories": ["Government", "Defense"],
    "motivation_tags": ["Espionage"],
    "malware_count": 8,
    "campaign_count": 3,
    "technique_count": 42
  }
}
```

**Malware mode:**
```json
{
  "mode": "malware",
  "clues": {
    "platforms": ["Windows"],
    "malware_category": "Supply Chain",
    "capability_summary": "Supply chain backdoor that modifies SolarWinds Orion updates",
    "aliases": ["Solorigate"],
    "actor_count": 1
  }
}
```

Note: `actor_names` are **not** in the payload. Listing the actor name would trivially reveal the answer on a themed day. Use counts only.

**Technique mode:**
```json
{
  "mode": "technique",
  "clues": {
    "tactics": ["Execution"],
    "platforms": ["Windows", "Linux", "macOS"],
    "is_subtechnique": true,
    "parent_name": "Command and Scripting Interpreter"
  }
}
```

Note: `attack_id` is **not** in the payload — it is the answer key.

**Timeline mode:**
```json
{
  "mode": "timeline",
  "clues": {
    "step_count": 4,
    "steps": [
      {"step_index": 1, "technique_name": "Supply Chain Compromise: Compromise Software Supply Chain"},
      {"step_index": 2, "technique_name": "Command and Scripting Interpreter: PowerShell"},
      {"step_index": 3, "technique_name": "OS Credential Dumping"},
      {"step_index": 4, "technique_name": "Remote Services"}
    ]
  }
}
```

Note: `attack_id` values for each step are **not** in the payload. Technique names only.

**Step indexing is 1-based.** The ingest pipeline stores `timeline_steps.step_index` starting at 1, and `timeline_sequences_v1.steps_json` carries those values through. The generator must preserve this convention. Do not convert to 0-based.

### 3.2 `answer_json` — hidden, used for judging

`answer_json` contains the hidden answer plus the comparison vector the server uses to evaluate guesses. The UI never receives this directly.

**Actor mode:**
```json
{
  "answer_key": "G0016",
  "answer_label": "APT29",
  "comparison": {
    "country_code": "RU",
    "first_observed_year": 2014,
    "target_categories": ["Government", "Defense"],
    "motivation_tags": ["Espionage"],
    "malware_count": 8,
    "campaign_count": 3,
    "technique_count": 42
  }
}
```

**Malware mode:**
```json
{
  "answer_key": "S0559",
  "answer_label": "SUNBURST",
  "comparison": {
    "platforms": ["Windows"],
    "malware_category": "Supply Chain",
    "aliases": ["Solorigate"],
    "actor_names": ["APT29"]
  }
}
```

`actor_names` lives in the answer, not the payload. It is used for post-solve reveal, not for judging.

**Technique mode:**
```json
{
  "answer_key": "T1059.001",
  "answer_label": "PowerShell",
  "comparison": {
    "tactics": ["Execution"],
    "platforms": ["Windows", "Linux", "macOS"],
    "is_subtechnique": true,
    "parent_attack_id": "T1059",
    "parent_name": "Command and Scripting Interpreter"
  }
}
```

**Timeline mode:**
```json
{
  "answer_key": "G0016",
  "answer_label": "APT29",
  "answer_type": "actor",
  "comparison": {
    "steps": [
      {"step_index": 1, "attack_id": "T1195.002", "technique_name": "Compromise Software Supply Chain"},
      {"step_index": 2, "attack_id": "T1059.001", "technique_name": "PowerShell"},
      {"step_index": 3, "attack_id": "T1003",     "technique_name": "OS Credential Dumping"},
      {"step_index": 4, "attack_id": "T1021",     "technique_name": "Remote Services"}
    ]
  }
}
```

The `attack_id` values for each step live in the answer only. Step indices are 1-based, matching the pipeline convention.

---

## 4. Selection Strategy

### 4.1 Determinism

**This is a hard requirement.** The same `(snapshot_id, day_key)` must always produce the same 4 answers.

Determinism uses a **two-level seed model**:

**Day-level seed:** `hashlib.sha256(f"{snapshot_id}:{day_key}".encode()).digest()` → `random.Random` instance. This seed is used for anchor actor selection in themed mode. All four modes share this seed for any decision that must be coordinated across modes (anchor selection, theme eligibility checks).

**Mode-level seed:** `hashlib.sha256(f"{snapshot_id}:{day_key}:{mode}".encode()).digest()` → separate `random.Random` instance per mode. This seed is used for all within-mode decisions: choosing the specific answer from the filtered candidate pool, breaking ties, and fallback selection.

**Why two levels:** Themed selection requires one shared anchor actor across all 4 modes. If each mode used only its own seed, the anchor would need to be derived independently per mode — and there is no guarantee the same actor would be chosen four times. The day-level seed picks the anchor once; the mode-level seeds then independently select answers from the anchor-filtered (or fallback) pools.

Do not use global `random` state anywhere in the generator.

### 4.2 Repeat windows

Repeat windows prevent the same answer from appearing twice within a rolling window of days. The source of truth is the existing `puzzle_day` table.

| Mode | Window |
|---|---|
| actor | 14 days |
| timeline | 21 days |
| malware | 21 days |
| technique | 10 days |

To check: query `puzzle_day` for all `answer_key` values where `mode = ?` and `day_key >= (day_key minus window days)`. Exclude those keys from the candidate pool before selecting.

**Design decision:** Do not create a separate repeat-tracking table. `puzzle_day` already has all the information needed. A simple date arithmetic query on `day_key` (which is a `YYYY-MM-DD` string, so lexicographic comparison works) is sufficient.

**Implementation note:** The `answer_key` lives inside `answer_json`, not as a top-level column. The repeat-window query must extract it via `json_extract(answer_json, '$.answer_key')`. SQLite's JSON1 extension supports this. Example: `SELECT json_extract(answer_json, '$.answer_key') AS answer_key FROM puzzle_day WHERE mode = ? AND day_key >= ?`.

**Soft-fallback behavior:** If every candidate in a mode's pool falls within the repeat window, the implementation falls back to the full unfiltered pool rather than raising an error. This means repeat avoidance is best-effort, not strict. This is the correct trade-off for small pools (e.g., technique with only 10-day window against a limited themed subset). It ensures generation never fails due to pool exhaustion, at the cost of an occasional repeat. The 30-day preview run (Step 9) should quantify how often this triggers.

### 4.3 Themed selection (`theme_mode=prefer`)

The cross-linkable pool is computed at generation time by querying which actors simultaneously have:
- An entry in `actor_candidates_v1` for this snapshot
- At least one entry in `timeline_candidates_v1` where `answer_key = actor.attack_group_id`
- At least one linked malware that is in `malware_candidates_v1`
- At least one linked technique that is in `technique_candidates_v1`

**Do not hard-code the 7 actor names.** Compute this dynamically from the snapshot. The pool will grow as more flows and overrides are added.

Themed selection proceeds as follows:

1. Build the cross-linkable actor pool (excluding actors in the repeat window).
2. If the pool is empty, fall back to independent selection for all four modes.
3. Otherwise, seed-select an anchor actor from the pool.
4. For the **timeline** mode: filter `timeline_candidates_v1` to entries where `answer_key = anchor.attack_group_id`. If multiple timelines exist, seed-select one. If none pass quality gates, fall back to independent timeline selection.
5. For the **malware** mode: get malware linked to the anchor actor via `actor_malware`, intersect with `malware_candidates_v1`, exclude repeat window. Seed-select one. If none, fall back to independent malware selection.
6. For the **technique** mode: get techniques linked to the anchor actor via `actor_techniques`, intersect with `technique_candidates_v1`, exclude repeat window. Apply quality gate (see Section 6). Seed-select one. If none, fall back to independent technique selection.
7. Any mode that falls back to independent selection is still deterministic (same seed, just drawing from the full pool instead of the anchor-filtered pool).

**`theme_mode=strict`:** Same algorithm, but if steps 4–6 all have candidates, the set is accepted. If any of the four modes cannot be filled from the anchor's pool, raise an error rather than falling back. This mode is intended for testing and debugging, not production use.

**`theme_mode=off`:** Skip steps 1–3 entirely. All four modes select independently using deterministic seed.

### 4.4 Timeline preference

Within independent timeline selection (when not themed), prefer `answer_type = 'actor'` rows over `answer_type = 'incident'` rows. Specifically: try the actor-only subset first; if no candidates remain after excluding the repeat window, fall back to the full pool.

---

## 5. CLI Commands

Follow the exact same structure as existing commands in `cli.py`:
- Use `run_with_connection` for all DB operations
- Print `json.dumps(result, indent=2, sort_keys=True)` for machine-readable output
- Return a meaningful result dict from every function

### Implemented commands:

```
generate-puzzle-day
  --snapshot-id   (required) Snapshot to generate from
  --day-key       (required) Date string in YYYY-MM-DD format
  --theme-mode    (optional) off | prefer | strict. Default: prefer
  --force         (optional) If a row already exists for this day+mode, overwrite it.
                  Without --force, raise an error if any of the 4 rows already exist.

generate-puzzle-range
  --snapshot-id   (required)
  --start-day     (required) YYYY-MM-DD
  --days          (required) Integer number of days to generate
  --theme-mode    (optional) Default: prefer
  --force         (optional) Same as above; applied to all days in the range

preview-puzzle-day
  --snapshot-id   (required)
  --day-key       (required)
  --theme-mode    (optional) Default: prefer
  Prints chosen answers and clue sources to stdout. Does NOT write to puzzle_day.
  Output includes: mode, answer_key, answer_label, theme_anchor (if themed), fallback_modes (list of modes that fell back to independent selection).
```

**Critical: `preview-puzzle-day` must never write to the database.** It should call the selection logic with a read-only connection or wrap the transaction and roll it back. The simplest approach is to pass a `dry_run=True` flag through to the generator function and branch before the INSERT.

---

## 6. Quality Gates

Quality gates are evaluated during selection, not during profiling. They are applied to the candidate as it is being chosen, after repeat-window filtering.

### Actor quality gate

An actor candidate is rejected for a given day if **fewer than 2** of the following differentiating fields are present:
- `country_code` is not null
- `first_observed_year` is not null
- `target_categories` has at least 1 item
- `motivation_tags` has at least 1 item

**Rationale:** `clue_score >= 4` is the admission bar to `actor_candidates_v1`. The quality gate here is a secondary check on the clue fields that directly drive the Wordle-style deduction grid. An actor with only `malware_count` and `technique_count` but no profile fields cannot generate a useful deduction grid.

### Malware quality gate

In addition to the candidate eligibility rules in Section 2, reject a malware answer if:
- Its display summary (override `capability_summary` for Tier 1, `description` for Tier 2) is fewer than 20 characters after stripping whitespace. This catches placeholder overrides and stub descriptions.

During themed selection, prefer Tier 1 (`summary_tier = 1`) candidates linked to the anchor actor. If no Tier 1 candidates exist for the anchor, accept Tier 2. During independent (non-themed) selection, mix Tier 1 and Tier 2 freely — the tier is a preference signal, not a hard partition.

### Technique quality gate

Reject a technique candidate if:
- It has fewer than 2 platforms (a technique with only one platform is too easy to narrow down and is less interesting as a puzzle answer)
- **Exception:** subtechniques may have only 1 platform if they have at least 2 tactics

**Rationale:** The technique pool is large. A technique with `platforms: ["Windows"]` and `tactics: ["Execution"]` is a weak puzzle because Windows + Execution covers a huge fraction of techniques. The quality gate pushes toward answers that require more genuine deduction.

### Themed set quality gate

After assembling a themed set, apply a final validation:

Reject the themed set entirely (and regenerate using `theme_mode=off` semantics) if fewer than 3 of the 4 chosen answers can be connected to the anchor actor through their canonical ATT&CK relationships. This catches the edge case where a malware or technique was selected from the actor's linked set but the link was indirect (e.g., via a campaign that was later cleaned up).

---

## 7. Where the Code Lives

Follow the existing module structure. Do not create new top-level packages.

| New file | Purpose |
|---|---|
| `src/threatdle/services/puzzle_generator.py` | Core generation logic: candidate pool loading, deterministic seed selection, themed selection, quality gates, puzzle_day row construction |

**No new modules beyond this one.** The schema changes go in `schema.py`. The candidate population goes in `puzzle_views.py`. The CLI wiring goes in `cli.py`. The generator service is the only new file.

---

## 8. Test Coverage

Tests live in `tests/test_puzzle_generator.py` and use the same fixture/conftest pattern as `test_ingest_pipeline.py`.

Current coverage:

1. **Determinism test:** Generate the same `(snapshot_id, day_key)` twice; assert both calls produce identical `payload_json` and `answer_json` for all 4 modes.

2. **Repeat window test:** Generate days 1 through 15 for actor mode; assert that no `answer_key` appears in both day 1 and day 15 (the window is 14 days).

3. **`theme_mode=strict` failure test:** With a snapshot that has only 1 cross-linkable actor, generate a range long enough to exhaust that actor from the repeat window, then assert that `generate-puzzle-day` with `theme_mode=strict` raises an appropriate error.

4. **Malware candidate eligibility test:** Assert that a malware row with no `capability_summary` override and a `description` longer than 300 characters does not appear in `malware_candidates_v1`. Assert that a malware row with no override but a `description` between 50–300 characters does appear with `summary_tier = 2`. Assert that a malware row with an override appears with `summary_tier = 1`.

5. **`preview-puzzle-day` no-write test:** Run `preview-puzzle-day` and then assert `puzzle_day` is still empty.

6. **Technique quality gate test:** Assert that a technique with only 1 platform and 1 tactic (and not a subtechnique) does not survive the technique quality gate.

---

## 9. Implementation Order

This is the recommended build order. Each step should be independently committed and testable.

1. **Schema + candidate tables.** Add `malware_candidates_v1` and `technique_candidates_v1` to `schema.py`. Add them to `PUZZLE_TABLES`.

2. **Candidate population in `puzzle_views.py`.** Add malware and technique candidate insertion at the end of `build_puzzle_tables`, after the profile inserts, using the eligibility rules from Section 2. Add `malware_candidates` and `technique_candidates` to the returned counts dict. Update the end-to-end test in `test_ingest_pipeline.py` to assert on these new counts.

3. **`puzzle_generator.py` — pool loading.** Implement the functions that load each candidate pool from the DB and apply repeat-window filtering. Write unit tests for pool loading in isolation.

4. **`puzzle_generator.py` — deterministic selection.** Implement seed derivation and seeded selection. Write the determinism test.

5. **`puzzle_generator.py` — themed selection.** Implement the cross-linkable pool query and themed anchor selection. Write the fallback and strict-failure tests.

6. **`puzzle_generator.py` — row assembly.** Implement `payload_json` and `answer_json` construction per the schemas in Section 3. This is straightforward but must be exact — the UI will depend on these shapes.

7. **`puzzle_generator.py` — quality gates.** Add the actor, malware, technique, and themed-set quality gates. Write the quality gate tests.

8. **CLI wiring.** Add `generate-puzzle-day`, `generate-puzzle-range`, and `preview-puzzle-day` to `cli.py`.

9. **30-day preview run.** Run `generate-puzzle-range --snapshot-id <latest> --start-day 2026-03-16 --days 30 --theme-mode prefer` and review the console output before writing batch-04 flows.

10. **Manual review.** Manually inspect the first 7 generated days before resuming batch-04 authoring. If any day produces a weak or confusing themed set, adjust the quality gates and regenerate.

---

## 10. Decisions Not to Revisit

The following decisions were considered and closed. Do not reopen them without a concrete problem.

**Candidate table placement in `puzzle_views.py`, not a separate service.** All four profile+candidate materializations happen in one atomic `build_puzzle_tables` call. Splitting them across two services would make the pipeline non-atomic and complicate re-runs.

**`puzzle_day` as the sole repeat history store.** No new tracking table. `puzzle_day` already carries `day_key`, `mode`, and `answer_key` (inside `answer_json`). A simple query is sufficient.

**No `clue_score` on malware or technique candidates.** Binary eligibility is the right model for these two modes. The actor mode has a numeric score because its gameplay is graded (easy/standard difficulty). Malware and technique modes do not have graded difficulty in V1.

**`--snapshot-id` is required for all generator commands.** The generator is snapshot-aware. There is no concept of a "current snapshot" that would allow omitting it. This follows the same pattern as every other command in the pipeline.

**Technique names (not IDs) in the Timeline puzzle payload.** The step names alone are the puzzle. Showing IDs in the payload would trivially identify techniques and break the game.

**`actor_names` excluded from the Malware puzzle payload.** Including them would make themed days too easy to solve — the malware answer would directly name the actor answer.
