# Publishable Entry Rules

This document records what currently qualifies as a publishable actor-based puzzle entry, how that differs from broader materialized candidate tables, and the main lessons learned from the recent backfill work.

Phase 4 timeline play is no longer part of the live daily game. Timeline and exact-incident data may still exist internally for provenance and validation, but published days now use only the first 3 phases.

## Current product definition

The current scalable gameplay model is an actor-based 3-phase day:

1. Phase 1: Advanced Persistent Threat Identification
2. Phase 2: Malware Identification
3. Phase 3: Tactics, Techniques, and Procedures Identification

Under this model, a publishable entry means an actor can support all 3 phases without missing Phase 1 clue data.

## Strict publishable rule

An actor is considered publishable for the current 3-phase game only if all of the following are true:

- `country_code` is present
- `first_observed_year` is present
- `target_categories` is non-empty
- `motivation_tags` is non-empty
- `malware_count >= 1`
- `technique_count >= 3`

This is the strict rule used by the backfill reports to measure the real playable pool.

In code:

- Phase 1 completeness is defined in [_has_complete_actor_phase_one_clues](/C:/Users/Home/Threatdle/src/threatdle/services/puzzle_views.py#L27).
- The reporting-side strict pool check is implemented in [actor_backfill_report.py](/C:/Users/Home/Threatdle/src/threatdle/services/actor_backfill_report.py#L126).

As of snapshot `2026-03-15-backfill-04`, that strict rule yields:

- `135` actors with enough Phase 2 and Phase 3 relationship data
- `88` publishable actors
- `10` actors one field away, all missing only `country`

Reference report:

- [actor_backfill_report.json](/C:/Users/Home/Threatdle/data/snapshots/2026-03-15-backfill-04/reports/actor_backfill_report.json)

## Candidate table alignment

`actor_candidates_v1` now follows the same strict publishable rule as the live 3-phase game.

An actor is inserted into `actor_candidates_v1` only if it has:

- complete Phase 1 clues
- `1+` malware relationships
- `3+` technique relationships

That logic is materialized in [puzzle_views.py](/C:/Users/Home/Threatdle/src/threatdle/services/puzzle_views.py).

This means the baked daily puzzle pool now matches the strict actor-based 3-phase playable pool instead of a looser candidate definition.

## Lessons learned

### 1. The main bottleneck is Phase 1 metadata, not ATT&CK relationship coverage

ATT&CK already provides enough malware and technique relationships for many more actors than the UI can publish.

The limiting fields were:

- `target_categories`
- `motivation_tags`
- `country_code`
- `first_observed_year`

Backfilling those fields increased the publishable pool much faster than adding more malware or technique sources.

### 2. `target_categories` and `motivation_tags` were the highest-yield fields to backfill first

The fastest growth came from actors that already had:

- country
- year
- malware
- techniques

but were missing only targets and motivation.

That tranche alone moved the pool from `42` to `72`.

### 3. Country remained the most stubborn unresolved field

After tranche 2, the remaining near-ready actors are all blocked only by country attribution.

This confirms that:

- country should be treated conservatively
- unknown origin should remain valid data when supported
- the UI must handle `UN` cleanly instead of forcing fake flags

### 4. Exact incident chaining is much harder than actor-based gameplay

ATT&CK campaigns are strong for actor, software, and technique relationships, but they are weak as a direct source of incident-ordered chronology.

That means:

- exact incident mode is still content-constrained
- actor-based 3-phase gameplay is the practical scaling path today

### 5. Sophos-style actor profiles are helpful enrichment, not a primary eligibility multiplier

The Sophos threat-profile JSON was useful for:

- alias resolution
- objective hints
- occasional country hints

But it did not materially expand the playable pool by itself. It worked best as a review aid layered on top of ATT&CK-derived actor descriptions.

### 6. Manual review is still required for high-quality publishing

Heuristic extraction is useful for triage, but not safe enough to bulk-seed without review.

Common failure modes were:

- inferring the wrong country from vague regional language
- treating ransomware as financial motivation when the reported use was destructive cover
- generating overly broad target categories from generic terms like "organizations"

The best workflow is:

1. generate tranche reports
2. review them manually
3. seed only curated rows into `actor_overrides.csv`
4. rebuild the snapshot and remeasure

## Current bottlenecks after tranche 2

On snapshot `2026-03-15-backfill-04`, the remaining blockers are:

- `10` actors missing only `country`
- `37` actors still not software/TTP ready:
  - `23` with no malware link
  - `10` with fewer than `3` techniques
  - `4` with neither

So the next highest-yield path is:

1. resolve the remaining country-only actors where defensible
2. then expand malware coverage for actors with strong Phase 1 metadata but no malware support
