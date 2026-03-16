# Threatdle Database Decision

Recorded on: 2026-03-15

## Question

Should Threatdle expand the pre-existing database from the earlier APT next-step prediction project, or start a new database that only ingests data relevant to Threatdle?

## Decision

Start a new Threatdle-specific database.

Do not reuse the old prediction database as the primary product database.

The older database can still be useful as a reference for source discovery, sample queries, and one-off exports, but it should not define the core schema for Threatdle.

## Why A Fresh Database Is Better

The old project optimized for sequence prediction:

- ordered edges
- transition counts
- flow graphs
- next-step inference

Threatdle needs a different shape of data:

- rich clue attributes on actors
- rich clue attributes on malware
- technique metadata for comparison gameplay
- campaign sequences that are understandable to players

Those are different product requirements, and forcing puzzle logic into a prediction-oriented schema will create unnecessary complexity and maintenance debt.

There are also practical reasons not to reuse the old database directly:

- some extraction tables were empty
- some report linkages were fuzzy
- some sequence inputs were not fully reproducible
- large parts of the schema are only relevant to modeling, not gameplay

## What Threatdle Actually Needs

### Actor Guessing

Threat actor records should include clue-ready fields such as:

- actor id
- actor name
- aliases
- country or suspected origin
- target sectors
- motivation
- first observed year
- associated malware
- associated techniques
- associated campaigns

### Malware Guessing

Malware records should include:

- malware id
- malware name
- aliases
- family or category
- platform
- capability summary
- actor associations
- technique associations
- campaign associations

### TTP Mode

Technique records should include:

- ATT&CK id
- technique name
- tactic
- platform
- subtechnique flag
- parent technique
- short description

### Campaign / Timeline Mode

Sequence-ready campaign records should include:

- campaign id
- campaign name
- linked actor
- linked malware
- linked techniques
- ordered technique steps where available
- campaign year or time range
- source provenance

## Recommended Source Stack

### Core Sources

- MITRE ATT&CK STIX bundle
- Attack Flow corpus

### Supporting Sources

- structured actor profile data layered on top of ATT&CK
- malware metadata source for family, category, and platform clues

### Optional Later Sources

- ATT&CK Evaluations or adversary emulation plans for more sequence material
- selected advisory/report sources if they can be normalized cleanly

## V1 Recommendation

Skip APTnotes and broad report extraction for the first version.

Threatdle does not need a report corpus to function, and the older report layer was not reliable enough to justify carrying it into the initial game database.

## Suggested Database Shape

A Threatdle-specific schema should center on a small set of puzzle-oriented tables:

- `actors`
- `actor_aliases`
- `malware`
- `malware_aliases`
- `techniques`
- `campaigns`
- `actor_techniques`
- `actor_malware`
- `campaign_techniques`
- `campaign_actors`
- `campaign_malware`
- `sequence_steps`
- `source_references`

The design goal should be clue generation and puzzle validation, not prediction.

## Bottom Line

Threatdle should start with a new database built specifically for puzzle generation.

Use the older prediction project as a source of lessons and possibly raw extracts, but not as the product schema.
