# Curated Flow Contract

Each file in this directory must be a valid JSON STIX bundle that follows the minimal contract below.

Required objects:
- One `attack-flow` object with a stable `id`, `name`, and at least one `external_references[].url`
- Exactly one `intrusion-set` object with a MITRE ATT&CK group external ID such as `G0016`
- Three to eight `attack-action` objects
- `relationship` objects that define a linear chain

Required relationships:
- One `relationship` with `relationship_type = "attributed-to"` linking the `attack-flow` object to the actor object
- One `relationship` with `relationship_type = "effect"` linking the `attack-flow` object to the first `attack-action`
- One `relationship` with `relationship_type = "effect"` between each adjacent pair of `attack-action` objects

Required action fields:
- `type = "attack-action"`
- `id`
- `name`
- `technique_id` containing a MITRE ATT&CK technique or sub-technique ID such as `T1566.001`
- Do not use `technique_ref`. The handoff contract requires `technique_id` only.

Intentionally unsupported in V1:
- `.afb` project files
- `attack-asset`
- `attack-condition`
- `attack-operator`
- branching graphs

Validation expectations:
- Keep flows linear, actor-attributed, and puzzle-friendly.
- Prefer 4-7 steps, but 3-8 is the hard limit.
- Every `technique_id` must exist in Enterprise ATT&CK `v18.1`.
- Avoid overlap with existing flows. If a new ordered ATT&CK chain overlaps more than 60% with an existing flow, skip it unless the incident remains clearly distinct and you can justify it in batch notes.

Existing live corpus:
- `solarwinds_apt29.json`: `T1195.002 -> T1059.001 -> T1003 -> T1021`
- `notpetya_sandworm.json`: `T1195.002 -> T1105 -> T1210 -> T1486`
- `wannacry_lazarus.json`: `T1210 -> T1105 -> T1490 -> T1486`
- `hafnium_exchange.json`: `T1190 -> T1505.003 -> T1059.001 -> T1003`
- `apt28_dnc.json`: `T1566.001 -> T1047 -> T1055 -> T1105`
