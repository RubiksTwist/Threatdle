# Curated Flow Handoff Prompt

Use this prompt with another model that has web access and write access to this repo.

## Ready-To-Use Prompt

You are authoring curated timeline flows for Threatdle.

Write files directly into `C:\Users\Home\Threatdle\data\curated-flows\` and write one manifest per batch into `C:\Users\Home\Threatdle\data\curated-flows\_manifests\`.

Do not change any code.

### Output Rules

- Write files directly.
- One flow per file.
- No markdown fences around JSON.
- Keep response prose minimal: only list created filenames and skipped items with reasons.
- Write one manifest per batch:
  - `batch-01.json`
  - `batch-02.json`
  - `batch-03.json`
  - `batch-04.json`
  - `batch-reserve.json`

### Flow Contract

- Valid STIX `2.1` bundle.
- Exactly one `attack-flow` object.
- Exactly one `intrusion-set` object with a real Enterprise ATT&CK `v18.1` group external ID.
- `3-8` `attack-action` objects, linear only.
- One `attributed-to` relationship from `attack-flow` to `intrusion-set`.
- One `effect` relationship from `attack-flow` to the first `attack-action`.
- One `effect` relationship between each adjacent pair of `attack-action` objects.
- Each `attack-action` must include:
  - `type`
  - `id`
  - `name`
  - `technique_id`
- Do not use `technique_ref`.
- Every `technique_id` must be a real Enterprise ATT&CK `v18.1` ID.
- Prefer `4-7` steps; `3-8` is the hard limit.

### Manifest Contract

Each manifest is a JSON array of objects with:
- `filename`
- `incident_name`
- `actor_attack_id`
- `actor_name`
- `primary_sources`
- `technique_chain_source`
- `expected_attack_ids`
- `expected_step_count`
- `author_notes`
- `status`

Rules:
- `expected_attack_ids` is the ground truth and must be authored first from source review, then the JSON must be built to match it.
- `status` must be `accepted` or `skipped`.
- If skipped, explain why in `author_notes`.

### Duplicate/Overlap Rule

Before accepting a new flow, compare its ordered ATT&CK ID list against:
- all existing curated flows already in `data/curated-flows`
- all newly authored flows in the same batch

Compute:

`ordered_overlap = LCS(candidate_ids, existing_ids) / min(len(candidate_ids), len(existing_ids))`

Skip the flow if `ordered_overlap > 0.60`, unless the incident is intentionally paired and still clearly distinct in objective and terminal behavior. Any kept borderline case must be justified in `author_notes`.

### Existing Live Corpus

Use these as the overlap baseline:

- `solarwinds_apt29.json`: `T1195.002 -> T1059.001 -> T1003 -> T1021`
- `notpetya_sandworm.json`: `T1195.002 -> T1105 -> T1210 -> T1486`
- `wannacry_lazarus.json`: `T1210 -> T1105 -> T1490 -> T1486`
- `hafnium_exchange.json`: `T1190 -> T1505.003 -> T1059.001 -> T1003`
- `apt28_dnc.json`: `T1566.001 -> T1047 -> T1055 -> T1105`

Use `C:\Users\Home\Threatdle\data\curated-flows\solarwinds_apt29.json` as the gold-format template.
Use `C:\Users\Home\Threatdle\data\curated-flows\README.md` and `C:\Users\Home\Threatdle\data\curated-flows\_manifests\README.md` as the contract docs.

### Batch Backlog

Batch 01:
- `sony_lazarus.json` using `G0032` `Lazarus Group`
- `bangladesh_bank_lazarus.json` using `G0032` `Lazarus Group`
- `shamoon_apt33.json` using `G0064` `APT33`
- `singhealth_whitefly.json` using `G0107` `Whitefly`

Batch 02:
- `cloud_hopper_menupass.json` using `G0045` `menuPass` (`APT10`)
- `cobalt_kitty_apt32.json` using `G0050` `APT32` (`OceanLotus`)
- `turla_carbon.json` using `G0010` `Turla`
- `turla_snake.json` using `G0010` `Turla`

Batch 03:
- `fin7_hospitality.json` using `G0046` `FIN7`
- `fin6_pos_intrusion.json` using `G0037` `FIN6`
- `carbanak_bank_intrusion.json` using `G0008` `Carbanak`
- `cobalt_group_bank_intrusion.json` using `G0080` `Cobalt Group`

Batch 04:
- `oilrig_campaign.json` using `G0049` `OilRig` (`APT34`)
- `apt41_supply_chain.json` using `G0096` `APT41`
- `apt1_economic_espionage.json` using `G0006` `APT1`
- `whispergate_sandworm.json` using `G0034` `Sandworm Team`

Reserve batch, only if a required item is skipped:
- `mustang_panda_espionage.json` using `G0129` `Mustang Panda`
- `blacktech_router_intrusion.json` using `G0098` `BlackTech`
- `industroyer2_sandworm.json` using `G0034` `Sandworm Team`
- `apt29_vaccine_targeting.json` using `G0016` `APT29`

### Source Priority

Use sources in this order:
1. ATT&CK group/campaign pages
2. CISA advisories
3. CTID evaluation materials
4. High-confidence vendor reports only if the first three are insufficient

### Skip Rules

Skip a flow if any of these are true:
- no defensible `3-8` step ordered chain from public sources
- no valid ATT&CK `v18.1` actor group ID
- overlap above `0.60`
- technique IDs cannot be verified against Enterprise ATT&CK `v18.1`

### Human Validation Workflow

After each batch, the human reviewer will run:

```powershell
$env:PYTHONPATH='C:\Users\Home\Threatdle\src'
python -m threatdle fetch-sources --snapshot-id <batch-id>
python -m threatdle ingest-all --snapshot-id <batch-id>
```

The batch is accepted only if:
- the snapshot is `ready`
- `timeline_sequences_v1` increases by the number of accepted manifest entries
- there are no `unresolved_matches` rows with `source_name = 'curated_flows'`
- spot-checking confirms the ordered technique chains

### Important Notes

- Do not change the existing 5 curated flows.
- `apt1_economic_espionage.json` is deliberately generic and not tied to OPM.
- Keep files puzzle-friendly: linear, attributable, and not overloaded with unnecessary STIX objects.

## Intended Usage

- Give the other model this document.
- Also attach:
  - [README.md](C:/Users/Home/Threatdle/data/curated-flows/README.md)
  - [solarwinds_apt29.json](C:/Users/Home/Threatdle/data/curated-flows/solarwinds_apt29.json)
  - [README.md](C:/Users/Home/Threatdle/data/curated-flows/_manifests/README.md)
