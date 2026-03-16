# Batch Manifest Contract

The curated flow authoring workflow writes one manifest per batch into this directory.

Filename format:
- `batch-01.json`
- `batch-02.json`
- `batch-03.json`
- `batch-04.json`
- `batch-reserve.json`

Each manifest must be a JSON array of objects with these fields:
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
- `expected_attack_ids` is the ground truth and must be authored first from source review, then the STIX JSON must be built to match it.
- `status` must be `accepted` or `skipped`.
- If a flow is skipped, explain why in `author_notes`.
- Keep manifest files in this subdirectory so they are excluded from the current `data/curated-flows/*.json` ingest glob.

Example entry:

```json
{
  "filename": "solarwinds_apt29.json",
  "incident_name": "SolarWinds Intrusion",
  "actor_attack_id": "G0016",
  "actor_name": "APT29",
  "primary_sources": [
    "https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a"
  ],
  "technique_chain_source": "CISA AA21-008A attack sequence summary",
  "expected_attack_ids": [
    "T1195.002",
    "T1059.001",
    "T1003",
    "T1021"
  ],
  "expected_step_count": 4,
  "author_notes": "Linearized from the public incident timeline for gameplay.",
  "status": "accepted"
}
```
