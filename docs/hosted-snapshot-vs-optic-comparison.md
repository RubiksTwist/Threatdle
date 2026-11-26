# Hosted Snapshot vs Local Optic Postgres Comparison

Generated: `2026-04-27T15:59:24+00:00`
Hosted snapshot: `2026-03-19-live-mainpush`
Threatdle SQLite: `D:\Threatdle\data\processed\threatdle.db`
Optic Postgres container: `optic-postgres`

## Summary

- The hosted runtime bundle points at snapshot `2026-03-19-live-mainpush` and packages `30` puzzle days with `90` rows.
- The three sibling `*-live-*` snapshots share identical source hashes: `true`.
- Threatdle's active enterprise ATT&CK technique set overlaps the Optic enterprise ATT&CK catalog exactly: `691/691`.
- Every Threatdle ATT&CK-mapped actor and malware id is present in Optic: actors `187/187`, malware `696/696`.
- Optic's article corpus observes `440/691` Threatdle active techniques and `78/80` techniques used in Threatdle timelines.

## Hosted Snapshot

- Snapshot status: `ready`
- Created at: `2026-03-20T02:08:17+00:00`
- Ready at: `2026-03-20T02:09:38+00:00`
- Canonical SQLite state matches hosted snapshot: `true`
- Runtime bundle path: `D:\Threatdle\build\runtime\game-data.json`
- Runtime bundle generated_for: `live_runtime`
- Runtime bundle timezone: `America/New_York`

| Source | Ref | Artifact SHA-256 |
| --- | --- | --- |
| attack_stix | 18.1 | f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb |
| attackevals_ael | main | f7b3030efe7fc191c555b16e2cf41408b0aad525c34308991c9bbab2153e347d |
| ctid_emulation_library | master | 0307fb9658b4809bf4ceb56a82f62e20a4b92fee9a7067451db5481c2e574864 |
| curated_flows | curated-v1 | e87228e5e6e75d29e43f8501146f74b331c6e9152476a9017982cefc1f3f6077 |
| misp_threat_actors | main | a03450de134037ff2ea047ff1512d530a5a5f76efc24b58f2caafbdebe19f527 |

| Sibling Snapshot | Status | Actor Candidates | Malware Candidates | Technique Candidates | Timeline Candidates | Campaign Incidents | Puzzle Day Rows |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-03-19-live-archivefix | ready | 0 | 0 | 0 | 0 | 0 | 1005 |
| 2026-03-19-live-local | ready | 0 | 0 | 0 | 0 | 0 | 1092 |
| 2026-03-19-live-mainpush | ready | 88 | 95 | 691 | 71 | 15 | 90 |

| Threatdle Dataset | Count |
| --- | --- |
| Actors | 187 |
| Malware | 696 |
| Techniques (total) | 835 |
| Techniques (active enterprise) | 691 |
| Campaigns | 52 |
| Timelines | 71 |
| Distinct timeline techniques | 80 |

## Local Optic Postgres

- Article window: `2010-07-15` to `2026-03-26`
- Article count: `1671`
- ATT&CK catalog rows: `1294`

| Table | Rows |
| --- | --- |
| article_entity_mentions | 264914 |
| article_extractions | 7631 |
| article_relationships | 33079 |
| article_technique_facts | 46553 |
| articles | 1671 |
| attack_backfill_runs | 0 |
| attack_catalog | 1294 |
| attack_mappings | 184 |
| entities | 39726 |
| entity_aliases | 45984 |
| ingestion_runs | 262 |

| Entity Type | Rows |
| --- | --- |
| ioc | 28640 |
| malware | 4502 |
| technique | 1321 |
| threat_actor | 1308 |
| campaign | 1146 |
| tool | 1140 |
| cve | 944 |
| victim_sector | 424 |
| victim_country | 175 |
| victim_region | 108 |
| service | 18 |

| ATT&CK Domain | Total Rows | Active Rows |
| --- | --- | --- |
| enterprise | 835 | 691 |
| ics | 95 | 83 |
| mobile | 190 | 124 |
| pre-attack | 174 | 0 |

| Vendor | Articles |
| --- | --- |
| Unit 42 | 433 |
| Google/Mandiant | 402 |
| Cisco Talos | 293 |
| Microsoft Security | 281 |
| CrowdStrike | 147 |
| Sophos | 115 |

## Overlap

### ATT&CK Techniques

- Threatdle active enterprise ATT&CK ids: `691`
- Optic active enterprise ATT&CK ids: `691`
- Exact overlap: `691`
- Optic article facts cover `440/691` Threatdle active techniques (`63.7%`).
- Threatdle timeline techniques covered by Optic article facts: `78/80` (`97.5%`).
- Threatdle active techniques missing from Optic article facts: `251`. Sample: `T1001, T1001.001, T1001.002, T1001.003, T1003.007, T1011, T1011.001, T1016.002, T1020.001, T1021.003, T1021.008, T1025, T1027.007, T1027.011, T1027.014, T1027.015, T1027.016, T1027.017, T1029, T1036.002`.
- Optic article facts include one enterprise technique outside Threatdle's active set: `T1574.002`.
- Threatdle timeline techniques missing from Optic article facts: `T1505.002, T1561.002`.

### ATT&CK Threat Actors

- Threatdle ATT&CK-mapped actors: `187`
- Optic ATT&CK-mapped threat actors: `191`
- Exact ATT&CK id overlap: `187`
- Threatdle actor ids missing from Optic: `0`
- Optic-only ATT&CK actor ids: `G0097, G1000, G1027, G1029`

| Optic-Only Actor | ATT&CK ID |
| --- | --- |
| Bouncing Golf | G0097 |
| ALLANITE | G1000 |
| CyberAv3ngers | G1027 |
| UNC788 | G1029 |

### ATT&CK Malware

- Threatdle ATT&CK-mapped malware: `696`
- Optic ATT&CK-mapped malware: `821`
- Exact ATT&CK id overlap: `696`
- Threatdle malware ids missing from Optic: `0`
- Optic-only ATT&CK malware ids: `125`

| Optic-Only Malware Sample | ATT&CK ID |
| --- | --- |
| OldBoot | S0285 |
| OBAD | S0286 |
| ZergHelper | S0287 |
| KeyRaider | S0288 |
| Pegasus for iOS | S0289 |
| Gooligan | S0290 |
| PJApps | S0291 |
| AndroRAT | S0292 |
| BrainTest | S0293 |
| ShiftyBug | S0294 |

### Campaigns

- Threatdle campaigns: `52`
- Optic campaign entities: `1146`
- Optic ATT&CK campaign ids captured in schema: `0`
- Exact campaign name overlap: `4`. Sample: `3CX Supply Chain Attack, ArcaneDoor, Operation Dream Job, Operation MidnightEclipse`.

## Interpretation

- The hosted Threatdle snapshot is a curated, ATT&CK-pinned gameplay dataset built from five source artifacts and materialized into puzzle-oriented tables.
- The local Optic Postgres database is a broader article-derived CTI corpus with vendors, articles, mentions, relationships, IOCs, and a larger long-tail of extracted campaign and malware entities.
- Threatdle is not missing any ATT&CK actor or malware ids that Optic already maps for the shared core set. The main breadth gaps are Optic's extra ATT&CK-mapped malware families and four additional ATT&CK-mapped threat actors.
- The strongest practical alignment is on enterprise ATT&CK techniques: the reference catalogs match exactly, and almost all timeline techniques used by Threatdle already appear in Optic article facts.
- Campaign comparison is structurally limited because Optic's campaign entities do not currently store ATT&CK campaign ids, so campaign parity can only be approximated by name matching.
