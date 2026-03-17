# Threatdle

Threatdle is a daily cybersecurity deduction game built around advanced persistent threats, malware, and MITRE ATT&CK tradecraft. The project combines a Python ingest and puzzle-generation pipeline with a lightweight browser client so players can infer a threat actor from source-backed clues instead of memorizing isolated facts.

## What the project does

Threatdle turns structured threat intelligence into a playable daily experience. The current implementation centers on actor attribution and related tradecraft, with puzzle content derived from reviewed actor metadata, associated malware, and linked ATT&CK techniques.

Core layers:

- Python 3.11 ingest and puzzle-generation pipeline
- SQLite snapshot database for normalized entities and baked puzzle content
- Browser client built with HTML, CSS, and JavaScript
- Thin API architecture planned for public launch to protect answers and validate guesses server-side

## Data model

Threatdle is built primarily from:

- MITRE ATT&CK for threat groups, software, techniques, campaigns, and relationships
- MISP Galaxy threat-actor data for actor enrichment and alias coverage
- Reviewed override files for clue quality and publication readiness

The playable dataset is centered on what APTs are known to use in terms of tools and TTPs, not just incident summaries. In practice, the most important curation work is deciding which malware, techniques, and actor attributes can be defensibly linked to a specific group.

The hand-authored files in `data/curated-flows/` are intentionally part of the public project corpus. They document the puzzle-friendly tradecraft chains and curation choices that shape the game, and they are distinct from downloaded source snapshots or generated exports.

## Repository layout

- `src/threatdle/`: ingest, normalization, database, API, and puzzle services
- `public/`: browser client assets
- `data/`: curated inputs, overrides, processed outputs, and snapshots
- `docs/`: architecture notes, implementation decisions, and product docs
- `tests/`: pipeline and game behavior tests

## Development notes

The repository contains both source code and data-oriented workflow assets. The intended public repo shape keeps original code, docs, tests, overrides, and curated flows, while excluding generated outputs such as processed databases, baked bundles, Python cache artifacts, and downloaded snapshot/vendor data.

## Deployment notes

For production hosting on Netlify, the preferred deployment model is:

- serve the browser client from `public/`
- serve clue delivery and guess validation from Netlify Functions
- keep the hidden runtime bundle out of `public/`
- prefer downloading a prebuilt private `game-data.json` artifact during deploy instead of regenerating long puzzle ranges on Netlify

The build script supports a prebuilt bundle through:

- `GAME_RUNTIME_BUNDLE_URL`
- optional `GAME_RUNTIME_BUNDLE_BEARER_TOKEN`
- optional `GAME_RUNTIME_BUNDLE_SHA256`

It also supports direct Cloudflare R2 downloads through:

- `R2_ACCOUNT_ID`
- `R2_BUCKET`
- `R2_ACCESS_KEY_ID`
- `R2_SECRET_ACCESS_KEY`
- `GAME_RUNTIME_BUNDLE_KEY`
- optional `R2_REGION` (defaults to `auto`)
- optional `GAME_RUNTIME_BUNDLE_SHA256`

If those are not set, the build falls back to generating the runtime bundle from source inputs.

## License

The original code in this repository is licensed under the MIT License. See [LICENSE](./LICENSE).

Important: the MIT license applies to original code and original documentation in this repository. Third-party data sources, downloaded artifacts, logos, bundled datasets, and other external materials may be subject to their own licenses or terms of use.

If you make this repository public, do not assume that every file in `data/`, `dist/`, or generated output directories can be freely redistributed. Review the terms for each upstream source before publishing snapshots, processed databases, or exported demo bundles. The presence of original curated flows in the repo does not imply that downloaded source archives or generated snapshot data should also be published.

## Public repo checklist

Before making the repository public, review [docs/public-repo-checklist.md](./docs/public-repo-checklist.md).
