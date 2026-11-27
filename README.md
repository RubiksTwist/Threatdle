# Threatdle

A daily guessing game about real hacking cases. Each day has two cases, one per mode:

- **SOC Analyst** (easy): name the culprit from the Most Wanted roster. No guess limit; the score is the number of guesses.
- **Threat Hunter** (hard): name the culprit from every ATT&CK group, in 6 guesses.

The design contract is `docs/two-modes-design.md`.

## Working on it
- `npm test`: unit tests for the rules core, the API and the scheduler.
- `npm run check`: checks every drafted case (shape, facts, leaks, copied vendor text, the SOC Analyst elimination ladder).
- `npm run export`: rebuilds `data/pool.json`, `public/pool.json`, `data/cases.json` and `data/review.md`.
- `node tools/approve.mjs <case id> ...`, then `npm run export` and `npm run schedule`: approve reviewed cases and schedule them.
- Local play on draft cases: `npm run schedule:drafts`, then `THREATDLE_DRAFTS=1 netlify dev --offline`, then `npm run e2e` for the Playwright run at 390 and 1440 with axe. Screenshots land in `tests/screenshots/`.
- `npm run build` is the Netlify build. It fetches the answers from R2 and fails unless they verify and the approved schedule covers 60 days. `THREATDLE_DRAFTS` only works under `netlify dev`.

Writing new cases: `docs/drafting-cases.md`.

## The answers stay out of git
This repo is public. Everything that ties a case or a day to its culprit is gitignored and lives only on the editors' disks and in Cloudflare R2: `data/cases.json`, `data/drafts/`, `data/review.md`, `data/schedule.json`, `data/schedule.drafts.json` and the e2e screenshots. `data/approved.json` (case ids and hashes) is committed.

To publish, after approve, export and schedule:

```sh
export R2_ACCOUNT_ID=... R2_BUCKET=... R2_ACCESS_KEY_ID=... R2_SECRET_ACCESS_KEY=...
node tools/publish.mjs --dry-run   # prints the bundle and its sha256, uploads nothing
node tools/publish.mjs             # uploads cases + schedule to threatdle/two-modes/private.json
```

Then set `GAME_RUNTIME_BUNDLE_SHA256` on Netlify to the printed sha256 (or delete it to skip the pin) and deploy. The Netlify build reads the same `R2_*` variables and optional `R2_REGION`. `THREATDLE_BUNDLE_KEY` overrides the object key in both. `GAME_RUNTIME_BUNDLE_KEY` is v1's key and is no longer read.
