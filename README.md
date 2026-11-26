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
- `npm run build` (the Netlify build) fails unless the approved schedule covers 60 days. Never set `THREATDLE_DRAFTS` on a deployed site: it serves unapproved drafts.

Writing new cases: `docs/drafting-cases.md`.
