# Threatdle: two modes (production design)

Source of truth for rules and evidence: `D:\Threatdle-prototypes\gameloop\SPEC.md` (sections "DECIDED" and "Modes"). The prototype in that folder is the reference for look and behaviour. This file fixes the data shapes, the API and the build steps the production game is written against.

## The game
- Two modes, each with its **own** daily case. Both modes roll over at midnight America/New_York.
- **SOC Analyst** (easy): the culprit is one of the Most Wanted roster, which holds only groups with a well-known nickname (about 52). Free-text autocomplete plus a Browse sheet grouped by home ("Russia · Bear · Blizzard"). No guess cap. Score = guesses. Each wrong guess adds a 5-column row (Home, Type, Motive, Since, Targets) and declassifies the next clue.
- **Threat Hunter** (hard): the culprit is any eligible ATT&CK group, and the guess pool is all of them (about 178). 6 guesses. Each wrong guess adds a 7-column row (Home, Type, Motive, Since, Targets, Tools, Tricks; Tools and Tricks as none/some/many buckets) and declassifies the next clue. 6 misses = case gone cold.
- Clues are plain-English rewrites of a vendor fact. Each keeps its source quote for review. Verbatim quotes are never shown to players.
- Reward and playability follow the 12-game -dle study:
  - share text with case number, mode, score, grid and streak
  - "N analysts closed this case today", your rank, and a "better than X%" line
  - a guess-distribution chart, a countdown to the next case and yesterday's culprit
  - streaks per mode that only today's case builds
  - a "Next mode" button that leads to the other mode's own case
  - an inline how-to card, never an overlay
  - a reveal with a 2-3 sentence "What happened" and the report link

## Data (build-time, written by `tools/export.mjs` from OPTIC; the client never sees answers)

`data/pool.json` is public: everything a guess can resolve to, with no answers.
```json
{ "version": "2026-11-26",
  "actors": [{ "id": "G0007", "name": "APT28", "nickname": "Fancy Bear", "aliases": ["Forest Blizzard"],
    "home": "RU", "type": "state", "motive": ["Espionage"], "since": 2004, "targets": ["Government", "Military"],
    "profile": "Russian military intelligence hackers", "roster": true, "tools": ["S0..."], "tricks": ["T1..."] }] }
```
`roster: true` marks the SOC Analyst roster. `tools` and `tricks` (ATT&CK ids) never leave the server. The client gets a trimmed copy without them.

`data/cases.json` is private and server-only.
```json
{ "cases": [{ "id": "c-0001", "mode": "analyst", "culprit": "G0000", "reviewed": false,
    "clues": [{ "kind": "victim", "text": "Locked up the computers of hospitals and clinics in several countries.",
                "source": { "quote": "encrypted systems at hospitals and medical clinics ...", "articleId": 123 } }],
    "fold": { "targets": ["Healthcare"] },
    "story": "A ransomware crew broke into hospitals with a stolen password ...",
    "report": { "vendor": "Example Security", "title": "...", "url": "https://...", "date": "2026-01-01" } }] }
```
- **Analyst clue order** is the elimination ladder: victim, then state or crime and motive, then region, then a tradecraft or tool detail, then tip-offs. Target: 5 or fewer roster groups fit by clue 4, checked by `tools/check-cases.mjs` against roster facts.
- **Hunter clue order** is harder first. A clue that names the group always comes last.
- `fold` holds the clue facts that are added to the culprit's profile when its rows and end card are computed. A row only folds the facts of clues shown so far.

`data/schedule.json` is private and maps a day to a case per mode. `tools/schedule.mjs` generates it from **reviewed** cases only: no culprit repeats within 14 days per mode, and it runs at least 365 days ahead. Build fails when the runway is under 60 days.

## API (Netlify Functions, stateless about a player's game)
- `GET /api/today?mode=analyst|hunter` returns `{ day, caseNumber, mode, msUntilNext, clue1, solvedCount, yesterday: { name, nickname } | null }`. The client loads the pool from the static trimmed `pool.json`.
- `POST /api/guess` takes `{ mode, day, guesses: [actorId...], playerId }`. It recomputes everything from the guess list and returns `{ rows, clues, status: "playing" | "solved" | "cold", result? }`. `result` = `{ culprit, story, report, tries, rank, solvedCount, betterThan, distribution }`.
- A day other than today returns 409 with today's day. Future days are never served. Unknown ids, duplicates, a malformed body, or more guesses than the mode allows return 400.
- Solve records live in Netlify Blobs, one record per (mode, day, player) with no read-modify-write. Count, rank, percentile and distribution are derived by listing.

## Build steps (each ends in a check)
1. Remove v1: the Python pipeline, the 5-button client and the old functions. Tests: none left.
2. Shared rules core `lib/rules.mjs`: compare, buckets, fold, calendar, share text. Unit tests.
3. Export: OPTIC → pool.json and draft cases.json, plus `review.md` for a human. Check: counts, roster size, and the fit-by-clue-4 report.
4. Functions plus Blobs solve records. API tests.
5. Client ported from the prototype (both modes, end screen, share, stats). Playwright end-to-end at 390 and 1440, axe 0 violations.
6. Schedule with a runway check. Nothing deploys without the owner's OK.
