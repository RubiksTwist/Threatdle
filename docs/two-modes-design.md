# Threatdle: two modes (production design)

Source of truth for rules and evidence: `D:\Threatdle-prototypes\gameloop\SPEC.md` (sections "DECIDED" and "Modes"). The prototype in that folder is the reference for look and behaviour. This file fixes the data shapes, the API and the build steps the production game is written against.

## The game
- Two modes, each with its **own** daily case. Both modes roll over at midnight America/New_York.
- **SOC Analyst** (easy): the culprit is one of the Most Wanted roster, which holds only groups with a well-known nickname (about 52). Free-text autocomplete plus a Browse sheet grouped by home ("Russia · Bear · Blizzard"). No guess cap. Score = guesses. The case opens on two clues. Each wrong guess adds a 5-column row (Home, Motive, Since, Victims, Targets) and declassifies the next clue.
- **Threat Hunter** (hard): the culprit is any eligible ATT&CK group, and the guess pool is all of them (about 178), through the same guess box and Browse sheet as SOC Analyst (search ignores spaces and dashes, so "apt 28" finds APT28). 6 guesses. Each wrong guess adds a 6-column row (Home, Motive, Since, Victims, Targets, Tools; Tools as a none/some/many bucket) and declassifies the next clue. 6 misses = case gone cold.
- A row's cells describe the guessed group and their colour compares it with the culprit. Home: green same country, amber same part of the world. Motive: the whole combination ("Spy+Money"). Since: the year, with an arrow toward the culprit, amber within 2 years. Victims: the country the guess hit most; green when it is the culprit's too, amber when the culprit hit it at all. Targets: the guess's rarest sector plus a count, compared without Government (most groups list it) unless one side lists only Government. Type stays in the data for clues and the tracker, but not on the board.
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

`tools/export.mjs` reads the OPTIC/ATT&CK extraction vendored in `data/source/` (actor facts, the Most Wanted ids, a few hand-filled facts) and the drafted cases in `data/drafts/*.json` (recipe: `docs/drafting-cases.md`). It writes `data/pool.json` for the server and the trimmed `public/pool.json` for the client.

`data/pool.json`: everything a guess can resolve to, with no answers.
```json
{ "version": "2026-11-26",
  "actors": [{ "id": "G0007", "name": "APT28", "nickname": "Fancy Bear", "aliases": ["Forest Blizzard"],
    "home": "RU", "type": "state", "motive": ["Espionage"], "since": 2004, "targets": ["Government", "Military"],
    "victims": ["UA", "US"], "profile": "Russian military intelligence hackers", "roster": true, "tools": ["S0..."] }] }
```
`roster: true` marks the SOC Analyst roster. `tools` (ATT&CK software ids) never leave the server. The client gets a trimmed copy without them.

`data/cases.json` is private and server-only: gitignored, and published to R2 with the schedule (README, "The answers stay out of git").
```json
{ "cases": [{ "id": "c-1a2b3c4d", "mode": "analyst", "culprit": "G0000", "article": "1a2b3c4d-...", "reviewed": false,
    "clues": [{ "kind": "victim", "text": "Locked up the computers of hospitals and clinics in several countries.",
                "facts": { "targets": ["Healthcare"] },
                "source": { "quote": "encrypted systems at hospitals and medical clinics ..." } }],
    "story": "A ransomware crew broke into hospitals with a stolen password ...",
    "report": { "vendor": "Example Security", "title": "...", "url": "https://...", "date": "2026-01-01" } }] }
```
- **Analyst clue order** runs from least to most telling for a well-read player, measured blind (`tools/clue-scores.mjs`). A clue's facts only say what a newcomer can strike off; they miss what a reader recognizes. "Caused a blackout in Ukraine" fits 30 groups on facts and names one to anyone who followed the news, and before this order the giveaways sat evenly across clues 1 to 6. The two opening clues never give the country or naming family, in facts or words; neither is a giveaway (a reader 50%+ sure); and together they leave 20 roster groups or fewer on facts, the "possible" count a player sees first (it was a median of 28, up to 52, then clue 3 dropped it to 7; now a median of 11, then 7, then 2). Clue 1 never points back at another clue. On facts: 5 or fewer roster groups fit by clue 4. `tools/check-cases.mjs` checks all of it, and `tools/resequence.mjs` orders every case.
- **Suspect tracker.** SOC Analyst's Browse sheet greys out the groups the clues rule out, and the groups already guessed. Reading the rows is the player's skill (simulated: an ideal player solves in 2.0 guesses, a newcomer who reads Home, Motive and Victims in 2.3, one who trusts only the list in 2.9). Threat Hunter's tracker reads the rows too: a newcomer without it wins 78% of games, the tracker 100% (`tests/simulation.txt`, Round 7). `MODES[mode].trackRows` holds the switch.
- **Hunter clue order** is harder first. A clue that names the group always comes last.
- Export also folds every drafted clue's facts into its culprit's public card in `pool.json` (targets, motive, tools; home and type only where unknown). Without it, 50 of 144 drafts had a clue the culprit's own card contradicted, so a careful player ruled out the real culprit (simulated SOC Analyst careful player: 12.1 mean guesses with that bug, 2.6 without).
- Each clue's `facts` say what it asserts (`targets`, `home`, `type`, `motive`, `tools`, `name`). They drive the ladder check and the fold: a row folds the facts of the clues shown when it was made into the culprit's profile. (Changed from a case-level `fold`, which could not tell which facts were shown yet.)
- `reviewed` is derived: `data/approved.json` maps a case id to a hash of the exact case a human approved (`node tools/approve.mjs <id>`). Editing an approved case un-approves it.

`data/schedule.json` is private and maps a day to a case per mode. `tools/schedule.mjs` generates it from **reviewed** cases only: no culprit repeats within 14 days per mode, and it runs at least 365 days ahead. The Netlify build fetches both from R2 and fails when the runway is under 60 days.

## API (Netlify Functions, stateless about a player's game)
- `GET /api/today?mode=analyst|hunter` returns `{ day, caseNumber, mode, msUntilNext, clues, clueCount, solvedCount, yesterday: { name, nickname } | null }`. `clues` holds the opening clues: two in SOC Analyst, one in Threat Hunter (`MODES[mode].open`). The client loads the pool from the static trimmed `pool.json`.
- `POST /api/guess` takes `{ mode, day, guesses: [actorId...], playerId }`. It recomputes everything from the guess list and returns `{ rows, clues, status: "playing" | "solved" | "cold", result? }`. `result` = `{ culprit, story, report, tries, rank, solvedCount, betterThan, distribution }`.
- A day other than today returns 409 with today's day. Future days are never served. Unknown ids, duplicates, a malformed body, or more guesses than the mode allows return 400.
- Solve records live in Netlify Blobs, one record per (mode, day, player) with no read-modify-write. Count, rank, percentile and distribution are derived by listing.

## Build steps (each ends in a check)
1. Remove v1: the Python pipeline, the 5-button client and the old functions. Tests: none left.
2. Shared rules core `public/js/rules.mjs`: compare, buckets, fold, calendar, share text. Unit tests. It sits under `public/` so the browser imports the same file the functions bundle; the rules hold no answers.
3. Export: OPTIC → pool.json and draft cases.json, plus `review.md` for a human. Check: counts, roster size, and the fit-by-clue-4 report.
4. Functions plus Blobs solve records. API tests.
5. Client ported from the prototype (both modes, end screen, share, stats). Playwright end-to-end at 390 and 1440, axe 0 violations.
6. Schedule with a runway check. Nothing deploys without the owner's OK.
