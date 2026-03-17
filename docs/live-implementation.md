# Threatdle Live Implementation

Recorded on: 2026-03-16

## Purpose

This note records the intended live implementation for Threatdle. It is the production target for a public launch and is separate from any static demo export used for presentations, reviews, or portfolio sharing.

## Launch priorities

The production concerns that matter most for launch are:

1. Answer leakage
2. Daily reset logic
3. Puzzle state
4. Authentication
5. Analytics

## 1. Answer leakage

This is the first problem to solve before a public launch.

If puzzle data is shipped as a static JSON bundle that includes the hidden answer, anyone can inspect the client payload and extract it. That is tolerable for a demo, but not for a public launch where answers will be posted and shared quickly.

The live implementation should use a thin backend API that:

- returns only puzzle clues to the client
- keeps answer keys and validation logic on the server
- validates guesses server-side

## 2. Daily reset logic

The current production target is to determine the active puzzle day on the server, not in the browser.

Client-side date checks are easy to spoof and make timezone handling messy. The live API should serve "today's" puzzle according to server-controlled time and expose archive days explicitly.

## 3. Puzzle state

Threatdle should keep player progress in `localStorage` for launch.

This matches the expected behavior for a Wordle-style daily game:

- no authentication required
- no per-guess database writes
- progress remains on the player's device

The tradeoff is no cross-device sync. That is acceptable for the initial public release.

## 4. Authentication

Full user authentication should be skipped for launch.

If streaks, lightweight persistence, or leaderboards are added later, the preferred first step is a small anonymous identifier seeded from `localStorage`. A full auth system adds complexity that is not necessary for the initial launch or for demonstrating the project.

## 5. Analytics

Threatdle should use a privacy-respecting analytics tool for launch. Plausible and Fathom are both acceptable options.

The goal is basic product telemetry such as:

- daily active players
- return rate
- completion rate by puzzle mode

## Live stack

| Layer | Planned service | Role |
| --- | --- | --- |
| Browser game UI | Netlify | Hosts the public client |
| Thin API | Netlify Functions preferred; Render acceptable fallback | Serves clues, validates guesses, and controls daily puzzle selection |
| Puzzle state | `localStorage` | Stores per-device progress |
| Analytics | Plausible or Fathom | Tracks lightweight product usage |
| Domain and DNS | Cloudflare | Domain and DNS management |

## Cost assumptions

These are launch-planning estimates from the implementation decision, not permanent guarantees:

| Layer | Estimated cost at decision time |
| --- | --- |
| Netlify hosting | $0 |
| Thin API on Netlify Functions or Render free tier | $0 |
| `localStorage` puzzle state | $0 |
| Analytics | $0 at entry tier assumption |
| Cloudflare domain and DNS | Approximately $4.99/year, depending on TLD |

## API hosting note

Render is acceptable for early testing, but cold starts are a real launch risk for a daily game because they create a poor first-load experience.

Netlify Functions are the preferred launch path because:

- the frontend is already a good fit for Netlify hosting
- the API needs are thin
- the serverless model avoids maintaining a separate always-on application for simple clue delivery and validation

## Production shape

The intended live production shape is:

- a browser-based game client hosted statically
- a thin backend API for clue delivery, answer protection, and guess validation
- client-side persistence in `localStorage`
- no full authentication in V1

## Deployment note

For production deploys, Threatdle should prefer a prebuilt private runtime bundle over generating puzzle data on Netlify during each deploy.

Recommended shape:

- generate `game-data.json` offline or in CI from the Python pipeline
- store that artifact in private storage
- configure Netlify to download it into `build/runtime/`
- bundle it only with Netlify Functions, not with the public site

For the current implementation, Cloudflare R2 is a strong fit for this runtime bundle:

- the artifact is small
- deploys only need one object read
- the bucket can remain private
- Netlify can fetch the object during build with R2 credentials instead of rebuilding puzzle data

This keeps deploy times predictable and avoids rebuilding large puzzle archives during every production publish.

## Bottom line

Threatdle should launch as a lightweight browser game with a thin server-side validation layer. The key architectural rule is simple: the client can render the puzzle and store local progress, but the server must own the answer and the decision about what puzzle is active today.
