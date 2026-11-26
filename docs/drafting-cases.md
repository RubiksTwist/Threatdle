# Drafting Threatdle cases

A case is one real hacking report turned into a short run of plain-English clues that end in one answer: the group behind it. The audience is curious people, not experts. Every clue must read easily on a phone, be true to the report, and never copy the vendor's wording.

Data shapes and the game rules are in `docs/two-modes-design.md`. This file is the recipe for writing a case.

## Inputs
- A reading packet per candidate report (`node tools/packets.mjs <b_days_all.json> <bodies.jsonl.gz> <out dir>`): the culprit and its pool facts, its aliases, the report, the OPTIC candidate quotes and the article body.
- `data/source/attack-software.json`: ATT&CK software ids for `tools` facts.
- `public/js/rules.mjs`: the fact vocabulary (`SECTORS`, `COUNTRY`, `TYPES`, `MOTIVES`, `KINDS`).

## Output
One JSON file per batch in `data/drafts/`, shaped `{ "cases": [Case, ...] }`:

```json
{ "id": "c-1a2b3c4d", "mode": "analyst", "culprit": "G0000", "article": "1a2b3c4d-0000-4000-8000-000000000000", "reviewed": false,
  "clues": [
    { "kind": "victim", "text": "Locked up the computers of hospitals and clinics in several countries.",
      "facts": { "targets": ["Healthcare"] },
      "source": { "quote": "the group encrypted systems at hospitals and medical clinics across Europe and North America" } },
    { "kind": "tipoff", "text": "The researchers say the crew is in it for the money.", "facts": { "type": "crime", "motive": ["Financial Gain"] },
      "source": { "quote": "a financially motivated ransomware operation" } },
    { "kind": "breakin", "text": "Got in through a stolen password for a remote access server with no second login step.", "facts": {},
      "source": { "quote": "initial access was gained using valid credentials against a VPN appliance that lacked multifactor authentication" } },
    { "kind": "victim", "text": "Also hit schools and universities.", "facts": { "targets": ["Education"] },
      "source": { "quote": "Education was the second most affected sector" } }
  ],
  "story": "A ransomware crew broke into hospitals with a stolen password, copied patient files and then locked every computer it could reach. It demanded payment to unlock them and to keep the files private.",
  "report": { "vendor": "Example Security", "title": "An example ransomware report", "url": "https://example.com/report", "date": "2026-01-01" } }
```

- `id` is `c-` plus the first 8 characters of the OPTIC article id. `article` is the full id. `reviewed` is always `false`; only the owner approves.
- `report` comes from the packet. The title often names the group; players only see it at the end.

## Rules for every clue
1. **Plain English.** Write for a smart 14-year-old. Say "a booby-trapped shortcut file", not "a malicious LNK"; "fake login page", not "credential phishing portal". At most 170 characters, one or two short sentences.
2. **Your own words.** Never reuse 6 or more words in a row from the quote. `tools/check-cases.mjs` rejects it.
3. **No new facts.** The clue says only what its quote says. If the quote names a sector, the clue may name it; it may not add a country the quote does not give.
4. **Never name the culprit** or any alias in the packet's alias list, in any clue. Avoid vendor-specific names that are aliases (Secret Blizzard is Turla).
5. **`source.quote`** is the original sentence or phrase from the article body, copied exactly (no `[ACTOR]` redactions), at least 20 characters. Add `"note"` to `source` when the fact needs a reason the quote does not show.
6. **`facts`** record what the clue asserts, in the vocabulary below. Only facts the quote supports. A clue with no checkable fact (a tradecraft detail) has `"facts": {}`.
7. **`kind`**: `victim`, `breakin`, `tool`, `took` (what they stole or wanted), `hid` (how they stayed hidden), `tipoff` (attribution, motive, origin, a name).

### Fact vocabulary
| Fact | Values | When |
| --- | --- | --- |
| `targets` | `SECTORS` in rules.mjs | The quote names who was hit. Map plainly: ministries, embassies, agencies → Government; armed forces → Military; defense contractors → Defense; banks, crypto exchanges → Finance; software, IT, cloud → Technology; telecoms → Telecommunications; power, oil, gas → Energy; hospitals → Healthcare; universities, schools → Education; think tanks, NGOs → NGOs; activists, dissidents → Civil society; journalists → Media; hotels, restaurants → Hospitality; shops → Retail; factories → Manufacturing. One sector per clue cuts hardest. |
| `type` | `state`, `crime`, `activist` | The quote says state-sponsored, nation-state, government, intelligence service (`state`); ransomware gang, cybercriminal, financially motivated (`crime`). |
| `motive` | `Espionage`, `Financial Gain`, `Sabotage`, `Hacktivism` | The quote says spying, stealing money, destroying or disrupting, a cause. |
| `home` | `COUNTRY` codes | The quote ties the attackers to a country ("Russian state actor", "North Korean hackers"). |
| `tools` | ATT&CK `S` ids | A tool or malware clue whose software has an ATT&CK id. |
| `name` | not used | No clue in either mode names the group, its nickname or any alias. |
| `family` | a vendor naming word: `Bear`, `Panda`, `Typhoon`, `Tempest`... | A naming-family hint. Text exactly `CrowdStrike's name for this group ends in "Spider".` (CrowdStrike animals) or `Microsoft files this group under "Sleet".` (Microsoft weather words). The quote is a sentence that uses that name; add `"note": "<name> is the culprit's CrowdStrike name."`. |

## SOC Analyst cases (easy)
- Culprit must be on the Most Wanted (`Most Wanted: yes` in the packet).
- 4 to 7 clues in the **elimination ladder** order: (1) victim, (2) state or crime, and motive, (3) home country, (4) a tradecraft or tool detail, (5-6) tip-offs, (last) the closing clue.
- **Closing clue:** after the last clue 1 Most Wanted group fits (2 is accepted when nothing fair gets to 1). It never states the answer. `node tools/closing.mjs <bodies.jsonl.gz>` adds a naming-family hint ("CrowdStrike's name for this group ends in Spider") quoting an OPTIC article that uses that name. Where no hint gets there, add a true victim or motive fact from the article; drop the case if nothing gets it to 2.
- **Opening target:** 6 to 14 of the Most Wanted fit clue 1 (aim for about 9), then a slow descent so the tracker has work to do. Lead with whatever cuts deepest: the home country, state or crime, or a rare victim sector. `node tools/resequence.mjs` reorders, merges two clues that quote the same passage, or makes a "That government is..." clue stand alone when that is all a case needs.
- **Ladder target:** at most 5 Most Wanted groups still fit after clue 4. Run the check; it prints how many fit after each clue (`fit 30>12>6>4`). To fix a failing ladder: pick a sharper victim sector (one that groups listing only "Government" or "Private sector" lack), or put a second victim clue at position 4. Never bend a fact to pass. If it still fails, drop the case.
- A crime gang with no known home skips the country clue; use a second victim or the motive instead.

## Threat Hunter cases (hard)
- Any group may be the culprit. Prefer groups that are not on the Most Wanted.
- Exactly **6 clues**, harder first: break-in, how they hid, what they took, tools, then victim and motive, then country and tip-offs. No clue names the group: a name as clue 6 hands the player a free last guess. Clue 6 is a naming-family hint or a fact that sets the group apart.
- Expert tells are welcome early (a malware family only this group uses is fine at clue 3-4, not clue 1).

## Story (both modes)
2 or 3 plain sentences on what happened: who was hit, what the attackers did, who the vendor says did it. It may name the group. It must not copy the article.

## Drop a candidate when
- The article is not about an attack by this culprit (a how-to, a roundup, a passing mention).
- It cannot support 4 true clues (Analyst) or 6 (Threat Hunter).
- The Analyst ladder fails after honest fixes.

## Check
`node tools/check-cases.mjs data/drafts/<batch>.json` must print `0 failing`. Then `node tools/export.mjs` rebuilds `data/cases.json` and `data/review.md`.
