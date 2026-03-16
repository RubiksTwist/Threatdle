# Threatle Product Brief

Recorded on: 2026-03-15

## Purpose

This note records a product-planning conversation about building a daily cybersecurity puzzle game. It preserves the core game idea, the data strategy, and the main product risks.

## Core Concept

Threatle is a daily cyber puzzle game built around four parts of threat intelligence:

1. Threat actor attribution
2. Campaign behavior and attack sequencing
3. Malware identification
4. MITRE ATT&CK technique recognition

The strongest framing is "cyber investigation," not trivia.

## Daily Puzzle Structure

Each daily puzzle set contains four short challenges:

1. APT Guess
2. Campaign Timeline
3. Malware Guess
4. TTP Wordle

Target session length: 5 to 7 minutes.

## Puzzle Formats

### APT Guess

Players identify the threat group from feedback-driven guesses.

Possible examples:

- APT29
- APT28
- Lazarus Group

Possible feedback attributes:

- Country
- Targets
- First observed
- Techniques

### Campaign Timeline

Players identify a campaign or actor from an ordered attack chain.

Example sequence:

1. Spearphishing email
2. Macro document execution
3. PowerShell beacon
4. Credential dumping
5. Lateral movement

### Malware Guess

Players identify a malware family from a small set of clues.

Example clue types:

- Malware type
- Propagation method
- Implementation language

Example answers:

- Emotet
- TrickBot
- Stuxnet

### TTP Wordle

Players guess a MITRE ATT&CK technique and receive attribute-based feedback.

Example attributes:

- ATT&CK tactic
- Platforms
- Privilege requirement
- Detection difficulty
- Remote vs local execution
- User interaction required

## Best Theme Direction

The daily experience is stronger if all four puzzles teach one coherent incident story.

Example theme:

- Theme: SolarWinds attack
- APT answer: APT29
- Campaign answer: SolarWinds intrusion
- Malware answer: SUNBURST
- TTP answer: supply chain compromise

This makes the game feel like learning a real intrusion instead of solving four unrelated puzzles.

## Why The Concept Could Work

The game maps cleanly to real threat intelligence skills:

| Puzzle | Skill learned |
| --- | --- |
| APT Guess | Threat actor attribution |
| Campaign Timeline | Attack chain analysis |
| Malware Guess | Malware identification |
| TTP Wordle | MITRE ATT&CK familiarity |

This fits how analysts think about incidents and aligns naturally with MITRE ATT&CK and related defensive frameworks.

## Dataset Scope

The conversation narrowed the dataset goal to 365 curated daily puzzles instead of an automatically generated multi-year corpus.

That is a better starting scope because it reduces:

- generation complexity
- validation effort
- quality-control burden

## Data Sources

### Primary Source

MITRE ATT&CK should be the main structured source because it already models:

- threat groups
- techniques
- malware
- campaigns
- relationships between those entities

That relationship graph is exactly what the puzzle system needs.

### Validation Sources

Suggested cross-check sources:

- CISA advisories
- CrowdStrike reports
- Mandiant reports

These help confirm that a clue or campaign narrative is grounded in real reporting.

## Accuracy Strategy

The key recommendation from the conversation was simple:

Only generate clues from relationships that already exist in ATT&CK.

Examples:

- group uses technique
- group uses malware
- campaign uses technique

A practical V1 content policy:

1. Use ATT&CK as the source of truth for entity relationships.
2. Use external reports only to confirm or enrich narrative context.
3. Do not include any clue unless it can be traced back to a supported source.

## Example Puzzle Record

```json
{
  "apt_guess": {
    "answer": "APT29",
    "country": "Russia",
    "first_seen": 2008
  },
  "campaign_timeline": {
    "steps": [
      "Spearphishing",
      "PowerShell",
      "Credential dumping",
      "Lateral movement"
    ],
    "answer": "APT29"
  },
  "malware_guess": {
    "hints": [
      "Supply chain attack",
      "Targets enterprise networks"
    ],
    "answer": "SUNBURST"
  },
  "ttp_wordle": {
    "answer": "Spearphishing Attachment",
    "tactic": "Initial Access",
    "platform": "Windows"
  }
}
```

## Main Product Risks

The conversation identified three major risks:

1. The game may be too niche.
2. The game may feel too hard if players do not already know the vocabulary.
3. The game may feel like trivia instead of investigation.

## What Makes It Fun

The strongest design insight was that the game becomes more compelling when it behaves like a deduction system.

The player should feel like they are investigating an intrusion, not recalling isolated facts from memory.

## Recommended Core Mechanic

### Threat Intel Deduction Grid

Instead of blind guessing, show a constrained set of plausible actors or entities and let the player narrow them down with evidence.

Example flow:

1. Start with a list of possible actors.
2. Reveal a clue such as victim sector.
3. Eliminate actors that do not match.
4. Reveal a technique or malware clue.
5. Narrow to the final answer.

This improves playability because:

- it rewards reasoning
- it helps players who are not experts
- it mirrors real analytical workflows

## Supporting Mechanics

### Intel Unlocks

Correct guesses or clue spends unlock additional evidence, such as:

- target sector
- infrastructure
- malware family
- campaign year

### Intel Budget

Players can choose only a limited number of clues to reveal, adding strategy and replay value.

Example clue menu:

- country attribution
- malware
- initial access
- target sector
- campaign year

### Unknown Actor Outcome

Some puzzles could resolve to `UNKNOWN ACTOR` to reflect real-world attribution uncertainty.

## Accessibility Recommendation

Autocomplete or constrained answer lists are likely required. Without them, many players will fail because they do not know the full space of valid APT, malware, or ATT&CK names.

## Audience Fit

The best target audiences are likely:

- cybersecurity students
- SOC analysts
- threat intelligence analysts
- ATT&CK learners
- security community audiences on social platforms

This is probably a niche product, but the niche is active and can support a strong daily ritual if the gameplay loop feels investigative.

## Product Conclusion

The dataset problem is solvable with ATT&CK and careful validation.

The real product challenge is making the experience feel like cyber investigation instead of cyber trivia.

## Suggested Next Steps

1. Define a canonical data schema for actors, campaigns, malware, techniques, and clues.
2. Build a small verified corpus of 20 to 30 linked puzzle sets before targeting all 365.
3. Prototype the deduction-grid mechanic before implementing all four puzzle types.
4. Decide whether every daily puzzle set should be theme-linked.
5. Define a clue confidence policy so every displayed fact is traceable to a source.

## One-Sentence Summary

Threatle should be built as a daily cyber investigation game that uses ATT&CK-backed relationships to produce accurate, deduction-first puzzles across actor, campaign, malware, and technique domains.
