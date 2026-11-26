// Reorders SOC Analyst clues so the first clue leaves 6-14 of the Most Wanted, keeping the ladder (5 or fewer by clue 4),
// 2 or fewer at the end, and a last clue that narrows the field or says something new. Two clues quoting the same passage (one quote inside the other) may merge into one.
// A clue that leans on the one before it ("That government...", "Also...") never moves ahead of it.
// Among passing orders it prefers a slow descent (many suspects left after clues 2 and 3, clue 1 near 10), so the
// tracker has work to do, then the fewest moved clues. Safe to rerun: a case that passes check-cases is left alone.
// Usage: node tools/resequence.mjs [--dry]
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { buildPool } from './export.mjs';
import { COUNTRY } from '../public/js/rules.mjs';
import { ladder, deadCloser, checkCase, FIRST_MIN, FIRST_MAX, LADDER_AT, LADDER_MAX, CLOSE_MAX } from './check-cases.mjs';

const dry = process.argv.includes('--dry');
const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
const dir = new URL('../data/drafts/', import.meta.url);
const files = readdirSync(dir).filter(f => f.endsWith('.json')).map(f => ({ f, j: JSON.parse(readFileSync(new URL(f, dir), 'utf8')) }));
const LEANS = /^(that|those|this|these|its|their|also|it also|they also|the same|then|later|both|another|again|once inside|after that)\b/i;
const passes = c => { const l = ladder(c, byId); return l[0] >= FIRST_MIN && l[0] <= FIRST_MAX && l[Math.min(LADDER_AT, l.length) - 1] <= LADDER_MAX && l.at(-1) <= CLOSE_MAX && !deadCloser(c, byId); };

const perms = a => (a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map(p => [x, ...p])));
// Index lists the clue order may take: each clue that leans on its predecessor stays after it.
const orders = clues => perms(clues.map((_, i) => i)).filter(p => p.every((ci, pos) => !LEANS.test(clues[ci].text.trim()) || ci === 0 || p.indexOf(ci - 1) < pos));
const sameQuote = (a, b) => a.includes(b) || b.includes(a);
const moved = p => p.reduce((s, ci, pos) => s + Math.abs(ci - pos), 0);
function merge(clues, i, j) {
  const a = clues[i], b = clues[j];
  const facts = { ...a.facts, ...b.facts };
  if (a.facts.targets && b.facts.targets) facts.targets = [...new Set([...a.facts.targets, ...b.facts.targets])];
  const text = `${a.text.trim().replace(/\.$/, '')}. ${b.text.trim().replace(/^That government is/, 'It is').replace(/^Also /, '')}`;
  const out = clues.filter((_, k) => k !== j);
  const source = a.source.quote.length >= b.source.quote.length ? a.source : b.source;
  out[i] = { kind: a.kind, text: text[0].toUpperCase() + text.slice(1), facts, source };
  return out;
}

// "That government is Russia's." can only follow the clue it points back to. When its own quote names the state, it can stand alone.
function standalone(k) {
  if (!/^That (government|country) is /.test(k.text) || !k.facts.home) return null;
  const state = /state|government|nation-state|intelligence/i.test(k.source.quote);
  return { ...k, text: `The report ties the attackers to ${COUNTRY[k.facts.home]}${state ? "'s government" : ''}.`, facts: { ...k.facts, ...(state ? { type: 'state' } : {}) } };
}

let fixedOrder = 0, fixedMerge = 0, fixedAlone = 0;
const stuck = [];
for (const { j } of files) for (const c of j.cases) {
  if (c.mode !== 'analyst' || !checkCase(c, byId).length) continue;
  const tries = [{ clues: c.clues, merged: false }];
  for (let i = 0; i < c.clues.length; i++) for (let k = i + 1; k < c.clues.length; k++)
    if (sameQuote(c.clues[i].source.quote, c.clues[k].source.quote) && Object.keys(c.clues[i].facts).length && Object.keys(c.clues[k].facts).length) {
      const m = merge(c.clues, i, k);
      if (m[i].text.length <= 170) tries.push({ clues: m, merged: true });
    }
  const alone = c.clues.map(k => standalone(k) || k);
  if (alone.some((k, i) => k !== c.clues[i])) tries.push({ clues: alone, merged: false, alone: true });
  let best = null;
  for (const t of tries) for (const p of orders(t.clues)) {
    const cand = { ...c, clues: p.map(i => t.clues[i]) };
    if (!passes(cand)) continue;
    const l = ladder(cand, byId);
    const cost = (t.merged ? 100 : 0) + (t.alone ? 50 : 0) - (l[1] + l[2]) * 5 + Math.abs(l[0] - 10) * 3 + moved(p) * 0.1;
    if (!best || cost < best.cost) best = { cost, clues: cand.clues, merged: t.merged, alone: t.alone };
  }
  if (!best) { stuck.push(`${c.id} ${byId[c.culprit].name} (${ladder(c, byId).join('>')})`); continue; }
  best.merged ? fixedMerge++ : best.alone ? fixedAlone++ : fixedOrder++;
  c.clues = best.clues;
}
if (!dry) for (const { f, j } of files) writeFileSync(new URL(f, dir), JSON.stringify(j, null, 1) + '\n');
console.log(`${dry ? '(dry run) ' : ''}ordered as is or reordered ${fixedOrder}, merged two clues that share a quote ${fixedMerge}, made a "That government..." clue stand alone ${fixedAlone}, cannot meet the rules ${stuck.length}`);
for (const s of stuck) console.log('  ' + s);
