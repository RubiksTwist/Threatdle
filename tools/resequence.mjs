// Orders SOC Analyst clues from least to most telling for a well-read player (tools/clue-scores.mjs), within the rules:
// no country or naming family in the opening clues, no giveaway in them and not all of them vague, the ladder (5 or fewer by
// clue 4), 2 or fewer at the end, and a last clue that narrows the field or says something new. Two clues quoting the same
// passage (one quote inside the other) may merge into one. A clue that leans on the one before it ("That government...",
// "Also...") never moves ahead of it. Every case is reordered, not only failing ones; ties keep the current order, so a rerun changes nothing.
// Usage: node tools/resequence.mjs [--dry]
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { buildPool } from './export.mjs';
import { COUNTRY } from '../public/js/rules.mjs';
import { ladder, deadCloser, homeAt, openingReads, loadScores, SCORES, HOME_FROM, LEANS_BACK, LADDER_AT, LADDER_MAX, CLOSE_MAX } from './check-cases.mjs';

const dry = process.argv.includes('--dry');
const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
const dir = new URL('../data/drafts/', import.meta.url);
const files = readdirSync(dir).filter(f => f.endsWith('.json')).map(f => ({ f, j: JSON.parse(readFileSync(new URL(f, dir), 'utf8')) }));
const LEANS = /^(that|those|this|these|also|it also|they also|the same|then|later|both|another|again|once inside|after that)\b/i;
const scores = loadScores();
// The rules on facts. A case whose clues cannot also meet the reader rules in any order still gets its best order on facts,
// and is listed as needing a clue redrafted: a sharper one when every clue is vague, a vaguer one when nearly all give it away.
const factsPass = c => { const l = ladder(c, byId); return homeAt(c, byId) >= HOME_FROM && !LEANS_BACK.test(c.clues[0].text)
  && l[Math.min(LADDER_AT, l.length) - 1] <= LADDER_MAX && l.at(-1) <= CLOSE_MAX && !deadCloser(c, byId); };
// How much a clue gives a reader: a recognized clue (tell > 0) outranks any unrecognized one, which ranks by how far it narrows.
const value = s => (s.tell > 0 ? 30 + s.tell : 30 * (1 - s.fits / 52));

const perms = a => (a.length <= 1 ? [a] : a.flatMap((x, i) => perms([...a.slice(0, i), ...a.slice(i + 1)]).map(p => [x, ...p])));
// Index lists the clue order may take: each clue that leans on its predecessor stays after it.
// One that points back anywhere in its text ("another of its interests") never moves ahead of a clue it followed.
const orders = clues => perms(clues.map((_, i) => i)).filter(p => p.every((ci, pos) => (!LEANS.test(clues[ci].text.trim()) || ci === 0 || p.indexOf(ci - 1) < pos)
  && (!LEANS_BACK.test(clues[ci].text) || !p.slice(pos + 1).some(x => x < ci))));
const sameQuote = (a, b) => a.includes(b) || b.includes(a);
const moved = p => p.reduce((s, ci, pos) => s + Math.abs(ci - pos), 0);
let cid;
function merge(clues, i, j) {
  const a = clues[i], b = clues[j];
  const facts = { ...a.facts, ...b.facts };
  if (a.facts.targets && b.facts.targets) facts.targets = [...new Set([...a.facts.targets, ...b.facts.targets])];
  const text = `${a.text.trim().replace(/\.$/, '')}. ${b.text.trim().replace(/^That government is/, 'It is').replace(/^Also /, '')}`;
  const out = clues.filter((_, k) => k !== j);
  const source = a.source.quote.length >= b.source.quote.length ? a.source : b.source;
  out[i] = { kind: a.kind, text: text[0].toUpperCase() + text.slice(1), facts, source };
  // The merged clue tells a reader at least as much as either half.
  const sa = scores[cid][a.text], sb = scores[cid][b.text];
  if (sa && sb) scores[cid][out[i].text] = { tell: Math.max(sa.tell, sb.tell), fits: Math.min(sa.fits, sb.fits) };
  return out;
}

// "That government is Russia's." can only follow the clue it points back to. When its own quote names the state, it can stand alone.
function standalone(k) {
  if (!/^That (government|country) is /.test(k.text) || !k.facts.home) return null;
  const state = /state|government|nation-state|intelligence/i.test(k.source.quote);
  const text = `The report ties the attackers to ${COUNTRY[k.facts.home]}${state ? "'s government" : ''}.`;
  if (scores[cid][k.text]) scores[cid][text] = scores[cid][k.text];
  return { ...k, text, facts: { ...k.facts, ...(state ? { type: 'state' } : {}) } };
}

let fixedOrder = 0, fixedMerge = 0, fixedAlone = 0;
const stuck = [], redraft = [];
for (const { j } of files) for (const c of j.cases) {
  if (c.mode !== 'analyst') continue;
  cid = c.id;
  scores[cid] ??= {};
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
    if (!factsPass(cand)) continue;
    const reads = openingReads(cand, scores).length === 0;
    // Telling clues late: each clue's value weighs by how many clues follow it.
    const n = cand.clues.length;
    const cost = (reads ? 0 : 10000) + (t.merged ? 1000 : 0) + (t.alone ? 500 : 0) + cand.clues.reduce((s, k, pos) => s + value(scores[cid][k.text]) * (n - 1 - pos), 0) + moved(p) * 0.01;
    if (!best || cost < best.cost) best = { cost, reads, clues: cand.clues, merged: t.merged, alone: t.alone };
  }
  if (!best) { stuck.push(`${c.id} ${byId[c.culprit].name} (${ladder(c, byId).join('>')})`); continue; }
  if (!best.reads) redraft.push(`${c.id} ${byId[c.culprit].name}: ${openingReads({ ...c, clues: best.clues }, scores).join('; ')}`);
  if (best.clues.every((k, i) => k === c.clues[i])) continue;
  best.merged ? fixedMerge++ : best.alone ? fixedAlone++ : fixedOrder++;
  c.clues = best.clues;
}
if (!dry) {
  for (const { f, j } of files) writeFileSync(new URL(f, dir), JSON.stringify(j, null, 1) + '\n');
  writeFileSync(SCORES, JSON.stringify(scores, null, 1) + '\n');
}
console.log(`${dry ? '(dry run) ' : ''}reordered ${fixedOrder}, merged two clues that share a quote ${fixedMerge}, made a "That government..." clue stand alone ${fixedAlone}, cannot meet the rules ${stuck.length}`);
for (const s of stuck) console.log('  ' + s);
if (redraft.length) console.log(`best order on facts, but a clue needs redrafting to meet the reader rules: ${redraft.length}`);
for (const s of redraft) console.log('  ' + s);
