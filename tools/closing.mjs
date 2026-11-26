// Closes SOC Analyst cases without stating the answer: the last clue is a vendor naming-family hint
// ("CrowdStrike's name for this group ends in Spider"), quoting an OPTIC article that uses that name.
// It first removes any closing clue that names the group, and any family hint that rules out no group where it stands
// (after the country clue every group shares a family). Target: 1 Most Wanted group left; 2 is accepted when no hint gets to 1.
// Safe to rerun: a case that passes check-cases is left alone.
// Usage: node tools/closing.mjs <bodies.jsonl.gz>
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
import { buildPool } from './export.mjs';
import { ladder, checkCase, CLOSE_MAX, ANALYST_MAX_CLUES } from './check-cases.mjs';

import { FAMILIES } from '../public/js/rules.mjs';
const { CrowdStrike: CS, Microsoft: MS } = FAMILIES;
const hint = f => (CS.includes(f) ? `CrowdStrike's name for this group ends in "${f}".` : `Microsoft files this group under "${f}".`);
const bodiesFile = process.argv[2];
if (!bodiesFile) { console.error('usage: node tools/closing.mjs <bodies.jsonl.gz>'); process.exit(1); }

const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
const dir = new URL('../data/drafts/', import.meta.url);
const files = readdirSync(dir).filter(f => f.endsWith('.json')).map(f => ({ f, j: JSON.parse(readFileSync(new URL(f, dir), 'utf8')) }));
const names = a => [a.name, a.nickname, ...a.aliases].filter(n => n && n.length >= 4);
const esc = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const says = (text, n) => new RegExp(`(^|[^A-Za-z0-9])${esc(n)}(?![A-Za-z0-9])`, 'i').test(text);

const bodies = new Map();
// Split on newlines only: some bodies hold a raw carriage return, which a line reader would break on.
for (const line of gunzipSync(readFileSync(bodiesFile)).toString('utf8').split(String.fromCharCode(10))) {
  if (!line) continue;
  const r = JSON.parse(line);
  if (r.body_text) bodies.set(r.article_id, r.body_text);
}
function sentence(body, i, len) {
  let a = i, b = i + len;
  while (a > 0 && !/[.!?\n]/.test(body[a - 1]) && i - a < 220) a--;
  while (b < body.length && !/[.!?\n]/.test(body[b]) && b - i < 220) b++;
  if (b < body.length && /[.!?]/.test(body[b])) b++;
  return body.slice(a, b).trim();
}
// A sentence that uses this name, from the case's own article if it has one, else from any OPTIC article.
function cite(name, own) {
  const re = new RegExp(`(^|[^A-Za-z0-9])${esc(name)}(?![A-Za-z0-9])`, 'i');
  for (const [id, body] of [[own, bodies.get(own) || ''], ...[...bodies].filter(([id]) => id !== own)]) {
    const m = re.exec(body);
    if (!m) continue;
    const quote = sentence(body, m.index + m[1].length, name.length);
    if (quote.length >= 20) return id === own ? { quote } : { quote, articleId: id };
  }
  return null;
}

let kept = 0, toOne = 0, toTwo = 0, stuck = [];
for (const { j } of files) for (const c of j.cases) {
  if (c.mode !== 'analyst' || !checkCase(c, byId).length) continue;
  const a = byId[c.culprit];
  const before = c.clues.length;
  c.clues = c.clues.filter(k => !k.facts?.name && !names(a).some(n => says(k.text, n)));
  const idle = (k, i) => { const l = ladder(c, byId); return Object.keys(k.facts || {}).join() === 'family' && i > 0 && l[i] === l[i - 1]; };
  for (let i; (i = c.clues.findIndex(idle)) >= 0;) c.clues.splice(i, 1);
  if (c.clues.length === before && ladder(c, byId).at(-1) === 1) { kept++; continue; }
  let best = null;
  for (const family of [...new Set(names(a).map(n => [...CS, ...MS].find(f => n.endsWith(' ' + f))).filter(Boolean))]) {
    const fit = ladder({ ...c, clues: [...c.clues, { facts: { family } }] }, byId).at(-1);
    if (fit >= ladder(c, byId).at(-1) || (best && best.fit <= fit)) continue;
    const name = names(a).find(n => n.endsWith(' ' + family) && cite(n, c.article));
    if (name) best = { fit, clue: { kind: 'tipoff', text: hint(family), facts: { family }, source: { ...cite(name, c.article), note: `${name} is the culprit's ${CS.includes(family) ? 'CrowdStrike' : 'Microsoft'} name.` } } };
  }
  if (best && c.clues.length >= ANALYST_MAX_CLUES) {
    const i = c.clues.findLastIndex(k => !Object.keys(k.facts || {}).length);
    if (i >= 0) c.clues.splice(i, 1); else best = null;
  }
  if (best) c.clues.push(best.clue);
  const end = ladder(c, byId).at(-1);
  if (end === 1) toOne++; else if (end <= CLOSE_MAX) toTwo++; else stuck.push(`${c.id} ${a.name} ends at ${end}`);
}
for (const { f, j } of files) writeFileSync(new URL(f, dir), JSON.stringify(j, null, 1) + '\n');
console.log(`SOC Analyst: already closed ${kept}, closed at 1 ${toOne}, at 2 ${toTwo}, cannot get to ${CLOSE_MAX} or fewer ${stuck.length}`);
for (const s of stuck) console.log('  ' + s);
