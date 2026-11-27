// Applies editors' case-review verdicts to the drafts. Safe to rerun.
// Usage: node tools/apply-review.mjs <verdict dir>   (every *.json in it, in name order; a later file overrides an earlier one)
//   Verdict = { id, culprit, verdict: 'approve' | 'fix' | 'reject', issues: string[], fixes: Fix[] }
//   Fix     = { clue, field, to }   clue is 1-based in the reviewed case; 0 means the case.
//     text | kind      clue text or kind
//     facts            "home: RU; targets: Healthcare, Telecommunications", a facts object or its JSON; replaces the clue's facts
//     source           { quote, note?, articleId? }; replaces the clue's source
//     story | date     the case story, or report.date (YYYY-MM-DD or null)
//     order            "1,2,4,3": reviewed clue numbers in their new order; a clue left out is dropped. Any clue number means the case.
//   A reject drops the case.
// The first run writes data/review-baseline.json (case id -> hash of the case the editors reviewed). A case is fixed only
// while it still matches its baseline, so a rerun skips what it already changed. Export marks a case REVISED once it differs.
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { caseHash } from './export.mjs';

const dir = process.argv[2];
if (!dir) { console.error('usage: node tools/apply-review.mjs <verdict dir>'); process.exit(1); }
const root = new URL('../data/', import.meta.url), drafts = new URL('drafts/', root), baseFile = new URL('review-baseline.json', root);
const batches = readdirSync(drafts).filter(f => f.endsWith('.json')).sort().map(f => ({ f, j: JSON.parse(readFileSync(new URL(f, drafts), 'utf8')) }));
const all = batches.flatMap(b => b.j.cases);
if (!existsSync(baseFile)) writeFileSync(baseFile, JSON.stringify(Object.fromEntries(all.map(c => [c.id, caseHash(c)])), null, 1) + '\n');
const baseline = JSON.parse(readFileSync(baseFile, 'utf8'));

const ARRAY = new Set(['targets', 'tools']), SINGLE = new Set(['home', 'type', 'motive', 'family', 'name']);
function parseFacts(to) {
  if (to && typeof to === 'object') return to;
  if (/^s*{/.test(to)) return JSON.parse(to);
  const facts = {};
  for (const part of String(to).split(';').map(s => s.trim()).filter(Boolean)) {
    const [, key, rest] = /^(\w+)\s*:\s*(.+)$/.exec(part) || [];
    const vals = (rest || '').split(',').map(s => s.trim()).filter(Boolean);
    if (ARRAY.has(key)) facts[key] = vals;
    else if (SINGLE.has(key) && vals.length === 1) facts[key] = vals[0];
    else throw new Error(`cannot read facts "${part}"`);
  }
  return facts;
}
const orderOf = to => (Array.isArray(to) ? to : String(to).split(',')).map(Number);

// Verdicts per case, in file order. Later files win on the same (clue, field).
const files = readdirSync(dir).filter(f => f.endsWith('.json')).sort();
const byCase = new Map();
for (const f of files) for (const v of JSON.parse(readFileSync(new URL(f, `file:///${dir.replace(/\\/g, '/').replace(/\/?$/, '/')}`), 'utf8')))
  (byCase.get(v.id) || byCase.set(v.id, []).get(v.id)).push({ ...v, file: f });

const log = [], tally = { fixed: 0, fixes: 0, dropped: 0, skipped: 0, overrides: 0, failed: 0 };
for (const [id, verdicts] of byCase) {
  const batch = batches.find(b => b.j.cases.some(c => c.id === id));
  const c = batch?.j.cases.find(x => x.id === id);
  if (!c) { log.push(`${id}: not in the drafts (already dropped)`); continue; }
  if (caseHash(c) !== baseline[id]) { tally.skipped++; log.push(`${id}: changed since review, skipped`); continue; }
  if (verdicts.some(v => v.verdict === 'reject') && !verdicts.some(v => v.verdict === 'fix')) {
    batch.j.cases = batch.j.cases.filter(x => x !== c);
    tally.dropped++;
    log.push(`${id}: rejected, dropped (${verdicts.filter(v => v.verdict === 'reject').map(v => v.file).join(', ')})`);
    continue;
  }
  const fixes = new Map();
  for (const v of verdicts) for (const x of v.fixes || []) {
    const key = x.field === 'order' || x.field === 'story' || x.field === 'date' ? `0.${x.field}` : `${x.clue}.${x.field}`;
    if (fixes.has(key)) { tally.overrides++; log.push(`${id}: ${v.file} overrides ${fixes.get(key).file} on ${key}`); }
    fixes.set(key, { ...x, file: v.file });
  }
  if (!fixes.size) continue;
  const reviewed = c.clues.map(k => structuredClone(k));
  const clues = reviewed.map(k => structuredClone(k));
  let order = null, bad = [];
  for (const x of fixes.values()) {
    try {
      if (x.field === 'order') { order = orderOf(x.to); continue; }
      if (x.field === 'story') { c.story = x.to; continue; }
      if (x.field === 'date') { c.report = { ...c.report, date: x.to }; continue; }
      const k = clues[x.clue - 1];
      if (!k) throw new Error(`clue ${x.clue} does not exist`);
      if (x.field === 'text') k.text = x.to;
      else if (x.field === 'kind') k.kind = x.to;
      else if (x.field === 'facts') k.facts = parseFacts(x.to);
      else if (x.field === 'source') k.source = x.to;
      else throw new Error(`unknown field ${x.field}`);
    } catch (e) { bad.push(`${x.file} clue ${x.clue} ${x.field}: ${e.message}`); }
  }
  if (order && (order.some(n => !clues[n - 1]) || new Set(order).size !== order.length)) { bad.push(`order ${order} does not fit ${clues.length} clues`); order = null; }
  if (bad.length) { tally.failed++; log.push(`${id}: NOT APPLIED: ${bad.join('; ')}`); continue; }
  c.clues = order ? order.map(n => clues[n - 1]) : clues;
  tally.fixed++; tally.fixes += fixes.size;
  log.push(`${id}: ${fixes.size} fixes${order ? `, order ${order.join(',')}${order.length < reviewed.length ? ` (dropped ${reviewed.length - order.length})` : ''}` : ''} (${[...new Set([...fixes.values()].map(x => x.file))].join(', ')})`);
}
for (const { f, j } of batches) writeFileSync(new URL(f, drafts), JSON.stringify(j, null, 1) + '\n');
console.log(log.join('\n'));
console.log(`\nfixed ${tally.fixed} cases with ${tally.fixes} fixes, dropped ${tally.dropped}, skipped ${tally.skipped} already changed, ${tally.overrides} overrides, ${tally.failed} not applied`);
if (tally.failed) process.exitCode = 1;
