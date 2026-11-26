// Checks drafted cases: shape, facts, leaks, verbatim vendor text, and the SOC Analyst elimination ladder.
// Usage: node tools/check-cases.mjs [data/drafts/batch.json ...]   (no args = every draft). Exits 1 on any failure.
import { readFileSync } from 'node:fs';
import { KINDS, COUNTRY, TYPES, MOTIVES, SECTORS, isMode, isDay, fits } from '../public/js/rules.mjs';
import { buildPool, buildCases } from './export.mjs';

export const LADDER_AT = 4, LADDER_MAX = 5;
const SOFTWARE = new Set(JSON.parse(readFileSync(new URL('../data/source/attack-software.json', import.meta.url), 'utf8')).map(s => s.id));

// Most Wanted groups that still fit after each clue, on facts a player can see. The culprit always counts.
export function ladder(c, byId) {
  const roster = Object.values(byId).filter(a => a.roster && a.id !== c.culprit);
  return c.clues.map((_, i) => 1 + roster.filter(a => c.clues.slice(0, i + 1).every(k => fits(a, k.facts))).length);
}

const words = s => s.toLowerCase().replace(/[^a-z0-9$ ]+/g, ' ').split(/\s+/).filter(Boolean);
function sharedRun(a, b) {
  const x = words(a), y = words(b);
  let best = 0;
  for (let i = 0; i < x.length; i++) for (let j = 0; j < y.length; j++) {
    let k = 0;
    while (x[i + k] && x[i + k] === y[j + k]) k++;
    best = Math.max(best, k);
  }
  return best;
}
const names = a => [a.name, a.nickname, ...a.aliases].filter(n => n && n.length >= 4);
const mentions = (text, n) => new RegExp(`(^|[^A-Za-z0-9])${n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}([^A-Za-z0-9]|$)`, 'i').test(text);

const FACTS = {
  targets: v => Array.isArray(v) && v.length > 0 && v.every(s => SECTORS.includes(s)),
  home: v => Object.hasOwn(COUNTRY, v),
  type: v => TYPES.includes(v),
  motive: v => MOTIVES.includes(v),
  tools: v => Array.isArray(v) && v.length > 0 && v.every(s => SOFTWARE.has(s)),
  name: v => typeof v === 'string' && v.length > 1,
};

export function checkCase(c, byId, all = [c]) {
  const bad = [];
  if (!/^c-[0-9a-f]{8}$/.test(c.id || '')) bad.push('id must be c- plus 8 hex digits');
  if (all.filter(x => x.id === c.id).length > 1) bad.push('duplicate id');
  if (all.filter(x => x.report && c.report && x.report.url === c.report.url).length > 1) bad.push('report used by another case');
  if (!isMode(c.mode)) return [...bad, 'unknown mode'];
  const a = byId[c.culprit];
  if (!a) return [...bad, 'culprit not in the pool'];
  if (c.mode === 'analyst' && !a.roster) bad.push('analyst culprit is not on the Most Wanted');
  const n = c.clues?.length || 0;
  if (c.mode === 'hunter' ? n !== 6 : n < LADDER_AT || n > 6) bad.push(`${n} clues (${c.mode === 'hunter' ? 'need 6' : 'need 4-6'})`);
  (c.clues || []).forEach((k, i) => {
    const at = `clue ${i + 1}`, f = k.facts || {};
    if (!KINDS[k.kind]) bad.push(`${at}: unknown kind ${k.kind}`);
    if (!k.text || k.text.length > 170) bad.push(`${at}: text missing or over 170 characters`);
    if (!k.source || !k.source.quote || k.source.quote.length < 20) bad.push(`${at}: source quote missing`);
    for (const [key, v] of Object.entries(f)) if (!FACTS[key] || !FACTS[key](v)) bad.push(`${at}: bad fact ${key}=${JSON.stringify(v)}`);
    if (f.home && a.home && f.home !== a.home) bad.push(`${at}: says home ${f.home}, the culprit is ${a.home}`);
    if (f.type && a.type && f.type !== a.type) bad.push(`${at}: says ${f.type}, the culprit is ${a.type}`);
    if (f.name && !names(a).concat(a.name).some(x => x.toLowerCase() === f.name.toLowerCase())) bad.push(`${at}: name ${f.name} is not the culprit's`);
    if (f.name && i !== n - 1) bad.push(`${at}: a clue that names the group must come last`);
    if (!fits(a, f)) bad.push(`${at}: the culprit's public card contradicts this clue`);
    const leak = names(a).find(x => mentions(k.text || '', x));
    if (leak && !(f.name && i === n - 1)) bad.push(`${at}: names the culprit (${leak})`);
    if (k.source && sharedRun(k.text || '', k.source.quote || '') >= 6) bad.push(`${at}: copies 6+ words of the vendor quote`);
  });
  if (c.mode === 'analyst' && n >= LADDER_AT) {
    const fit = ladder(c, byId)[LADDER_AT - 1];
    if (fit > LADDER_MAX) bad.push(`ladder: ${fit} Most Wanted groups still fit after clue ${LADDER_AT} (max ${LADDER_MAX})`);
  }
  const sentences = (c.story || '').replace(/\b(?:[A-Z]\.){2,}/g, 'X').split(/(?<=[.!?])\s+(?=[A-Z0-9"'])/).filter(Boolean).length;
  if (sentences < 2 || sentences > 3 || c.story.length > 480) bad.push(`story has ${sentences} sentences or is too long`);
  const r = c.report || {};
  if (!r.vendor || !r.title || !/^https:\/\//.test(r.url || '') || !isDay(r.date)) bad.push('report needs vendor, title, https url and date');
  if (typeof c.article !== 'string' || c.article.length < 8) bad.push('missing OPTIC article id');
  return bad;
}

if (import.meta.main) {
  const pool = buildPool();
  const byId = Object.fromEntries(pool.actors.map(a => [a.id, a]));
  const every = buildCases();
  const files = process.argv.slice(2);
  const cases = files.length ? files.flatMap(f => JSON.parse(readFileSync(f, 'utf8')).cases) : every;
  let failed = 0;
  for (const c of cases) {
    const bad = checkCase(c, byId, files.length ? cases.concat(every.filter(x => !cases.some(y => y.id === x.id))) : every);
    const fit = c.mode === 'analyst' && byId[c.culprit] ? ` fit ${ladder(c, byId).join('>')}` : '';
    console.log(`${bad.length ? 'FAIL' : 'ok  '} ${c.id} ${c.mode} ${byId[c.culprit]?.name ?? c.culprit}${fit}${bad.length ? '\n     ' + bad.join('\n     ') : ''}`);
    if (bad.length) failed++;
  }
  const by = m => cases.filter(c => c.mode === m).length;
  console.log(`\n${cases.length} cases (analyst ${by('analyst')}, hunter ${by('hunter')}), ${failed} failing`);
  process.exit(failed ? 1 : 0);
}
