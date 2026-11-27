// Checks drafted cases: shape, facts, leaks, verbatim vendor text, and the SOC Analyst elimination ladder.
// Usage: node tools/check-cases.mjs [data/drafts/batch.json ...]   (no args = every draft). Exits 1 on any failure.
import { readFileSync } from 'node:fs';
import { KINDS, COUNTRY, TYPES, MOTIVES, SECTORS, isMode, isDay, fits } from '../public/js/rules.mjs';
import { buildPool, buildCases } from './export.mjs';

// HOME_FROM: in SOC Analyst no clue before clue 3 gives the culprit's country or naming family. Opening on "tied to Iran"
// left 7 of 52 groups, and the Browse sheet is grouped by country, so the first guess was nearly free.
export const LADDER_AT = 4, LADDER_MAX = 5, ANALYST_MAX_CLUES = 7, HOME_FROM = 3, CLOSE_MAX = 2;
// A clue gives the country when its facts say so or its words name the culprit's own country ("Russia's military spy agency").
// A victim's country ("went after Ukraine") is left to the player to reason about.
const OWN = { RU: 'Russia|Russian|Moscow|Kremlin', CN: 'China|Chinese|Beijing', IR: 'Iran|Iranian|Tehran', KP: 'North Korea|North Korean|Pyongyang' };
const namesHome = (text, home) => Boolean(home) && new RegExp(`\\b(?:${OWN[home] || COUNTRY[home]})\\b`, 'i').test(text);
export const homeAt = (c, byId) => c.clues.findIndex(k => k.facts?.home || k.facts?.family || namesHome(k.text, byId[c.culprit]?.home)) + 1 || Infinity;
// A clue that points back at an earlier one ("the same group", "also", "another of its interests", "that country's spy service")
// cannot open a case.
export const LEANS_BACK = /\b(?:also|another|again|same|too|as well|th(?:at|e) (?:country|government|nation|state)(?:'s)?)\b/i;
const SOFTWARE = new Set(JSON.parse(readFileSync(new URL('../data/source/attack-software.json', import.meta.url), 'utf8')).map(s => s.id));

// Most Wanted groups that still fit after each clue, on facts a player can see. The culprit always counts.
export function ladder(c, byId) {
  const roster = Object.values(byId).filter(a => a.roster && a.id !== c.culprit);
  return c.clues.map((_, i) => 1 + roster.filter(a => c.clues.slice(0, i + 1).every(k => fits(a, k.facts))).length);
}

// Groups that fit the first n clues: the Most Wanted in SOC Analyst, every group in Threat Hunter. The culprit counts.
export function fitAfter(c, byId, n) {
  const pool = Object.values(byId).filter(a => (c.mode === 'hunter' || a.roster) && a.id !== c.culprit);
  return 1 + pool.filter(a => c.clues.slice(0, n).every(k => fits(a, k.facts))).length;
}
// Does the clue say something no earlier clue said? A clue with no facts is a tradecraft detail, which is new by itself.
// A family hint is never new on its own: it only counts if it narrows.
function newFact(f = {}, earlier) {
  if (!Object.keys(f).length) return true;
  return Object.entries(f).some(([key, v]) => key !== 'family'
    && [].concat(v).some(x => !earlier.some(k => [].concat(k.facts?.[key] ?? []).includes(x))));
}
// The last clue is the player's last help: it must narrow the field or say something no earlier clue said.
export function deadCloser(c, byId) {
  const n = c.clues.length;
  return n > 1 && fitAfter(c, byId, n) >= fitAfter(c, byId, n - 1) && !newFact(c.clues[n - 1].facts, c.clues.slice(0, -1));
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
  family: v => /^[A-Z][a-z]+$/.test(v),
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
  if (c.mode === 'hunter' ? n !== 6 : n < LADDER_AT || n > ANALYST_MAX_CLUES) bad.push(`${n} clues (${c.mode === 'hunter' ? 'need 6' : `need ${LADDER_AT}-${ANALYST_MAX_CLUES}`})`);
  (c.clues || []).forEach((k, i) => {
    const at = `clue ${i + 1}`, f = k.facts || {};
    if (!KINDS[k.kind]) bad.push(`${at}: unknown kind ${k.kind}`);
    if (!k.text || k.text.length > 170) bad.push(`${at}: text missing or over 170 characters`);
    if (!k.source || !k.source.quote || k.source.quote.length < 20) bad.push(`${at}: source quote missing`);
    for (const [key, v] of Object.entries(f)) if (!FACTS[key] || !FACTS[key](v)) bad.push(`${at}: bad fact ${key}=${JSON.stringify(v)}`);
    if (f.home && a.home && f.home !== a.home) bad.push(`${at}: says home ${f.home}, the culprit is ${a.home}`);
    if (f.type && a.type && f.type !== a.type) bad.push(`${at}: says ${f.type}, the culprit is ${a.type}`);
    if (f.name && !names(a).concat(a.name).some(x => x.toLowerCase() === f.name.toLowerCase())) bad.push(`${at}: name ${f.name} is not the culprit's`);
    if (f.name) bad.push(`${at}: a clue never names the group`);
    if (!fits(a, f)) bad.push(`${at}: the culprit's public card contradicts this clue`);
    const leak = names(a).find(x => mentions(k.text || '', x));
    // No clue in either mode states the answer: a name as clue 6 hands a Threat Hunter a free last guess.
    if (leak) bad.push(`${at}: names the culprit (${leak})`);
    if (k.source && sharedRun(k.text || '', k.source.quote || '') >= 6) bad.push(`${at}: copies 6+ words of the vendor quote`);
  });
  if (c.mode === 'analyst' && n >= LADDER_AT) {
    const fit = ladder(c, byId)[LADDER_AT - 1];
    if (fit > LADDER_MAX) bad.push(`ladder: ${fit} Most Wanted groups still fit after clue ${LADDER_AT} (max ${LADDER_MAX})`);
    if (homeAt(c, byId) < HOME_FROM) bad.push(`opening: clue ${homeAt(c, byId)} gives the country or naming family (not before clue ${HOME_FROM})`);
    if (LEANS_BACK.test(c.clues[0].text)) bad.push('opening: clue 1 points back at an earlier clue');
    const last = ladder(c, byId).at(-1);
    if (last > CLOSE_MAX) bad.push(`closing: ${last} Most Wanted groups still fit after the last clue (max ${CLOSE_MAX})`);
  }
  if (n > 1 && deadCloser(c, byId)) bad.push(`closing: the last clue rules out no group (${fitAfter(c, byId, n)} fit) and states no new fact`);
  const sentences = (c.story || '').replace(/\b(?:[A-Z]\.){2,}/g, 'X').split(/(?<=[.!?])\s+(?=[A-Z0-9"'])/).filter(Boolean).length;
  if (sentences < 2 || sentences > 3 || c.story.length > 480) bad.push(`story has ${sentences} sentences or is too long`);
  const r = c.report || {};
  // Some vendor pages (Sophos threat profiles) carry no publish date: date is null then, never a made-up day.
  if (!r.vendor || !r.title || !/^https:\/\//.test(r.url || '') || !(r.date === null || isDay(r.date))) bad.push('report needs vendor, title, https url and a date or null');
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
