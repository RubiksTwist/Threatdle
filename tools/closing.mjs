// Adds a closing clue to every SOC Analyst draft whose clues leave more than one Most Wanted group, so the case always ends solvable.
// The clue quotes the article's own sentence that names the group. It gives the vendor naming family ("a name ending in Tempest")
// when that alone closes the case, else the name itself. Safe to rerun: a case that already closes is left alone.
// Usage: node tools/closing.mjs <bodies.jsonl.gz>   (the OPTIC article bodies from the extraction)
import { readFileSync, writeFileSync, readdirSync, createReadStream } from 'node:fs';
import { createGunzip } from 'node:zlib';
import { createInterface } from 'node:readline';
import { buildPool } from './export.mjs';
import { ladder, ANALYST_MAX_CLUES } from './check-cases.mjs';

const FAMILIES = ['Bear', 'Panda', 'Kitten', 'Chollima', 'Spider', 'Tiger', 'Leopard', 'Buffalo', 'Jackal', 'Crane', 'Wolf', 'Ocelot', 'Hawk', 'Lynx', 'Saiga',
  'Blizzard', 'Typhoon', 'Sandstorm', 'Sleet', 'Tempest', 'Hail', 'Dust', 'Cyclone', 'Rain', 'Flood', 'Tsunami'];
const bodiesFile = process.argv[2];
if (!bodiesFile) { console.error('usage: node tools/closing.mjs <bodies.jsonl.gz>'); process.exit(1); }

const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
const dir = new URL('../data/drafts/', import.meta.url);
const files = readdirSync(dir).filter(f => f.endsWith('.json')).map(f => ({ f, j: JSON.parse(readFileSync(new URL(f, dir), 'utf8')) }));
const open = files.flatMap(({ j }) => j.cases).filter(c => c.mode === 'analyst' && ladder(c, byId).at(-1) !== 1);
const want = new Set(open.map(c => c.article));
const bodies = new Map();
for await (const line of createInterface({ input: createReadStream(bodiesFile).pipe(createGunzip()) })) {
  const id = line.slice(15, 51);
  if (want.has(id)) bodies.set(id, JSON.parse(line).body_text || '');
}

// The sentence around position i, as an exact slice of the body.
function sentence(body, i, len) {
  let a = i, b = i + len;
  while (a > 0 && !/[.!?\n]/.test(body[a - 1]) && i - a < 220) a--;
  while (b < body.length && !/[.!?\n]/.test(body[b]) && b - i < 220) b++;
  if (b < body.length && /[.!?]/.test(body[b])) b++;
  return body.slice(a, b).trim();
}
const stem = a => /^(.+) (Team|Group)$/.exec(a.name)?.[1];
// Every place the article names the culprit, with the quote around it.
function namings(a, body) {
  const out = [];
  // Vendors write names in capitals (SCATTERED SPIDER) or drop a trailing Team/Group (Sandworm), so match without case and with the stem.
  for (const alias of [...new Set([a.nickname, ...a.aliases, a.name, stem(a)].filter(n => n && n.length >= 4))]) {
    const re = new RegExp(`(^|[^A-Za-z0-9])${alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?![A-Za-z0-9])`, 'i');
    const m = re.exec(body);
    if (m) out.push({ alias, quote: sentence(body, m.index + m[1].length, alias.length) });
  }
  return out.filter(x => x.quote.length >= 20);
}

let fam = 0, named = 0, none = [];
for (const c of open) {
  const a = byId[c.culprit], found = namings(a, bodies.get(c.article) || '');
  const close = clue => ladder({ ...c, clues: [...c.clues, clue] }, byId).at(-1) === 1;
  let clue = null;
  for (const { alias, quote } of found) {
    const family = FAMILIES.find(s => alias.endsWith(' ' + s));
    const k = family && { kind: 'tipoff', text: `In the report, the group's name ends in "${family}".`, facts: { family }, source: { quote } };
    if (k && close(k)) { clue = k; fam++; break; }
  }
  if (!clue && found.length) {
    // Prefer a vendor name over the group's best-known one, so the last clue is a decode, not a giveaway.
    const pick = found.find(x => x.alias !== (a.nickname || a.name)) || found[0];
    clue = { kind: 'tipoff', text: `The report names the group: ${pick.alias}.`, facts: { name: pick.alias === stem(a) ? a.name : pick.alias }, source: { quote: pick.quote } };
    named++;
  }
  if (!clue) { none.push(c.id); continue; }
  if (c.clues.length >= ANALYST_MAX_CLUES) c.clues.splice(c.clues.findLastIndex((k, i) => i >= 4 && !Object.keys(k.facts || {}).length), 1);
  c.clues.push(clue);
}
for (const { f, j } of files) writeFileSync(new URL(f, dir), JSON.stringify(j, null, 1) + '\n');
console.log(`open cases ${open.length}: closed by family ${fam}, by name ${named}, no naming sentence ${none.length}${none.length ? ' (' + none.join(' ') + ')' : ''}`);
