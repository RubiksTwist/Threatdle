// Fills group names ATT&CK leaves out (CrowdStrike and Microsoft names, Google's HOODOO...) from the MISP threat-actor galaxy.
// Writes data/source/aliases.json, which export adds to each group's aliases. Safe to rerun.
// Usage: node tools/fill-aliases.mjs <misp galaxy threat-actor.json>
// A MISP entry maps to an ATT&CK group when its own name is that group's ATT&CK name or alias, else by the one group id
// it cites (a G-number synonym or an attack.mitre.org/groups ref). A name is added only when no other ATT&CK group already
// carries it and no other mapped MISP entry claims it, so a lumped MISP entry cannot move a name between groups.
import { readFileSync, writeFileSync } from 'node:fs';

const file = process.argv[2];
if (!file) { console.error('usage: node tools/fill-aliases.mjs <threat-actor.json>'); process.exit(1); }
const galaxy = JSON.parse(readFileSync(file, 'utf8'));
const groups = JSON.parse(readFileSync(new URL('../data/source/attack-actors.json', import.meta.url), 'utf8'));
const key = n => n.toLowerCase().replace(/[\s_-]+/g, ' ').trim();

const owner = new Map();  // ATT&CK name or alias -> group ids
for (const g of groups) for (const n of [g.name, ...g.aliases]) owner.set(key(n), [...new Set([...(owner.get(key(n)) || []), g.attack_id])]);
const ids = new Set(groups.map(g => g.attack_id));

const claims = new Map();  // name key -> Set of group ids MISP gives it to
const mapped = [];
for (const v of galaxy.values) {
  const syn = v.meta?.synonyms || [];
  const cited = new Set([...syn.filter(s => /^G\d{4}$/.test(s)), ...(v.meta?.refs || []).map(r => (/attack\.mitre\.org\/groups\/(G\d{4})/.exec(r) || [])[1])]
    .filter(x => x && ids.has(x)));
  const byName = owner.get(key(v.value)) || [];
  const id = byName.length === 1 ? byName[0] : cited.size === 1 && !byName.length ? [...cited][0] : null;
  if (!id) continue;
  const names = [v.value, ...syn].filter(n => !/^G\d{4}$/.test(n) && n.trim().length >= 3);
  mapped.push({ id, misp: v.value, names });
  for (const n of names) (claims.get(key(n)) || claims.set(key(n), new Set()).get(key(n))).add(id);
}

const actors = {};
let skipped = 0;
for (const { id, misp, names } of mapped) {
  for (const n of names) {
    const k = key(n), own = owner.get(k) || [];
    if (own.includes(id)) continue;  // ATT&CK already has it
    if (own.length || claims.get(k).size > 1) { skipped++; continue; }
    const a = (actors[id] ||= { misp: [], add: [] });
    if (!a.misp.includes(misp)) a.misp.push(misp);
    if (!a.add.some(x => key(x) === k)) a.add.push(n);
  }
}
const out = { source: `MISP threat-actor galaxy version ${galaxy.version} (${galaxy.uuid})`, actors: Object.fromEntries(Object.entries(actors).sort()) };
writeFileSync(new URL('../data/source/aliases.json', import.meta.url), JSON.stringify(out, null, 1) + '\n');
const added = Object.values(actors).reduce((s, a) => s + a.add.length, 0);
console.log(`MISP entries mapped to ATT&CK groups ${mapped.length}; added ${added} names to ${Object.keys(actors).length} groups; skipped ${skipped} names another group holds or shares`);
