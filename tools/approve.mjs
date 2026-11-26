// Approves drafted cases after a human read them in data/review.md. Pins each to a hash of its exact content.
// Usage: node tools/approve.mjs c-1234abcd ... && node tools/export.mjs
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { buildPool, buildCases, caseHash } from './export.mjs';

const file = new URL('../data/approved.json', import.meta.url);
const approved = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : {};
const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
const cases = Object.fromEntries(buildCases(byId).map(({ reviewed, batch, ...c }) => [c.id, c]));
const ids = process.argv.slice(2);
const unknown = ids.filter(id => !cases[id]);
if (!ids.length || unknown.length) { console.error(ids.length ? `unknown case ids: ${unknown.join(' ')}` : 'usage: node tools/approve.mjs <case id> ...'); process.exit(1); }
for (const id of ids) approved[id] = caseHash(cases[id]);
writeFileSync(file, JSON.stringify(Object.fromEntries(Object.entries(approved).sort()), null, 1) + '\n');
console.log(`approved ${ids.length}; run node tools/export.mjs to refresh data/cases.json`);
