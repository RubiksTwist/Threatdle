// Writes one reading packet per OPTIC case candidate, for whoever drafts the plain-English clues.
// Inputs come from the OPTIC extraction (gameloop-work in the 2026-11-26 audit): candidate days and gzipped article bodies.
// Usage: node tools/packets.mjs <b_days_all.json> <bodies.jsonl.gz> <out dir> [article id prefix ...]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
// Bodies split on newlines only: some hold a raw carriage return, which a line reader would break on.
import { buildPool } from './export.mjs';

const [daysFile, bodiesFile, outDir, ...want] = process.argv.slice(2);
if (!outDir) { console.error('usage: node tools/packets.mjs <b_days_all.json> <bodies.jsonl.gz> <out dir> [article id prefix ...]'); process.exit(1); }
const days = JSON.parse(readFileSync(daysFile, 'utf8')).filter(d => !want.length || want.some(w => d.article_id.startsWith(w)));
const ids = new Set(days.map(d => d.article_id));
const bodies = new Map();
for (const line of gunzipSync(readFileSync(bodiesFile)).toString('utf8').split(String.fromCharCode(10))) {
  const id = line.slice(15, 51);
  if (ids.has(id)) bodies.set(id, JSON.parse(line).body_text || '');
}
const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
mkdirSync(outDir, { recursive: true });
for (const d of days) {
  const a = byId[d.answer.attack_id];
  const body = (bodies.get(d.article_id) || '').replace(/\n{3,}/g, '\n\n');
  const text = [
    `=== case c-${d.article_id.slice(0, 8)} | article ${d.article_id}`,
    `culprit ${a.id} ${a.name}${a.nickname ? ` (${a.nickname})` : ''} | Most Wanted: ${a.roster ? 'yes' : 'no'}`,
    `pool facts: home ${a.home ?? '?'} | type ${a.type ?? '?'} | motive ${a.motive.join(', ') || '?'} | since ${a.since ?? '?'} | targets ${a.targets.join(', ') || '?'}`,
    `aliases (never in a clue before a name clue): ${[a.name, ...a.aliases].join(', ')}`,
    `report: ${d.article.vendor} | ${d.article.publication_date} | ${d.article.title} | ${d.article.url}`,
    '', 'OPTIC candidate quotes ([ACTOR]/[MALWARE] redacted):',
    ...d.clues.filter(c => c.kind !== 'source').map(c => `- ${c.kind} | ${c.label} | ${c.text_redacted}`),
    '', `ARTICLE BODY (${body.length} chars${body.length > 14000 ? ', first 14000 shown' : ''}):`, body.slice(0, 14000),
  ].join('\n');
  writeFileSync(`${outDir}/c-${d.article_id.slice(0, 8)}.txt`, text + '\n');
}
console.log(`${days.length} packets in ${outDir}`);
