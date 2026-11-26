// Builds the game data from the OPTIC/ATT&CK extraction and the drafted cases. Safe to rerun.
//   data/source/attack-actors.json  every ATT&CK 20.1 group with country, year, motive, targets, tools and tricks
//                                   (extracted from ATT&CK, Threatdle/MISP and OPTIC by the 2026-11-26 audit scripts)
//   data/source/roster.json         Most Wanted ids;  data/source/overrides.json  hand-filled facts
//   data/source/aliases.json        names ATT&CK lacks, from the MISP galaxy (tools/fill-aliases.mjs)
//   data/drafts/*.json              drafted cases, one file per batch;  data/approved.json  case id -> hash of the approved case
// Writes data/pool.json (server), public/pool.json (client, no tools or tricks), data/cases.json and data/review.md.
// Usage: node tools/export.mjs
import { readFileSync, writeFileSync, readdirSync, renameSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { checkCase, ladder } from './check-cases.mjs';
import { FAMILIES } from '../public/js/rules.mjs';

const read = p => JSON.parse(readFileSync(new URL('../' + p, import.meta.url), 'utf8'));
const write = (p, s) => { const f = new URL('../' + p, import.meta.url), t = new URL(f.href + '.tmp'); writeFileSync(t, s); renameSync(t, f); };
const json = o => JSON.stringify(o, null, 1) + '\n';

// ---------- pool ----------
// The nickname is the group's CrowdStrike name, else its Microsoft name, from ATT&CK's names first and the filled ones after.
const suffix = n => (/^[A-Z][A-Za-z]+ ([A-Z][a-z]+)$/.exec(n || '') || [])[1];
const nickname = names => { for (const sys of Object.values(FAMILIES)) { const hit = names.find(n => sys.includes(suffix(n))); if (hit) return hit; } return null; };
const typeOf = m => (m.includes('Espionage') || m.includes('Sabotage') ? 'state' : m.includes('Financial Gain') ? 'crime' : m.includes('Hacktivism') ? 'activist' : null);

// Hand-written profiles for groups a casual player may have read about. Each stays true to the group's home and motive.
const PROFILE = {
  G0007: 'Russian military intelligence hackers', G0016: 'Russian foreign intelligence hackers', G0034: 'Russian military saboteurs who black out power grids',
  G0010: 'Russian security-service spies', G0032: 'North Korean state hackers and bank robbers', G0094: 'North Korean spies who phish think tanks',
  G0096: 'Chinese state spies who also hack for money', G1017: 'Chinese hackers who pre-position in utilities', G0069: "Iran's intelligence-ministry hackers",
  G0059: 'Iranian spies who pose as journalists', G1015: 'Young English-speaking crew that phones help desks', G0046: 'Card-stealing crime gang that hit restaurants',
  G0102: 'Russian-speaking ransomware crew', G0047: 'Russian spies who hammer Ukraine', G0129: 'Chinese spies who target Asian governments',
};
const DEMONYM = { RU: 'Russian', CN: 'Chinese', IR: 'Iranian', KP: 'North Korean', KR: 'South Korean', PS: 'Palestinian', LB: 'Lebanese', TR: 'Turkish', VN: 'Vietnamese',
  IN: 'Indian', PK: 'Pakistani', BY: 'Belarusian', BR: 'Brazilian', US: 'American', AE: 'Emirati', NG: 'Nigerian', RO: 'Romanian' };
const MOTIVE = { Espionage: 'state spies', 'Financial Gain': 'cybercrime gang', Sabotage: 'saboteurs', Hacktivism: 'hacktivists' };
const MIXED = { 'Espionage+Financial Gain': 'state spies who also steal money', 'Espionage+Sabotage': 'state spies and saboteurs',
  'Financial Gain+Sabotage': 'thieves and saboteurs', 'Espionage+Financial Gain+Sabotage': 'spies, thieves and saboteurs' };
function profile(a) {
  if (PROFILE[a.id]) return PROFILE[a.id];
  const mot = a.motive.filter(m => MOTIVE[m]);
  const s = mot.length === 1 ? MOTIVE[mot[0]] : MIXED[[...mot].sort().join('+')] || (mot.length ? mot.map(m => MOTIVE[m]).join(' and ') : 'hackers');
  const dem = DEMONYM[a.home];
  return dem ? `${dem} ${s}` : s[0].toUpperCase() + s.slice(1);
}

// A group's public card carries every fact a drafted clue states about it (the spec's "fold the fact into the card").
// Otherwise a player who checks the Browse card against a clue would rule out the real culprit.
export function buildPool() {
  const src = read('data/source/attack-actors.json'), roster = new Set(read('data/source/roster.json').ids), over = read('data/source/overrides.json').actors;
  const filled = read('data/source/aliases.json').actors;
  const facts = {};
  for (const c of readDrafts()) for (const k of c.clues) (facts[c.culprit] ||= []).push(k.facts || {});
  const actors = src.map(r => {
    const o = over[r.attack_id] || {};
    const a = {
      id: r.attack_id, name: r.name, nickname: null, aliases: [...new Set([...r.aliases, ...(filled[r.attack_id]?.add || [])])].filter(x => x !== r.name),
      home: o.home ?? (r.country && r.country !== 'UN' ? r.country : null), type: null, motive: o.motive ?? r.motivation ?? [],
      since: o.since ?? r.first_seen_year ?? null, targets: o.targets ?? r.targets ?? [], profile: '', roster: roster.has(r.attack_id),
      tools: r.malware_ids, tricks: r.technique_ids,
    };
    a.type = o.type ?? typeOf(a.motive);
    for (const f of facts[a.id] || []) {
      for (const t of f.targets || []) if (!a.targets.includes(t)) a.targets = [...a.targets, t];
      if (f.motive && !a.motive.includes(f.motive)) a.motive = [...a.motive, f.motive];
      for (const t of f.tools || []) if (!a.tools.includes(t)) a.tools = [...a.tools, t];
      a.home ??= f.home ?? null;
      a.type ??= f.type ?? null;
    }
    a.type ??= typeOf(a.motive);
    a.nickname = nickname([r.name, ...r.aliases]) || nickname(a.aliases);
    a.profile = profile(a);
    return a;
  });
  return { version: createHash('sha256').update(JSON.stringify(actors)).digest('hex').slice(0, 10), actors };
}

// ---------- cases ----------
export const caseHash = c => createHash('sha256').update(JSON.stringify({ ...c, reviewed: undefined })).digest('hex').slice(0, 16);

function readDrafts() {
  const dir = new URL('../data/drafts/', import.meta.url);
  const files = existsSync(dir) ? readdirSync(dir).filter(f => f.endsWith('.json')).sort() : [];
  return files.flatMap(f => read('data/drafts/' + f).cases.map(c => ({ ...c, batch: f.replace(/\.json$/, '') })));
}

export function buildCases() {
  const approved = existsSync(new URL('../data/approved.json', import.meta.url)) ? read('data/approved.json') : {};
  return readDrafts().map(({ batch, ...c }) => ({ ...c, reviewed: approved[c.id] === caseHash(c), batch }));
}

// ---------- review sheet ----------
const FACT = f => Object.entries(f || {}).map(([k, v]) => `${k}: ${[].concat(v).join(', ')}`).join('; ');
const cell = s => String(s ?? '').replace(/\|/g, '\\|').replace(/\s+/g, ' ').trim();
function review(cases, byId, problems) {
  const out = ['# Threatdle case review', '',
    'Each case below shows the rewrite a player sees next to the vendor quote it came from. Check that each rewrite is true to its quote, adds no facts, and does not name the culprit early.',
    '', 'Approve cases with `node tools/approve.mjs <case id> ...`. An approval pins the exact text; editing an approved case later puts it back in this queue.',
    `Only approved cases are scheduled. Cases: ${cases.length}, approved: ${cases.filter(c => c.reviewed).length}.`, ''];
  for (const mode of ['analyst', 'hunter']) {
    const list = cases.filter(c => c.mode === mode);
    out.push(`## ${mode === 'analyst' ? 'SOC Analyst' : 'Threat Hunter'} (${list.length})`, '');
    for (const c of list) {
      const a = byId[c.culprit], fit = mode === 'analyst' ? ladder(c, byId) : null, bad = problems.get(c.id) || [];
      out.push(`### ${c.id} · ${a.name}${a.nickname ? ` (${a.nickname})` : ''} · ${c.reviewed ? 'approved' : 'NOT REVIEWED'}`, '',
        `Report: [${cell(c.report.title)}](${c.report.url}) · ${c.report.vendor} · ${c.report.date}`, '');
      if (fit) out.push(`Most Wanted groups that still fit after each clue: ${fit.join(' → ')}`, '');
      if (bad.length) out.push(`**Check failures:** ${bad.join('; ')}`, '');
      out.push('| # | Kind | Player sees | Facts | Source quote |', '| --- | --- | --- | --- | --- |');
      c.clues.forEach((k, i) => out.push(`| ${i + 1} | ${k.kind} | ${cell(k.text)} | ${cell(FACT(k.facts))} | ${cell(k.source.quote)}${k.source.note ? ` **Note:** ${cell(k.source.note)}` : ""} |`));
      out.push('', `What happened: ${c.story}`, '');
    }
  }
  return out.join('\n');
}

if (import.meta.main) {
  const pool = buildPool();
  const byId = Object.fromEntries(pool.actors.map(a => [a.id, a]));
  const cases = buildCases();
  const problems = new Map(cases.map(c => [c.id, checkCase(c, byId, cases)]));
  write('data/pool.json', json(pool));
  write('public/pool.json', JSON.stringify({ version: pool.version, actors: pool.actors.map(({ tools, tricks, ...a }) => a) }) + '\n');
  write('data/cases.json', json({ cases: cases.map(({ batch, ...c }) => c) }));
  write('data/review.md', review(cases, byId, problems));
  const n = m => cases.filter(c => c.mode === m).length;
  const failing = [...problems.values()].filter(p => p.length).length;
  console.log(`pool: ${pool.actors.length} actors, roster ${pool.actors.filter(a => a.roster).length}`);
  console.log(`cases: analyst ${n('analyst')}, hunter ${n('hunter')}, approved ${cases.filter(c => c.reviewed).length}, failing checks ${failing}`);
}
