// Where each group's victims are, from the OPTIC article database (vendor reports with quoted, extracted relationships).
// ATT&CK records no victim countries; OPTIC does, as "actor targets country" and "campaign (attributed to actor) targets country".
// Usage: node tools/optic-victims.mjs   needs `ssh node3` (OPTIC's Postgres runs there in Docker container optic-postgres).
// Writes data/source/victims.json: per ATT&CK group, the victim countries most reported first, never its own home.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { buildPool } from './export.mjs';

// \copy takes one line, and ON_ERROR_STOP makes a bad query fail the run instead of printing an empty result.
const sql = q => execFileSync('ssh', ['node3', 'docker exec -i optic-postgres psql -v ON_ERROR_STOP=1 -U optic -d optic -At'],
  { input: `set search_path=optic;\n\\copy (${q.replace(/\s+/g, ' ')}) to stdout with (format csv, header)\n`, maxBuffer: 1 << 30, encoding: 'utf8' });
function csv(text) {
  const rows = []; let row = [], f = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += c; }
    else if (c === '"') q = true; else if (c === ',') { row.push(f); f = ''; }
    else if (c === '\n') { row.push(f.replace(/\r$/, '')); rows.push(row); row = []; f = ''; } else f += c;
  }
  return rows.filter(r => r.length > 1).slice(1); // drop psql's SET line and the header
}
const norm = s => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');

// Country names as extracted ("the Russian Federation", "U.S.", "Ukraine / Ukrainian theater of war") to ISO codes.
const dn = new Intl.DisplayNames(['en'], { type: 'region' });
const RETIRED = new Set(['UK', 'FX', 'EU', 'EZ', 'UN', 'QO', 'XA', 'XB', 'ZZ', 'DD', 'SU', 'YU', 'CS', 'BU', 'TP', 'ZR', 'DY', 'HV', 'NH', 'RH', 'VD', 'YD']);
const CC = {};
for (let a = 65; a < 91; a++) for (let b = 65; b < 91; b++) {
  const code = String.fromCharCode(a, b); let n; try { n = dn.of(code); } catch { continue; }
  if (n && n !== code && !RETIRED.has(code) && !CC[norm(n)]) CC[norm(n)] = code;
}
for (const [k, v] of Object.entries({ us: 'US', 'u.s.': 'US', usa: 'US', 'united states of america': 'US', america: 'US', uk: 'GB', 'u.k.': 'GB', britain: 'GB', 'great britain': 'GB',
  england: 'GB', 'south korea': 'KR', 'republic of korea': 'KR', korea: 'KR', 'north korea': 'KP', 'russian federation': 'RU', russia: 'RU', uae: 'AE', czechia: 'CZ',
  'czech republic': 'CZ', taiwan: 'TW', vietnam: 'VN', 'viet nam': 'VN', turkey: 'TR', turkiye: 'TR', iran: 'IR', syria: 'SY', 'hong kong': 'HK', palestine: 'PS', gaza: 'PS',
  myanmar: 'MM', burma: 'MM', laos: 'LA', moldova: 'MD', 'the netherlands': 'NL', holland: 'NL' })) CC[norm(k)] = v;
const countryOf = name => {
  const n = norm(String(name).replace(/^the\s+/i, '').replace(/\s*(\(.*\)|\/.*)$/, ''));
  if (CC[n]) return CC[n];
  const m = Object.keys(CC).filter(k => k.length >= 4 && n.includes(k)).sort((a, b) => b.length - a.length)[0];
  return m && n.length - m.length <= 12 ? CC[m] : null;
};

// Each OPTIC actor cluster goes to the ATT&CK group that shares the most names with it (its ATT&CK name counts double); ties go to neither.
const pool = buildPool().actors;
const ents = csv(sql(`select e.entity_id, coalesce(c.cluster_entity_id, e.entity_id), coalesce(c.cluster_name, e.canonical_name), e.canonical_name,
  coalesce((select string_agg(alias_name, '|') from entity_aliases a where a.entity_id = e.entity_id), '')
  from entities e left join actor_clusters c on c.entity_id = e.entity_id where e.entity_type = 'threat_actor'`));
const clusterOf = Object.fromEntries(ents.map(r => [r[0], r[1]]));
const cnames = {};
for (const [, cid, cname, canon, al] of ents) for (const n of [cname, canon, ...al.split('|')].filter(Boolean)) (cnames[cid] ??= new Set()).add(norm(n));
const owner = {};
for (const [cid, set] of Object.entries(cnames)) {
  const sc = pool.map(a => {
    const ns = [...new Set([a.name, a.nickname, ...(a.aliases || [])].filter(Boolean).map(norm))].filter(k => k.length >= 4 || /^apt\d/.test(k));
    return [a.id, ns.filter(k => set.has(k)).length + (set.has(norm(a.name)) ? 1 : 0)];
  }).filter(x => x[1]).sort((x, y) => y[1] - x[1]);
  if (sc.length && !(sc.length > 1 && sc[0][1] === sc[1][1])) owner[cid] = sc[0][0];
}

const rows = csv(sql(`select r.subject_entity_id, r.object_name, r.article_id, a.vendor, left(regexp_replace(r.source_quote, '\\s+', ' ', 'g'), 300)
  from article_relationships r join articles a using (article_id) where r.subject_type = 'threat_actor' and r.predicate = 'targets_country'
  union all select at.object_entity_id, r.object_name, r.article_id, a.vendor, left(regexp_replace(r.source_quote, '\\s+', ' ', 'g'), 300)
  from article_relationships r join articles a using (article_id) join article_relationships at on at.article_id = r.article_id
  and at.subject_entity_id = r.subject_entity_id and at.predicate = 'attributed_to' and at.object_type = 'threat_actor'
  where r.subject_type = 'campaign' and r.predicate = 'targets_country'`));
const home = Object.fromEntries(pool.map(a => [a.id, a.home]));
const per = {};
for (const [e, obj, art, vendor, quote] of rows) {
  const g = owner[clusterOf[e]], cc = g && countryOf(obj);
  if (!cc || cc === home[g]) continue;
  const x = ((per[g] ??= {})[cc] ??= { arts: new Set(), vendors: new Set(), quote: '' });
  x.arts.add(art); x.vendors.add(vendor); if (!x.quote && quote) x.quote = `${vendor}: ${quote}`;
}
// Most reported first. A list whose top is a one-article tie has no clear main victim, so it stays empty.
const actors = {};
for (const a of pool) {
  const r = Object.entries(per[a.id] || {}).map(([cc, x]) => ({ cc, n: x.arts.size, v: x.vendors.size, quote: x.quote })).sort((x, y) => y.n - x.n || y.v - x.v || x.cc.localeCompare(y.cc));
  if (!r.length || (r[0].n === 1 && r.length > 1)) continue;
  const list = r.filter(x => x.n >= Math.max(1, r[0].n / 5)).slice(0, 6);
  actors[a.id] = { victims: list.map(x => x.cc), articles: list.map(x => x.n), why: list[0].quote };
}
writeFileSync(new URL('../data/source/victims.json', import.meta.url), JSON.stringify({
  why: 'Victim countries per group from OPTIC (vendor reports, extracted with quotes), most reported first, the group\'s own home left out. articles[i] counts reports naming victims[i]. Regenerate with node tools/optic-victims.mjs; hand fixes go in overrides.json.',
  actors }, null, 1) + '\n');
const roster = pool.filter(a => a.roster);
console.log(`victims for ${Object.keys(actors).length} of ${pool.length} groups, ${roster.filter(a => actors[a.id]).length} of ${roster.length} Most Wanted`);
