// Threatdle rules core. Pure functions shared by the Netlify functions, the build tools and the browser.
//
// Actor  = { id, name, nickname, aliases, home, type, motive, since, targets, profile, roster, tools? }
//          home: ISO-3166 alpha-2 or null; type: 'state' | 'crime' | 'activist' | null; tools: ATT&CK software ids (server only)
// Clue   = { kind, text, facts, source }   facts: { targets?, home?, type?, motive?, tools?, name? }
// Case   = { id, mode, culprit, reviewed, clues: Clue[], story, report }
// Row    = { id, name, home, correct, cells: Cell[] }   Cell = { k, text, tone, arrow?, say }

// open: clues shown before the first guess. SOC Analyst opens on two, so a case never starts on one vague line.
// trackRows: whether the suspect tracker also reads the rows. SOC Analyst's follows the clues only, so reading the rows is the
// player's skill (simulated mean 2.9 guesses on the list alone, 2.7 reading Home and Type). Threat Hunter's reads both: without it a newcomer wins 37% of games.
export const MODES = {
  analyst: { name: 'SOC Analyst', max: null, open: 2, cols: ['home', 'type', 'motive', 'since', 'targets'], who: 'analysts', trackRows: false },
  hunter: { name: 'Threat Hunter', max: 6, open: 1, cols: ['home', 'type', 'motive', 'since', 'targets', 'tools'], who: 'hunters', trackRows: true },
};
export const isMode = m => Object.hasOwn(MODES, m);
export const other = m => (m === 'hunter' ? 'analyst' : 'hunter');

export const COUNTRY = {
  RU: 'Russia', CN: 'China', IR: 'Iran', KP: 'North Korea', KR: 'South Korea', PS: 'Palestine', LB: 'Lebanon', TR: 'Turkey', VN: 'Vietnam',
  IN: 'India', PK: 'Pakistan', BY: 'Belarus', BR: 'Brazil', US: 'USA', AE: 'UAE', NG: 'Nigeria', RO: 'Romania', UA: 'Ukraine', KZ: 'Kazakhstan',
};
// Same country = match; same part of the world = near.
export const REGION = {
  RU: 'Europe', BY: 'Europe', RO: 'Europe', UA: 'Europe', CN: 'East Asia', KP: 'East Asia', KR: 'East Asia', VN: 'East Asia',
  IR: 'Middle East', PS: 'Middle East', LB: 'Middle East', AE: 'Middle East', TR: 'Middle East', IN: 'South Asia', PK: 'South Asia', KZ: 'Central Asia',
  US: 'Americas', BR: 'Americas', NG: 'Africa',
};
export const TYPES = ['state', 'crime', 'activist'];
export const MOTIVES = ['Espionage', 'Financial Gain', 'Sabotage', 'Hacktivism'];
export const SECTORS = ['Government', 'Military', 'Defense', 'Private sector', 'Finance', 'Technology', 'Telecommunications', 'Energy', 'Healthcare',
  'Education', 'Civil society', 'NGOs', 'Media', 'Individuals', 'Hospitality', 'Retail', 'Manufacturing', 'Transportation', 'Critical infrastructure',
  'Legal', 'Pharmaceuticals', 'Religious organization', 'Food and agriculture'];
export const KINDS = { victim: 'Victim', breakin: 'Break-in', tool: 'Tool', took: 'What they took', hid: 'How they hid', tipoff: 'Tip-off' };

export const displayName = a => a.nickname || a.name;

// Vendor naming families: the last word of a CrowdStrike or Microsoft name tells a newcomer where a group is from.
export const FAMILIES = {
  CrowdStrike: ['Bear', 'Panda', 'Kitten', 'Chollima', 'Spider', 'Tiger', 'Leopard', 'Buffalo', 'Jackal', 'Crane', 'Wolf', 'Ocelot', 'Hawk', 'Lynx', 'Saiga'],
  Microsoft: ['Blizzard', 'Typhoon', 'Sandstorm', 'Sleet', 'Tempest', 'Hail', 'Dust', 'Cyclone', 'Rain', 'Flood', 'Tsunami'],
};
export const vendorOf = family => Object.keys(FAMILIES).find(v => FAMILIES[v].includes(family)) || null;
const lastWord = n => (/\s([A-Za-z]+)$/.exec(n || '') || [])[1]?.toLowerCase();
// The family words of a group's known names from one vendor ("Refined Kitten" gives kitten). Empty when that vendor's name is unknown.
export const familiesOf = (a, vendor) => [...new Set([a.name, a.nickname, ...(a.aliases || [])].map(lastWord)
  .filter(w => w && FAMILIES[vendor].some(f => f.toLowerCase() === w)))];

// ---------- calendar: one case per mode per day, rolling over at midnight in New York ----------
export const ZONE = 'America/New_York';
const fmt = new Intl.DateTimeFormat('en-CA', { timeZone: ZONE, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
function zoned(t) {
  const p = Object.fromEntries(fmt.formatToParts(t).map(x => [x.type, x.value]));
  return { y: +p.year, m: +p.month, d: +p.day, H: +p.hour, M: +p.minute, S: +p.second };
}
export function dayOf(t = Date.now()) {
  const { y, m, d } = zoned(t);
  return `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}
const offsetAt = t => { const z = zoned(t); return Date.UTC(z.y, z.m - 1, z.d, z.H, z.M, z.S) - Math.floor(t / 1000) * 1000; };
export function msUntilNext(t = Date.now()) {
  const { y, m, d } = zoned(t);
  const wall = Date.UTC(y, m - 1, d + 1);
  return wall - offsetAt(wall - offsetAt(wall)) - t;
}
const dayMs = day => Date.UTC(+day.slice(0, 4), +day.slice(5, 7) - 1, +day.slice(8, 10));
export const addDays = (day, n) => new Date(dayMs(day) + n * 864e5).toISOString().slice(0, 10);
export const daysBetween = (a, b) => Math.round((dayMs(b) - dayMs(a)) / 864e5);
export const isDay = s => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && addDays(s, 0) === s;

// ---------- clue facts ----------
// Sector overlap a player can check: "Private sector" overlaps every company sector, "Critical infrastructure" overlaps energy.
const COMPANY = new Set(['Private sector', 'Finance', 'Technology', 'Telecommunications', 'Energy', 'Healthcare', 'Hospitality', 'Retail', 'Manufacturing',
  'Transportation', 'Legal', 'Pharmaceuticals', 'Food and agriculture', 'Media', 'Defense', 'Critical infrastructure']);
const sectorNear = (t, x) => t === x || (t === 'Private sector' && COMPANY.has(x)) || (x === 'Private sector' && COMPANY.has(t))
  || (t === 'Critical infrastructure' && x === 'Energy') || (x === 'Critical infrastructure' && t === 'Energy');

// Does an actor fit what one clue says, on facts a player can see (tools need expert knowledge and never count)?
// Unknown targets never rule a group out; an unknown home, type or motive does. A naming-family hint rules a group out only
// when its name from that vendor is known and in another family: an unknown name stays possible, like unknown targets.
export function fits(a, f = {}) {
  if (f.home && a.home !== f.home) return false;
  if (f.type && a.type !== f.type) return false;
  if (f.motive && !(a.motive || []).includes(f.motive)) return false;
  if (f.targets && a.targets && a.targets.length && !f.targets.some(x => a.targets.some(t => sectorNear(t, x)))) return false;
  if (f.name && ![a.name, a.nickname, ...(a.aliases || [])].some(n => n && n.toLowerCase() === f.name.toLowerCase())) return false;
  if (f.family) { const known = familiesOf(a, vendorOf(f.family)); if (known.length && !known.includes(f.family.toLowerCase())) return false; }
  return true;
}
export const fitsAll = (a, clues) => clues.every(c => fits(a, c.facts));

// The culprit as the given clues describe it. Rows and the end card use this, so a player who trusts the clues never rules out the culprit.
export function fold(a, clues) {
  const p = { ...a, targets: [...(a.targets || [])], motive: [...(a.motive || [])], tools: [...(a.tools || [])] };
  for (const { facts: f = {} } of clues) {
    for (const s of f.targets || []) if (!p.targets.includes(s)) p.targets.push(s);
    if (f.home) p.home = f.home;
    if (f.type) p.type = f.type;
    if (f.motive && !p.motive.includes(f.motive)) p.motive.push(f.motive);
    for (const t of f.tools || []) if (!p.tools.includes(t)) p.tools.push(t);
  }
  return p;
}

// ---------- compare ----------
// Buckets, not counts: exact shared counts let anyone with ATT&CK open solve in 2. A cell shows its bucket as a range
// ("0", "1-2", "3+"), so it reads as "how many the guess shares with the culprit" and never as "this group has no tools".
// Most groups share no malware: across every hunter culprit and every guess, Tools is 0 for 73% of pairs, 1-2 for 21%, 3+ for 6%.
export const TOOL_CUTS = [1, 3];
export const bucket = (n, [some, many]) => (n >= many ? 'many' : n >= some ? 'some' : 'none');
// A group ATT&CK lists no software for is unknown, not "shares none".
const bucketOf = (a, b, cuts) => (a?.length && b?.length ? bucket(shared(a, b), cuts) : 'unknown');
const range = ([some, many]) => ({ none: '0', some: some === many - 1 ? String(some) : `${some}–${many - 1}`, many: `${many}+`, unknown: '?' });
const shared = (a, b) => { const s = new Set(b || []); return (a || []).filter(x => s.has(x)).length; };
function setCmp(a, b) {
  if (!a || !b || !a.length || !b.length) return 'unknown';
  if (a.length === b.length && a.every(x => b.includes(x))) return 'match';
  return a.some(x => b.includes(x)) ? 'partial' : 'miss';
}

// Feedback for guess g against culprit profile p. A correct guess is all match.
// A crime gang with no known country has the crime badge ($) for a home: two such gangs match, and against a country it is a miss.
export const homeOf = a => a.home || (a.type === 'crime' ? '$' : null);
export function compare(g, p) {
  if (g.id === p.id) return { correct: true, home: 'match', type: 'match', motive: 'match', since: 'match', targets: 'match', tools: 'match' };
  const gh = homeOf(g), ph = homeOf(p);
  const home = !gh || !ph ? 'unknown' : gh === ph ? 'match' : REGION[gh] && REGION[gh] === REGION[ph] ? 'near' : 'miss';
  const type = !g.type || !p.type ? 'unknown' : g.type === p.type ? 'match' : 'miss';
  const since = g.since == null || p.since == null ? 'unknown' : g.since === p.since ? 'match' : p.since > g.since ? 'up' : 'down';
  return {
    correct: false, home, type, motive: setCmp(g.motive, p.motive), since, targets: setCmp(g.targets, p.targets),
    tools: bucketOf(g.tools, p.tools, TOOL_CUTS),
  };
}

const TONE = { match: 'hit', near: 'near', partial: 'near', miss: 'miss', unknown: 'unk', up: 'miss', down: 'miss', none: 'miss', some: 'near', many: 'hit' };
const SHORT_MOTIVE = { Espionage: 'Spying', 'Financial Gain': 'Money', Sabotage: 'Damage', Hacktivism: 'Cause' };
const cap = s => s[0].toUpperCase() + s.slice(1);
const OVERLAP = { match: 'Same', partial: 'Some', miss: 'None', unknown: '?' };
const OVERLAP_SAY = { match: 'same', partial: 'some overlap', miss: 'no overlap', unknown: 'unknown' };

// Cells in display order for a mode. Text describes the guessed group; tone compares it with the culprit.
export function cells(mode, g, f) {
  const mot = (g.motive || []).map(m => SHORT_MOTIVE[m] || m);
  const all = {
    home: { text: homeOf(g) || '?', say: `home ${g.home ? COUNTRY[g.home] || g.home : homeOf(g) ? 'crime gang' : 'unknown'}: ${f.home === 'near' ? 'same part of the world' : f.home}` },
    type: { text: g.type ? cap(g.type) : '?', say: `type ${g.type || 'unknown'}: ${f.type}` },
    motive: { text: mot.length ? mot[0] + (mot.length > 1 ? '+' : '') : '?', say: `motive ${mot.join(' and ') || 'unknown'}: ${f.motive}` },
    since: { text: g.since ? String(g.since) : '?', arrow: f.since === 'up' ? '↑' : f.since === 'down' ? '↓' : '',
      say: `first seen ${g.since || 'unknown'}: ${f.since === 'up' ? 'culprit is newer' : f.since === 'down' ? 'culprit is older' : f.since}` },
    targets: { text: OVERLAP[f.targets], say: `targets: ${OVERLAP_SAY[f.targets]}` },
    tools: { text: f.tools === 'match' ? 'Same' : range(TOOL_CUTS)[f.tools], say: `shared tools: ${f.tools === 'match' ? 'all' : f.tools === 'unknown' ? 'unknown' : range(TOOL_CUTS)[f.tools].replace('–', ' to ')}` },
  };
  return MODES[mode].cols.map(k => ({ k, tone: TONE[f[k]], ...all[k] }));
}

// ---------- a game, recomputed from the guess list ----------
// The mode's opening clues show before any guess, and each wrong guess shows one more. Row i compares guess i with the culprit folded with the clues shown when it was made.
export function play(mode, kase, guesses, byId) {
  const n = kase.clues.length, { max, open } = MODES[mode], culprit = byId[kase.culprit];
  const at = k => fold(culprit, kase.clues.slice(0, Math.min(n, k)));
  const rows = guesses.map((id, i) => {
    const g = id === culprit.id ? at(i + open) : byId[id];
    return { id, name: displayName(g), home: g.home, correct: id === culprit.id, cells: cells(mode, g, compare(g, at(i + open))) };
  });
  const solved = guesses.at(-1) === culprit.id;
  const status = solved ? 'solved' : max && guesses.length >= max ? 'cold' : 'playing';
  const shown = status === 'playing' ? Math.min(n, guesses.length + open) : n;
  return { rows, status, tries: guesses.length, clues: kase.clues.slice(0, shown).map(shownClue), clueCount: n };
}

// What a shown clue tells the page: its words and the checkable facts they state. Tool ids stay on the server.
export const shownClue = c => { const { tools, ...facts } = c.facts || {}; return { kind: c.kind, text: c.text, facts }; };

// The suspect tracker: which candidates the player can still believe, from what the page already shows.
// A candidate stays if it fits every shown clue, was not guessed wrong, and (when the mode tracks rows) for each row, comparing
// that guess with the candidate (folded with the clues shown when the row was made) gives the row the player got. Tools
// need server data, so they are skipped. The culprit always stays: the server built each row the same way from the same public facts.
export function possible(mode, candidates, clues, rows, byId, trackRows = MODES[mode].trackRows) {
  const cols = MODES[mode].cols.filter(k => k !== 'tools');
  return candidates.filter(x => fitsAll(x, clues) && rows.every((r, i) => {
    if (r.correct) return r.id === x.id;
    if (r.id === x.id) return false;
    if (!trackRows) return true;
    const g = byId[r.id], got = cells(mode, g, compare(g, fold(x, clues.slice(0, i + MODES[mode].open))));
    return cols.every(k => { const a = got.find(c => c.k === k), b = r.cells.find(c => c.k === k); return a.tone === b.tone && (a.arrow || '') === (b.arrow || ''); });
  }));
}

// Reasons a guess list cannot be a real game. null = fine.
export function guessError(mode, kase, guesses, byId) {
  if (!Array.isArray(guesses) || guesses.some(g => typeof g !== 'string')) return 'guesses must be a list of ids';
  if (new Set(guesses).size !== guesses.length) return 'duplicate guess';
  const pool = mode === 'analyst' ? id => byId[id] && byId[id].roster : id => Boolean(byId[id]);
  if (!guesses.every(pool)) return 'unknown id';
  const max = MODES[mode].max;
  if (max && guesses.length > max) return 'too many guesses';
  const hit = guesses.indexOf(kase.culprit);
  if (hit >= 0 && hit !== guesses.length - 1) return 'guesses after the solve';
  return null;
}

// ---------- share ----------
const EMO = { hit: '🟩', near: '🟨', miss: '⬛', unk: '⬛' };
export const shareRow = row => row.cells.map(c => (c.arrow ? (c.arrow === '↑' ? '⬆️' : '⬇️') : EMO[c.tone])).join('');
export const SHARE_ROWS = 8;
export function shareText({ mode, caseNumber, status, rows, streak }) {
  const n = rows.length;
  const score = mode === 'hunter' ? `${status === 'solved' ? n : 'X'}/${MODES.hunter.max}` : `${n} ${n === 1 ? 'guess' : 'guesses'}`;
  const sep = mode === 'hunter' ? ' ' : ' · ';
  const lines = rows.length > SHARE_ROWS ? [...rows.slice(0, SHARE_ROWS - 1).map(shareRow), `+${n - SHARE_ROWS} more`, shareRow(rows.at(-1))] : rows.map(shareRow);
  return [`Threatdle #${caseNumber} · ${MODES[mode].name}${sep}${score} · 🔥${streak}`, ...lines].join('\n');
}

// ---------- streak: per mode, only today's case builds it ----------
// s = { day, n, won } for the last finished case. Returns the streak after finishing `day`.
export function nextStreak(s, day, won) {
  if (s && s.day === day) return s;
  const n = !won ? 0 : s && s.won && addDays(s.day, 1) === day ? s.n + 1 : 1;
  return { day, n, won };
}
// The streak to show on `today`: a gap of a missed day breaks it.
export const currentStreak = (s, today) => (s && s.won && (s.day === today || addDays(s.day, 1) === today) ? s.n : 0);

// ---------- Most Wanted sections for the Browse sheet ----------
const NICK = { Bear: 'RU', Blizzard: 'RU', Panda: 'CN', Typhoon: 'CN', Kitten: 'IR', Sandstorm: 'IR', Chollima: 'KP', Sleet: 'KP', Spider: 'crime', Tempest: 'crime' };
export const SECTIONS = [['RU', 'Russia', 'Bear · Blizzard'], ['CN', 'China', 'Panda · Typhoon'], ['IR', 'Iran', 'Kitten · Sandstorm'],
  ['KP', 'North Korea', 'Chollima · Sleet'], ['crime', 'Crime gangs', 'Spider · Tempest'], ['other', 'Elsewhere', 'Everyone else']];
export function sectionOf(a) {
  const suffix = /\s([A-Z][a-z]+)$/.exec(a.nickname || '');
  const s = (suffix && NICK[suffix[1]]) || a.home || (a.type === 'crime' ? 'crime' : 'other');
  return SECTIONS.some(([k]) => k === s) ? s : 'other';
}
