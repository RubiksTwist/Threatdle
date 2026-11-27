// Simulated players on the real case set, played through the same rules the server and page use.
// Usage: node tools/simulate.mjs [N] [--approved] [--data <dir with cases.json and pool.json>]
//   N = games per case for each random player (default 200). --data replays an older case set.
// Players:
//   random   taps any Most Wanted group it has not tried (Hunter: any group).
//   newcomer knows no group facts. Without the tracker it reads the clues against the Browse cards (home, profile, targets)
//            and the Home and Type cells of its rows, then guesses any group that still looks possible.
//   tracker  guesses any group the page's suspect tracker still lists (SOC Analyst's follows the clues only, Threat Hunter's the rows too).
//   ideal    knows every public card, reads every row, and picks the guess that splits the suspects best.
import { readFileSync } from 'node:fs';
import { MODES, fits, fitsAll, fold, compare, play, possible } from '../public/js/rules.mjs';
import { buildPool, buildCases } from './export.mjs';

const args = process.argv.slice(2), N = +(args.find(a => /^\d+$/.test(a)) || 200);
const dataDir = args.includes('--data') ? args[args.indexOf('--data') + 1] : null;
const read = f => JSON.parse(readFileSync(`${dataDir}/${f}`, 'utf8'));
const pool = dataDir ? read('pool.json').actors : buildPool().actors;
const serverById = Object.fromEntries(pool.map(a => [a.id, a]));
const byId = Object.fromEntries(pool.map(({ tools, tricks, ...a }) => [a.id, a]));  // what the page has
const cases = (dataDir ? read('cases.json').cases : buildCases()).filter(c => !args.includes('--approved') || c.reviewed);

function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6D2B79F5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const ROSTER = Object.values(byId).filter(a => a.roster), ALL = Object.values(byId);

// The newcomer without the tracker: clue facts it can check on a card, plus the Home and Type cells.
function looksPossible(mode, x, g) {
  if (!fitsAll(x, g.clues)) return false;
  return g.rows.every((r, i) => {
    if (r.id === x.id) return false;
    const f = compare(byId[r.id], fold(x, g.clues.slice(0, i + 1)));
    return ['home', 'type'].every(k => r.cells.find(c => c.k === k).tone === { match: 'hit', near: 'near', partial: 'near', miss: 'miss', unknown: 'unk' }[f[k]]);
  });
}
const key = (mode, f) => [f.correct, ...MODES[mode].cols.filter(k => k !== 'tools' && k !== 'tricks').map(k => f[k])].join('|');
function bestSplit(mode, cands, options, clues) {
  if (cands.length === 1) return cands[0];
  let best = null, score = Infinity;
  for (const g of options) {
    const parts = new Map();
    for (const c of cands) { const k = c === g ? 'win' : key(mode, compare(g, fold(c, clues))); parts.set(k, (parts.get(k) || 0) + 1); }
    const s = [...parts.values()].reduce((x, n) => x + n * n, 0) - (cands.includes(g) ? 0.5 : 0);
    if (s < score) { score = s; best = g; }
  }
  return best;
}

// One game through the real rules. Returns guesses to solve, or 'X' when a hunter goes cold.
function game(mode, kase, who, R) {
  const options = mode === 'analyst' ? ROSTER : ALL, guesses = [];
  for (;;) {
    const g = play(mode, kase, guesses, serverById);
    if (g.status === 'solved') return guesses.length;
    if (g.status === 'cold') return 'X';
    const left = options.filter(a => !guesses.includes(a.id));
    const pickFrom = who === 'random' ? left
      : who === 'newcomer' ? left.filter(x => looksPossible(mode, x, g))
        : possible(mode, left, g.clues, g.rows, byId, who === 'ideal' || MODES[mode].trackRows);
    const p = pickFrom.length ? pickFrom : left;
    guesses.push((who === 'ideal' ? bestSplit(mode, p, left, g.clues) : p[Math.floor(R() * p.length)]).id);
  }
}

const mean = xs => xs.reduce((a, b) => a + b, 0) / xs.length;
const q = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const share = (xs, f) => `${((100 * xs.filter(f).length) / xs.length).toFixed(0)}%`;
const A = cases.filter(c => c.mode === 'analyst'), H = cases.filter(c => c.mode === 'hunter');
console.log(`cases: analyst ${A.length}, hunter ${H.length}; N=${N} games per case for each random player${dataDir ? `; data ${dataDir}` : ''}`);
console.log('SOC Analyst   player    | mean  median P90 | 1    2    3    4    5    6-9  10+');
for (const who of ['random', 'newcomer', 'tracker', 'ideal']) {
  const R = rng(7), xs = [];
  for (const c of A) for (let i = 0; i < (who === 'ideal' ? 1 : N); i++) xs.push(game('analyst', c, who, R));
  const b = [1, 2, 3, 4, 5].map(n => share(xs, x => x === n).padEnd(4));
  console.log(`SOC Analyst   ${who.padEnd(9)} | ${mean(xs).toFixed(2).padEnd(5)} ${String(q(xs, 0.5)).padEnd(6)} ${String(q(xs, 0.9)).padEnd(3)} | ${b.join(' ')} ${share(xs, x => x >= 6 && x <= 9).padEnd(4)} ${share(xs, x => x >= 10)}`);
}
console.log('Threat Hunter player    | win    median when solved | 1    2    3    4    5    6    cold');
for (const who of ['random', 'newcomer', 'tracker', 'ideal']) {
  const R = rng(11), xs = [];
  for (const c of H) for (let i = 0; i < (who === 'ideal' ? 1 : N); i++) xs.push(game('hunter', c, who, R));
  const wins = xs.filter(x => x !== 'X');
  console.log(`Threat Hunter ${who.padEnd(9)} | ${share(xs, x => x !== 'X').padEnd(6)} ${String(wins.length ? q(wins, 0.5) : '-').padEnd(19)} | ${[1, 2, 3, 4, 5, 6].map(n => share(xs, x => x === n).padEnd(4)).join(' ')} ${share(xs, x => x === 'X')}`);
}
