// Simulated players on the real case set: the SOC Analyst guess spread and the Threat Hunter win rate and spread.
// Usage: node tools/simulate.mjs [--approved] [N]   (default: every draft, N=200 games per case per random strategy)
// A player model sees only what the page shows: the clues so far, the rows so far, and each group's public card.
import { MODES, fits, fold, compare, play } from '../public/js/rules.mjs';
import { buildPool, buildCases } from './export.mjs';

const args = process.argv.slice(2), N = +(args.find(a => /^\d+$/.test(a)) || 200);
const pool = buildPool().actors, byId = Object.fromEntries(pool.map(a => [a.id, a]));
const cases = buildCases().filter(c => !args.includes('--approved') || c.reviewed);
const ROSTER = pool.filter(a => a.roster);

function rng(seed) { let s = seed >>> 0; return () => { s = (s + 0x6D2B79F5) | 0; let t = Math.imul(s ^ (s >>> 15), 1 | s); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const key = (mode, f) => [f.correct, ...MODES[mode].cols.map(k => f[k])].join('|');
// An expert also knows which tools each group uses.
const expertFits = (a, f) => fits(a, f) && (!f.tools || f.tools.some(t => a.tools.includes(t)));

// Could x be the culprit, given the clues shown and the rows so far? (cols limits which row cells the player reads.)
function consistent(mode, kase, x, guesses, shown, fitFn, cols = MODES[mode].cols) {
  if (!kase.clues.slice(0, shown).every(c => fitFn(x, c.facts))) return false;
  const truth = byId[kase.culprit];
  return guesses.every((g, i) => {
    if (g === x.id) return false;
    const at = kase.clues.slice(0, Math.min(kase.clues.length, i + 1));
    const seen = compare(byId[g], fold(truth, at)), mine = compare(byId[g], fold(x, at));
    return cols.every(k => seen[k] === mine[k]);
  });
}
function bestSplit(mode, kase, cands, options, shown) {
  if (cands.length === 1) return cands[0];
  const at = kase.clues.slice(0, shown);
  let best = null, score = Infinity;
  for (const g of options) {
    const parts = new Map();
    for (const c of cands) { const k = c === g ? 'win' : key(mode, compare(g, fold(c, at))); parts.set(k, (parts.get(k) || 0) + 1); }
    const s = [...parts.values()].reduce((x, n) => x + n * n, 0) - (cands.includes(g) ? 0.5 : 0);
    if (s < score) { score = s; best = g; }
  }
  return best;
}

// One game. Returns guesses to solve, or 'X' when a hunter goes cold.
function game(mode, kase, strat, R) {
  const options = mode === 'analyst' ? ROSTER : pool, max = MODES[mode].max || Infinity, n = kase.clues.length;
  const fitFn = mode === 'hunter' && strat === 'ideal' ? expertFits : fits;
  const guesses = [];
  while (guesses.length < max) {
    const shown = Math.min(n, guesses.length + 1), left = options.filter(a => !guesses.includes(a.id));
    let g;
    if (strat === 'random') g = left[Math.floor(R() * left.length)];
    else {
      const cols = strat === 'casual' ? ['home', 'type'] : undefined;
      const C = left.filter(x => consistent(mode, kase, x, guesses, shown, fitFn, cols));
      const p = C.length ? C : left;
      g = strat === 'ideal' ? bestSplit(mode, kase, p, left, shown) : p[Math.floor(R() * p.length)];
    }
    guesses.push(g.id);
    if (g.id === kase.culprit) return guesses.length;
  }
  return 'X';
}

const mean = xs => xs.reduce((a, b) => a + b, 0) / xs.length;
const sd = xs => { const m = mean(xs); return Math.sqrt(mean(xs.map(x => (x - m) ** 2))); };
const pct = (xs, p) => { const s = [...xs].sort((a, b) => a - b); return s[Math.min(s.length - 1, Math.floor(p * s.length))]; };
const hist = (xs, bins) => bins.map(([lo, hi, label]) => `${label}:${((100 * xs.filter(x => (x === 'X' ? lo === 'X' : x >= lo && x <= hi)).length) / xs.length).toFixed(0)}%`).join(' ');

// Sanity: replaying the culprit through the real rules solves every case on the spot.
for (const c of cases) if (play(c.mode, c, [c.culprit], byId).status !== 'solved') throw new Error(`${c.id} does not solve`);

const A = cases.filter(c => c.mode === 'analyst'), H = cases.filter(c => c.mode === 'hunter');
console.log(`cases: analyst ${A.length}, hunter ${H.length}; N=${N} games per case per random strategy`);
const ABINS = [[1, 1, '1'], [2, 2, '2'], [3, 3, '3'], [4, 4, '4'], [5, 5, '5'], [6, 9, '6-9'], [10, 19, '10-19'], [20, 99, '20+']];
for (const strat of ['random', 'casual', 'consistent', 'ideal']) {
  const R = rng(7), all = [];
  for (const c of A) for (let i = 0; i < (strat === 'ideal' ? 1 : N); i++) all.push(game('analyst', c, strat, R));
  console.log(`SOC Analyst ${strat.padEnd(10)} mean ${mean(all).toFixed(2)} sd ${sd(all).toFixed(2)} P10-P90 ${pct(all, 0.1)}-${pct(all, 0.9)} | ${hist(all, ABINS)}`);
}
const HBINS = [[1, 1, '1'], [2, 2, '2'], [3, 3, '3'], [4, 4, '4'], [5, 5, '5'], [6, 6, '6'], ['X', 'X', 'X']];
for (const strat of ['random', 'casual', 'consistent', 'ideal']) {
  const R = rng(11), all = [];
  for (const c of H) for (let i = 0; i < (strat === 'ideal' ? 1 : N); i++) all.push(game('hunter', c, strat, R));
  const wins = all.filter(x => x !== 'X');
  console.log(`Threat Hunter ${strat.padEnd(10)} win ${((100 * wins.length) / all.length).toFixed(1)}% | mean guesses when solved ${wins.length ? mean(wins).toFixed(2) : '-'} | ${hist(all, HBINS)}`);
}
