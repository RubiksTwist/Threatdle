// The game API without Netlify: checks requests, plays the guess list, records finishes and derives the crowd stats.
// The function files only adapt HTTP and Netlify Blobs to this.
//   store = { list(prefix) -> Promise<string[]>, set(key, value) -> Promise }
// A finish is one key, never rewritten: `${mode}/${day}/${playerId}.${status}.${tries}.${ms}`. A player's first finish counts.
import { MODES, isMode, isDay, dayOf, msUntilNext, addDays, daysBetween, play, guessError, fold, displayName, shownClue } from '../../public/js/rules.mjs';

const PLAYER = /^[A-Za-z0-9_-]{8,64}$/;
const reply = (status, body) => ({ status, body });

export function createGame({ pool, cases, schedule }) {
  const byId = Object.fromEntries(pool.actors.map(a => [a.id, a]));
  const byCase = Object.fromEntries(cases.map(c => [c.id, c]));
  const entry = (mode, day) => {
    const i = daysBetween(schedule.start, day), d = i >= 0 ? schedule.days[i] : null;
    return d && byCase[d[mode]] ? { kase: byCase[d[mode]], caseNumber: i + 1 } : null;
  };

  async function finishes(store, mode, day) {
    const first = new Map();
    for (const key of await store.list(`${mode}/${day}/`)) {
      const m = /\/([^/.]+)\.(solved|cold)\.(\d+)\.(\d+)$/.exec(key);
      if (!m) continue;
      const f = { player: m[1], status: m[2], tries: +m[3], at: +m[4] };
      const had = first.get(f.player);
      if (!had || f.at < had.at) first.set(f.player, f);
    }
    return [...first.values()];
  }

  async function today(mode, now, store) {
    if (!isMode(mode)) return reply(400, { error: 'mode must be analyst or hunter' });
    const day = dayOf(now), e = entry(mode, day);
    if (!e) return reply(503, { error: 'no case scheduled today' });
    const y = entry(mode, addDays(day, -1)), yc = y && byId[y.kase.culprit];
    const solved = (await finishes(store, mode, day)).filter(f => f.status === 'solved').length;
    return reply(200, {
      day, caseNumber: e.caseNumber, mode, msUntilNext: msUntilNext(now), clue1: shownClue(e.kase.clues[0]), clueCount: e.kase.clues.length,
      solvedCount: solved, yesterday: yc ? { name: yc.name, nickname: yc.nickname, home: yc.home, profile: yc.profile } : null,
    });
  }

  async function guess(body, now, store) {
    if (!body || typeof body !== 'object') return reply(400, { error: 'body must be JSON' });
    const { mode, day, guesses, playerId } = body;
    if (!isMode(mode)) return reply(400, { error: 'mode must be analyst or hunter' });
    if (!isDay(day)) return reply(400, { error: 'day must be YYYY-MM-DD' });
    const current = dayOf(now);
    if (day !== current) return reply(409, { error: 'not today', today: current });
    if (typeof playerId !== 'string' || !PLAYER.test(playerId)) return reply(400, { error: 'bad playerId' });
    const e = entry(mode, day);
    if (!e) return reply(503, { error: 'no case scheduled today' });
    const bad = guessError(mode, e.kase, guesses, byId);
    if (bad) return reply(400, { error: bad });
    const g = play(mode, e.kase, guesses, byId);
    const out = { day, caseNumber: e.caseNumber, mode, rows: g.rows, clues: g.clues, clueCount: g.clueCount, status: g.status };
    if (g.status === 'playing') return reply(200, out);

    let all = await finishes(store, mode, day);
    let mine = all.find(f => f.player === playerId);
    if (!mine) {
      mine = { player: playerId, status: g.status, tries: g.tries, at: now };
      await store.set(`${mode}/${day}/${playerId}.${g.status}.${g.tries}.${now}`, '');
      all = [...all, mine];
    }
    out.result = { culprit: profile(byId[e.kase.culprit], e.kase), story: e.kase.story, report: e.kase.report, tries: g.tries, ...stats(mode, all, mine) };
    return reply(200, out);
  }

  return { today, guess };
}

function profile(a, kase) {
  const { tools, tricks, ...p } = fold(a, kase.clues);
  return { ...p, display: displayName(p) };
}

// Crowd stats from first finishes. Score order: fewer tries is better, a cold case is worst.
export function stats(mode, all, mine) {
  const solved = all.filter(f => f.status === 'solved');
  const score = f => (f.status === 'solved' ? f.tries : Infinity);
  const others = all.filter(f => f.player !== mine.player);
  const distribution = {};
  for (const f of all) {
    const k = f.status === 'cold' ? 'X' : MODES[mode].max || f.tries < 10 ? String(f.tries) : '10+';
    distribution[k] = (distribution[k] || 0) + 1;
  }
  return {
    solvedCount: solved.length,
    rank: mine.status === 'solved' ? 1 + solved.filter(f => f.at < mine.at || (f.at === mine.at && f.player < mine.player)).length : null,
    betterThan: others.length ? Math.round((100 * others.filter(f => score(f) > score(mine)).length) / others.length) : null,
    distribution,
  };
}
