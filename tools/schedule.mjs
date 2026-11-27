// Schedules one case per mode per day from approved cases. Safe to rerun: days up to today never change,
// later days are kept while their cases stay approved, then the schedule is extended as far as the cases allow.
//   node tools/schedule.mjs            write data/schedule.json from approved cases, starting today
//   node tools/schedule.mjs --drafts [--start YYYY-MM-DD]   write data/schedule.drafts.json from every draft (local dev and tests only)
// Rules: each case is used once; no culprit repeats within 14 days in a mode; the two modes never share a culprit on a day.
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { addDays, daysBetween, dayOf, isDay } from '../public/js/rules.mjs';
import { buildPool, buildCases } from './export.mjs';

export const GAP = 14, MIN_RUNWAY = 60;
const MODES = ['analyst', 'hunter'];

// schedule = { start: day, days: [{ analyst: caseId, hunter: caseId } | null] }   day i = start + i
export function extend(schedule, cases, today) {
  const ok = new Set(cases.map(c => c.id)), byCase = Object.fromEntries(cases.map(c => [c.id, c]));
  const start = schedule?.start ?? today;
  const old = schedule?.days ?? [];
  const frozen = Math.max(0, daysBetween(start, today) + 1);
  let keep = old.findIndex((d, i) => i >= frozen && !(d && ok.has(d.analyst) && ok.has(d.hunter)));
  if (keep < 0) keep = old.length;
  const days = old.slice(0, keep);
  while (old.length && days.length < frozen - 1) days.push(null);  // a lapsed schedule restarts today; the missed days stay empty
  const culprit = id => byCase[id]?.culprit;
  const used = new Set(days.flatMap(d => (d ? [d.analyst, d.hunter] : [])));
  const order = id => createHash('sha256').update(id).digest('hex');
  const pools = Object.fromEntries(MODES.map(m => [m, cases.filter(c => c.mode === m && !used.has(c.id)).sort((a, b) => order(a.id).localeCompare(order(b.id)))]));
  for (;;) {
    const day = {};
    for (const m of MODES) {
      const recent = new Set(days.slice(-GAP).map(d => d && culprit(d[m])));
      const taken = new Set(Object.values(day).map(culprit));
      const left = {};
      for (const c of pools[m]) left[c.culprit] = (left[c.culprit] || 0) + 1;
      // Prefer the culprit with the most cases left, so a busy group does not strand its cases at the end.
      const pick = pools[m].filter(c => !recent.has(c.culprit) && !taken.has(c.culprit)).sort((a, b) => left[b.culprit] - left[a.culprit])[0];
      if (!pick) return { start, days };
      day[m] = pick.id;
      pools[m] = pools[m].filter(c => c !== pick);
    }
    days.push(day);
  }
}
export const runway = (schedule, today) => Math.max(0, daysBetween(today, addDays(schedule.start, schedule.days.length)));

if (import.meta.main) {
  const args = process.argv.slice(2), drafts = args.includes('--drafts');
  const file = new URL(`../data/schedule${drafts ? '.drafts' : ''}.json`, import.meta.url);
  const today = dayOf();
  const current = existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : null;
  const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
  const cases = buildCases().filter(c => drafts || c.reviewed);
  const startArg = args[args.indexOf('--start') + 1];
  const base = drafts && args.includes('--start') && isDay(startArg) ? { start: startArg, days: [] } : current;
  const next = extend(base, cases, today);
  writeFileSync(new URL(file.href + '.tmp'), JSON.stringify(next, null, 1) + '\n');
  renameSync(new URL(file.href + '.tmp'), file);
  const n = runway(next, today);
  console.log(`${drafts ? 'draft ' : ''}schedule: ${next.days.length} days from ${next.start}, runway ${n} days from ${today} (minimum ${MIN_RUNWAY})`);
  if (!drafts && n < MIN_RUNWAY) process.exitCode = 1;
}
