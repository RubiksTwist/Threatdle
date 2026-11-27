import { test } from 'node:test';
import assert from 'node:assert/strict';
import { extend, runway, GAP } from '../tools/schedule.mjs';
import { addDays } from '../public/js/rules.mjs';

// 16 culprits per mode (8 shared across modes), 40 cases each: the gap rule and the cross-mode rule both bite.
const mk = (mode, n, actors) => Array.from({ length: n }, (_, i) => ({ id: `c-${mode[0]}${String(i).padStart(7, '0')}`, mode, culprit: actors[i % actors.length] }));
const g = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => 'G' + (a + i));
const cases = [...mk('analyst', 40, g(1, 16)), ...mk('hunter', 40, g(9, 24))];
const byCase = Object.fromEntries(cases.map(c => [c.id, c]));
const today = '2026-12-10';

test('no culprit repeats within the gap per mode, and the modes never share a culprit on a day', () => {
  const s = extend(null, cases, today);
  assert.equal(s.start, today);
  s.days.forEach((d, i) => {
    assert.notEqual(byCase[d.analyst].culprit, byCase[d.hunter].culprit);
    for (const m of ['analyst', 'hunter']) {
      const recent = s.days.slice(Math.max(0, i - GAP), i).map(x => byCase[x[m]].culprit);
      assert.ok(!recent.includes(byCase[d[m]].culprit), `day ${i} ${m}`);
    }
  });
  assert.ok(s.days.length >= 30, `${s.days.length} days`);
  assert.equal(new Set(s.days.flatMap(d => [d.analyst, d.hunter])).size, s.days.length * 2, 'each case used once');
});

test('rerunning changes nothing; served days stay put when a case loses approval', () => {
  const s = extend(null, cases, today);
  assert.deepEqual(extend(s, cases, today), s);
  const later = addDays(today, 3);
  const gone = s.days[1].analyst;
  const t = extend(s, cases.filter(c => c.id !== gone), later);
  assert.equal(t.days[1].analyst, gone, 'a served day never changes');
  const futureGone = s.days[6].hunter;
  const u = extend(s, cases.filter(c => c.id !== futureGone), later);
  assert.deepEqual(u.days.slice(0, 6), s.days.slice(0, 6));
  assert.ok(!u.days.some(d => d.hunter === futureGone));
});

test('runway counts days from today and a lapsed schedule restarts today', () => {
  const s = { start: today, days: extend(null, cases, today).days.slice(0, 5) };
  assert.equal(runway(s, today), 5);
  assert.equal(runway(s, addDays(today, 9)), 0);
  const restarted = extend(s, cases, addDays(today, 9));
  assert.equal(restarted.days[7], null, 'missed days stay empty');
  assert.ok(restarted.days[8] === null && restarted.days[9]);
  assert.ok(runway(restarted, addDays(today, 9)) > 0);
});
