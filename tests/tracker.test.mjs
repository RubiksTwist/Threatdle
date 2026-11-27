import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { play, possible, shownClue } from '../public/js/rules.mjs';

// Runs the tracker the way the page does: public pool facts only, and only what /api/guess returned.
const read = p => JSON.parse(readFileSync(new URL('../' + p, import.meta.url), 'utf8'));
const server = read('data/pool.json').actors, cases = read('data/cases.json').cases;
const serverById = Object.fromEntries(server.map(a => [a.id, a]));
const pub = read('public/pool.json').actors, byId = Object.fromEntries(pub.map(a => [a.id, a]));
function rng(seed) { let s = seed; return () => { s = (s * 1103515245 + 12345) % 2 ** 31; return s / 2 ** 31; }; }

test('shown clues never carry tool ids', () => {
  assert.deepEqual(shownClue({ kind: 'tool', text: 't', facts: { tools: ['S1'], home: 'RU' } }), { kind: 'tool', text: 't', facts: { home: 'RU' } });
});

test('on every drafted case the culprit is never ruled out, and the suspect list only shrinks', () => {
  const R = rng(42);
  for (const kase of cases) {
    const cands = kase.mode === 'analyst' ? pub.filter(a => a.roster) : pub;
    for (let run = 0; run < 3; run++) {
      const guesses = [];
      let last = Infinity;
      for (;;) {
        const g = play(kase.mode, kase, guesses, serverById);
        if (g.status !== 'playing') break;
        const left = possible(kase.mode, cands, g.clues, g.rows, byId);
        assert.ok(left.some(a => a.id === kase.culprit), `${kase.id}: culprit ruled out after ${guesses.length} guesses`);
        assert.ok(left.length <= last, `${kase.id}: the list grew`);
        last = left.length;
        // Guess a still-possible suspect that is not the culprit while one exists, so rows pile up.
        const wrong = left.filter(a => a.id !== kase.culprit && !guesses.includes(a.id));
        guesses.push(wrong.length ? wrong[Math.floor(R() * wrong.length)].id : kase.culprit);
      }
    }
  }
});

test('a row rules out a group whose own comparison would differ', () => {
  const kase = cases.find(c => c.mode === 'analyst');
  const roster = pub.filter(a => a.roster);
  const before = possible('analyst', roster, play('analyst', kase, [], serverById).clues, [], byId).length;
  const wrong = roster.find(a => a.id !== kase.culprit);
  const g = play('analyst', kase, [wrong.id], serverById);
  const after = possible('analyst', roster, g.clues.slice(0, 1), g.rows, byId);
  assert.ok(!after.some(a => a.id === wrong.id), 'the guessed group is out');
  assert.ok(after.length < before, `${before} -> ${after.length}`);
});
