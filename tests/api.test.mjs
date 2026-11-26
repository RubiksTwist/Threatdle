import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createGame } from '../netlify/lib/game.mjs';

const A = (id, o = {}) => ({ id, name: id, nickname: null, aliases: [], home: 'RU', type: 'state', motive: ['Espionage'], since: 2010, targets: ['Government'], profile: 'p', roster: true, tools: ['S1'], tricks: ['T1'], ...o });
const actors = [A('G1', { nickname: 'Fancy Bear' }), A('G2'), A('G3'), A('G4', { roster: false }), ...Array.from({ length: 8 }, (_, i) => A('X' + i, { roster: false }))];
const clues = n => Array.from({ length: n }, (_, i) => ({ kind: 'victim', text: `clue ${i + 1}`, facts: {}, source: { quote: 'secret vendor quote' } }));
const cases = [
  { id: 'c-aaaaaaaa', mode: 'analyst', culprit: 'G1', clues: clues(5), story: 'Story A.', report: { vendor: 'V', title: 'T', url: 'https://x', date: '2026-01-01' } },
  { id: 'c-bbbbbbbb', mode: 'hunter', culprit: 'G4', clues: clues(6), story: 'Story H.', report: { vendor: 'V', title: 'T', url: 'https://y', date: '2026-01-01' } },
  { id: 'c-cccccccc', mode: 'analyst', culprit: 'G2', clues: clues(5), story: 'Story Y.', report: { vendor: 'V', title: 'T', url: 'https://z', date: '2026-01-01' } },
  { id: 'c-dddddddd', mode: 'hunter', culprit: 'G3', clues: clues(6), story: 'S.', report: { vendor: 'V', title: 'T', url: 'https://w', date: '2026-01-01' } },
];
// 2026-12-01 is yesterday, 2026-12-02 today, 2026-12-03 tomorrow.
const schedule = { start: '2026-12-01', days: [{ analyst: 'c-cccccccc', hunter: 'c-dddddddd' }, { analyst: 'c-aaaaaaaa', hunter: 'c-bbbbbbbb' }, { analyst: 'c-cccccccc', hunter: 'c-dddddddd' }] };
const NOW = Date.parse('2026-12-02T17:00:00Z');
const memory = () => {
  const keys = new Map();
  return { keys, list: async p => [...keys.keys()].filter(k => k.startsWith(p)), set: async (k, v) => { assert.ok(!keys.has(k), 'a record is never rewritten'); keys.set(k, v); } };
};
const game = createGame({ pool: { actors }, cases, schedule });
const post = (store, o, now = NOW) => game.guess({ mode: 'analyst', day: '2026-12-02', playerId: 'player-0001', guesses: [], ...o }, now, store);

test('today serves only the first clue, the case number and yesterday', async () => {
  const r = await game.today('analyst', NOW, memory());
  assert.equal(r.status, 200);
  assert.equal(r.body.day, '2026-12-02');
  assert.equal(r.body.caseNumber, 2);
  assert.deepEqual(r.body.clue1, { kind: 'victim', text: 'clue 1' });
  assert.equal(r.body.clueCount, 5);
  assert.equal(r.body.yesterday.name, 'G2');
  assert.equal(r.body.msUntilNext, Date.parse('2026-12-03T05:00:00Z') - NOW);
  const s = JSON.stringify(r.body);
  assert.ok(!s.includes('G1') && !s.includes('secret') && !s.includes('Story'), 'no answer, quote or story leaks');
});

test('today rejects a bad mode and says when nothing is scheduled', async () => {
  assert.equal((await game.today('lineup', NOW, memory())).status, 400);
  assert.equal((await game.today('analyst', Date.parse('2027-06-01T12:00:00Z'), memory())).status, 503);
});

test('a guess for another day gets 409 with today, including tomorrow', async () => {
  for (const day of ['2026-12-01', '2026-12-03']) {
    const r = await post(memory(), { day, guesses: ['G2'] });
    assert.equal(r.status, 409);
    assert.equal(r.body.today, '2026-12-02');
  }
});

test('malformed bodies, unknown ids, duplicates, over-cap lists and bad players get 400', async () => {
  const store = memory();
  for (const body of [null, { mode: 'x' }, { day: '2026-13-01' }, { guesses: ['nope'] }, { guesses: ['G2', 'G2'] }, { guesses: ['G4'] },
    { guesses: ['G1', 'G2'] }, { playerId: 'x' }, { guesses: 'G1' }]) {
    const r = body === null ? await game.guess(null, NOW, store) : await post(store, body);
    assert.equal(r.status, 400, JSON.stringify(body));
  }
  const seven = ['G1', 'G2', 'G3', 'X0', 'X1', 'X2', 'X3'];
  assert.equal((await post(store, { mode: 'hunter', guesses: seven })).status, 400);
  assert.equal(store.keys.size, 0);
});

test('a wrong guess returns a row and the next clue but no answer', async () => {
  const store = memory();
  const r = await post(store, { guesses: ['G2'] });
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'playing');
  assert.equal(r.body.rows.length, 1);
  assert.equal(r.body.rows[0].cells.length, 5);
  assert.deepEqual(r.body.clues.map(c => c.text), ['clue 1', 'clue 2']);
  assert.equal(r.body.result, undefined);
  assert.ok(!JSON.stringify(r.body).includes('G1'));
  assert.equal(store.keys.size, 0, 'nothing is recorded before the end');
});

test('a solve is recorded once, and replaying it keeps the same rank', async () => {
  const store = memory();
  const a = await post(store, { guesses: ['G2', 'G1'] });
  assert.equal(a.body.status, 'solved');
  assert.equal(a.body.result.rank, 1);
  assert.equal(a.body.result.culprit.id, 'G1');
  assert.equal(a.body.result.culprit.tools, undefined, 'tools never leave the server');
  assert.equal(a.body.result.story, 'Story A.');
  assert.equal(a.body.clues.length, 5, 'every clue shows at the end');
  const again = await post(store, { guesses: ['G2', 'G1'] }, NOW + 60e3);
  assert.equal(again.body.result.rank, 1);
  assert.equal(store.keys.size, 1);
});

test('rank, better-than and the distribution come from first finishes', async () => {
  const store = memory();
  await post(store, { playerId: 'player-aaaa', guesses: ['G2', 'G3', 'G1'] }, NOW);
  await post(store, { playerId: 'player-bbbb', guesses: ['G3', 'G1'] }, NOW + 1);
  const c = await post(store, { playerId: 'player-cccc', guesses: ['G1'] }, NOW + 2);
  assert.equal(c.body.result.rank, 3);
  assert.equal(c.body.result.solvedCount, 3);
  assert.equal(c.body.result.betterThan, 100);
  assert.deepEqual(c.body.result.distribution, { 1: 1, 2: 1, 3: 1 });
  assert.equal((await game.today('analyst', NOW + 3, store)).body.solvedCount, 3);
  assert.equal((await game.today('hunter', NOW + 3, store)).body.solvedCount, 0, 'modes count apart');
});

test('a hunter who misses six times goes cold, is recorded, and still sees the culprit', async () => {
  const store = memory();
  const r = await post(store, { mode: 'hunter', guesses: ['G1', 'G2', 'G3', 'X0', 'X1', 'X2'] });
  assert.equal(r.body.status, 'cold');
  assert.equal(r.body.result.culprit.id, 'G4');
  assert.equal(r.body.result.rank, null);
  assert.equal(r.body.rows[0].cells.length, 7);
  const w = await post(store, { mode: 'hunter', playerId: 'player-0002', guesses: ['G4'] }, NOW + 5);
  assert.ok(w.body.rows[0].cells.every(c => c.tone === 'hit'), 'the winning row is all match');
  assert.equal(w.body.result.betterThan, 100);
  assert.deepEqual(w.body.result.distribution, { X: 1, 1: 1 });
});
