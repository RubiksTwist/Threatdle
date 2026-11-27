import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkCase } from '../tools/check-cases.mjs';
import { buildPool } from '../tools/export.mjs';

const byId = Object.fromEntries(buildPool().actors.map(a => [a.id, a]));
const clue = (text, facts = {}) => ({ kind: 'tipoff', text, facts, source: { quote: 'a quote long enough to pass the length check' } });
const hunter = (last, culprit = 'G0096') => ({
  id: 'c-0000aaaa', mode: 'hunter', culprit, article: '00000000-0000', reviewed: false,
  clues: [clue('One.'), clue('Two.'), clue('Three.'), clue('Four.'), clue('Spies for a state in China.', { home: 'CN', type: 'state' }), last],
  story: 'Something happened. A vendor said who did it.',
  report: { vendor: 'V', title: 'T', url: 'https://example.com', date: null },
});
const closing = c => checkCase(c, byId).filter(p => p.startsWith('closing'));

test('a family hint after the country clue that rules out no group is a dead closer', () => {
  assert.equal(closing(hunter(clue('CrowdStrike\'s name for this group ends in "Panda".', { family: 'Panda' }))).length, 1);
});

test('a closer that narrows, or states a new fact, or adds a tradecraft detail is fine', () => {
  assert.deepEqual(closing(hunter(clue('Went after video game makers.', { targets: ['Technology'] }))), []);
  assert.deepEqual(closing(hunter(clue('Hid its servers behind hacked routers.'))), []);
});

test('no clue may use a filled alias such as HOODOO', () => {
  assert.ok(checkCase(hunter(clue('Google tracks this group as HOODOO.')), byId).some(p => p.includes('names the culprit (HOODOO)')));
});

test('SOC Analyst never opens on a clue a reader recognizes', async () => {
  const { openingReads } = await import('../tools/check-cases.mjs');
  const c = { id: 'c-0000bbbb', clues: [clue('Spies for a government.'), clue('Hacked hotels.'), clue('Blacked out a power grid.')] };
  const reads = (...s) => ({ 'c-0000bbbb': Object.fromEntries(c.clues.map((k, i) => [k.text, s[i]])) });
  assert.deepEqual(openingReads(c, reads({ tell: 0, fits: 40 }, { tell: 0, fits: 8 }, { tell: 90, fits: 1 })), []);
  assert.match(openingReads(c, reads({ tell: 0, fits: 40 }, { tell: 60, fits: 1 }, { tell: 0, fits: 8 }))[0], /clue 2 gives the group away/);
  assert.match(openingReads(c, {})[0], /3 clues unscored/);
});

test('SOC Analyst opening clues that leave more than 20 Most Wanted groups fail', () => {
  const analyst = { id: 'c-0000cccc', mode: 'analyst', culprit: 'G0007', clues: [clue('One.'), clue('Two.'), clue('Three.'), clue('Four.')] };
  assert.ok(checkCase(analyst, byId).some(p => /^opening: \d+ Most Wanted groups still fit the opening clues \(max 20\)/.test(p)));
});
