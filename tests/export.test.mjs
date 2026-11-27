import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPool } from '../tools/export.mjs';

const { actors } = buildPool();

test('every group carries a victims list of country codes', () => {
  assert.ok(actors.every(a => Array.isArray(a.victims) && a.victims.every(c => /^[A-Z]{2}$/.test(c))));
  assert.ok(actors.some(a => a.victims.length), 'some groups have known victims');
});

test('targets come rarest across the pool first, so the board shows the most distinctive one', () => {
  const seen = {};
  for (const a of actors) for (const t of a.targets) seen[t] = (seen[t] || 0) + 1;
  for (const a of actors) assert.ok(a.targets.every((t, i) => i === 0 || seen[a.targets[i - 1]] <= seen[t]), a.id);
});
