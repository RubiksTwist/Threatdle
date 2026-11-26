// Netlify wiring: the bundled game data and the Blobs store. THREATDLE_DRAFTS=1 serves the draft schedule (local dev and tests only).
import { getStore } from '@netlify/blobs';
import pool from '../../data/pool.json' with { type: 'json' };
import cases from '../../data/cases.json' with { type: 'json' };
import live from '../../data/schedule.json' with { type: 'json' };
import drafts from '../../data/schedule.drafts.json' with { type: 'json' };
import { createGame } from './game.mjs';

export const game = createGame({ pool, cases: cases.cases, schedule: process.env.THREATDLE_DRAFTS === '1' ? drafts : live });

export function solves() {
  const store = getStore({ name: 'solves', consistency: 'strong' });
  return {
    async list(prefix) {
      const keys = [];
      for await (const page of store.list({ prefix, paginate: true })) keys.push(...page.blobs.map(b => b.key));
      return keys;
    },
    set: (key, value) => store.set(key, value),
  };
}

export const json = ({ status, body }) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
});
