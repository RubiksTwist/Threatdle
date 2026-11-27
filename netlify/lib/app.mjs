// Netlify wiring: the game data and the Blobs store.
// Deployed, the answers come from build/private.json, which tools/build.mjs fetches from R2 and netlify.toml packs with the functions.
// Under netlify dev they come from data/, and THREATDLE_DRAFTS=1 serves the draft schedule.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { getStore } from '@netlify/blobs';
import pool from '../../data/pool.json' with { type: 'json' };
import { createGame } from './game.mjs';

const read = p => JSON.parse(readFileSync(join(process.env.LAMBDA_TASK_ROOT ?? process.cwd(), p), 'utf8'));
const { cases, schedule } = process.env.NETLIFY_DEV === 'true'
  ? { cases: read('data/cases.json').cases, schedule: read(process.env.THREATDLE_DRAFTS === '1' ? 'data/schedule.drafts.json' : 'data/schedule.json') }
  : read('build/private.json');

export const game = createGame({ pool, cases, schedule });

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
