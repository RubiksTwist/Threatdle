import { game, solves, json } from '../lib/app.mjs';

export default async req => {
  const text = await req.text();
  if (text.length > 8192) return json({ status: 413, body: { error: 'body too large' } });
  let body;
  try { body = JSON.parse(text); } catch { return json({ status: 400, body: { error: 'body must be JSON' } }); }
  return json(await game.guess(body, Date.now(), solves()));
};
export const config = { path: '/api/guess', method: 'POST' };
