import { game, solves, json } from '../lib/app.mjs';

export default async req => json(await game.today(new URL(req.url).searchParams.get('mode'), Date.now(), solves()));
export const config = { path: '/api/today', method: 'GET' };
