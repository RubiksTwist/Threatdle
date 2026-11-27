// Publishes the answers: packs the approved schedule and its cases into one private bundle and uploads it to Cloudflare R2.
// The answers never go in git; the Netlify build (tools/build.mjs) fetches this bundle.
//   node tools/publish.mjs [--dry-run]
// Reads data/schedule.json and data/cases.json, so run export and schedule first. Needs R2_ACCOUNT_ID, R2_BUCKET,
// R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY and optionally R2_REGION; THREATDLE_BUNDLE_KEY overrides the object key.
// --dry-run prints what it would upload and needs none of them. Prints the bundle's sha256: set it as
// GAME_RUNTIME_BUNDLE_SHA256 on Netlify to pin deploys to this exact bundle.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dayOf, isDay } from '../public/js/rules.mjs';
import { runway, MIN_RUNWAY } from './schedule.mjs';

// bundle = { cases: [Case], schedule: { start: day, days: [{ analyst: caseId, hunter: caseId } | null] } }
export const bundleKey = () => process.env.THREATDLE_BUNDLE_KEY || 'threatdle/two-modes/private.json';
export const sha256 = text => createHash('sha256').update(text, 'utf8').digest('hex');

// Throws unless every scheduled case is in the bundle and approved, and the schedule covers MIN_RUNWAY days from today.
export function checkBundle(bundle, today) {
  const { cases, schedule } = bundle ?? {};
  if (!Array.isArray(cases) || !isDay(schedule?.start) || !Array.isArray(schedule.days)) throw new Error('bundle must be { cases: [...], schedule: { start, days } }');
  const byCase = new Map(cases.map(c => [c.id, c]));
  for (const id of schedule.days.flatMap(d => (d ? [d.analyst, d.hunter] : []))) {
    if (!byCase.has(id)) throw new Error(`scheduled case ${id} is missing from the bundle`);
    if (byCase.get(id).reviewed !== true) throw new Error(`scheduled case ${id} is not approved`);
  }
  const n = runway(schedule, today);
  if (n < MIN_RUNWAY) throw new Error(`schedule runway from ${today} is ${n} days, minimum ${MIN_RUNWAY}`);
  return n;
}

export async function r2() {
  const missing = ['R2_ACCOUNT_ID', 'R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY'].filter(k => !process.env[k]);
  if (missing.length) throw new Error(`missing R2 settings: ${missing.join(', ')}. Set them in the environment (see README.md).`);
  const { S3Client } = await import('@aws-sdk/client-s3');
  const client = new S3Client({
    region: process.env.R2_REGION || 'auto',
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: { accessKeyId: process.env.R2_ACCESS_KEY_ID, secretAccessKey: process.env.R2_SECRET_ACCESS_KEY },
  });
  return { client, bucket: process.env.R2_BUCKET };
}

if (import.meta.main) {
  try {
    const dryRun = process.argv.includes('--dry-run'), r = dryRun ? null : await r2();
    const read = p => JSON.parse(readFileSync(new URL('../' + p, import.meta.url), 'utf8'));
    const schedule = read('data/schedule.json');
    const ids = new Set(schedule.days.flatMap(d => (d ? [d.analyst, d.hunter] : [])));
    const bundle = { cases: read('data/cases.json').cases.filter(c => ids.has(c.id)), schedule };
    const text = JSON.stringify(bundle), today = dayOf(), key = bundleKey();
    console.log(`bundle: ${bundle.cases.length} cases, ${schedule.days.length} days from ${schedule.start}, ${Buffer.byteLength(text)} bytes`);
    console.log(`key: ${key}\nsha256: ${sha256(text)}`);
    console.log(`runway from ${today}: ${checkBundle(bundle, today)} days (minimum ${MIN_RUNWAY})`);
    if (dryRun) console.log('dry run: nothing uploaded');
    else {
      const { client, bucket } = r;
      const { PutObjectCommand } = await import('@aws-sdk/client-s3');
      await client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: text, ContentType: 'application/json', Metadata: { sha256: sha256(text) } }));
      console.log(`uploaded to r2://${bucket}/${key}. Set GAME_RUNTIME_BUNDLE_SHA256 on Netlify to the sha256 above, then deploy.`);
    }
  } catch (e) {
    console.error(`publish failed: ${e.message}`);
    process.exit(1);
  }
}
