// The Netlify build. Fetches the private bundle (tools/publish.mjs uploads it) from R2 into build/private.json,
// which netlify.toml packs with the functions. Fails closed: nothing deploys without the R2 settings, a bundle whose
// sha256 matches GAME_RUNTIME_BUNDLE_SHA256 when that is set, and an approved schedule covering 60 days.
import { mkdirSync, writeFileSync } from 'node:fs';
import { dayOf } from '../public/js/rules.mjs';
import { MIN_RUNWAY } from './schedule.mjs';
import { bundleKey, checkBundle, r2, sha256 } from './publish.mjs';

try {
  const { client, bucket } = await r2(), key = bundleKey();
  const { GetObjectCommand } = await import('@aws-sdk/client-s3');
  const text = await (await client.send(new GetObjectCommand({ Bucket: bucket, Key: key }))).Body.transformToString('utf8');
  const want = process.env.GAME_RUNTIME_BUNDLE_SHA256?.trim().toLowerCase(), got = sha256(text);
  if (want && got !== want) throw new Error(`r2://${bucket}/${key} has sha256 ${got}, GAME_RUNTIME_BUNDLE_SHA256 is ${want}`);
  const today = dayOf(), n = checkBundle(JSON.parse(text), today);
  mkdirSync(new URL('../build/', import.meta.url), { recursive: true });
  writeFileSync(new URL('../build/private.json', import.meta.url), text);
  console.log(`fetched r2://${bucket}/${key} (sha256 ${got}${want ? ', pinned' : ''}); runway from ${today}: ${n} days (minimum ${MIN_RUNWAY})`);
} catch (e) {
  console.error(`build failed: ${e.message}`);
  process.exit(1);
}
