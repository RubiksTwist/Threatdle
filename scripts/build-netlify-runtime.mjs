import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const rootDir = process.cwd();
const runtimeBundleUrl = process.env.GAME_RUNTIME_BUNDLE_URL;
const runtimeBundleToken = process.env.GAME_RUNTIME_BUNDLE_BEARER_TOKEN;
const runtimeBundleSha256 = process.env.GAME_RUNTIME_BUNDLE_SHA256;
const runtimeBundleKey = process.env.GAME_RUNTIME_BUNDLE_KEY;
const r2AccountId = process.env.R2_ACCOUNT_ID;
const r2AccessKeyId = process.env.R2_ACCESS_KEY_ID;
const r2SecretAccessKey = process.env.R2_SECRET_ACCESS_KEY;
const r2Bucket = process.env.R2_BUCKET;
const r2Region = process.env.R2_REGION || "auto";
const timezone = process.env.GAME_TIMEZONE || "America/New_York";
const startDay = process.env.GAME_START_DAY;
const dayCount = process.env.GAME_DAYS || "365";
const themeMode = process.env.GAME_THEME_MODE || "prefer";
const chainMode = process.env.GAME_CHAIN_MODE || "linked";
const outDir = path.resolve(rootDir, "build", "runtime");
const bundlePath = path.resolve(outDir, "game-data.json");

mkdirSync(outDir, { recursive: true });

function fail(message) {
  console.error(message);
  process.exit(1);
}

function writeValidatedBundle(text, sourceLabel) {
  const payload = JSON.parse(text);
  validateBundleShape(payload);
  writeFileSync(bundlePath, JSON.stringify(payload, null, 2), "utf8");
  console.log(`${sourceLabel} for snapshot ${payload.snapshot.snapshot_id}.`);
}

function validateBundleShape(payload) {
  if (!payload || typeof payload !== "object") {
    throw new Error("Runtime bundle is not a JSON object.");
  }
  if (!payload.snapshot?.snapshot_id) {
    throw new Error("Runtime bundle is missing snapshot.snapshot_id.");
  }
  if (!Array.isArray(payload.days)) {
    throw new Error("Runtime bundle is missing days.");
  }
  if (!payload.game_days || typeof payload.game_days !== "object") {
    throw new Error("Runtime bundle is missing game_days.");
  }
  if (!payload.answers || typeof payload.answers !== "object") {
    throw new Error("Runtime bundle is missing answers.");
  }
}

async function downloadPrebuiltBundle() {
  const headers = {};
  if (runtimeBundleToken) {
    headers.Authorization = `Bearer ${runtimeBundleToken}`;
  }

  const response = await fetch(runtimeBundleUrl, { headers });
  if (!response.ok) {
    throw new Error(`Failed to download runtime bundle (${response.status} ${response.statusText}).`);
  }

  const text = await response.text();
  if (runtimeBundleSha256) {
    const digest = createHash("sha256").update(text, "utf8").digest("hex");
    if (digest !== runtimeBundleSha256.toLowerCase()) {
      throw new Error("Downloaded runtime bundle failed SHA-256 verification.");
    }
  }

  writeValidatedBundle(text, "Downloaded prebuilt runtime bundle");
}

async function downloadBundleFromR2() {
  if (!r2AccountId || !r2AccessKeyId || !r2SecretAccessKey || !r2Bucket || !runtimeBundleKey) {
    throw new Error("Incomplete R2 configuration for runtime bundle download.");
  }

  const { GetObjectCommand, S3Client } = await import("@aws-sdk/client-s3");
  const client = new S3Client({
    region: r2Region,
    endpoint: `https://${r2AccountId}.r2.cloudflarestorage.com`,
    credentials: {
      accessKeyId: r2AccessKeyId,
      secretAccessKey: r2SecretAccessKey
    }
  });

  const response = await client.send(
    new GetObjectCommand({
      Bucket: r2Bucket,
      Key: runtimeBundleKey
    })
  );

  if (!response.Body || typeof response.Body.transformToString !== "function") {
    throw new Error("R2 returned an unreadable runtime bundle body.");
  }

  const text = await response.Body.transformToString("utf8");
  if (runtimeBundleSha256) {
    const digest = createHash("sha256").update(text, "utf8").digest("hex");
    if (digest !== runtimeBundleSha256.toLowerCase()) {
      throw new Error("R2 runtime bundle failed SHA-256 verification.");
    }
  }

  writeValidatedBundle(text, "Downloaded runtime bundle from R2");
}

const baseArgs = [
  "-m",
  "threatdle",
  "build-live-runtime",
  "--out-dir",
  outDir,
  "--timezone",
  timezone,
  "--days",
  dayCount,
  "--theme-mode",
  themeMode,
  "--chain-mode",
  chainMode
];

if (process.env.GAME_SNAPSHOT_ID) {
  baseArgs.push("--snapshot-id", process.env.GAME_SNAPSHOT_ID);
}

if (startDay) {
  baseArgs.push("--start-day", startDay);
}

const candidates = process.platform === "win32"
  ? [
      ["py", ["-3", ...baseArgs]],
      ["python", baseArgs]
    ]
  : [
      ["python3", baseArgs],
      ["python", baseArgs]
    ];

const env = {
  ...process.env,
  PYTHONPATH: [path.resolve(rootDir, "src"), process.env.PYTHONPATH]
    .filter(Boolean)
    .join(path.delimiter)
};

let completed = false;

async function main() {
  if (runtimeBundleUrl) {
    await downloadPrebuiltBundle();
    return;
  }

  if (runtimeBundleKey && r2AccountId && r2AccessKeyId && r2SecretAccessKey && r2Bucket) {
    await downloadBundleFromR2();
    return;
  }

  for (const [command, args] of candidates) {
    const result = spawnSync(command, args, {
      cwd: rootDir,
      env,
      stdio: "inherit"
    });
    if (!result.error && result.status === 0) {
      completed = true;
      break;
    }
  }

  if (!completed) {
    fail("Failed to export the live runtime bundle.");
  }
}

main().catch((error) => fail(error instanceof Error ? error.message : "Failed to build runtime bundle."));
