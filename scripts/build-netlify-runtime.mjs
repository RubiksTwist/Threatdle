import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const rootDir = process.cwd();
const runtimeBundleUrl = process.env.GAME_RUNTIME_BUNDLE_URL;
const runtimeBundleToken = process.env.GAME_RUNTIME_BUNDLE_BEARER_TOKEN;
const runtimeBundleSha256 = process.env.GAME_RUNTIME_BUNDLE_SHA256;
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

  const payload = JSON.parse(text);
  validateBundleShape(payload);
  writeFileSync(bundlePath, JSON.stringify(payload, null, 2), "utf8");
  console.log(`Downloaded prebuilt runtime bundle for snapshot ${payload.snapshot.snapshot_id}.`);
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
