import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";

const rootDir = process.cwd();
const timezone = process.env.GAME_TIMEZONE || "America/New_York";
const startDay = process.env.GAME_START_DAY;
const dayCount = process.env.GAME_DAYS || "365";
const themeMode = process.env.GAME_THEME_MODE || "prefer";
const chainMode = process.env.GAME_CHAIN_MODE || "linked";
const outDir = path.resolve(rootDir, "build", "runtime");

mkdirSync(outDir, { recursive: true });

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
  console.error("Failed to export the live runtime bundle.");
  process.exit(1);
}
