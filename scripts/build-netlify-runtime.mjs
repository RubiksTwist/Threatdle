import { spawnSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import path from "node:path";

const rootDir = process.cwd();
const snapshotId = process.env.GAME_SNAPSHOT_ID;
const timezone = process.env.GAME_TIMEZONE || "America/New_York";
const outDir = path.resolve(rootDir, "build", "runtime");

if (!snapshotId) {
  console.error("GAME_SNAPSHOT_ID is required to build the Netlify runtime bundle.");
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });

const baseArgs = [
  "-m",
  "threatdle",
  "export-live-runtime",
  "--snapshot-id",
  snapshotId,
  "--out-dir",
  outDir,
  "--timezone",
  timezone
];

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
