import { access, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const BUNDLE_CANDIDATES = [
  new URL("../../../build/runtime/game-data.json", import.meta.url),
  new URL("../build/runtime/game-data.json", import.meta.url),
  new URL("../../build/runtime/game-data.json", import.meta.url)
].map((url) => fileURLToPath(url));

let bundlePromise = null;

async function resolveBundlePath() {
  const candidates = [
    ...(process.env.LAMBDA_TASK_ROOT
      ? [path.resolve(process.env.LAMBDA_TASK_ROOT, "build", "runtime", "game-data.json")]
      : []),
    path.resolve(process.cwd(), "build", "runtime", "game-data.json"),
    ...BUNDLE_CANDIDATES
  ];

  for (const candidate of candidates) {
    try {
      await access(candidate);
      return candidate;
    } catch {
      // Keep checking fallback locations.
    }
  }

  throw new Error(`Runtime bundle not found in expected locations: ${candidates.join(", ")}`);
}

export async function loadGameData() {
  if (!bundlePromise) {
    bundlePromise = resolveBundlePath()
      .then((bundlePath) => readFile(bundlePath, "utf8"))
      .then((payload) => JSON.parse(payload));
  }
  return bundlePromise;
}
