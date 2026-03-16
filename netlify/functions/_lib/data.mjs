import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const BUNDLE_URL = new URL("../../../build/runtime/game-data.json", import.meta.url);

let bundlePromise = null;

export async function loadGameData() {
  if (!bundlePromise) {
    bundlePromise = readFile(fileURLToPath(BUNDLE_URL), "utf8").then((payload) => JSON.parse(payload));
  }
  return bundlePromise;
}
