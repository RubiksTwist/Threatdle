import { loadGameData } from "./_lib/data.mjs";
import { errorResponse, getQueryParams, jsonResponse } from "./_lib/http.mjs";
import { getGamePool } from "./_lib/game.mjs";

export async function handler(event) {
  try {
    const params = getQueryParams(event);
    if (!params.day_key || !params.mode) {
      return errorResponse("day_key and mode query parameters required");
    }
    const bundle = await loadGameData();
    const payload = getGamePool(bundle, {
      snapshotId: params.snapshot_id || null,
      dayKey: params.day_key,
      mode: params.mode
    });
    return jsonResponse(payload);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : "Failed to load game pool");
  }
}
