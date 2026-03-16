import { loadGameData } from "./_lib/data.mjs";
import { errorResponse, getQueryParams, jsonResponse } from "./_lib/http.mjs";
import { getGameSummary } from "./_lib/game.mjs";

export async function handler(event) {
  try {
    const params = getQueryParams(event);
    if (!params.day_key) {
      return errorResponse("day_key query parameter required");
    }
    const bundle = await loadGameData();
    const payload = getGameSummary(bundle, {
      snapshotId: params.snapshot_id || null,
      dayKey: params.day_key
    });
    return jsonResponse(payload);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : "Failed to load game summary");
  }
}
