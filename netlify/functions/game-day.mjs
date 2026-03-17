import { loadGameData } from "./_lib/data.mjs";
import { errorResponse, getQueryParams, jsonResponse } from "./_lib/http.mjs";
import { getGameDay } from "./_lib/game.mjs";

export default async (request) => {
  try {
    const params = getQueryParams(request);
    if (!params.day_key) {
      return errorResponse("day_key query parameter required", 400);
    }
    const bundle = await loadGameData();
    const payload = getGameDay(bundle, {
      snapshotId: params.snapshot_id || null,
      dayKey: params.day_key
    });
    return jsonResponse(payload);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : "Failed to load game day", 500);
  }
};
