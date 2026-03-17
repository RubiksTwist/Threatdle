import { loadGameData } from "./_lib/data.mjs";
import { errorResponse, getQueryParams, jsonResponse } from "./_lib/http.mjs";
import { resolveToday } from "./_lib/game.mjs";

export default async (request) => {
  try {
    const bundle = await loadGameData();
    const params = getQueryParams(request);
    const payload = resolveToday(bundle, {
      snapshotId: params.snapshot_id || null,
      requestedDayKey: params.day_key || null
    });
    return jsonResponse(payload);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : "Failed to resolve active game day", 500);
  }
};
