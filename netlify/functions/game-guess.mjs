import { loadGameData } from "./_lib/data.mjs";
import { errorResponse, parseJsonBody, jsonResponse } from "./_lib/http.mjs";
import { validateGameGuess } from "./_lib/game.mjs";

export default async (request) => {
  try {
    const body = await parseJsonBody(request);
    if (!body.snapshot_id || !body.day_key || !body.mode) {
      return errorResponse("snapshot_id, day_key, and mode are required", 400);
    }
    if (body.mode === "timeline") {
      if (!Array.isArray(body.guess_steps) || !body.guess_steps.length) {
        return errorResponse("guess_steps is required for timeline guesses", 400);
      }
    } else if (!body.guess_key) {
      return errorResponse("guess_key is required for non-timeline guesses", 400);
    }

    const bundle = await loadGameData();
    const payload = validateGameGuess(bundle, {
      snapshotId: body.snapshot_id,
      dayKey: body.day_key,
      mode: body.mode,
      guessKey: body.guess_key || null,
      guessSteps: body.guess_steps || null
    });
    return jsonResponse(payload);
  } catch (error) {
    return errorResponse(error instanceof Error ? error.message : "Failed to validate guess", 500);
  }
};
