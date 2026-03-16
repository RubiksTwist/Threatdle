import { loadGameData } from "./_lib/data.mjs";
import { errorResponse, parseJsonBody, jsonResponse } from "./_lib/http.mjs";
import { validateGameGuess } from "./_lib/game.mjs";

export async function handler(event) {
  try {
    const body = parseJsonBody(event);
    if (!body.snapshot_id || !body.day_key || !body.mode) {
      return errorResponse("snapshot_id, day_key, and mode are required");
    }
    if (body.mode === "timeline") {
      if (!Array.isArray(body.guess_steps) || !body.guess_steps.length) {
        return errorResponse("guess_steps is required for timeline guesses");
      }
    } else if (!body.guess_key) {
      return errorResponse("guess_key is required for non-timeline guesses");
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
    return errorResponse(error instanceof Error ? error.message : "Failed to validate guess");
  }
}
