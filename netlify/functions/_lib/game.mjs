import { dayKeyForTimezone } from "./time.mjs";

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function assertSnapshot(bundle, snapshotId) {
  const expected = bundle?.snapshot?.snapshot_id;
  if (snapshotId && expected && snapshotId !== expected) {
    throw new Error(`Unknown snapshot ${snapshotId}`);
  }
}

function compareString(guessVal, trueVal) {
  if (!trueVal && !guessVal) return "match";
  if (!trueVal || !guessVal) return "mismatch";
  if (String(guessVal).trim().toLowerCase() === String(trueVal).trim().toLowerCase()) {
    return "match";
  }
  return "mismatch";
}

function compareNumeric(guessVal, trueVal) {
  if (trueVal === null && guessVal === null) return "match";
  if (trueVal === null || trueVal === undefined || guessVal === null || guessVal === undefined) {
    return "mismatch";
  }

  const guessNum = Number(guessVal);
  const trueNum = Number(trueVal);
  if (Number.isNaN(guessNum) || Number.isNaN(trueNum)) {
    return "mismatch";
  }
  if (guessNum === trueNum) return "match";
  return guessNum < trueNum ? "higher" : "lower";
}

function compareList(guessList, trueList) {
  if ((!guessList || !guessList.length) && (!trueList || !trueList.length)) return "match";
  const guessSet = new Set((guessList || []).map((value) => String(value).trim().toLowerCase()).filter(Boolean));
  const trueSet = new Set((trueList || []).map((value) => String(value).trim().toLowerCase()).filter(Boolean));
  if (!guessSet.size || !trueSet.size) return "mismatch";
  if (guessSet.size === trueSet.size && [...guessSet].every((value) => trueSet.has(value))) return "match";
  if ([...guessSet].some((value) => trueSet.has(value))) return "partial";
  return "mismatch";
}

function scoreActor(guessAttrs, trueAttrs) {
  return {
    country: { status: compareString(guessAttrs.country_code, trueAttrs.country_code), value: guessAttrs.country_code },
    year: { status: compareNumeric(guessAttrs.first_observed_year, trueAttrs.first_observed_year), value: guessAttrs.first_observed_year },
    targets: { status: compareList(guessAttrs.target_categories, trueAttrs.target_categories), value: guessAttrs.target_categories },
    motivation: { status: compareList(guessAttrs.motivation_tags, trueAttrs.motivation_tags), value: guessAttrs.motivation_tags },
    malware: { status: compareNumeric(guessAttrs.malware_count, trueAttrs.malware_count), value: guessAttrs.malware_count },
    techniques: { status: compareNumeric(guessAttrs.technique_count, trueAttrs.technique_count), value: guessAttrs.technique_count }
  };
}

function scoreMalware(guessAttrs, trueAttrs) {
  return {
    platforms: { status: compareList(guessAttrs.platforms, trueAttrs.platforms), value: guessAttrs.platforms },
    aliases: { status: compareList(guessAttrs.aliases, trueAttrs.aliases), value: guessAttrs.aliases },
    actors: { status: compareList(guessAttrs.actor_names, trueAttrs.actor_names), value: guessAttrs.actor_names }
  };
}

function scoreTechnique(guessAttrs, trueAttrs) {
  return {
    tactics: { status: compareList(guessAttrs.tactics, trueAttrs.tactics), value: guessAttrs.tactics },
    platforms: { status: compareList(guessAttrs.platforms, trueAttrs.platforms), value: guessAttrs.platforms },
    subtechnique: { status: compareString(String(guessAttrs.is_subtechnique), String(trueAttrs.is_subtechnique)), value: guessAttrs.is_subtechnique },
    parent: { status: compareString(guessAttrs.parent_name, trueAttrs.parent_name), value: guessAttrs.parent_name }
  };
}

function scoreTimeline(guessSteps, trueSteps) {
  const trueAttackIds = new Set((trueSteps || []).map((step) => String(step.attack_id || "")));
  const feedback = {};
  (trueSteps || []).forEach((trueStep, index) => {
    const guessedStep = guessSteps[index] || {};
    const guessedAttackId = String(guessedStep.attack_id || "");
    let status = "mismatch";
    if (guessedAttackId === String(trueStep.attack_id || "")) {
      status = "match";
    } else if (trueAttackIds.has(guessedAttackId)) {
      status = "partial";
    }
    feedback[`step_${index + 1}`] = {
      status,
      value: guessedStep.technique_name || guessedStep.attack_id
    };
  });
  return feedback;
}

export function resolveToday(bundle, { snapshotId = null, requestedDayKey = null, now = new Date() } = {}) {
  assertSnapshot(bundle, snapshotId);
  const timeZone = process.env.GAME_TIMEZONE || bundle.timezone || "America/New_York";
  const serverDayKey = dayKeyForTimezone(timeZone, now);
  const allDayKeys = (bundle.days || []).map((row) => row.day_key).slice().sort().reverse();
  let availableDays = allDayKeys.filter((dayKey) => dayKey <= serverDayKey);
  if (!availableDays.length) {
    availableDays = allDayKeys;
  }
  const latestDay = availableDays[0] || null;
  const selectedDay = requestedDayKey && availableDays.includes(requestedDayKey)
    ? requestedDayKey
    : latestDay;

  return {
    snapshot_id: bundle.snapshot.snapshot_id,
    timezone: timeZone,
    server_day_key: serverDayKey,
    day_key: selectedDay,
    latest_day: latestDay,
    available_days: clone(availableDays)
  };
}

export function getGameDay(bundle, { snapshotId = null, dayKey }) {
  assertSnapshot(bundle, snapshotId);
  const payload = bundle.game_days?.[dayKey];
  if (!payload) {
    throw new Error(`No puzzle data for ${dayKey}`);
  }
  return clone(payload);
}

export function getGamePool(bundle, { snapshotId = null, dayKey, mode }) {
  assertSnapshot(bundle, snapshotId);
  return clone(bundle.pools?.[dayKey]?.[mode] || []);
}

export function getGameSummary(bundle, { snapshotId = null, dayKey }) {
  assertSnapshot(bundle, snapshotId);
  const payload = bundle.summaries?.[dayKey];
  if (!payload) {
    throw new Error(`No puzzle summary for ${dayKey}`);
  }
  return clone(payload);
}

export function validateGameGuess(bundle, { snapshotId = null, dayKey, mode, guessKey = null, guessSteps = null }) {
  assertSnapshot(bundle, snapshotId);
  const trueAnswer = bundle.answers?.[dayKey]?.[mode];
  if (!trueAnswer) {
    throw new Error(`No puzzle found for ${dayKey} mode ${mode}`);
  }

  if (mode === "timeline") {
    const trueSteps = trueAnswer.comparison?.steps || [];
    const stepNameLookup = Object.fromEntries(
      trueSteps.map((step) => [String(step.attack_id || ""), step.technique_name || step.attack_id])
    );
    const normalizedGuessSteps = (guessSteps || []).map((attackId) => ({
      attack_id: String(attackId),
      technique_name: stepNameLookup[String(attackId)] || String(attackId)
    }));
    const feedback = scoreTimeline(normalizedGuessSteps, trueSteps);
    const solved = normalizedGuessSteps.length === trueSteps.length
      && normalizedGuessSteps.every((step, index) => step.attack_id === String(trueSteps[index]?.attack_id || ""));
    return {
      guess_key: guessKey,
      solved,
      feedback
    };
  }

  const guessAttrs = bundle.compare?.[mode]?.[guessKey];
  if (!guessAttrs) {
    throw new Error(`Guess ${guessKey} not found in pool`);
  }

  const trueAttrs = trueAnswer.comparison || {};
  let feedback;
  if (mode === "actor") {
    feedback = scoreActor(guessAttrs, trueAttrs);
  } else if (mode === "malware") {
    feedback = scoreMalware(guessAttrs, trueAttrs);
  } else if (mode === "technique") {
    feedback = scoreTechnique(guessAttrs, trueAttrs);
  } else {
    throw new Error(`Unsupported scoring mode ${mode}`);
  }

  return {
    guess_key: guessKey,
    solved: guessKey === trueAnswer.answer_key,
    feedback
  };
}
