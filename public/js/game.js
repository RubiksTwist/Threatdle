/**
 * Threatdle Game Client Logic - Option 2 (Stepped Flow + 5 Options)
 */

const API_BASE = '/api/game';
const STATIC_DEMO_FILE = window.THREATDLE_STATIC_DEMO_FILE || null;
const IS_STATIC_DEMO = Boolean(STATIC_DEMO_FILE);
let staticDemoDataPromise = null;

// Elements
const elDate = document.getElementById('current-date');
const elModesContainer = document.getElementById('game-modes-container');
const elProgressDots = document.querySelectorAll('.progress-dot');

const modeOrder = ['actor', 'malware', 'technique'];
let currentModeIndex = 0;
let todayKey = null;
let activeDayLoadToken = 0;
let pendingEntranceAnimation = null;
let activeRevealTimers = [];

const STAMP_IN = 200;
const STAMP_HOLD = 500;
const CARD_START = 800;
const CARD_STAGGER = 80;
const CHOICE_START = 1400;
const CHOICE_STAGGER = 60;
const REVEAL_CLEANUP = 2000;

// Game State
let currentState = {
  snapshot_id: null,
  day_key: null,
  modes: {}, // Stores puzzle payload exactly as received
  drafts: {},
  guesses: {
    actor: [],
    malware: [],
    technique: []
  },
  solved: {
    actor: false,
    malware: false,
    technique: false
  }
};

// Cache for autocomplete pools
const pools = {
  actor: [],
  malware: [],
  technique: []
};

// Archive navigation
let availableDays = [];
let latestDay = null;
let previousWrongGuessCounts = {
  actor: 0,
  malware: 0,
  technique: 0
};


function getLocalDayKey(date = new Date()) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}


function getStorageKey(dayKey = currentState.day_key, snapshotId = currentState.snapshot_id) {
  return `threatdle_state_${snapshotId}_${dayKey}`;
}


function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}


function deepCopy(value) {
  if (value === null || value === undefined) return value;
  return JSON.parse(JSON.stringify(value));
}


function clearRevealTimers() {
  activeRevealTimers.forEach(timerId => clearTimeout(timerId));
  activeRevealTimers = [];
}


function scheduleRevealStep(callback, delay) {
  const timerId = window.setTimeout(() => {
    activeRevealTimers = activeRevealTimers.filter(id => id !== timerId);
    callback();
  }, delay);
  activeRevealTimers.push(timerId);
}


function renderLoadingBoard(mode = modeOrder[currentModeIndex] || modeOrder[0], message = 'Loading today\'s intelligence...') {
  elModesContainer.innerHTML = `
    <div class="mode-panel mode-panel-loading">
      <div class="mode-header">
        <h3>Phase ${currentModeIndex + 1}: ${getModeTitle(mode)}</h3>
        <span class="mode-status">${escapeHtml(message)}</span>
      </div>
      <div class="loading-shell" aria-hidden="true">
        <div class="loading-indicator">
          <span class="loading-indicator-dot"></span>
          <span class="loading-indicator-dot"></span>
          <span class="loading-indicator-dot"></span>
        </div>
      </div>
    </div>
  `;
}


async function getStaticDemoData() {
  if (!IS_STATIC_DEMO) return null;
  if (!staticDemoDataPromise) {
    staticDemoDataPromise = fetch(STATIC_DEMO_FILE).then(async response => {
      if (!response.ok) {
        throw new Error(`Failed to load static demo data from ${STATIC_DEMO_FILE}`);
      }
      return response.json();
    });
  }
  return staticDemoDataPromise;
}


function compareString(guessVal, trueVal) {
  if (!trueVal && !guessVal) return 'match';
  if (!trueVal || !guessVal) return 'mismatch';
  if (String(guessVal).trim().toLowerCase() === String(trueVal).trim().toLowerCase()) return 'match';
  return 'mismatch';
}


function compareNumeric(guessVal, trueVal) {
  if (trueVal === null && guessVal === null) return 'match';
  if (trueVal === null || trueVal === undefined || guessVal === null || guessVal === undefined) return 'mismatch';
  const guessNum = Number(guessVal);
  const trueNum = Number(trueVal);
  if (Number.isNaN(guessNum) || Number.isNaN(trueNum)) return 'mismatch';
  if (guessNum === trueNum) return 'match';
  return guessNum < trueNum ? 'higher' : 'lower';
}


function compareList(guessList, trueList) {
  if ((!guessList || !guessList.length) && (!trueList || !trueList.length)) return 'match';
  const guessSet = new Set((guessList || []).map(value => String(value).trim().toLowerCase()).filter(Boolean));
  const trueSet = new Set((trueList || []).map(value => String(value).trim().toLowerCase()).filter(Boolean));
  if (!guessSet.size || !trueSet.size) return 'mismatch';
  if (guessSet.size === trueSet.size && [...guessSet].every(value => trueSet.has(value))) return 'match';
  if ([...guessSet].some(value => trueSet.has(value))) return 'partial';
  return 'mismatch';
}


function scoreStaticGuess(mode, guessAttrs, trueAttrs) {
  if (mode === 'actor') {
    return {
      country: { status: compareString(guessAttrs.country_code, trueAttrs.country_code), value: guessAttrs.country_code },
      year: { status: compareNumeric(guessAttrs.first_observed_year, trueAttrs.first_observed_year), value: guessAttrs.first_observed_year },
      targets: { status: compareList(guessAttrs.target_categories, trueAttrs.target_categories), value: guessAttrs.target_categories },
      motivation: { status: compareList(guessAttrs.motivation_tags, trueAttrs.motivation_tags), value: guessAttrs.motivation_tags },
      malware: { status: compareNumeric(guessAttrs.malware_count, trueAttrs.malware_count), value: guessAttrs.malware_count },
      techniques: { status: compareNumeric(guessAttrs.technique_count, trueAttrs.technique_count), value: guessAttrs.technique_count }
    };
  }
  if (mode === 'malware') {
    return {
      platforms: { status: compareList(guessAttrs.platforms, trueAttrs.platforms), value: guessAttrs.platforms },
      aliases: { status: compareList(guessAttrs.aliases, trueAttrs.aliases), value: guessAttrs.aliases },
      actors: { status: compareList(guessAttrs.actor_names, trueAttrs.actor_names), value: guessAttrs.actor_names }
    };
  }
  if (mode === 'technique') {
    return {
      tactics: { status: compareList(guessAttrs.tactics, trueAttrs.tactics), value: guessAttrs.tactics },
      platforms: { status: compareList(guessAttrs.platforms, trueAttrs.platforms), value: guessAttrs.platforms },
      subtechnique: { status: compareString(String(guessAttrs.is_subtechnique), String(trueAttrs.is_subtechnique)), value: guessAttrs.is_subtechnique },
      parent: { status: compareString(guessAttrs.parent_name, trueAttrs.parent_name), value: guessAttrs.parent_name }
    };
  }
  throw new Error(`Unsupported static scoring mode: ${mode}`);
}


async function apiListSnapshots() {
  if (!IS_STATIC_DEMO) {
    const response = await fetch('/api/snapshots');
    return response.json();
  }
  const bundle = await getStaticDemoData();
  return deepCopy(bundle.snapshots || []);
}


async function apiListDays(snapshotId) {
  if (!IS_STATIC_DEMO) {
    const response = await fetch(`/api/days?snapshot_id=${snapshotId}`);
    return response.json();
  }
  const bundle = await getStaticDemoData();
  if (!bundle.snapshot || bundle.snapshot.snapshot_id !== snapshotId) {
    throw new Error(`Static demo snapshot ${snapshotId} not found`);
  }
  return deepCopy(bundle.days || []);
}


async function apiGetToday(snapshotId = null, requestedDayKey = null) {
  if (!IS_STATIC_DEMO) {
    const params = new URLSearchParams();
    if (snapshotId) params.set('snapshot_id', snapshotId);
    if (requestedDayKey) params.set('day_key', requestedDayKey);
    const query = params.toString();
    const response = await fetch(`${API_BASE}/today${query ? `?${query}` : ''}`);
    if (!response.ok) {
      throw new Error('Failed to resolve active game day');
    }
    return response.json();
  }

  const bundle = await getStaticDemoData();
  const resolvedSnapshotId = snapshotId || bundle.snapshot?.snapshot_id;
  if (!resolvedSnapshotId) {
    throw new Error('Static demo snapshot not found');
  }

  const serverDayKey = getLocalDayKey();
  const allDayKeys = (bundle.days || []).map(row => row.day_key).slice().sort().reverse();
  let availableDayKeys = allDayKeys.filter(dayKey => dayKey <= serverDayKey);
  if (!availableDayKeys.length) {
    availableDayKeys = allDayKeys;
  }
  const latestDayKey = availableDayKeys[0] || null;
  const selectedDayKey = requestedDayKey && availableDayKeys.includes(requestedDayKey)
    ? requestedDayKey
    : latestDayKey;

  return {
    snapshot_id: resolvedSnapshotId,
    timezone: 'local-browser',
    server_day_key: serverDayKey,
    day_key: selectedDayKey,
    latest_day: latestDayKey,
    available_days: deepCopy(availableDayKeys)
  };
}


async function apiGetDay(snapshotId, dayKey) {
  if (!IS_STATIC_DEMO) {
    const response = await fetch(`${API_BASE}/day?snapshot_id=${snapshotId}&day_key=${dayKey}`);
    return response.json();
  }
  const bundle = await getStaticDemoData();
  const day = bundle.game_days?.[dayKey];
  if (!day || day.snapshot_id !== snapshotId) {
    throw new Error(`Static demo day ${dayKey} not found`);
  }
  return deepCopy(day);
}


async function apiGetPool(snapshotId, dayKey, mode) {
  if (!IS_STATIC_DEMO) {
    const response = await fetch(`${API_BASE}/pool?snapshot_id=${snapshotId}&day_key=${dayKey}&mode=${mode}`);
    return response.json();
  }
  const bundle = await getStaticDemoData();
  if (!bundle.snapshot || bundle.snapshot.snapshot_id !== snapshotId) {
    throw new Error(`Static demo snapshot ${snapshotId} not found`);
  }
  return deepCopy(bundle.pools?.[dayKey]?.[mode] || []);
}


async function apiSubmitGuess(snapshotId, dayKey, mode, guessKey, extraBody = {}) {
  if (!IS_STATIC_DEMO) {
    const response = await fetch(`${API_BASE}/guess`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        snapshot_id: snapshotId,
        day_key: dayKey,
        mode,
        ...(guessKey ? { guess_key: guessKey } : {}),
        ...extraBody
      })
    });
    if (!response.ok) {
      throw new Error('Guess validation failed');
    }
    return response.json();
  }
  const bundle = await getStaticDemoData();
  const trueAnswer = bundle.answers?.[dayKey]?.[mode];
  if (!trueAnswer) {
    throw new Error(`Static demo answer not found for ${dayKey} ${mode}`);
  }
  const guessAttrs = bundle.compare?.[mode]?.[guessKey] || {};
  return {
    guess_key: guessKey,
    solved: guessKey === trueAnswer.answer_key,
    feedback: scoreStaticGuess(mode, guessAttrs, trueAnswer.comparison || {})
  };
}


async function apiGetSummary(snapshotId, dayKey) {
  if (!IS_STATIC_DEMO) {
    const response = await fetch(`${API_BASE}/summary?snapshot_id=${snapshotId}&day_key=${dayKey}`);
    if (!response.ok) {
      throw new Error('Failed to fetch game summary');
    }
    return response.json();
  }
  const bundle = await getStaticDemoData();
  if (!bundle.snapshot || bundle.snapshot.snapshot_id !== snapshotId) {
    throw new Error(`Static demo snapshot ${snapshotId} not found`);
  }
  return deepCopy(bundle.summaries?.[dayKey] || {});
}


function mitreUrlForKey(answerKey) {
  if (typeof answerKey !== 'string') return null;
  const normalized = answerKey.trim().toUpperCase();
  if (/^G\d{4}$/.test(normalized)) {
    return `https://attack.mitre.org/groups/${normalized}/`;
  }
  if (/^S\d{4}$/.test(normalized)) {
    return `https://attack.mitre.org/software/${normalized}/`;
  }
  if (/^T\d{4}(?:\.\d{3})?$/.test(normalized)) {
    return `https://attack.mitre.org/techniques/${normalized.replace('.', '/')}/`;
  }
  return null;
}


function renderMitreSummaryLink(guess, fallbackLabel = 'Unknown') {
  const label = guess?.guess_label || fallbackLabel;
  const answerKey = guess?.guess_key || '';
  const url = mitreUrlForKey(answerKey);
  if (!url) {
    return escapeHtml(label);
  }
  return `
    <a class="summary-resource-link" href="${url}" target="_blank" rel="noopener noreferrer">
      <span class="summary-resource-name">${escapeHtml(label)}</span>
      <span class="summary-resource-id">${escapeHtml(answerKey)}</span>
      <span class="summary-resource-icon" aria-hidden="true">&#8599;</span>
    </a>
  `;
}


function isActiveMode(mode) {
  return modeOrder.includes(mode);
}


function countSolvedModes(state = currentState) {
  return modeOrder.filter(mode => Boolean(state.solved?.[mode])).length;
}


function areAllModesSolved(state = currentState) {
  return modeOrder.every(mode => Boolean(state.solved?.[mode]));
}


function getModeTitle(mode) {
  if (mode === 'actor') return 'Advanced Persistent Threat Identification';
  if (mode === 'malware') return 'Malware Identification';
  if (mode === 'technique') return 'Tactics, Techniques, and Procedures Identification';
  if (mode === 'timeline') return 'Timeline Reconstruction';
  return `${mode} Identification`;
}


function countryCodeToFlagEmoji(countryCode) {
  if (typeof countryCode !== 'string') return null;
  const normalized = countryCode.trim().toUpperCase();
  if (normalized === 'UN' || normalized === 'ZZ') return null;
  if (!/^[A-Z]{2}$/.test(normalized)) return null;
  return String.fromCodePoint(
    ...Array.from(normalized, char => 127397 + char.charCodeAt(0))
  );
}


function isUnknownCountryCode(countryCode) {
  if (typeof countryCode !== 'string') return false;
  const normalized = countryCode.trim().toUpperCase();
  return normalized === 'UN' || normalized === 'ZZ';
}


function renderCountryFlagChip(countryCode, extraClass = '') {
  const normalized = typeof countryCode === 'string' ? countryCode.trim().toUpperCase() : '';
  if (isUnknownCountryCode(normalized)) {
    const className = extraClass
      ? `country-flag-chip country-flag-chip-unknown ${extraClass}`
      : 'country-flag-chip country-flag-chip-unknown';
    return `
      <span class="${className}" title="Unknown origin">
        <span class="country-chip-text">Unknown</span>
      </span>
    `;
  }
  const flag = countryCodeToFlagEmoji(normalized);
  if (!flag) {
    return normalized || 'Unknown';
  }
  const className = extraClass
    ? `country-flag-chip ${extraClass}`
    : 'country-flag-chip';
  return `
    <span class="${className}" title="${normalized}">
      <img
        src="https://flagcdn.com/w40/${normalized.toLowerCase()}.png"
        alt="${normalized}"
        class="flag-icon clue-flag-icon"
        loading="lazy"
        data-country-code="${normalized}"
      >
      <span class="country-flag-fallback" role="img" aria-label="Country flag for ${normalized}">${flag}</span>
    </span>
  `;
}


function getClueLabel(mode, key) {
  const labels = {
    actor: {
      country_code: 'Country',
      first_observed_year: 'First Seen',
      target_categories: 'Target Categories',
      motivation_tags: 'Motivation',
      malware_count: 'Known Malware',
      technique_count: 'Known Techniques'
    },
    malware: {
      actor_count: 'Threat Actors'
    },
    technique: {
      tactics: 'Tactics',
      platforms: 'Platforms',
      is_subtechnique: 'Technique Scope',
      parent_name: 'Parent Technique'
    }
  };
  return labels[mode]?.[key] || key.replace(/_/g, ' ');
}


function bindFlagFallback(scope) {
  scope.querySelectorAll('.clue-flag-icon').forEach(img => {
    const showFallback = () => {
      img.style.display = 'none';
      const fallback = img.nextElementSibling;
      if (fallback) {
        fallback.style.display = 'inline-flex';
      }
    };
    img.addEventListener('error', showFallback, { once: true });
    if (img.complete && img.naturalWidth === 0) {
      showFallback();
    }
  });
}


function getTimelineCanonicalSteps(modeData = currentState.modes.timeline) {
  return (modeData?.payload?.clues?.steps || []).map(step => ({
    attack_id: step.attack_id,
    technique_name: step.technique_name,
    step_index: step.step_index
  }));
}


function getTimelineScrambledSteps(modeData = currentState.modes.timeline) {
  const scrambled = (modeData?.payload?.clues?.scrambled_steps || []).map(step => ({
    attack_id: step.attack_id,
    technique_name: step.technique_name,
    step_index: step.step_index
  }));
  return scrambled.length ? scrambled : getTimelineCanonicalSteps(modeData);
}


function isTimelineInCanonicalOrder(draft, canonicalSteps) {
  return (
    Array.isArray(draft) &&
    draft.length === canonicalSteps.length &&
    draft.every((step, index) => step.attack_id === canonicalSteps[index]?.attack_id)
  );
}


function buildUnsolvedTimelineDraft(modeData = currentState.modes.timeline) {
  const canonicalSteps = getTimelineCanonicalSteps(modeData);
  if (!canonicalSteps.length) return [];
  const scrambled = getTimelineScrambledSteps(modeData);
  if (!isTimelineInCanonicalOrder(scrambled, canonicalSteps)) {
    return scrambled;
  }
  if (canonicalSteps.length > 1) {
    return [...canonicalSteps.slice(1), canonicalSteps[0]];
  }
  return [...canonicalSteps];
}


function getTimelineLockedStates(modeData = currentState.modes.timeline, draft = ensureTimelineDraft(modeData)) {
  const canonicalSteps = getTimelineCanonicalSteps(modeData);
  return draft.map((step, index) => step.attack_id === canonicalSteps[index]?.attack_id);
}


function getTimelineMoveTargetIndex(index, direction, lockedStates) {
  if (!Array.isArray(lockedStates) || index < 0 || index >= lockedStates.length || lockedStates[index]) {
    return -1;
  }
  const step = direction === 'up' ? -1 : 1;
  for (let candidate = index + step; candidate >= 0 && candidate < lockedStates.length; candidate += step) {
    if (!lockedStates[candidate]) {
      return candidate;
    }
  }
  return -1;
}


function getTimelineLockedCount(modeData = currentState.modes.timeline, draft = ensureTimelineDraft(modeData)) {
  return getTimelineLockedStates(modeData, draft).filter(Boolean).length;
}


function isTimelineSolved(modeData = currentState.modes.timeline, draft = ensureTimelineDraft(modeData)) {
  return draft.length > 0 && getTimelineLockedCount(modeData, draft) === draft.length;
}


function hasMatchingTimelineSteps(draft, canonicalSteps) {
  if (!Array.isArray(draft) || draft.length !== canonicalSteps.length) return false;
  const draftIds = draft.map(step => step.attack_id).slice().sort().join('|');
  const canonicalIds = canonicalSteps.map(step => step.attack_id).slice().sort().join('|');
  return draftIds === canonicalIds;
}


function ensureTimelineDraft(modeData = currentState.modes.timeline) {
  const canonicalSteps = getTimelineCanonicalSteps(modeData);
  if (!canonicalSteps.length) {
    currentState.drafts.timeline = [];
    return [];
  }
  if (!hasMatchingTimelineSteps(currentState.drafts.timeline, canonicalSteps)) {
    currentState.drafts.timeline = currentState.solved.timeline
      ? [...canonicalSteps]
      : buildUnsolvedTimelineDraft(modeData);
    saveLocalState();
    return currentState.drafts.timeline;
  }
  if (!currentState.solved.timeline && isTimelineInCanonicalOrder(currentState.drafts.timeline, canonicalSteps)) {
    currentState.drafts.timeline = buildUnsolvedTimelineDraft(modeData);
    saveLocalState();
  }
  return currentState.drafts.timeline;
}


function resetTimelineDraft(modeData = currentState.modes.timeline) {
  currentState.drafts.timeline = buildUnsolvedTimelineDraft(modeData);
  currentState.solved.timeline = false;
  saveLocalState();
}


function syncTimelineSolvedState(modeData = currentState.modes.timeline) {
  currentState.guesses.timeline = [];
  const draft = hasMatchingTimelineSteps(currentState.drafts.timeline, getTimelineCanonicalSteps(modeData))
    ? currentState.drafts.timeline
    : ensureTimelineDraft(modeData);
  currentState.solved.timeline = isTimelineSolved(modeData, draft);
}


function nudgeTimelineStep(index, direction, modeData = currentState.modes.timeline) {
  const draft = [...ensureTimelineDraft(modeData)];
  const lockedStates = getTimelineLockedStates(modeData, draft);
  const targetIndex = getTimelineMoveTargetIndex(index, direction, lockedStates);
  if (index < 0 || index >= draft.length) return;
  if (targetIndex < 0 || targetIndex >= draft.length) return;
  [draft[index], draft[targetIndex]] = [draft[targetIndex], draft[index]];
  currentState.drafts.timeline = draft;
  syncTimelineSolvedState(modeData);
  saveLocalState();
  renderBoard();
  updateProgressIndicators();
  if (areAllModesSolved()) {
    setTimeout(showSummaryModal, 400);
  }
}


// --- Initialization ---

async function initGame() {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const todayPayload = await apiGetToday(
      urlParams.get('snapshot_id'),
      urlParams.get('day_key')
    );

    currentState.snapshot_id = todayPayload.snapshot_id;
    todayKey = todayPayload.server_day_key;
    availableDays = Array.isArray(todayPayload.available_days)
      ? todayPayload.available_days.slice()
      : [];
    if (!availableDays.length) {
      throw new Error(`No puzzle days available on or before ${todayKey}`);
    }

    latestDay = todayPayload.latest_day || availableDays[0];
    currentState.day_key = todayPayload.day_key || latestDay;

    syncDayUrl(currentState.day_key);

    await loadDay(currentState.day_key);

    // Enable dot navigation
    elProgressDots.forEach((dot, index) => {
      dot.style.cursor = 'pointer';
      dot.addEventListener('click', () => {
        currentModeIndex = index;
        renderBoard();
        updateProgressIndicators();
      });
    });

    // Drawer buttons
    document.getElementById('archive-btn').addEventListener('click', openDrawer);
    document.getElementById('drawer-close').addEventListener('click', closeDrawer);
    document.getElementById('drawer-overlay').addEventListener('click', closeDrawer);

    // Logo = home (go to today's puzzle)
    document.querySelector('.logo-container').style.cursor = 'pointer';
    document.querySelector('.logo-container').addEventListener('click', () => {
      const url = new URL(window.location);
      url.searchParams.delete('day_key');
      window.history.pushState({}, '', url);
      loadDay(latestDay);
    });

  } catch (err) {
    console.error("Failed to initialize game:", err);
    elDate.textContent = "Error Loading Game";
  }
}

async function loadDay(dayKey) {
  const loadToken = ++activeDayLoadToken;
  clearRevealTimers();
  pendingEntranceAnimation = null;
  if (!availableDays.includes(dayKey)) {
    dayKey = latestDay;
  }

  // Reset in-memory state for the new day
  currentState.day_key = dayKey;
  currentState.drafts = {};
  currentState.guesses = { actor: [], malware: [], technique: [] };
  currentState.solved = { actor: false, malware: false, technique: false };
  previousWrongGuessCounts = { actor: 0, malware: 0, technique: 0 };
  modeOrder.forEach(mode => {
    pools[mode] = [];
  });

  elDate.textContent = dayKey;
  loadLocalState();

  currentModeIndex = modeOrder.findIndex(m => !currentState.solved[m]);
  if (currentModeIndex === -1) currentModeIndex = modeOrder.length - 1;
  renderLoadingBoard(modeOrder[currentModeIndex], 'Preparing dossier...');
  updateProgressIndicators();

  const dayData = await apiGetDay(currentState.snapshot_id, dayKey);
  if (loadToken !== activeDayLoadToken) return;
  currentState.modes = dayData.modes;
  currentModeIndex = modeOrder.findIndex(m => !currentState.solved[m]);
  if (currentModeIndex === -1) currentModeIndex = modeOrder.length - 1;

  await Promise.all(modeOrder.map(mode => fetchPool(mode)));
  if (loadToken !== activeDayLoadToken) return;

  const activeMode = modeOrder[currentModeIndex];
  const canAnimateEntrance = activeMode && !currentState.solved[activeMode] && activeMode !== 'timeline';
  pendingEntranceAnimation = canAnimateEntrance
    ? { dayKey: currentState.day_key, mode: activeMode }
    : null;
  renderBoard();
  updateProgressIndicators();
}

async function fetchAvailableDays() {
  try {
    const days = await apiListDays(currentState.snapshot_id);
    availableDays = days
      .map(d => d.day_key)
      .filter(dayKey => dayKey <= todayKey)
      .sort()
      .reverse();
  } catch (e) {
    console.error('Failed to fetch available days', e);
  }
}

function syncDayUrl(dayKey) {
  const url = new URL(window.location);
  if (dayKey === latestDay) {
    url.searchParams.delete('day_key');
  } else {
    url.searchParams.set('day_key', dayKey);
  }
  window.history.replaceState({}, '', url);
}

function openDrawer() {
  buildCaseCards();
  document.getElementById('drawer-overlay').classList.remove('hidden');
  document.getElementById('case-files-drawer').classList.add('open');
}

function closeDrawer() {
  document.getElementById('drawer-overlay').classList.add('hidden');
  document.getElementById('case-files-drawer').classList.remove('open');
}

function buildCaseCards() {
  const container = document.getElementById('drawer-content');
  container.innerHTML = '';

  availableDays.forEach((dayKey, i) => {
    const card = document.createElement('div');
    card.className = 'case-card';
    if (dayKey === currentState.day_key) card.classList.add('current-day');

    // Read status from localStorage
    const saved = localStorage.getItem(getStorageKey(dayKey));
    let statusClass = 'sealed';
    let statusLabel = 'SEALED';
    let scoreHTML = '';

    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        const solvedModes = countSolvedModes(parsed);
        if (solvedModes === modeOrder.length) {
          statusClass = 'declassified';
          statusLabel = 'DECLASSIFIED';
          let incorrect = 0;
          modeOrder.forEach(mode => {
            const guesses = parsed.guesses?.[mode] || [];
            incorrect += Math.max(0, guesses.length - 1);
          });
          scoreHTML = `<span class="case-score">${incorrect} incorrect deduction${incorrect !== 1 ? 's' : ''}</span>`;
        } else if (solvedModes > 0) {
          statusClass = 'in-progress';
          statusLabel = `IN PROGRESS (${solvedModes}/${modeOrder.length})`;
        }
      } catch (e) { /* ignore */ }
    }

    const caseNum = availableDays.length - i;
    card.innerHTML = `
      <div class="case-info">
        <span class="case-number">Case #${String(caseNum).padStart(3, '0')}</span>
        <span class="case-date">${dayKey}</span>
        ${scoreHTML}
      </div>
      <span class="case-status ${statusClass}">${statusLabel}</span>
    `;

    card.addEventListener('click', () => {
      closeDrawer();
      switchDay(dayKey);
    });

    container.appendChild(card);
  });
}

async function switchDay(dayKey) {
  if (dayKey === currentState.day_key || !availableDays.includes(dayKey)) return;
  // Update URL without reloading
  syncDayUrl(dayKey);
  await loadDay(dayKey);
}

async function fetchPool(mode) {
  try {
    pools[mode] = await apiGetPool(currentState.snapshot_id, currentState.day_key, mode);
  } catch (e) {
    console.error(`Failed to fetch pool for ${mode}`, e);
  }
}

// --- State Management ---

function loadLocalState() {
  const saved = localStorage.getItem(getStorageKey());
  if (saved) {
    try {
      const parsed = JSON.parse(saved);
      currentState.drafts = parsed.drafts && typeof parsed.drafts === 'object' ? parsed.drafts : currentState.drafts;
      modeOrder.forEach(mode => {
        currentState.guesses[mode] = Array.isArray(parsed.guesses?.[mode]) ? parsed.guesses[mode] : currentState.guesses[mode];
        currentState.solved[mode] = Boolean(parsed.solved?.[mode]);
      });
      currentState.guesses.actor = (currentState.guesses.actor || []).map(guess => {
        if (!guess?.feedback || typeof guess.feedback !== 'object') {
          return guess;
        }
        const { operations, campaigns, ...feedback } = guess.feedback;
        return { ...guess, feedback };
      });
    } catch (e) {
      console.warn("Could not parse saved state", e);
    }
  }
}

function saveLocalState() {
  const stateToSave = {
    drafts: currentState.drafts,
    guesses: currentState.guesses,
    solved: currentState.solved
  };
  localStorage.setItem(getStorageKey(), JSON.stringify(stateToSave));
}

// --- UI Rendering ---

function updateProgressIndicators() {
  elProgressDots.forEach(dot => {
    const mode = dot.dataset.mode;
    dot.classList.remove('solved');
    dot.classList.remove('active');
    if (!isActiveMode(mode)) {
      return;
    }
    if (currentState.solved[mode]) {
      dot.classList.add('solved');
    }
    if (dot.dataset.mode === modeOrder[currentModeIndex]) {
      dot.classList.add('active');
    }
  });
}

function shouldAnimateBoardEntrance(mode) {
  return Boolean(
    pendingEntranceAnimation &&
    pendingEntranceAnimation.dayKey === currentState.day_key &&
    pendingEntranceAnimation.mode === mode &&
    !currentState.solved[mode] &&
    mode !== 'timeline'
  );
}


function runBoardRevealSequence(panel, finalStatusLabel) {
  clearRevealTimers();

  const stamp = panel.querySelector('.stamp');
  const stampContainer = panel.querySelector('.stamp-container');
  const status = panel.querySelector('.mode-status');
  const overlays = panel.querySelectorAll('.redact-overlay');
  const choiceButtons = panel.querySelectorAll('.choices-area .choice-btn');

  if (!stamp || !overlays.length) {
    pendingEntranceAnimation = null;
    return;
  }

  if (status) {
    status.textContent = 'Preparing dossier...';
  }

  stamp.className = 'stamp';
  overlays.forEach(overlay => overlay.classList.remove('revealed'));
  choiceButtons.forEach(button => button.classList.remove('visible'));

  scheduleRevealStep(() => {
    if (!panel.isConnected) return;
    stamp.classList.add('show');
  }, STAMP_IN);

  scheduleRevealStep(() => {
    if (!panel.isConnected) return;
    stamp.classList.remove('show');
    stamp.classList.add('hide');
    if (status) {
      status.textContent = finalStatusLabel;
    }
  }, STAMP_IN + STAMP_HOLD);

  overlays.forEach((overlay, index) => {
    scheduleRevealStep(() => {
      if (!panel.isConnected) return;
      overlay.classList.add('revealed');
    }, CARD_START + index * CARD_STAGGER);
  });

  choiceButtons.forEach((button, index) => {
    scheduleRevealStep(() => {
      if (!panel.isConnected) return;
      button.classList.add('visible');
    }, CHOICE_START + index * CHOICE_STAGGER);
  });

  scheduleRevealStep(() => {
    if (!panel.isConnected) return;
    stampContainer?.remove();
  }, REVEAL_CLEANUP);

  pendingEntranceAnimation = null;
}

function renderBoard() {
  clearRevealTimers();
  elModesContainer.innerHTML = '';
  
  const mode = modeOrder[currentModeIndex];
  const modeData = currentState.modes[mode];
  if (!modeData) return;
  const timelineDraft = mode === 'timeline' ? ensureTimelineDraft(modeData) : [];
  const timelineLockedStates = mode === 'timeline' ? getTimelineLockedStates(modeData, timelineDraft) : [];
  const timelineLockedCount = mode === 'timeline' ? timelineLockedStates.filter(Boolean).length : 0;
  const animateEntrance = shouldAnimateBoardEntrance(mode);
  
  const panel = document.createElement('div');
  panel.className = `mode-panel active-panel${animateEntrance ? ' mode-panel-reveal' : ''}`;
  
  let interactionHTML = '';
  if (!currentState.solved[mode]) {
    if (mode === 'timeline') {
      interactionHTML = `
        <div class="timeline-builder-wrapper">
          <p class="timeline-builder-copy">Use the arrow buttons to move each technique into the source-reported execution order. Correct placements lock automatically.</p>
          <div class="timeline-builder" id="timeline-builder">
            ${timelineDraft.map((step, index) => {
              const isLocked = timelineLockedStates[index];
              const moveUpTarget = getTimelineMoveTargetIndex(index, 'up', timelineLockedStates);
              const moveDownTarget = getTimelineMoveTargetIndex(index, 'down', timelineLockedStates);
              const controlsHTML = isLocked
                ? `<div class="timeline-card-controls timeline-card-controls-locked"><span class="timeline-card-controls-note">Position fixed</span></div>`
                : `<div class="timeline-card-controls">
                    <button class="timeline-move-btn" data-direction="up" data-index="${index}" aria-label="Move ${step.technique_name} up" ${moveUpTarget === -1 ? 'disabled' : ''}>&#8593;</button>
                    <button class="timeline-move-btn" data-direction="down" data-index="${index}" aria-label="Move ${step.technique_name} down" ${moveDownTarget === -1 ? 'disabled' : ''}>&#8595;</button>
                  </div>`;
              return `
                <div class="timeline-card ${isLocked ? 'locked' : ''}" data-attack-id="${step.attack_id}">
                  <div class="timeline-card-order">${index + 1}</div>
                  <div class="timeline-card-body">
                    <span class="timeline-card-id">${step.attack_id}</span>
                    <span class="timeline-card-name">${step.technique_name}</span>
                    <span class="timeline-card-state">${isLocked ? 'Locked' : 'Reorder'}</span>
                  </div>
                  ${controlsHTML}
                </div>
              `;
            }).join('')}
          </div>
          <div class="timeline-builder-actions">
            <span class="timeline-progress">${timelineLockedCount}/${timelineDraft.length} locked</span>
            <button class="modal-btn timeline-reset-btn" id="timeline-reset-btn">Reset Order</button>
          </div>
        </div>
      `;
    } else {
      const pool = pools[mode] || [];
      const hasLoadedPool = pool.length > 0;
      interactionHTML = `
        ${hasLoadedPool
          ? `<div class="${animateEntrance ? 'choices-area' : 'multiple-choice-grid'}">
              ${pool.map((opt) => `<button class="choice-btn" data-key="${opt.guess_key}">${opt.guess_label}</button>`).join('')}
            </div>`
          : `<div class="pool-loading">
              <div class="loading-indicator loading-indicator-compact" aria-hidden="true">
                <span class="loading-indicator-dot"></span>
                <span class="loading-indicator-dot"></span>
                <span class="loading-indicator-dot"></span>
              </div>
            </div>`}
      `;
    }
  } else {
    const isLast = currentModeIndex === modeOrder.length - 1;
    if (mode === 'timeline') {
      interactionHTML = `
        <div class="timeline-builder-wrapper">
          <p class="timeline-builder-copy">Incident timeline reconstructed in source-reported order.</p>
          <div class="timeline-builder" id="timeline-builder">
            ${timelineDraft.map((step, index) => `
              <div class="timeline-card locked" data-attack-id="${step.attack_id}">
                <div class="timeline-card-order">${index + 1}</div>
                <div class="timeline-card-body">
                  <span class="timeline-card-id">${step.attack_id}</span>
                  <span class="timeline-card-name">${step.technique_name}</span>
                  <span class="timeline-card-state">Locked</span>
                </div>
              </div>
            `).join('')}
          </div>
          <div class="next-phase-container">
            <button class="modal-btn next-phase-btn" id="next-btn-${mode}">
              ${isLast ? 'View Final Report' : 'Proceed to Next Phase'}
            </button>
          </div>
        </div>
      `;
    } else {
      interactionHTML = `
        <div class="next-phase-container">
          <button class="modal-btn next-phase-btn" id="next-btn-${mode}">
            ${isLast ? 'View Final Report' : 'Proceed to Next Phase'}
          </button>
        </div>
      `;
    }
  }

  const statusLabel = currentState.solved[mode]
    ? 'Solved'
    : mode === 'timeline'
      ? `${timelineLockedCount}/${timelineDraft.length} Locked`
      : 'In progress';

  panel.innerHTML = `
    <div class="mode-header">
      <h3>Phase ${currentModeIndex + 1}: ${getModeTitle(mode)}</h3>
      <span class="mode-status ${currentState.solved[mode] ? 'solved' : ''}">
        ${statusLabel}
      </span>
    </div>
    
    <div class="clues-container" id="clues-${mode}"></div>
    
    ${mode === 'timeline' ? '' : `<div class="deduction-grid" id="grid-${mode}"></div>`}
    
    <div class="guess-section" id="guess-section-${mode}">
      ${interactionHTML}
    </div>
    ${animateEntrance ? `<div class="stamp-container" aria-hidden="true"><div class="stamp">Classified</div></div>` : ''}
  `;
  
  elModesContainer.appendChild(panel);
  
  renderClues(mode, modeData.payload.clues, { animateEntrance });
  if (mode !== 'timeline') {
    renderGridHistory(mode);
  }
  
  // Attach Listeners
  if (!currentState.solved[mode]) {
    if (mode === 'timeline') {
      attachTimelineInteraction(panel, modeData);
    } else {
      const btns = panel.querySelectorAll('.choice-btn');
      btns.forEach(btn => {
        // If already guessed, disable the button
        if (currentState.guesses[mode].some(g => g.guess_key === btn.dataset.key)) {
          btn.disabled = true;
          btn.classList.add('guessed-wrong');
        }

        btn.addEventListener('click', () => {
          btns.forEach(b => b.disabled = true);
          submitGuess(mode, btn.dataset.key, btn.textContent);
        });
      });
    }
  } else {
    const nextBtn = panel.querySelector('.next-phase-btn');
    if (nextBtn) {
      nextBtn.addEventListener('click', () => {
        if (currentModeIndex < modeOrder.length - 1) {
          currentModeIndex++;
          renderBoard();
          updateProgressIndicators();
        } else {
          showSummaryModal();
        }
      });
    }
  }

  if (animateEntrance) {
    runBoardRevealSequence(panel, statusLabel);
  }
}


function attachTimelineInteraction(panel, modeData) {
  const resetBtn = panel.querySelector('#timeline-reset-btn');

  panel.querySelectorAll('.timeline-move-btn').forEach(button => {
    button.addEventListener('click', () => {
      const index = Number(button.dataset.index);
      nudgeTimelineStep(index, button.dataset.direction, modeData);
    });
  });

  if (resetBtn) {
    resetBtn.addEventListener('click', () => {
      resetTimelineDraft(modeData);
      updateProgressIndicators();
      renderBoard();
    });
  }
}

function renderClues(mode, clues, options = {}) {
  const { animateEntrance = false } = options;
  const container = document.getElementById(`clues-${mode}`);
  container.innerHTML = '';
  container.classList.toggle('technique-clues-grid', mode === 'technique');
  container.classList.toggle('card-grid', animateEntrance);
  
  if (mode === 'timeline') {
    const stepCount = clues.step_count || (clues.steps || []).length;
    const orderingBasis = clues.ordering_basis || 'Arrange the techniques in the source-reported execution order.';
    [
      { label: 'reported steps', value: stepCount },
      { label: 'ordering basis', value: orderingBasis }
    ].forEach(item => {
      const div = document.createElement('div');
      div.className = 'clue-item';
      div.innerHTML = `
        <span class="clue-label">${item.label}</span>
        <span class="clue-value">${item.value}</span>
      `;
      container.appendChild(div);
    });
    return;
  }
  
  const wrongGuesses = currentState.guesses[mode].filter(g => !g.is_correct).length;
  const unlockThresholds = {
    actor: { country_code: 1, target_categories: 2 },
    malware: { platforms: 1, actor_count: 2 },
    technique: { platforms: 1, is_subtechnique: 2 }
  };
  const clueDisplayOrder = {
    actor: ['country_code', 'first_observed_year', 'malware_count', 'motivation_tags', 'target_categories', 'technique_count'],
    malware: ['capability_summary', 'platforms', 'actor_count', 'aliases'],
    technique: ['tactics', 'parent_name', 'platforms', 'is_subtechnique']
  };
  const orderedClues = Object.entries(clues).sort(([keyA], [keyB]) => {
    const order = clueDisplayOrder[mode] || [];
    const indexA = order.indexOf(keyA);
    const indexB = order.indexOf(keyB);
    const rankA = indexA === -1 ? Number.MAX_SAFE_INTEGER : indexA;
    const rankB = indexB === -1 ? Number.MAX_SAFE_INTEGER : indexB;
    if (rankA !== rankB) return rankA - rankB;
    return keyA.localeCompare(keyB);
  });

  orderedClues.forEach(([key, value]) => {
    if (value === null || value === undefined) return;
    if (mode === 'actor' && (key === 'operations_count' || key === 'campaign_count')) return;
    if (mode === 'malware' && key === 'malware_category') return;
    if (key === 'steps' || typeof value === 'object' && !Array.isArray(value)) return;
    
    const rawTextValue = Array.isArray(value)
      ? value.join(', ')
      : mode === 'technique' && key === 'is_subtechnique'
        ? (value ? 'Sub-technique' : 'Top-level technique')
        : typeof value === 'boolean'
        ? (value ? 'Yes' : 'No')
        : value;
    let displayVal = rawTextValue;
    const unlockThreshold = unlockThresholds[mode]?.[key];
    const isLocked = unlockThreshold !== undefined && wrongGuesses < unlockThreshold;
    const justUnlocked = unlockThreshold !== undefined && previousWrongGuessCounts[mode] < unlockThreshold && wrongGuesses >= unlockThreshold;
    
    if (isLocked) {
      displayVal = '<span class="redacted-intel">Classified</span>';
    }
    
    // Summary Text Redactions
    if (typeof displayVal === 'string') {
        displayVal = displayVal.replace(/\[THIS MALWARE\]/g, '<span class="redacted-intel">Classified</span>');
        displayVal = displayVal.replace(/\[CLASSIFIED\]/g, '<span class="redacted-intel">Classified</span>');
    }

    if (
      mode === 'actor' &&
      key === 'country_code' &&
      !isLocked &&
      typeof value === 'string' &&
      value.length === 2
    ) {
      displayVal = renderCountryFlagChip(value);
    }

    const div = document.createElement('div');
    div.className = animateEntrance ? 'clue-item attr-card' : 'clue-item';
    if (key === 'capability_summary' || key === 'description' || (typeof rawTextValue === 'string' && rawTextValue.length > 100)) {
        div.classList.add('full-width');
    }
    if (justUnlocked) {
        div.classList.add('intel-unsealed', 'intel-unsealed-now');
    }
    
    div.innerHTML = `
      <span class="clue-label">${getClueLabel(mode, key)}</span>
      <span class="clue-value">${displayVal}</span>
    `;
    bindFlagFallback(div);
    if (animateEntrance) {
      const overlay = document.createElement('div');
      overlay.className = 'redact-overlay';
      overlay.innerHTML = `
        <div class="redact-bars">
          <span class="redact-bar"></span>
          <span class="redact-bar short"></span>
        </div>
      `;
      div.appendChild(overlay);
    }
    container.appendChild(div);
  });
  previousWrongGuessCounts[mode] = wrongGuesses;
}

function renderGridHistory(mode) {
  const container = document.getElementById(`grid-${mode}`);
  container.innerHTML = '';
  
  const history = currentState.guesses[mode];
  if (!history || history.length === 0) return;
  
  history.forEach(guessObj => {
     const row = document.createElement('div');
     row.className = 'grid-row';
     
     const label = document.createElement('div');
     label.className = 'grid-label';
     label.textContent = guessObj.guess_label || guessObj.guess_key;
     
     const cells = document.createElement('div');
     cells.className = 'grid-cells';
     
     if (guessObj.feedback) {
       let delayIndex = 0;
       
       const fbKeys = Object.keys(guessObj.feedback).filter(k => {
         if (k === 'status' || k === 'guess_key' || k === 'true_answer_key') return false;
         if (mode === 'actor' && (k === 'operations' || k === 'campaigns')) return false;
         if (mode === 'malware' && k === 'category') return false;
         return true;
       });
       
       if (fbKeys.length > 0) {
         fbKeys.forEach(attr => {
           const data = guessObj.feedback[attr];
           const status = typeof data === 'object' ? data.status : data;
           let val = typeof data === 'object' ? data.value : '';
           
           if (Array.isArray(val)) val = val.join(', ');
           if (val && typeof val === 'string' && val.length > 20) val = val.substring(0, 20) + '...';
           if (val === null || val === undefined || val === '') val = 'None';
           
           const cell = document.createElement('div');
           cell.className = `grid-cell ${status}`;
           cell.title = `${attr}: ${status}`;
           
           if (attr === 'country' && typeof val === 'string' && val.length === 2 && val !== 'None') {
               cell.innerHTML = `
                  <div class="cell-label">${attr.replace(/_/g, ' ')}</div>
                  <div class="cell-value">${renderCountryFlagChip(val, 'country-flag-chip-grid')}</div>
               `;
               bindFlagFallback(cell);
           } else {
               let prefix = '';
               if (status === 'higher') prefix = '↑ ';
               if (status === 'lower') prefix = '↓ ';
               cell.innerHTML = `
                  <div class="cell-label">${attr.replace(/_/g, ' ')}</div>
                  <div class="cell-value">${prefix}${val}</div>
               `;
           }
           
           cell.style.animationDelay = `${delayIndex * 0.15}s`;
           delayIndex++;
           cells.appendChild(cell);
         });
       }
       
       // Preserve a readable row when a mode only returns a solved/unsolved result.
       if (fbKeys.length === 0) {
           const cell = document.createElement('div');
           const status = guessObj.is_correct ? 'match' : 'mismatch';
           cell.className = `grid-cell ${status}`;
           cell.innerHTML = `
              <div class="cell-label">Result</div>
              <div class="cell-value">${status === 'match' ? 'Correct' : 'Incorrect'}</div>
           `;
           cell.style.animationDelay = `${delayIndex * 0.15}s`;
           cells.appendChild(cell);
       }
     }
     
     row.appendChild(label);
     row.appendChild(cells);
     container.appendChild(row);
  });
}

// --- Guess Loop ---

async function submitGuess(mode, guess_key, guess_label, extraBody = {}) {
  if (currentState.solved[mode]) return;
  
  try {
    const result = await apiSubmitGuess(
      currentState.snapshot_id,
      currentState.day_key,
      mode,
      guess_key,
      extraBody,
    );
    
    currentState.guesses[mode].push({
       guess_key: guess_key,
       guess_label: guess_label,
       feedback: result.feedback,
       is_correct: result.solved
    });
    
    if (result.solved) {
      currentState.solved[mode] = true;
      if (mode === 'timeline') {
        currentState.drafts.timeline = [];
      }
    }
    
    saveLocalState();
    
    renderBoard();
    updateProgressIndicators();
    
    if (areAllModesSolved()) {
      setTimeout(showSummaryModal, 800); 
    }

  } catch (err) {
    console.error("Error submitting guess", err);
    alert("Failed to submit guess");
  }
}

async function showSummaryModal() {
  const modal = document.getElementById('summary-modal');
  const content = document.getElementById('summary-content');
  
  // Calculate total incorrect guesses
  let incorrectGuesses = 0;
  modeOrder.forEach(mode => {
      incorrectGuesses += Math.max(0, (currentState.guesses[mode] || []).length - 1);
  });
  
  let summaryHTML = '';
  try {
      const summaryData = await apiGetSummary(currentState.snapshot_id, currentState.day_key);
      if (summaryData.incident_source && summaryData.incident_source.url) {
          const source = summaryData.incident_source;
          summaryHTML += `<div class="event-summary">
            <p><strong>Incident Source:</strong> <a href="${source.url}" target="_blank">${source.title || 'Incident source'}</a></p>
          </div>`;
      } else if (summaryData.timeline_provenance && summaryData.timeline_provenance.source_url) {
          const prov = summaryData.timeline_provenance;
          summaryHTML += `<div class="event-summary">
            <p><strong>Incident Source:</strong> <a href="${prov.source_url}" target="_blank">${prov.flow_name || 'Campaign Report'}</a></p>
          </div>`;
      }
  } catch(e) {
      console.error("Failed to fetch game summary", e);
  }
  
  const answers = {
    actor: currentState.guesses.actor.slice(-1)[0],
    malware: currentState.guesses.malware.slice(-1)[0],
    technique: currentState.guesses.technique.slice(-1)[0]
  };
  
  content.innerHTML = `
    <p>You have successfully resolved all three phases for today.</p>
    
    <div class="score-container">
      <div class="score-label">Incorrect Deductions</div>
      <div class="score-value ${incorrectGuesses === 0 ? 'perfect' : ''}">${incorrectGuesses}</div>
    </div>
    
    <ul>
      <li><strong>Threat Actor:</strong> ${renderMitreSummaryLink(answers.actor)}</li>
      <li><strong>Malware Used:</strong> ${renderMitreSummaryLink(answers.malware)}</li>
      <li><strong>Key Technique:</strong> ${renderMitreSummaryLink(answers.technique)}</li>
    </ul>
    
    ${summaryHTML}
    
    <p class="return-msg">Return tomorrow for a new investigation or look in the archive for unsolved cases.</p>
  `;
  
  modal.classList.remove('hidden');
}

document.getElementById('close-modal-btn').addEventListener('click', () => {
  document.getElementById('summary-modal').classList.add('hidden');
});

// Start
document.addEventListener('DOMContentLoaded', initGame);
