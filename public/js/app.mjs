// Threatdle client. The server holds the answers: the page sends the guess list and draws what comes back.
// Per mode: game = { today, guesses, view, busy }. today = GET /api/today; view = the last POST /api/guess reply (rows, clues, status, result).
import { MODES, COUNTRY, KINDS, SECTIONS, other, sectionOf, displayName, shareText, nextStreak, currentStreak, possible } from './rules.mjs';

const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const reduce = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const store = {
  get(k, d) { try { const v = localStorage.getItem('threatdle:v2:' + k); return v == null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('threatdle:v2:' + k, JSON.stringify(v)); } catch { /* private mode: play on without saving */ } },
};
const playerId = (() => { let p = store.get('player', null); if (!p) { p = crypto.randomUUID(); store.set('player', p); } return p; })();
const fmt = n => n.toLocaleString('en-US');
const ord = n => fmt(n) + (n % 100 > 10 && n % 100 < 14 ? 'th' : { 1: 'st', 2: 'nd', 3: 'rd' }[n % 10] || 'th');
const plural = (n, one, many = one + 's') => `${n} ${n === 1 ? one : many}`;
const one = mode => MODES[mode].who.replace(/s$/, '');

let POOL = [], byId = {}, ROSTER = [], mode = 'analyst';
const games = { analyst: null, hunter: null };
let fresh = { row: false, clue: -1 }, clock = null, deadline = 0;

// ---------- server ----------
async function api(path, body) {
  const r = await fetch(path, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : {});
  return { status: r.status, body: await r.json().catch(() => ({})) };
}
const statusOf = m => games[m]?.view?.status ?? 'playing';
// The suspect tracker: groups the player can still believe, from the clues on screen (and the rows, in Threat Hunter).
function suspects(m) {
  const g = games[m];
  if (!g?.today) return new Set();
  return new Set(possible(m, listOf(m), g.view?.clues ?? g.today.clues, g.view?.rows ?? [], byId).map(a => a.id));
}
const finished = m => statusOf(m) !== 'playing';
// The groups a mode guesses from: the Most Wanted in SOC Analyst, every group in Threat Hunter.
const listOf = m => (m === 'analyst' ? ROSTER : POOL);
// Search ignores case, spaces and punctuation, so "apt 28", "APT-28" and "apt28" all find APT28.
const norm = s => String(s).toLowerCase().replace(/[^a-z0-9]/g, '');

async function loadToday(m) {
  const t = await api(`/api/today?mode=${m}`);
  if (t.status !== 200) return { today: null, guesses: [], view: null, error: t.body.error };
  const guesses = store.get(`game:${m}:${t.body.day}`, []);
  const g = { today: t.body, guesses, view: null, busy: false };
  if (guesses.length) {
    const r = await api('/api/guess', { mode: m, day: t.body.day, guesses, playerId });
    if (r.status === 200) g.view = r.body; else { g.guesses = []; store.set(`game:${m}:${t.body.day}`, []); }
  }
  return g;
}

// ---------- pieces ----------
const ICON = {
  victim: '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r=".6" fill="currentColor"/>',
  breakin: '<path d="M5 21V4a1 1 0 0 1 1-1h9l4 2v16"/><path d="M3 21h18"/><circle cx="14" cy="12" r=".8" fill="currentColor"/>',
  tool: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.2L3.5 17.3a1.8 1.8 0 0 0 2.5 2.5l5.8-5.8a4 4 0 0 0 5.2-5.4l-2.6 2.6-2.3-.4-.4-2.3z"/>',
  took: '<rect x="3" y="7" width="18" height="13" rx="1.5"/><path d="M9 7V5a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2M3 12h18"/>',
  hid: '<path d="M3 3l18 18M10.6 6.1A9.8 9.8 0 0 1 12 6c5 0 9 6 9 6a16 16 0 0 1-2.6 3.2M6.3 7.5C4.2 9 3 12 3 12s4 6 9 6a8.6 8.6 0 0 0 3.6-.8"/><path d="M9.9 10a3 3 0 0 0 4.2 4.2"/>',
  tipoff: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M15.5 15.5L21 21"/>',
  arrow: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  clock: '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
};
const icon = (k, cls = 'ico') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[k]}</svg>`;
const place = a => (a.home ? COUNTRY[a.home] || a.home : a.type === 'crime' ? 'Crime gang' : 'Unknown home');
const flagImg = (a, cls = 'flag') => (a.home
  ? `<img class="${cls}" src="https://flagcdn.com/w80/${a.home.toLowerCase()}.png" alt="${esc(place(a))} flag">`
  : `<span class="${cls} crime" aria-hidden="true">${a.type === 'crime' ? '$' : '?'}</span>`);
const TARGET = { Government: 'governments', Military: 'militaries', Defense: 'defense firms', 'Private sector': 'businesses', Finance: 'banks', Technology: 'tech firms',
  Telecommunications: 'telecoms', Energy: 'energy', Healthcare: 'hospitals', Education: 'universities', 'Civil society': 'activists', NGOs: 'charities', Media: 'journalists',
  Individuals: 'individuals', Hospitality: 'hotels', Retail: 'shops', Manufacturing: 'factories', Transportation: 'transport', 'Critical infrastructure': 'utilities', Legal: 'law firms',
  Pharmaceuticals: 'drugmakers', 'Religious organization': 'churches', 'Food and agriculture': 'farming' };
const hits = a => (a.targets?.length ? 'Hits ' + a.targets.map(t => TARGET[t] || t.toLowerCase()).join(', ') : 'Targets unknown');

function card(a, verdict) {
  const name = displayName(a);
  return `<div class="sus" data-id="${esc(a.id)}">
    <span class="who">${flagImg(a)}<span class="ctry">${esc(place(a))}</span></span>
    <span class="nm">${esc(name)}</span>
    <span class="ak">${name !== a.name ? 'ATT&amp;CK: ' + esc(a.name) : '&nbsp;'}</span>
    <span class="pf">${esc(a.profile)}</span>
    <span class="tg">${esc(hits(a))}</span>
    <span class="x">${verdict}</span>
  </div>`;
}

// Clues, newest on top.
function clueList(clues, total, freshIndex) {
  const items = [];
  for (let i = clues.length - 1; i >= 0; i--) {
    const c = clues[i], now = i === clues.length - 1;
    items.push(`<li class="clue ${now ? 'now' : ''} ${i === freshIndex && i > 0 && !reduce() ? 'lift' : ''}" ${now ? 'id="newClue" tabindex="-1"' : ''}>
      <span class="tag t-${c.kind}">${icon(c.kind)}${KINDS[c.kind]}</span><span class="txt">${esc(c.text)}</span><span class="no" aria-label="clue ${i + 1} of ${total}">${i + 1}/${total}</span></li>`);
  }
  return `<ol class="clues">${items.join('')}</ol>`;
}

const LEGEND = { home: 'Home', motive: 'Motive', since: 'Since', victims: 'Victims', targets: 'Targets', tools: 'Tools' };
// A cell may wrap at a '+' so it fits a phone: "Spy+|Money", "Money|+Harm", "Banks|+3".
const cellText = t => esc(t).replace(/\+(?=\d)/g, '<wbr>+').replace(/\+(?=\D)/g, '<wbr>+<wbr>');
function row(m, r, latest) {
  const g = byId[r.id] || { home: r.home, type: null };
  const r5 = m === 'analyst';
  return `<li class="fbr ${r5 ? 'r5' : ''} ${r.correct ? 'win' : ''} ${latest && !reduce() ? 'lift2' : ''}" aria-label="${esc(r.name)}${r.correct ? ': the culprit' : ': ' + esc(r.cells.map(c => c.say).join('; '))}">
    <span class="fn" title="${esc(r.name)}">${esc(r.name)}</span>
    ${r.cells.map(c => `<span class="fc ${c.tone}" aria-hidden="true">${c.k === 'home' ? (r5 ? flagImg({ ...g, home: r.home }, 'mini rf') : r.home ? flagImg({ ...g, home: r.home }, 'mini') + `<span>${esc(c.text)}</span>` : `<span>${esc(c.text)}</span>`) : `<span>${cellText(c.text)}</span>`}${c.arrow ? `<b class="arw">${c.arrow}</b>` : ''}</span>`).join('')}
  </li>`;
}

// Inline how-to on the first view of each mode, never an overlay.
const HOWTO = {
  analyst: () => [`Who hacked them? Guess from the ${ROSTER.length} Most Wanted.`, [
    'Read the clues. Type a group, or tap <b>Browse</b> and pick one.',
    'Each wrong guess unlocks a clue and adds a row about the group you picked: home, motive, first seen, the country it hit most, and what it targets. Green = same as the culprit. Amber = close. ↑ ↓ = the culprit showed up later or earlier.',
    'No limit. Your score is how many guesses it took.'],
    'Nicknames hint at home: Bear = Russia, Panda = China, Kitten = Iran, Chollima = N. Korea, Spider = crime.'],
  hunter: () => ['Name the hacker group behind a real case.', [
    'Type any group, nickname or APT number (Fancy Bear, APT28, Lazarus), or tap <b>Browse</b> and pick one.',
    'Each wrong accusation unlocks a clue and adds a row about the group you named: home, motive, first seen, the country it hit most, what it targets and its tools. Green = same as the culprit. Amber = close. ↑ ↓ = the culprit showed up later or earlier.',
    `You get ${MODES.hunter.max} accusations. Run out and the case goes cold.`],
    "Rows compare with the culprit as today's report describes it, so trust the clues."],
};
function howto(m) {
  if (store.get('howto:' + m, false)) return '';
  const [title, steps, foot] = HOWTO[m]();
  return `<section class="howto" aria-labelledby="howH"><p class="h1" id="howH">${title}</p><ol>${steps.map(s => `<li>${s}</li>`).join('')}</ol>
    <div class="hrow"><p class="hk">${foot}</p><button class="btn ghost" id="howOk">Got it</button></div></section>`;
}

function distribution(m, res, mine) {
  const d = res.distribution, keys = Object.keys(d).sort((a, b) => (a === 'X') - (b === 'X') || parseInt(a) - parseInt(b));
  const max = Math.max(...Object.values(d));
  const label = k => (k === 'X' ? 'Cold' : k);
  return `<h3 id="distH">How everyone did</h3><ul class="dist" aria-labelledby="distH">${keys.map(k => `<li class="${k === mine ? 'me' : ''}">
    <span>${label(k)}</span><span class="bar" style="width:${Math.max(8, Math.round((100 * d[k]) / max))}%"><span class="vh">${k === 'X' ? 'went cold' : plural(+k || 10, m === 'hunter' ? 'accusation' : 'guess', m === 'hunter' ? 'accusations' : 'guesses')}${k === '10+' ? ' or more' : ''}: </span>${fmt(d[k])}${k === mine ? '<span class="vh"> (you)</span>' : ''}</span></li>`).join('')}</ul>`;
}

function endScreen(m) {
  const g = games[m], v = g.view, res = v.result, won = v.status === 'solved', om = other(m);
  const streak = store.get('streak:' + m, null);
  const n = currentStreak(streak, g.today.day);
  const share = shareText({ mode: m, caseNumber: g.today.caseNumber, status: v.status, rows: v.rows, streak: n });
  const mine = won ? (m === 'analyst' && res.tries >= 10 ? '10+' : String(res.tries)) : 'X';
  const y = g.today.yesterday;
  const sub = m === 'hunter'
    ? (won ? `Named in ${res.tries} of ${MODES.hunter.max} accusations.` : `${MODES.hunter.max} wrong accusations. The trail went cold.`)
    : `Named in ${plural(res.tries, 'guess', 'guesses')}.`;
  return `<section class="endE ${reduce() ? '' : 'pop'}" aria-labelledby="endH">
    <h2 class="stampE ${won ? 'ok' : ''}" id="endH" tabindex="-1">${won ? 'Solved' : 'Case gone cold'}</h2>
    <p class="sub">${sub}</p>
    ${card(res.culprit, won ? 'Guilty' : 'It was them')}
    <p class="crowdEnd">${won ? `You're the ${ord(res.rank)} ${one(m)} to close it today.` : `${fmt(res.solvedCount)} ${MODES[m].who} closed it today.`}</p>
    ${won && res.betterThan >= 50 ? `<p class="better">Better than <b>${res.betterThan}%</b> of ${MODES[m].who} today</p>` : ''}
    ${distribution(m, res, mine)}
    <h3>What happened</h3><p class="wh">${esc(res.story)}</p>
    <p class="src"><a href="${esc(res.report.url)}" target="_blank" rel="noopener">Read the original report<span class="vh"> (opens in a new tab)</span></a><br><span>${esc(res.report.vendor)} · ${res.report.date ? esc(res.report.date) : 'undated'}</span></p>
    <pre class="shareE" aria-label="Your result">${esc(share)}</pre>
    <div class="endBtns">
      <button class="btn primary" id="shareBtn">Share result</button>
      <button class="btn next" id="nextMode" data-mode="${om}">${finished(om) ? `See your ${MODES[om].name} result` : `Now try today's ${MODES[om].name} case`} ${icon('arrow', 'ico ar')}</button>
    </div>
    <div class="after">
      <p class="cd" id="cd">${icon('clock')}<span>Next case in <b id="clock">${until()}</b></span></p>
      ${y ? `<div class="yday"><span class="yl">Yesterday's culprit</span>${flagImg(y)}<b>${esc(y.nickname || y.name)}</b><span class="yp">${esc(y.profile)}</span></div>` : ''}
      <p class="streak">Streak: ${plural(n, 'day')} as ${MODES[m].name}.</p>
    </div>
  </section>`;
}

// ---------- render ----------
function render() {
  const g = games[mode];
  document.body.dataset.mode = mode;
  for (const b of document.querySelectorAll('.mode')) {
    const s = statusOf(b.dataset.mode), done = b.querySelector('.done');
    b.setAttribute('aria-pressed', String(b.dataset.mode === mode));
    done.textContent = s === 'solved' ? 'Solved' : s === 'cold' ? 'Cold' : '';
    done.className = 'done ' + s;
    b.querySelector('.mt i').classList.toggle('hid', s !== 'playing');
  }
  const bar = $('#bar');
  bar.hidden = true;
  if (!g || !g.today) {
    $('#board').innerHTML = `<p class="loading">${g?.error === 'no case scheduled today' ? 'No case is filed for today. Check back tomorrow.' : "Couldn't open today's case file. Check your connection and reload."}</p>`;
    return padForBar(null);
  }
  const v = g.view, n = g.today.clueCount, clues = v?.clues ?? g.today.clues, rows = v?.rows ?? [], used = g.guesses.length;
  let h = howto(mode);
  if (finished(mode)) h += endScreen(mode);
  const left = suspects(mode).size;
  const poss = finished(mode) ? '' : `<span class="poss"><b>${left}</b> possible</span>`;
  const head = mode === 'hunter'
    ? `<span class="meter" role="img" aria-label="${MODES.hunter.max - used} of ${MODES.hunter.max} accusations left">${Array.from({ length: MODES.hunter.max }, (_, i) => `<i class="${i < MODES.hunter.max - used ? 'on' : ''}"></i>`).join('')}<b>${MODES.hunter.max - used} left</b></span>${poss}`
    : `<span class="gcount"><b>${used}</b> ${used === 1 ? 'guess' : 'guesses'}</span>${poss}`;
  const legend = MODES[mode].cols.map(k => `<span class="fc">${LEGEND[k]}</span>`).join('');
  h += `<section class="caseE" aria-label="Case file">
      <div class="caseHead"><h2 class="case">Case #${g.today.caseNumber}</h2>${head}</div>
      ${clueList(clues, n, fresh.clue)}</section>
    <section class="fbx" aria-labelledby="fbH">
      <h2 class="fbH" id="fbH">Your ${mode === 'hunter' ? 'accusations' : 'guesses'}</h2>
      ${rows.length ? `<div class="fbr ${mode === 'analyst' ? 'r5' : ''} head" aria-hidden="true"><span class="fn"></span>${legend}</div>
        <ol class="rows">${rows.slice().reverse().map((r, i) => row(mode, r, i === 0 && fresh.row)).join('')}</ol>
        <p class="fkey"><i class="sw hit"></i>Same <i class="sw near"></i>Close <i class="sw miss"></i>No <span>↑ culprit is newer · ↓ older</span><span>Victims: the country it hit most; amber = the culprit hit it too</span>${mode === 'hunter' ? '<span>Tools: how many the culprit shares with your guess</span>' : ''}</p>`
      : `<p class="empty">Not sure? <b>Browse</b> ${mode === 'analyst' ? `the ${ROSTER.length} Most Wanted` : `all ${POOL.length} groups`}. Each ${mode === 'hunter' ? 'accusation' : 'guess'} lands here, compared with the culprit.</p>`}
    </section>
    ${finished(mode) ? '' : `<p class="crowd">${g.today.solvedCount ? `${fmt(g.today.solvedCount)} ${MODES[mode].who} closed this case today` : `Be the first ${one(mode)} to close this case today`}</p>`}`;
  $('#board').innerHTML = h;
  fresh = { row: false, clue: -1 };
  bar.hidden = finished(mode);
  $('#browse').innerHTML = `Browse <small>${left}</small>`;
  padForBar(finished(mode) ? null : bar);
  const ok = $('#howOk');
  if (ok) ok.onclick = () => { store.set('howto:' + mode, true); render(); const b = $('.caseE'); b.setAttribute('tabindex', '-1'); b.focus(); };
  if (finished(mode)) wireEnd();
}

function wireEnd() {
  const b = $('#shareBtn'), text = $('.shareE').textContent;
  b.onclick = async () => {
    try {
      if (navigator.share && matchMedia('(pointer: coarse)').matches) { await navigator.share({ text }); b.textContent = 'Shared'; }
      else { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; say('Result copied.'); }
    } catch { /* the player closed the share sheet */ }
  };
  $('#nextMode').onclick = e => go(e.currentTarget.dataset.mode);
  startClock();
}

function until() {
  const s = Math.max(0, Math.floor((deadline - Date.now()) / 1000));
  return `${Math.floor(s / 3600)}h ${String(Math.floor(s / 60) % 60).padStart(2, '0')}m ${String(s % 60).padStart(2, '0')}s`;
}
function startClock() {
  clearInterval(clock);
  clock = setInterval(() => {
    const el = $('#clock');
    if (!el) return clearInterval(clock);
    if (Date.now() < deadline) { el.textContent = until(); return; }
    clearInterval(clock);
    $('#cd').innerHTML = `${icon('clock')}<span>New cases are ready.</span><button class="btn ghost sm" id="reload">Open them</button>`;
    $('#reload').onclick = () => location.reload();
  }, 1000);
}

function say(t) { const el = $('#sr'); el.textContent = ''; setTimeout(() => { el.textContent = t; }, 30); }
function padForBar(bar) { document.body.style.paddingBottom = (bar && !bar.hidden ? bar.offsetHeight + 20 : 24) + 'px'; }

function go(m) {
  if (m !== mode) { mode = m; store.set('mode', mode); }
  render();
  scrollTo({ top: 0 });
  const t = $('#howOk') || (!finished(mode) ? $('#guess') : $('#endH'));
  t?.focus({ preventScroll: true });
}

// ---------- a guess ----------
async function accuse(id) {
  const m = mode, g = games[m];
  if (!g?.today || g.busy || finished(m) || g.guesses.includes(id)) return;
  g.busy = true;
  const guesses = [...g.guesses, id], before = (g.view?.clues ?? g.today.clues).length;
  let r;
  try { r = await api('/api/guess', { mode: m, day: g.today.day, guesses, playerId }); } catch { r = { status: 0 }; }
  g.busy = false;
  if (r.status === 409) { say('A new day started. Loading the new cases.'); await boot(); return; }
  if (r.status !== 200) { say("Couldn't reach the case file. Try that guess again."); return; }
  g.guesses = guesses; g.view = r.body;
  store.set(`game:${m}:${g.today.day}`, guesses);
  const last = r.body.rows.at(-1);
  if (finished(m)) {
    store.set('streak:' + m, nextStreak(store.get('streak:' + m, null), g.today.day, r.body.status === 'solved'));
    render();
    const who = r.body.result.culprit;
    say(r.body.status === 'solved' ? `Solved. ${displayName(who)} did it, in ${plural(guesses.length, m === 'hunter' ? 'accusation' : 'guess', m === 'hunter' ? 'accusations' : 'guesses')}.`
      : `${last.name} is innocent. Case gone cold. It was ${displayName(who)}.`);
    $('#endH').focus({ preventScroll: true });
    scrollTo({ top: 0, behavior: reduce() ? 'auto' : 'smooth' });
    return;
  }
  fresh = { row: true, clue: r.body.clues.length > before ? before : -1 };
  render();
  const left = m === 'hunter' ? ` ${plural(MODES.hunter.max - guesses.length, 'accusation')} left.` : '';
  say(`${last.name} is innocent. ${last.cells.map(c => c.say).join('; ')}.${left} ${plural(suspects(m).size, 'suspect')} still possible.${r.body.clues.length > before ? ' New clue: ' + r.body.clues.at(-1).text : ''}`);
  if ($('.caseE').getBoundingClientRect().top < 0) scrollTo({ top: 0, behavior: reduce() ? 'auto' : 'smooth' });
}

// ---------- autocomplete over nickname, ATT&CK name and aliases ----------
function combobox(input, list, items, none) {
  let shown = [], sel = 0;
  const close = clear => { list.hidden = true; input.setAttribute('aria-expanded', 'false'); input.removeAttribute('aria-activedescendant'); shown = []; sel = 0; if (clear) input.value = ''; };
  const draw = () => {
    const q = norm(input.value);
    if (!q) return close(false);
    const all = items().filter(x => !games[mode]?.guesses.includes(x.id)), live = suspects(mode);
    shown = all.filter(x => x.key.startsWith(q)).sort((a, b) => a.label.length - b.label.length)
      .concat(all.filter(x => !x.key.startsWith(q) && x.q.includes(q)))
      .map(x => ({ ...x, out: !live.has(x.id) })).sort((a, b) => a.out - b.out).slice(0, 6);
    sel = Math.min(sel, Math.max(0, shown.length - 1));
    list.innerHTML = shown.length
      ? shown.map((x, i) => `<li role="option" id="${list.id}${i}" data-i="${i}" aria-selected="${i === sel}" class="${x.out ? 'ruled' : ''}">${x.flag}<span><b>${esc(x.label)}</b><small>${esc(x.sub)}</small></span>${x.out ? '<i>Ruled out</i>' : ''}</li>`).join('')
      : `<li class="none" role="option" aria-disabled="true" aria-selected="false">${none()}</li>`;
    list.hidden = false; input.setAttribute('aria-expanded', 'true');
    if (shown.length) input.setAttribute('aria-activedescendant', list.id + sel); else input.removeAttribute('aria-activedescendant');
  };
  const choose = i => {
    const x = shown[i];
    if (!x) { say(input.value.trim() ? 'Pick a group from the list.' : 'Type a group name first.'); input.focus(); return; }
    close(true);
    accuse(x.id).then(() => { if (!finished(mode)) input.focus(); });
  };
  input.oninput = () => { sel = 0; draw(); };
  input.onkeydown = e => {
    if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, shown.length - 1); draw(); e.preventDefault(); }
    else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
    else if (e.key === 'Enter') { choose(sel); e.preventDefault(); }
    else if (e.key === 'Escape') close(false);
  };
  input.onblur = () => setTimeout(() => { if (document.activeElement !== input) close(false); }, 150);
  list.onpointerdown = e => { const el = e.target.closest('[data-i]'); if (el) { e.preventDefault(); choose(+el.dataset.i); } };
}
const names = a => [displayName(a), a.name, ...a.aliases];
const entry = a => ({ id: a.id, label: displayName(a), key: norm(displayName(a)), flag: flagImg(a, 'mini'),
  sub: [displayName(a) !== a.name ? a.name : null, ...a.aliases.filter(x => x !== displayName(a)).slice(0, 3)].filter(Boolean).join(' · '),
  q: names(a).map(norm).join('|') });
const matches = (a, q) => !q || names(a).some(n => norm(n).includes(q));

// Browse: the mode's groups, grouped by home. Groups the tracker rules out sink, greyed, and hide unless asked for or
// searched for by name. Tap one to guess it.
let showRuled = false;
function browseHtml() {
  const m = mode, guessed = games[m]?.guesses ?? [], live = suspects(m), q = norm($('#rosterQ').value);
  const n = [...live].filter(id => !guessed.includes(id)).length;
  $('#rosterLive').innerHTML = `<b>${n}</b> ${n === 1 ? 'suspect fits' : 'suspects fit'} ${MODES[m].trackRows ? 'the clues and your rows.' : 'the clues. Your rows narrow it further.'}`;
  $('#showRuled').setAttribute('aria-pressed', String(showRuled));
  const html = SECTIONS.map(([k, label, hint]) => {
    const list = listOf(m).filter(a => sectionOf(a) === k).map(a => ({ a, out: guessed.includes(a.id), ruled: !live.has(a.id) }))
      .sort((x, y) => x.ruled - y.ruled || displayName(x.a).localeCompare(displayName(y.a)));
    const visible = list.filter(x => (showRuled || q || !x.ruled) && matches(x.a, q)), alive = list.filter(x => !x.ruled).length;
    if (!visible.length) return '';
    return `<section class="rsec" aria-labelledby="rs-${k}"><h3 id="rs-${k}"><span>${esc(label)}</span><small>${esc(hint)} · ${alive} of ${list.length} possible</small></h3>
      <div class="rgrid">${visible.map(({ a, out, ruled }) => `<button class="rc ${out ? 'out' : ruled ? 'ruled' : ''}" data-id="${a.id}" ${out ? 'disabled' : ''} aria-label="${esc(displayName(a))}, ${esc(a.profile)}. ${esc(hits(a))}${out ? ', already guessed' : ruled ? ', ruled out' : ''}">
          ${flagImg(a)}<span class="rt"><b>${esc(displayName(a))}</b><small>${esc(displayName(a) !== a.name ? a.name + ' · ' : '')}${esc(a.profile)}</small><small>${esc(hits(a))}</small></span>${out ? '<i>Cleared</i>' : ruled ? '<i>Ruled out</i>' : ''}</button>`).join('')}</div></section>`;
  }).join('');
  return html || `<p class="rnone">No group matches “${esc($('#rosterQ').value.trim())}”.</p>`;
}
function setupBrowse() {
  const dlg = $('#roster'), body = $('#rosterBody'), redraw = () => { body.innerHTML = browseHtml(); };
  // Opens on the mode's list, already searched for whatever is typed in the guess box.
  $('#browse').onclick = () => {
    $('#rosterT').textContent = mode === 'analyst' ? 'Most Wanted' : 'All groups';
    $('#rosterN').textContent = listOf(mode).length;
    $('#rosterQ').value = $('#guess').value.trim();
    redraw(); dlg.showModal(); body.scrollTop = 0;
  };
  $('#rosterQ').oninput = () => { redraw(); body.scrollTop = 0; };
  $('#rosterClose').onclick = () => dlg.close();
  $('#showRuled').onclick = () => { showRuled = !showRuled; redraw(); };
  dlg.addEventListener('click', e => { if (e.target === dlg) dlg.close(); });
  $('#rosterBody').onclick = e => { const b = e.target.closest('.rc:not(:disabled)'); if (!b) return; dlg.close(); accuse(b.dataset.id); };
}

// ---------- start ----------
async function boot() {
  const [m1, m2] = await Promise.all([loadToday('analyst'), loadToday('hunter')]);
  games.analyst = m1; games.hunter = m2;
  deadline = Date.now() + (m1.today?.msUntilNext ?? m2.today?.msUntilNext ?? 0);
  render();
}
async function start() {
  const p = await fetch('/pool.json').then(r => r.json());
  POOL = p.actors; byId = Object.fromEntries(POOL.map(a => [a.id, a])); ROSTER = POOL.filter(a => a.roster);
  $('#poolN').textContent = POOL.length;
  const entries = { analyst: ROSTER.map(entry), hunter: POOL.map(entry) };
  combobox($('#guess'), $('#aclist'), () => entries[mode],
    () => `${mode === 'analyst' ? 'Not on the Most Wanted' : 'No group by that name'}. Tap Browse to see all ${listOf(mode).length}.`);
  setupBrowse();
  $('#modes').onclick = e => { const b = e.target.closest('.mode'); if (b) go(b.dataset.mode); };
  const q = new URLSearchParams(location.search).get('mode');
  mode = MODES[q] ? q : MODES[store.get('mode', '')] ? store.get('mode', '') : 'analyst';
  await boot();
  document.body.dataset.ready = '1';
}
start().catch(() => { $('#board').innerHTML = '<p class="loading">Couldn\'t open the case file. Reload to try again.</p>'; });
