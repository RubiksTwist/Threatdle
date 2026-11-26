// End to end on netlify dev: both modes at 390x844 and 1440x900, with axe on every state.
// Run: THREATDLE_DRAFTS=1 netlify dev --offline   then   node tests/e2e.mjs   (BASE=http://localhost:8888)
// It reads today's answers from the draft schedule, as a test may; the page never sees them.
import { chromium } from 'playwright';
import { readFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dayOf, addDays, daysBetween } from '../public/js/rules.mjs';

const BASE = process.env.BASE || 'http://localhost:8888';
const SHOTS = new URL('./screenshots/', import.meta.url);
mkdirSync(SHOTS, { recursive: true });
const AXE = readFileSync(new URL('../node_modules/axe-core/axe.min.js', import.meta.url), 'utf8');
const read = p => JSON.parse(readFileSync(new URL('../' + p, import.meta.url), 'utf8'));
const pool = read('data/pool.json').actors, cases = read('data/cases.json').cases, sched = read('data/schedule.drafts.json');
const today = dayOf(), entry = sched.days[daysBetween(sched.start, today)];
const kase = m => cases.find(c => c.id === entry[m]);
const name = id => { const a = pool.find(x => x.id === id); return a.nickname || a.name; };
const culprit = { analyst: kase('analyst').culprit, hunter: kase('hunter').culprit };
const wrong = (m, n) => pool.filter(a => a.id !== culprit[m] && (m === 'hunter' || a.roster)).slice(3, 3 + n).map(a => a.id);

const results = [];
const check = (label, cond, detail = '') => { results.push({ label, ok: !!cond, detail }); if (!cond) console.log('FAIL', label, detail); };

async function axe(page, label) {
  await page.evaluate(() => Promise.all(document.getAnimations().map(a => a.finished)));
  if (!(await page.evaluate(() => !!window.axe))) await page.evaluate(AXE);
  const r = await page.evaluate(async () => (await window.axe.run(document, { runOnly: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'best-practice'] })).violations.map(v => `${v.id}: ${v.nodes.length} ${v.nodes.slice(0, 3).map(n => n.target.join(' ') + ' ' + (n.any[0]?.message || '')).join(' / ')}`));
  check(`axe ${label}`, r.length === 0, r.join(', '));
  const scroll = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  check(`no sideways scroll ${label}`, scroll <= 0, `${scroll}px`);
}
async function shot(page, file) { await page.evaluate(() => Promise.all(document.getAnimations().map(a => a.finished))); await page.screenshot({ path: fileURLToPath(new URL(file, SHOTS)), fullPage: true }); }

async function open(browser, vp, { mode, streak, seen } = {}) {
  const ctx = await browser.newContext({ viewport: { width: vp.w, height: vp.h }, deviceScaleFactor: vp.w < 500 ? 2 : 1, hasTouch: vp.w < 500 });
  await ctx.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: BASE });
  const errors = [];
  const page = await ctx.newPage();
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => m.type() === 'error' && !/flagcdn|Failed to load resource/.test(m.text()) && errors.push(m.text()));
  await page.addInitScript(([s, seen]) => {
    if (s) for (const [m, v] of Object.entries(s)) if (!localStorage.getItem('threatdle:v2:streak:' + m)) localStorage.setItem('threatdle:v2:streak:' + m, JSON.stringify(v));
    if (seen) for (const m of ['analyst', 'hunter']) localStorage.setItem('threatdle:v2:howto:' + m, 'true');
  }, [streak, seen]);
  await page.goto(`${BASE}/${mode ? '?mode=' + mode : ''}`);
  await page.waitForSelector('body[data-ready="1"]');
  await page.evaluate(() => document.fonts.ready);
  return { ctx, page, errors };
}
async function type(page, m, id) {
  const input = m === 'hunter' ? '#guess' : '#rguess';
  await page.fill(input, name(id));
  await page.press(input, 'Enter');
  await page.waitForFunction(n => document.querySelectorAll('.rows > li').length >= n || document.querySelector('.endE'), (await page.locator('.rows > li').count()) + 1);
}

async function run(browser, vp) {
  const tag = vp.w;
  // ---- SOC Analyst: first view, two wrong guesses (typed and browsed), then the win with a streak to extend.
  const streak = { analyst: { day: addDays(today, -1), n: 3, won: true } };
  const a = await open(browser, vp, { mode: 'analyst', streak });
  check(`analyst ${tag} how-to shows inline`, await a.page.isVisible('.howto'));
  check(`analyst ${tag} case number`, /Case #\d+/.test(await a.page.textContent('.case')));
  await shot(a.page, `analyst-first-${tag}.png`); await axe(a.page, `analyst first ${tag}`);
  await a.page.click('#howOk');
  const [w1, w2] = wrong('analyst', 2);
  await type(a.page, 'analyst', w1);
  await a.page.click('#browse');
  await a.page.waitForSelector('#roster[open]');
  if (tag === 390) await shot(a.page, 'analyst-browse-390.png');
  await axe(a.page, `analyst browse ${tag}`);
  check(`analyst ${tag} browse cards fit the sheet`, await a.page.evaluate(() => [...document.querySelectorAll('#rosterBody .rc')].every(c => c.getBoundingClientRect().right <= document.querySelector('#rosterBody').getBoundingClientRect().right + 0.5)));
  await a.page.click(`#rosterBody .rc[data-id="${w2}"]`);
  await a.page.waitForFunction(() => document.querySelectorAll('.rows > li').length === 2);
  check(`analyst ${tag} two rows, newest first`, (await a.page.textContent('.rows > li:first-child .fn')) === name(w2));
  check(`analyst ${tag} third clue declassified`, (await a.page.locator('.clue').count()) === 3);
  check(`analyst ${tag} rows have 5 cells`, (await a.page.locator('.rows > li:first-child .fc').count()) === 5);
  await shot(a.page, `analyst-mid-${tag}.png`); await axe(a.page, `analyst mid ${tag}`);
  await type(a.page, 'analyst', culprit.analyst);
  await a.page.waitForSelector('.endE');
  check(`analyst ${tag} solved stamp`, (await a.page.textContent('#endH')) === 'Solved');
  const share = await a.page.textContent('.shareE');
  check(`analyst ${tag} share text`, /^Threatdle #\d+ · SOC Analyst · 3 guesses · 🔥4\n/.test(share), share.split('\n')[0]);
  check(`analyst ${tag} share grid`, share.split('\n').length === 4 && share.split('\n')[3] === '🟩🟩🟩🟩🟩');
  check(`analyst ${tag} streak line`, /Streak: 4 days as SOC Analyst/.test(await a.page.textContent('.streak')));
  check(`analyst ${tag} rank line`, /You're the [\d,]+(st|nd|rd|th) analyst/.test(await a.page.textContent('.crowdEnd')));
  check(`analyst ${tag} distribution`, (await a.page.locator('.dist li.me').count()) === 1);
  check(`analyst ${tag} story and report`, (await a.page.textContent('.wh')).length > 40 && (await a.page.getAttribute('.src a', 'href')).startsWith('https://'));
  check(`analyst ${tag} toggle says solved`, (await a.page.textContent('.mode[data-mode="analyst"] .done')) === 'Solved');
  const c1 = await a.page.textContent('#clock');
  await a.page.waitForTimeout(1200);
  check(`analyst ${tag} countdown ticks`, /^\d+h \d\dm \d\ds$/.test(c1) && c1 !== (await a.page.textContent('#clock')), c1);
  check(`analyst ${tag} yesterday's culprit`, await a.page.isVisible('.yday'));
  if (tag === 1440) {
    await a.page.click('#shareBtn');
    await a.page.waitForFunction(() => document.querySelector('#shareBtn').textContent === 'Copied');
    { const clip = await a.page.evaluate(() => navigator.clipboard.readText()); check('share copies the text', clip.replace(/\r\n/g, '\n') === share, JSON.stringify([clip, share])); }
  }
  await shot(a.page, `analyst-win-${tag}.png`); await axe(a.page, `analyst win ${tag}`);
  await a.page.reload(); await a.page.waitForSelector('.endE');
  { const again = await a.page.textContent('.shareE'); check(`analyst ${tag} result survives a reload`, again === share, JSON.stringify([again, share])); }
  // Next mode leads to the other mode's own case.
  await a.page.click('#nextMode');
  await a.page.waitForSelector('body[data-mode="hunter"]');
  check(`next mode ${tag} opens Threat Hunter`, (await a.page.getAttribute('.mode[data-mode="hunter"]', 'aria-pressed')) === 'true' && await a.page.isVisible('#hbar'));
  check(`next mode ${tag} is a different case`, (await a.page.textContent('.clue.now .txt')) === kase('hunter').clues[0].text);
  await shot(a.page, `hunter-first-${tag}.png`); await axe(a.page, `hunter first ${tag}`);
  check(`analyst ${tag} no page errors`, a.errors.length === 0, a.errors.join(' | '));
  await a.ctx.close();

  // ---- Threat Hunter: six misses, the case goes cold.
  const h = await open(browser, vp, { mode: 'hunter', seen: true });
  const misses = wrong('hunter', 6);
  for (const [i, id] of misses.entries()) {
    await type(h.page, 'hunter', id);
    if (i === 2) {
      check(`hunter ${tag} rows have 7 cells`, (await h.page.locator('.rows > li:first-child .fc').count()) === 7);
      check(`hunter ${tag} meter`, (await h.page.textContent('.meter b')) === '3 left');
      await h.page.fill('#guess', 'bear');
      await h.page.waitForSelector('#aclist:not([hidden])');
      await shot(h.page, `hunter-autocomplete-${tag}.png`); await axe(h.page, `hunter autocomplete ${tag}`);
      await h.page.press('#guess', 'Escape'); await h.page.fill('#guess', '');
      await shot(h.page, `hunter-mid-${tag}.png`); await axe(h.page, `hunter mid ${tag}`);
    }
  }
  await h.page.waitForSelector('.endE');
  check(`hunter ${tag} cold stamp`, (await h.page.textContent('#endH')) === 'Case gone cold');
  const hs = await h.page.textContent('.shareE');
  check(`hunter ${tag} cold share`, /^Threatdle #\d+ · Threat Hunter X\/6 · 🔥0\n/.test(hs) && hs.split('\n').length === 7, hs.split('\n')[0]);
  check(`hunter ${tag} reveals the culprit`, (await h.page.textContent('.endE .nm')) === name(culprit.hunter));
  check(`hunter ${tag} toggle says cold`, (await h.page.textContent('.mode[data-mode="hunter"] .done')) === 'Cold');
  check(`hunter ${tag} streak broken`, /Streak: 0 days/.test(await h.page.textContent('.streak')));
  await shot(h.page, `hunter-loss-${tag}.png`); await axe(h.page, `hunter loss ${tag}`);
  check(`hunter ${tag} next mode offers the analyst case`, /Now try today's SOC Analyst case/.test(await h.page.textContent('#nextMode')));
  check(`hunter cold ${tag} no page errors`, h.errors.length === 0, h.errors.join(' | '));
  await h.ctx.close();

  // ---- Threat Hunter: two misses, then the win. The winning row is all green.
  const hw = await open(browser, vp, { mode: 'hunter', seen: true, streak: { hunter: { day: addDays(today, -1), n: 1, won: true } } });
  for (const id of wrong('hunter', 2)) await type(hw.page, 'hunter', id);
  await type(hw.page, 'hunter', culprit.hunter);
  await hw.page.waitForSelector('.endE');
  check(`hunter ${tag} solved`, (await hw.page.textContent('#endH')) === 'Solved');
  check(`hunter ${tag} winning row all match`, await hw.page.evaluate(() => [...document.querySelectorAll('.rows > li:first-child .fc')].every(c => c.classList.contains('hit'))));
  const ws = await hw.page.textContent('.shareE');
  check(`hunter ${tag} win share`, /^Threatdle #\d+ · Threat Hunter 3\/6 · 🔥2\n/.test(ws) && ws.split('\n')[3] === '🟩'.repeat(7), ws.split('\n')[0]);
  check(`hunter ${tag} crowd line`, /You're the [\d,]+(st|nd|rd|th) hunter/.test(await hw.page.textContent('.crowdEnd')));
  await shot(hw.page, `hunter-win-${tag}.png`); await axe(hw.page, `hunter win ${tag}`);
  check(`hunter win ${tag} no page errors`, hw.errors.length === 0, hw.errors.join(' | '));
  await hw.ctx.close();
}

const browser = await chromium.launch();
try {
  for (const vp of [{ w: 390, h: 844 }, { w: 1440, h: 900 }]) await run(browser, vp);
} finally { await browser.close(); }
const failed = results.filter(r => !r.ok);
console.log(`\n${results.length} checks, ${failed.length} failed`);
process.exit(failed.length ? 1 : 0);
