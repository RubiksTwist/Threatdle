import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as R from '../public/js/rules.mjs';

const A = (id, o = {}) => ({ id, name: id, nickname: null, aliases: [], home: null, type: null, motive: [], since: null, targets: [], victims: [], profile: '', roster: true, tools: [], ...o });
const bear = A('G1', { nickname: 'Fancy Bear', home: 'RU', type: 'state', motive: ['Espionage'], since: 2004, targets: ['Government', 'Military'], tools: ['S1', 'S2', 'S3'] });
const cozy = A('G2', { nickname: 'Cozy Bear', home: 'RU', type: 'state', motive: ['Espionage'], since: 2008, targets: ['Government'], tools: ['S1'] });
const panda = A('G3', { home: 'CN', type: 'state', motive: ['Espionage', 'Financial Gain'], since: 2012, targets: ['Technology'] });
const spider = A('G4', { nickname: 'Carbon Spider', type: 'crime', motive: ['Financial Gain'], since: 2015, targets: ['Hospitality', 'Retail'], roster: false });
const byId = Object.fromEntries([bear, cozy, panda, spider].map(a => [a.id, a]));
const kase = {
  culprit: 'G1',
  clues: [
    { kind: 'victim', text: 'Hit telecoms.', facts: { targets: ['Telecommunications'] } },
    { kind: 'tipoff', text: 'A state actor.', facts: { type: 'state' } },
    { kind: 'tipoff', text: 'From Russia.', facts: { home: 'RU' } },
  ],
};

test('compare: same country is a match, same region is near, other is a miss', () => {
  assert.equal(R.compare(cozy, bear).home, 'match');
  assert.equal(R.compare(A('x', { home: 'BY' }), bear).home, 'near');
  assert.equal(R.compare(panda, bear).home, 'miss');
  assert.equal(R.compare(spider, bear).home, 'miss', 'a crime gang against a state group is a miss');
  assert.equal(R.compare(A('n'), bear).home, 'unknown');
});

test('compare: two crime gangs with no known country share the crime badge', () => {
  const pinchy = A('G9', { type: 'crime', motive: ['Financial Gain'] });
  assert.equal(R.compare(pinchy, spider).home, 'match');
  assert.equal(R.compare(A('fin', { home: 'RU', type: 'crime' }), spider).home, 'miss');
  const cell = R.cells('analyst', pinchy, R.compare(pinchy, spider))[0];
  assert.deepEqual([cell.text, cell.tone], ['$', 'hit']);
});

test('compare: since points at the culprit, up when the culprit is newer', () => {
  assert.equal(R.compare(bear, cozy).since, 'up');
  assert.equal(R.compare(panda, cozy).since, 'down');
  assert.equal(R.compare(A('y', { since: 2008 }), cozy).since, 'match');
});

test('since within 2 years is amber and keeps its arrow; 3 years is a miss', () => {
  const cell = (since, cul) => R.cells('analyst', A('s', { since }), R.compare(A('s', { since }), A('c', { since: cul }))).find(c => c.k === 'since');
  assert.deepEqual([cell(2010, 2012).tone, cell(2010, 2012).arrow], ['near', '↑']);
  assert.deepEqual([cell(2010, 2008).tone, cell(2010, 2008).arrow], ['near', '↓']);
  assert.deepEqual([cell(2010, 2013).tone, cell(2010, 2013).arrow], ['miss', '↑']);
  assert.deepEqual([cell(2010, 2010).tone, cell(2010, 2010).arrow], ['hit', '']);
  assert.equal(cell(2010, null).tone, 'unk');
});

test('victims: same main victim is green, a victim the culprit also hit is amber, no list is unknown', () => {
  const cul = A('c', { victims: ['UA', 'US', 'PL'] });
  const cell = victims => R.cells('analyst', A('g', { victims }), R.compare(A('g', { victims }), cul)).find(c => c.k === 'victims');
  assert.deepEqual([cell(['UA', 'DE']).text, cell(['UA', 'DE']).tone], ['UA', 'hit']);
  assert.deepEqual([cell(['US', 'UA']).text, cell(['US', 'UA']).tone], ['US', 'near']);
  assert.deepEqual([cell(['JP', 'UA']).text, cell(['JP', 'UA']).tone], ['JP', 'miss'], 'only the guess main victim counts');
  assert.deepEqual([cell([]).text, cell([]).tone], ['?', 'unk']);
  assert.equal(R.compare(A('g', { victims: ['UA'] }), A('c')).victims, 'unknown', 'an unknown culprit list is unknown');
  assert.match(cell(['PH']).say, /Philippines/, 'say names the country');
  assert.equal(R.compare(A('g'), A('g')).victims, 'match', 'a correct guess is a match even with no victims');
});

test('motive shows the whole combination in short words', () => {
  const text = motive => R.cells('analyst', A('m', { motive }), R.compare(A('m', { motive }), bear)).find(c => c.k === 'motive').text;
  assert.equal(text(['Espionage']), 'Spy');
  assert.equal(text(['Espionage', 'Financial Gain']), 'Spy+Money');
  assert.equal(text(['Financial Gain', 'Espionage']), 'Spy+Money', 'always in the same order');
  assert.equal(text(['Espionage', 'Financial Gain', 'Sabotage']), 'Spy+Money+Harm');
  assert.equal(text([]), '?');
});

test('targets ignore Government unless it is all one side lists', () => {
  const t = (g, p) => R.compare(A('g', { targets: g }), A('p', { targets: p })).targets;
  assert.equal(t(['Government', 'Energy'], ['Government', 'Finance']), 'miss', 'sharing only Government is no overlap');
  assert.equal(t(['Government', 'Energy'], ['Energy']), 'match');
  assert.equal(t(['Government'], ['Government', 'Finance']), 'partial', 'a Government-only group still overlaps');
  assert.equal(t(['Government'], ['Government']), 'match');
  assert.equal(t(['Government'], ['Finance']), 'miss');
});

test('targets text is the first sector other than Government, plus how many more', () => {
  const text = targets => R.cells('analyst', A('t', { targets }), R.compare(A('t', { targets }), bear)).find(c => c.k === 'targets');
  assert.equal(text(['Energy', 'Government', 'Finance']).text, 'Energy+2');
  assert.equal(text(['Government', 'Telecommunications']).text, 'Telco+1');
  assert.equal(text(['Government']).text, 'Govt');
  assert.equal(text([]).text, '?');
  assert.match(text(['Energy', 'Government', 'Finance']).say, /energy, government, finance/, 'say lists every sector');
});

test('compare: targets and motive as same, some or none', () => {
  assert.equal(R.compare(cozy, bear).targets, 'partial');
  assert.equal(R.compare(panda, bear).targets, 'miss');
  assert.equal(R.compare(A('z', { targets: ['Military', 'Government'] }), bear).targets, 'match');
  assert.equal(R.compare(panda, bear).motive, 'partial');
});

test('compare: tools come as none/some/many buckets', () => {
  assert.equal(R.compare(cozy, bear).tools, 'some');
  assert.equal(R.compare(A('t', { tools: ['S1', 'S2', 'S3', 'S9'] }), bear).tools, 'many');
  assert.equal(R.compare(A('w', { tools: ['S9'] }), bear).tools, 'none');
  assert.equal(R.compare(panda, bear).tools, 'unknown', 'ATT&CK lists no software for panda');
});

test('compare: the culprit against itself is all match, even with unknown facts', () => {
  const f = R.compare(spider, spider);
  assert.equal(f.correct, true);
  for (const k of R.MODES.hunter.cols) assert.equal(f[k], 'match');
});

test('fold adds clue facts to the culprit without dropping its own', () => {
  const p = R.fold(bear, kase.clues);
  assert.deepEqual(p.targets, ['Government', 'Military', 'Telecommunications']);
  assert.equal(p.home, 'RU');
  assert.equal(bear.targets.length, 2, 'the pool actor is not mutated');
});

test('play: a row folds only the clues shown when it was made', () => {
  // Cozy Bear guessed first: only the two opening clues (telecoms, state) are shown, so targets compare with Government, Military, Telecommunications.
  const g = R.play('analyst', kase, ['G2'], byId);
  assert.equal(g.rows[0].cells.find(c => c.k === 'targets').tone, 'near');
  assert.equal(g.status, 'playing');
  assert.deepEqual(g.clues.map(c => c.text), ['Hit telecoms.', 'A state actor.', 'From Russia.']);
  // A guess that shares telecoms only matches through the fold.
  const tel = A('G5', { targets: ['Telecommunications'], roster: true });
  const g2 = R.play('analyst', kase, ['G5'], { ...byId, G5: tel });
  assert.equal(g2.rows[0].cells.find(c => c.k === 'targets').tone, 'near');
  // An energy clue shown second does not reach back into the first row.
  const ek = { culprit: 'G1', clues: [kase.clues[0], { kind: 'victim', text: 'Hit energy.', facts: { targets: ['Energy'] } }, kase.clues[2]] };
  const en1 = A('E1', { targets: ['Energy'] }), en2 = A('E2', { targets: ['Energy'] });
  const g3 = R.play('hunter', ek, ['E1', 'E2'], { ...byId, E1: en1, E2: en2 });
  assert.deepEqual(g3.rows.map(r => r.cells.find(c => c.k === 'targets').tone), ['miss', 'near']);
});

test('play: analyst has 5 columns and no cap; solving shows every clue', () => {
  const g = R.play('analyst', kase, ['G2', 'G3', 'G1'], byId);
  assert.equal(g.status, 'solved');
  assert.equal(g.tries, 3);
  assert.equal(g.rows[0].cells.length, 5);
  assert.equal(g.clues.length, 3);
  assert.ok(g.rows[2].correct);
  assert.ok(g.rows[2].cells.every(c => c.tone === 'hit'));
});

test('play: hunter goes cold after 6 misses and rows have 6 columns', () => {
  const ids = Array.from({ length: 6 }, (_, i) => 'H' + i);
  const pool = { ...byId, ...Object.fromEntries(ids.map(id => [id, A(id)])) };
  const hk = { ...kase, clues: [...kase.clues, ...kase.clues] };
  const g = R.play('hunter', hk, ids, pool);
  assert.equal(g.status, 'cold');
  assert.equal(g.rows[0].cells.length, 6);
  assert.equal(R.play('hunter', hk, ids.slice(0, 5), pool).status, 'playing');
});

test('guessError rejects what a real game cannot produce', () => {
  assert.equal(R.guessError('analyst', kase, ['G2', 'G3'], byId), null);
  assert.ok(R.guessError('analyst', kase, ['G2', 'G2'], byId));
  assert.ok(R.guessError('analyst', kase, ['nope'], byId));
  assert.ok(R.guessError('analyst', kase, ['G4'], byId), 'analyst guesses must be on the roster');
  assert.equal(R.guessError('hunter', kase, ['G4'], byId), null);
  assert.ok(R.guessError('analyst', kase, ['G1', 'G2'], byId), 'nothing after the solve');
  assert.ok(R.guessError('hunter', kase, ['G2', 'G3', 'G4', 'x', 'y', 'z', 'w'], { ...byId, x: A('x'), y: A('y'), z: A('z'), w: A('w') }));
  assert.ok(R.guessError('analyst', kase, 'G1', byId));
});

test('calendar: the day rolls over at midnight in New York, across DST', () => {
  assert.equal(R.dayOf(Date.parse('2026-11-27T04:59:59Z')), '2026-11-26');
  assert.equal(R.dayOf(Date.parse('2026-11-27T05:00:00Z')), '2026-11-27');
  assert.equal(R.dayOf(Date.parse('2026-07-04T03:59:59Z')), '2026-07-03');
  assert.equal(R.msUntilNext(Date.parse('2026-11-27T04:00:00Z')), 3600e3);
  // 2027-03-14 springs forward: the day before still lasts until 05:00Z, the day itself is 23 hours.
  assert.equal(R.msUntilNext(Date.parse('2027-03-13T05:00:00Z')), 24 * 3600e3);
  assert.equal(R.msUntilNext(Date.parse('2027-03-14T05:00:00Z')), 23 * 3600e3);
  assert.equal(R.addDays('2026-12-31', 1), '2027-01-01');
  assert.equal(R.daysBetween('2026-11-26', '2027-11-26'), 365);
  assert.ok(R.isDay('2026-02-28') && !R.isDay('2026-02-30') && !R.isDay('26-1-1'));
});

test('share text carries case number, mode, score, grid and streak', () => {
  const won = R.play('analyst', kase, ['G3', 'G1'], byId);
  const s = R.shareText({ mode: 'analyst', caseNumber: 12, status: 'solved', rows: won.rows, streak: 4 });
  const lines = s.split('\n');
  assert.equal(lines[0], 'Threatdle #12 · SOC Analyst · 2 guesses · 🔥4');
  assert.equal(lines.length, 3);
  assert.equal(lines[2], '🟩🟩🟩🟩🟩');
  const h = R.shareText({ mode: 'hunter', caseNumber: 3, status: 'cold', rows: R.play('hunter', kase, ['G3'], byId).rows, streak: 0 });
  assert.match(h, /^Threatdle #3 · Threat Hunter X\/6 · 🔥0\n/);
  assert.equal([...h.split('\n')[1]].filter(c => c !== '️').length, 6);
});

test('share grid uses only green, yellow, black and arrows', () => {
  const unknown = A('U', { since: null, targets: [], motive: [] });
  const rows = R.play('hunter', kase, ['G4', 'U'], { ...byId, U: unknown }).rows;
  const grid = R.shareText({ mode: 'hunter', caseNumber: 1, status: 'playing', rows, streak: 0 }).split('\n').slice(1).join('');
  assert.ok(rows.some(r => r.cells.some(c => c.tone === 'unk')), 'the fixture has an unknown cell');
  assert.deepEqual([...new Set(grid.replace(/️/g, ''))].filter(c => !['🟩', '🟨', '⬛', '⬆', '⬇'].includes(c)), []);
});

test('share text keeps a long analyst game short', () => {
  const rows = Array.from({ length: 20 }, () => ({ cells: [{ tone: 'miss' }] }));
  const lines = R.shareText({ mode: 'analyst', caseNumber: 1, status: 'solved', rows, streak: 1 }).split('\n');
  assert.equal(lines.length, 1 + R.SHARE_ROWS + 1);
  assert.equal(lines.at(-2), '+12 more');
});

test('streaks: only consecutive wins count; a missed day or a loss resets', () => {
  let s = R.nextStreak(null, '2026-12-01', true);
  s = R.nextStreak(s, '2026-12-02', true);
  assert.equal(s.n, 2);
  assert.equal(R.nextStreak(s, '2026-12-02', false).n, 2, 'finishing the same day twice changes nothing');
  assert.equal(R.currentStreak(s, '2026-12-03'), 2);
  assert.equal(R.currentStreak(s, '2026-12-04'), 0);
  assert.equal(R.nextStreak(s, '2026-12-04', true).n, 1);
  assert.equal(R.nextStreak(s, '2026-12-03', false).n, 0);
});

test('fits: victim clues never rule out unknown targets; home, type and motive do', () => {
  assert.ok(R.fits(A('n'), { targets: ['Energy'] }));
  assert.ok(!R.fits(A('n'), { home: 'RU' }));
  assert.ok(R.fits(A('p', { targets: ['Private sector'] }), { targets: ['Finance'] }));
  assert.ok(!R.fits(panda, { targets: ['Finance'] }));
  assert.ok(R.fits(bear, { name: 'fancy bear' }));
});

test('fits: a naming-family hint rules out only a known name from that vendor in another family', () => {
  const kitten = A('k', { name: 'APT33', aliases: ['Peach Sandstorm', 'REFINED KITTEN'] });
  assert.ok(R.fits(kitten, { family: 'Kitten' }), 'a filled name counts, whatever its case');
  assert.ok(!R.fits(bear, { family: 'Kitten' }), 'a known CrowdStrike name in another family rules the group out');
  assert.ok(R.fits(A('u', { aliases: ['Ruby Sleet'] }), { family: 'Chollima' }), 'no CrowdStrike name known: still possible');
  assert.ok(R.fits(bear, { family: 'Sleet' }), 'a CrowdStrike name says nothing about the Microsoft family');
  assert.ok(!R.fits(kitten, { family: 'Blizzard' }));
});

test('sectionOf files groups by nickname home, then by country', () => {
  assert.equal(R.sectionOf(bear), 'RU');
  assert.equal(R.sectionOf(spider), 'crime');
  assert.equal(R.sectionOf(A('q', { nickname: 'Midnight Blizzard', home: null })), 'RU');
  assert.equal(R.sectionOf(A('r', { home: 'VN' })), 'other');
});

test('Tools shows how many the guess shares as a range, and ? when ATT&CK lists none for a side', () => {
  const cul = A('C1', { tools: ['S1', 'S2', 'S3'] });
  const cell = (g, k) => R.cells('hunter', g, R.compare(g, cul)).find(c => c.k === k);
  assert.equal(cell(A('G1', { tools: ['S9'] }), 'tools').text, '0');
  assert.equal(cell(A('G2', { tools: ['S1', 'S9'] }), 'tools').text, '1–2');
  assert.equal(cell(A('G3', { tools: ['S1', 'S2', 'S3', 'S4'] }), 'tools').text, '3+');
  assert.equal(cell(A('G4', { tools: [] }), 'tools').text, '?');
  assert.equal(cell(A('G4', { tools: [] }), 'tools').tone, 'unk');
});
