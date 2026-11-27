// How much each SOC Analyst clue gives away to a well-read player, measured blind.
// The facts on a clue only say how many groups a newcomer can strike off. They miss what a reader recognizes: "caused a blackout in
// Ukraine" fits 30 groups on facts and names one to anyone who followed the news. So a blind reader scores every clue alone.
//
//   node tools/clue-scores.mjs prepare <dir>   writes <dir>/blind.json (roster plus every analyst clue, shuffled, no answers) and <dir>/key.json
//   (a reader, human or model, who has not seen the answers writes <dir>/guesses.json: [{ n, g: roster name, c: 0-100 sure, fits: 1-52 }])
//   node tools/clue-scores.mjs score <dir>     merges the reads into data/clue-scores.json (private: it sits next to the answers)
//
// A clue's score: `tell` = the reader's confidence when the guess was right, else 0; `fits` = how many groups the reader thinks it fits.
import { readFileSync, writeFileSync } from 'node:fs';
import { buildCases, buildPool } from './export.mjs';
import { SCORES, loadScores, scoreOf } from './check-cases.mjs';

const names = a => [a.name, a.nickname, ...(a.aliases || [])].filter(Boolean);
const [cmd, dir] = process.argv.slice(2);
if (import.meta.main) {
  if (!dir || !['prepare', 'score'].includes(cmd)) { console.error('usage: node tools/clue-scores.mjs prepare|score <dir>'); process.exit(1); }
  const at = f => new URL(f, `file:///${dir.replace(/\\/g, '/').replace(/\/?$/, '/')}`);
  const actors = buildPool().actors, byId = Object.fromEntries(actors.map(a => [a.id, a]));
  const cases = buildCases().filter(c => c.mode === 'analyst');
  if (cmd === 'prepare') {
    const scores = loadScores();
    const items = cases.flatMap(c => c.clues.filter(k => !scoreOf(scores, c, k)).map(k => ({ id: c.id, text: k.text })));
    for (let i = items.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [items[i], items[j]] = [items[j], items[i]]; }
    writeFileSync(at('blind.json'), JSON.stringify({ roster: actors.filter(a => a.roster).map(a => names(a).join(' / ')), clues: items.map((x, i) => ({ n: i + 1, text: x.text })) }, null, 1));
    writeFileSync(at('key.json'), JSON.stringify(items.map((x, i) => ({ n: i + 1, ...x }))));
    console.log(`${items.length} unscored clues written to ${dir}`);
  } else {
    const key = JSON.parse(readFileSync(at('key.json'), 'utf8')), reads = JSON.parse(readFileSync(at('guesses.json'), 'utf8'));
    const culprit = Object.fromEntries(cases.map(c => [c.id, byId[c.culprit]]));
    const scores = loadScores();
    let n = 0;
    for (const k of key) {
      const r = reads.find(x => x.n === k.n);
      if (!r) continue;
      const right = names(culprit[k.id]).some(x => x.toLowerCase() === String(r.g).trim().toLowerCase());
      (scores[k.id] ??= {})[k.text] = { tell: right ? r.c : 0, fits: r.fits };
      n++;
    }
    writeFileSync(SCORES, JSON.stringify(scores, null, 1) + '\n');
    console.log(`scored ${n} of ${key.length} clues`);
  }
}
