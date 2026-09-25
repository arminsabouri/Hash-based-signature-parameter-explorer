import fs from 'node:fs';

// formulas.js is a plain script, so it is evaluated here and the functions the
// tests use are handed back. Keeping it unmodified lets it be re-fetched from
// the pinned commit and diffed.
const src = fs.readFileSync(new URL('./formulas.js', import.meta.url), 'utf8');

const NAMES = [
  'wotsL', 'wotsThl', 'wotsPkC', 'wotsSignC', 'wotsVerifyWorstSteps', 'wotsVerifyC',
  'treeSizePerLayer', 'treeKeygenC', 'treeVerifyC',
  'xmssMtSize', 'xmssMtKeygenC', 'xmssMtVerifyC', 'xmssMtStateBytes',
  'uxmssIdxBytes', 'uxmssSize', 'uxmssKeygenC', 'uxmssVerifyC',
  'slhMetrics', 'computeTh', 'computeNu', 'idxBytes',
];

export const formulas = new Function(`${src};\nreturn { ${NAMES.join(', ')} };`)();

export const fixtures = JSON.parse(
  fs.readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'),
);
