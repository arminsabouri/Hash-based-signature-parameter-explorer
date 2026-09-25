import test from 'node:test';
import assert from 'node:assert/strict';

import sphincs from '../js/schemes/sphincs.js';
import xmssMt from '../js/schemes/xmss-mt.js';
import fxmss from '../js/schemes/fxmss.js';
import { bytes, derive } from './helpers.js';
import { fixtures, formulas } from './reference/load.js';
import { MIDSTATE, digestBits, verifyOffset } from './reference/conventions.js';

// test/reference-costs.test.js pins the figures the reference publishes. This
// sweeps the parameter space around them, so a formula that is right at those
// points and wrong elsewhere is caught. Offsets are the ones stated in
// test/reference/conventions.js.

const N = 128; // the reference model is fixed at n = 128.
const lg = (w) => Math.log2(w);

// The w the reference tabulates a target sum for, within the b slider's range.
const WS = Object.keys(fixtures.swn).map(Number).filter((w) => lg(w) <= 8);

// Counted so a grid that silently stops covering anything fails the test.
let comparisons = 0;
const same = (ours, theirs, where) => {
  comparisons += 1;
  assert.equal(ours, theirs, where);
};

test('XMSS^MT matches the reference across the parameter grid', () => {
  const before = comparisons;
  for (const w of WS) {
    const S = fixtures.swn[w];
    for (const hp of [1, 3, 5, 8, 9, 10, 14, 20]) {
      for (const d of [1, 2, 3, 5, 7, 10, 16]) {
        const h = hp * d;
        const o = derive(xmssMt, { n: N, b: lg(w), hp, d, z: 0, S, r: 32 });
        const where = `w=${w} h=${h} d=${d}`;
        same(bytes(o.sizes.sig), formulas.xmssMtSize(h, d, w, 'WC'), `${where} signature`);
        same(
          o.keygenCompressions - MIDSTATE,
          formulas.xmssMtKeygenC(h, d, w, 'WC'),
          `${where} key generation`,
        );
        same(
          o.verifyCompressions - verifyOffset(N),
          formulas.xmssMtVerifyC(h, d, w, S, 'WC', true),
          `${where} worst-case verification`,
        );
      }
    }
  }
  assert.ok(comparisons - before >= 800, 'the grid covers the intended range');
});

test('FXMSS matches the reference UXMSS model across depths', () => {
  const before = comparisons;
  for (const w of WS) {
    const S = fixtures.swn[w];
    for (const depth of [1, 2, 8, 31, 64, 127, 255]) {
      const o = derive(fxmss, { n: N, b: lg(w), shape: 'UXMSS', depth, z: 0, S, r: 32 });
      const where = `w=${w} depth=${depth}`;
      // The reference sizes a signature by the leaf it uses; the deepest leaf
      // is the one this site reports.
      same(bytes(o.sizes.sig), formulas.uxmssSize(depth, depth, w, 'WC'), `${where} signature`);
      same(
        o.keygenCompressions - MIDSTATE,
        formulas.uxmssKeygenC(depth, w, 'WC'),
        `${where} key generation`,
      );
      same(
        o.verifyCompressions - verifyOffset(N),
        formulas.uxmssVerifyC(depth, depth, w, S, 'WC', true),
        `${where} worst-case verification`,
      );
    }
  }
  assert.ok(comparisons - before >= 100, 'the grid covers the intended range');
});

test('SPHINCS+ matches the reference across the parameter grid', () => {
  const before = comparisons;
  for (const w of [16, 256]) {
    for (const hp of [3, 5, 8, 9, 10]) {
      for (const d of [1, 2, 5, 7, 10]) {
        for (const a of [6, 8, 9, 12, 14]) {
          for (const k of [10, 14, 17, 22, 33]) {
            const h = hp * d;
            const o = derive(sphincs, { n: N, b: lg(w), hp, d, a, k });
            const r = formulas.slhMetrics({ h, d, k, a, w });
            const where = `w=${w} h=${h} d=${d} k=${k} a=${a}`;
            same(bytes(o.sizes.sig), r.size, `${where} signature`);
            same(o.keygenCompressions - MIDSTATE, r.kg, `${where} key generation`);
            same(
              o.verifyCompressions - verifyOffset(N, digestBits({ k, a, hp, d })),
              r.svWorst,
              `${where} worst-case verification`,
            );
          }
        }
      }
    }
  }
  assert.ok(comparisons - before >= 1800, 'the grid covers the intended range');
});
