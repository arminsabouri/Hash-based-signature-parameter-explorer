import test from 'node:test';
import assert from 'node:assert/strict';

import hgWots from '../js/schemes/hg-wots.js';
import { bytes, derive } from './helpers.js';

// HG-WOTS at the HGT baseline (k, s, chain length, d_g, j, group chain length,
// d_h) = (7, 4, 16, 20, 5, 8, 11): 13 nodes, 477 hash calls to build a key and
// 68 to verify.

const choose = (n, k) => (k === 0 ? 1 : (choose(n - 1, k - 1) * n) / k);

test('the defaults are the HGT baseline leaf', () => {
  const d = derive(hgWots);
  assert.equal(d.nodes, 13);
  assert.equal(bytes(d.sizes.sig), 13 * 16);
  assert.equal(d.calls.keygen.th, 477);
  assert.equal(d.calls.verify.th, 68);
});

test('signing and verification together walk the key once', () => {
  for (const state of [{}, { k: 5, j: 3, s: 3, dg: 12, gl: 6, dh: 7 }]) {
    const d = derive(hgWots, state);
    assert.equal(d.calls.sign.th + d.calls.verify.th, d.calls.keygen.th);
  }
});

// One past signature covers a fresh one only when they are the same codeword.
test('after one signature, a forgery needs the same codeword', () => {
  const codewords = choose(7, 5) * 1631 ** 2 * 1190;
  const { forgeryLog2 } = derive(hgWots, { q: 1 });
  assert.ok(Math.abs(forgeryLog2 - Math.log2(codewords)) < 1e-6, `${forgeryLog2}`);
});

test('the forgery probability grows with every signature', () => {
  let last = Infinity;
  for (const q of [1, 2, 4, 8, 16, 32]) {
    const { forgeryLog2 } = derive(hgWots, { q });
    assert.ok(forgeryLog2 < last, `q = ${q}: ${forgeryLog2}`);
    last = forgeryLog2;
  }
});
