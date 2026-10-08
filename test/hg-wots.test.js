import test from 'node:test';
import assert from 'node:assert/strict';

import hgWots from '../js/schemes/hg-wots.js';
import { bytes, derive } from './helpers.js';

// The HGT baseline (k, s, chain length, d_g, j, group chain length, d_h) =
// (7, 4, 16, 20, 5, 8, 11) with N = 512 and K = 4: 2^-111.29 at r = 8, a
// grinding threshold of tau = 40,168 out of 2^32, 477 hash calls to build a
// leaf, 68 to verify one, and 8 signatures per instance at 16.7-bit grinding.

test('the defaults are the HGT baseline', () => {
  const d = derive(hgWots);
  assert.equal(d.nodes, 13);
  assert.equal(d.calls.keygen.th, 477);
  assert.equal(d.calls.verify.th, 68);
  assert.equal(d.bitsAtR.toFixed(2), '111.29');
  assert.equal(Math.floor(2 ** (32 - d.grinding)), 40168);
  assert.equal(d.perInstance, 8);
  assert.equal(bytes(d.sizes.leaves), 4 * 13 * 16);
});

test('bits fall as the tree instance signs more', () => {
  let last = Infinity;
  for (const r of [1, 4, 8, 16, 32]) {
    const { bitsAtR } = derive(hgWots, { r });
    assert.ok(bitsAtR < last, `r = ${r}: ${bitsAtR}`);
    last = bitsAtR;
  }
});
