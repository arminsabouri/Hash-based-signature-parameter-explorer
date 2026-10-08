import test from 'node:test';
import assert from 'node:assert/strict';

import * as hg from '../js/primitives/hg-wots.js';
import hgt from '../js/schemes/hgt.js';
import hgWots from '../js/schemes/hg-wots.js';
import haggrid from '../js/schemes/haggrid.js';
import { bytes, derive } from './helpers.js';

// HGT with N = 512 and K = 4 against its figures at 16.71-bit grinding. With
// the HGT baseline HG-WOTS leaf: 2^-111.29 at r = 8, a grinding threshold of
// tau = 40,168 out of 2^32, and 8 signatures per instance. With HagGrid
// leaves of 13 and 12 nodes: 127.8 and 121.9 bits, and 25 and 16 signatures.

test('HG-WOTS leaves give the HGT baseline', () => {
  const d = derive(hgt);
  assert.equal(d.nodes, 13);
  assert.equal(d.calls.keygen.th, 477);
  assert.equal(d.calls.verify.th, 68);
  assert.equal(d.bitsAtR.toFixed(2), '111.29');
  assert.equal(Math.floor(2 ** (32 - d.grinding)), 40168);
  assert.equal(d.perInstance, 8);
  assert.equal(bytes(d.sizes.leaves), 4 * 13 * 16);
});

const hagGrid = {
  13: { bits: '127.8', grinding: '0.25', perInstance: 25, state: {} },
  12: { bits: '121.9', grinding: '6.12', perInstance: 16, state: { c: 3, bs: 19 } },
};

for (const [name, want] of Object.entries(hagGrid)) {
  test(`HagGrid leaves of ${name} nodes`, () => {
    const d = derive(hgt, { leaf: 'HagGrid', ...want.state });
    assert.equal(d.nodes, Number(name));
    assert.equal(d.bitsAtR.toFixed(1), want.bits);
    assert.equal(d.grinding.toFixed(2), want.grinding);
    assert.equal(d.perInstance, want.perInstance);
  });
}

test('a leaf costs what its own tab says', () => {
  for (const [leaf, scheme] of [['HG-WOTS', hgWots], ['HagGrid', haggrid]]) {
    const tree = derive(hgt, { leaf });
    const key = derive(scheme);
    assert.equal(tree.nodes, key.nodes);
    assert.equal(tree.calls.keygen.th, key.calls.keygen.th);
    assert.equal(tree.calls.verify.th, key.calls.verify.th);
  }
});

test('bits fall as the tree signs more', () => {
  let last = Infinity;
  for (const r of [1, 4, 8, 16, hg.R_MAX]) {
    const { bitsAtR } = derive(hgt, { r });
    assert.ok(bitsAtR < last, `r = ${r}: ${bitsAtR}`);
    last = bitsAtR;
  }
});
