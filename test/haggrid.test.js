import test from 'node:test';
import assert from 'node:assert/strict';

import haggrid from '../js/schemes/haggrid.js';
import hgWots from '../js/schemes/hg-wots.js';
import { bytes, derive } from './helpers.js';

// HagGrid against its figures for N = 512, K = 4 and 16.7-bit grinding: bits
// at r = 8, grinding to 128 bits, signatures per instance, and hash calls to
// build and to verify one leaf. 13 nodes is (4, 3, 16, 15) three times over a
// (4, 4, 16, 20) bottom group. The 12 and 11 node shapes are the ones those
// figures fit: 12 nodes over a (3, 3, 16, 19) bottom group, and 11 with a last
// level of 3 units.

const shapes = {
  13: { nodes: 13, bits: '127.8', grinding: '0.25', perInstance: 25, keygen: 5185, verify: 114, state: {} },
  12: { nodes: 12, bits: '121.9', grinding: '6.12', perInstance: 16, keygen: 4225, verify: 113, state: { c: 3, bs: 19 } },
  11: { nodes: 11, bits: '114.4', grinding: '13.60', perInstance: 9, keygen: 3249, verify: 113, state: { u3: 3, c: 3, bs: 19 } },
};

for (const [name, want] of Object.entries(shapes)) {
  test(`HagGrid, ${name} nodes`, () => {
    const d = derive(haggrid, want.state);
    assert.equal(d.nodes, want.nodes);
    assert.equal(d.bitsAtR.toFixed(1), want.bits);
    assert.equal(d.grinding.toFixed(2), want.grinding);
    assert.equal(d.perInstance, want.perInstance);
    assert.equal(d.calls.keygen.th, want.keygen);
    assert.equal(d.calls.verify.th, want.verify);
    assert.equal(bytes(d.sizes.leaves), 4 * want.nodes * 16);
  });
}

test('one level of HagGrid is HG-WOTS that reveals one group', () => {
  const a = derive(haggrid, { levels: 1, u1: 6, l1: 8, h1: 11, c: 4, bw: 16, bs: 20 });
  const b = derive(hgWots, { k: 6, j: 5, gl: 8, dh: 11, s: 4, w: 16, dg: 20 });
  assert.equal(a.nodes, b.nodes);
  assert.equal(a.bitsAtR, b.bitsAtR);
  assert.equal(a.calls.keygen.th, b.calls.keygen.th);
  assert.equal(a.calls.verify.th, b.calls.verify.th);
});
