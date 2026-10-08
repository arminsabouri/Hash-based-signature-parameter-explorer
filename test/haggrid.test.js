import test from 'node:test';
import assert from 'node:assert/strict';

import haggrid from '../js/schemes/haggrid.js';
import hgWots from '../js/schemes/hg-wots.js';
import { bytes, derive } from './helpers.js';

// HagGrid against its hash calls to build and to verify one key. 13 nodes is
// (4, 3, 16, 15) three times over a (4, 4, 16, 20) bottom group, and 12 nodes
// is the same levels over a (3, 3, 16, 19) bottom group.

const shapes = {
  13: { nodes: 13, keygen: 5185, verify: 114, state: {} },
  12: { nodes: 12, keygen: 4225, verify: 113, state: { c: 3, bs: 19 } },
};

for (const [name, want] of Object.entries(shapes)) {
  test(`HagGrid, ${name} nodes`, () => {
    const d = derive(haggrid, want.state);
    assert.equal(d.nodes, want.nodes);
    assert.equal(bytes(d.sizes.sig), want.nodes * 16);
    assert.equal(d.calls.keygen.th, want.keygen);
    assert.equal(d.calls.verify.th, want.verify);
    assert.equal(d.calls.sign.th + d.calls.verify.th, d.calls.keygen.th);
  });
}

test('one level of HagGrid is HG-WOTS that reveals one group', () => {
  for (const q of [1, 4]) {
    const a = derive(haggrid, { levels: 1, u: 6, l: 8, h: 11, c: 4, bw: 16, bs: 20, q });
    const b = derive(hgWots, { k: 6, j: 5, gl: 8, dh: 11, s: 4, w: 16, dg: 20, q });
    assert.equal(a.nodes, b.nodes);
    assert.equal(a.forgeryLog2, b.forgeryLog2);
    assert.deepEqual(a.calls, b.calls);
  }
});
