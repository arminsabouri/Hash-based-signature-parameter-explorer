import test from 'node:test';
import assert from 'node:assert/strict';

import shrincs from '../js/schemes/shrincs.js';
import sphincs from '../js/schemes/sphincs.js';
import { derive } from './helpers.js';

// SHA-256 compression counts published by the SHRINCS BIP, from its
// `impl/meta.py`. The site counts one extra compression per operation for the
// cached PK.seed midstate, which the BIP's figures leave out, so the
// comparisons below subtract it where the site adds it.

test('SHRINCS reproduces the BIP key generation table', () => {
  // Structure, depth, and total compressions for both components.
  const table = [
    ['UXMSS', 31, 309054],
    ['UXMSS', 255, 425982],
    ['BXMSS', 5, 309054],
    ['BXMSS', 8, 425982],
    ['BXMSS', 10, 826878],
    ['BXMSS', 12, 2430462],
    ['BXMSS', 16, 34502142],
    ['BXMSS', 20, 547649022],
  ];
  for (const [shape, depth, want] of table) {
    const d = derive(shrincs, { shape, depth });
    assert.equal(d.keygen.compressions, want, `${shape} depth ${depth}`);
  }
});

test('SHRINCS reproduces the BIP verification bounds', () => {
  const deepest = derive(shrincs);
  const shallow = derive(shrincs, { depth: 1 });
  // Stateful: 255 at a depth-1 leaf, 509 at the deepest leaf.
  assert.equal(shallow.sf.verify.compressions, 255, 'stateful minimum');
  assert.equal(deepest.sf.verify.compressions, 509, 'stateful maximum');
  // Stateless: the maximum over all messages. The BIP also quotes a minimum of
  // 467, which the site does not report, since it shows worst case only.
  assert.equal(deepest.sl.verify.compressions, 2792, 'stateless maximum');
});

test('SPHINCS+ reproduces the BIP stateless component costs', () => {
  const bip = { n: 128, b: 4, hp: 9, d: 5, a: 13, k: 10 };
  const d = derive(sphincs, bip);
  // Key generation builds the top-layer XMSS tree: the BIP's total for a
  // structure, less the stateful component's share of it.
  const shrincsTotal = derive(shrincs, { shape: 'BXMSS', depth: 5 });
  const statelessOnly = 309054 - shrincsTotal.sf.keygen.compressions;
  assert.equal(statelessOnly, 292351, 'stateless key generation');
  assert.equal(d.keygenCompressions - 1, statelessOnly, 'SPHINCS+ key generation');
  assert.equal(d.verifyCompressions - 1, 2792, 'SPHINCS+ verification');
});

test('the midstate convention is the only difference from the BIP figures', () => {
  // Every operation the site reports adds exactly one compression for the
  // cached PK.seed block. Pinning that keeps the offset from drifting.
  const d = derive(shrincs);
  assert.equal(d.verifyCompressions, d.sf.verify.compressions + 1);
  assert.equal(d.keygenBoth, d.keygen.compressions + 1);
});
