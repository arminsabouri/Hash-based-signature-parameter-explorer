import test from 'node:test';
import assert from 'node:assert/strict';

import lamport from '../js/schemes/lamport.js';
import wots from '../js/schemes/wots.js';
import xmss from '../js/schemes/xmss.js';
import xmssMt from '../js/schemes/xmss-mt.js';
import fxmss from '../js/schemes/fxmss.js';
import fors from '../js/schemes/fors.js';
import sphincs from '../js/schemes/sphincs.js';
import shrincs from '../js/schemes/shrincs.js';
import { bytes, derive } from './helpers.js';

// The schemes share primitives, so the same structure reached two ways must
// give the same figures. These catch a change to one tab that silently moves
// another.

const OTS = { n: 128, b: 4, z: 0, S: 240, r: 32 };

test('a one-layer hypertree is an XMSS tree', () => {
  const a = derive(xmss, { ...OTS, h: 10 });
  const b = derive(xmssMt, { ...OTS, hp: 10, d: 1 });
  assert.equal(b.sizes.sig, a.sizes.sig);
  assert.equal(b.sizes.pk, a.sizes.pk);
  assert.equal(b.calls.verify.th, a.calls.verify.th);
  assert.equal(b.verifyCompressions, a.verifyCompressions);
  assert.equal(b.keygenCompressions, a.keygenCompressions);
});

test('a balanced FXMSS tree is an XMSS tree', () => {
  const a = derive(xmss, { ...OTS, h: 8 });
  const b = derive(fxmss, { ...OTS, shape: 'BXMSS', depth: 8 });
  assert.equal(b.sizes.sig, a.sizes.sig);
  assert.equal(b.sizes.cache, a.sizes.cache);
  assert.equal(b.verifyCompressions, a.verifyCompressions);
  assert.equal(b.keygenCompressions, a.keygenCompressions);
});

test('an unbalanced FXMSS tree grows one node per signature', () => {
  const d = derive(fxmss, { ...OTS, shape: 'UXMSS', depth: 20 });
  // Signature q uses a leaf at depth q, so each step adds one n-bit node.
  for (let q = 1; q < 20; q++) {
    assert.equal(d.sigAt(q + 1) - d.sigAt(q), 128, `step from ${q}`);
  }
});

test("SHRINCS's components match the standalone tabs", () => {
  const d = derive(shrincs);

  // The stateless component is the SPHINCS+ tab, plus the indicator byte.
  const sp = derive(sphincs, { n: 128, b: 4, hp: 9, d: 5, a: 13, k: 10 });
  assert.equal(d.sl.sizes.sig, sp.sizes.sig + 8, 'stateless signature');
  assert.equal(d.sl.sizes.fors, sp.sizes.fors, 'FORS part');
  assert.equal(d.sl.sizes.ht, sp.sizes.ots + sp.sizes.authPath, 'hypertree part');
  assert.equal(d.sl.keygen.compressions, sp.keygenCompressions - 1, 'key generation');

  // The stateful component is the FXMSS tab, whose signature carries a leaf
  // index and message randomness but no indicator byte.
  const fx = derive(fxmss, { ...OTS, r: 16, shape: 'UXMSS', depth: 255 });
  assert.equal(d.sf.sizes.authPath, fx.sizes.authPath, 'authentication path');
  assert.equal(d.sf.sizes.sig, fx.sizes.sig + 8, 'stateful signature');
  assert.equal(d.sf.keygen.compressions, fx.keygenCompressions - 1, 'key generation');
});

test('WOTS+C trades the checksum chains for a counter', () => {
  const tw = derive(wots, { n: 128, b: 4, plusC: false });
  const c = derive(wots, { n: 128, b: 4, z: 0, S: 240, r: 32, plusC: true });
  assert.equal(tw.len, 35, 'len1 + len2');
  assert.equal(c.l, 32, 'signed chains');
  // Three checksum chains drop out; a 32-bit counter comes in.
  assert.equal(c.sizes.sig, tw.sizes.sig - 3 * 128 + 32);
});

test('FORS+C drops the last tree and adds a counter', () => {
  const plain = derive(fors, { n: 128, k: 14, a: 12, plusC: false });
  const c = derive(fors, { n: 128, k: 14, a: 12, plusC: true, r: 32 });
  assert.equal(plain.built, 14);
  assert.equal(c.built, 13);
  // The last tree's authentication path goes; its first leaf and the counter stay.
  assert.equal(c.sizes.fors, plain.sizes.fors - 13 * 128 + 128 + 32);
});

test('Lamport sizes follow from the message and hash lengths', () => {
  const d = derive(lamport, { n: 256, N: 256, seedBased: true });
  assert.equal(bytes(d.sizes.sig), 256 * 256 / 8, 'one N-bit value per message bit');
  assert.equal(d.sizes.pk, 2 * 256 * 256 + 256, 'two per bit, plus P');
});

test('the block space figure divides the weight limit by signature plus public key', () => {
  const d = derive(sphincs);
  const perBlock = Math.floor(4000000 / (bytes(d.sizes.sig) + bytes(d.sizes.pk)));
  assert.equal(perBlock, Math.floor(4000000 / (7856 + 32)));
  assert.equal(perBlock, 507);
});
