import test from 'node:test';
import assert from 'node:assert/strict';

import sphincs from '../js/schemes/sphincs.js';
import shrincs from '../js/schemes/shrincs.js';
import fors from '../js/schemes/fors.js';
import wots from '../js/schemes/wots.js';
import * as wotsTw from '../js/primitives/wots-tw.js';
import { bytes, derive } from './helpers.js';

// Sizes published by FIPS 205 and by the SHRINCS BIP. These are the numbers a
// reader is most likely to check the site against, so they are pinned here.

// FIPS 205 Table 2, the SHA-2 parameter sets. `lg_w` is 4 throughout.
const SLH_DSA = [
  { name: 'SLH-DSA-SHA2-128s', n: 128, hp: 9, d: 7, a: 12, k: 14, sig: 7856, pk: 32, sk: 64 },
  { name: 'SLH-DSA-SHA2-128f', n: 128, hp: 3, d: 22, a: 6, k: 33, sig: 17088, pk: 32, sk: 64 },
  { name: 'SLH-DSA-SHA2-192s', n: 192, hp: 9, d: 7, a: 14, k: 17, sig: 16224, pk: 48, sk: 96 },
  { name: 'SLH-DSA-SHA2-192f', n: 192, hp: 3, d: 22, a: 8, k: 33, sig: 35664, pk: 48, sk: 96 },
  { name: 'SLH-DSA-SHA2-256s', n: 256, hp: 8, d: 8, a: 14, k: 22, sig: 29792, pk: 64, sk: 128 },
  { name: 'SLH-DSA-SHA2-256f', n: 256, hp: 4, d: 17, a: 9, k: 35, sig: 49856, pk: 64, sk: 128 },
];

test('SPHINCS+ reproduces every FIPS 205 SHA-2 parameter set', () => {
  for (const p of SLH_DSA) {
    const d = derive(sphincs, { n: p.n, b: 4, hp: p.hp, d: p.d, a: p.a, k: p.k });
    assert.equal(bytes(d.sizes.sig), p.sig, `${p.name} signature`);
    assert.equal(bytes(d.sizes.pk), p.pk, `${p.name} public key`);
    assert.equal(bytes(d.sizes.sk), p.sk, `${p.name} secret key`);
  }
});

// The parameter set of the SHRINCS stateless component, which is not one of
// the FIPS 205 sets. Constants from the BIP's "Stateless Constants" table.
const BIP_STATELESS = { n: 128, b: 4, hp: 9, d: 5, a: 13, k: 10 };

test('SPHINCS+ reproduces the SHRINCS stateless constants', () => {
  const d = derive(sphincs, BIP_STATELESS);
  assert.equal(bytes(d.sizes.fors), 2240, 'FORS_SIGNATURE_SIZE');
  assert.equal(bytes(d.sizes.ots + d.sizes.authPath), 3520, 'HYPERTREE_SIGNATURE_SIZE');
  assert.equal(bytes(d.sizes.ots + d.sizes.authPath) / 5, 704, 'SPHX_XMSS_SIGNATURE_SIZE');
  assert.equal(bytes(d.sizes.sig), 5776, 'SPHX_SIGNATURE_SIZE');
  // Slicing sf_root off a SHRINCS public key leaves the SLH-DSA public key.
  assert.equal(bytes(d.sizes.pk), 32, 'SLH-DSA public key');
  assert.equal(d.h, 45, 'h');
  assert.equal(Math.log2(d.leaves), 45, 'hypertree leaves');
});

test('WOTS-TW reproduces the SHRINCS stateless WOTS constants', () => {
  const { w, len1, len2, len } = wotsTw.lengths(128, 4);
  assert.equal(len1, 32, 'WOTS_TW_CHAIN_COUNT1');
  assert.equal(len2, 3, 'WOTS_TW_CHAIN_COUNT2');
  assert.equal(len, 35, 'WOTS_TW_CHAIN_COUNT');
  assert.equal(len1 * (w - 1), 480, 'WOTS_TW_CHECKSUM_MAX');

  const d = derive(wots, { n: 128, b: 4, plusC: false });
  assert.equal(bytes(d.sizes.sig), 560, 'WOTS_TW_CHAINS_SIZE');
});

test('WOTS+C reproduces the SHRINCS stateful WOTS constants', () => {
  const d = derive(wots, { n: 128, b: 4, z: 0, plusC: true });
  assert.equal(d.l, 32, 'WOTS_C_CHAIN_COUNT');
  assert.equal(bytes(d.l * 128), 512, 'WOTS_C_CHAINS_SIZE');
  // WOTS_C_CONSTANT_SUM is the parameter panel's default for S.
  const { S } = { ...{}, ...wotsDefaults() };
  assert.equal(S, 240, 'WOTS_C_CONSTANT_SUM');
});

function wotsDefaults() {
  const state = {};
  for (const p of wots.parameters) if (typeof p.default !== 'function') state[p.key] = p.default;
  for (const p of wots.parameters) if (typeof p.default === 'function') state[p.key] = p.default(state);
  return state;
}

test('FORS reproduces the published signature sizes', () => {
  // SHRINCS FORS_SIGNATURE_SIZE, and the FORS part of SLH-DSA-SHA2-128s.
  assert.equal(bytes(derive(fors, { n: 128, k: 10, a: 13 }).sizes.fors), 2240);
  assert.equal(bytes(derive(fors, { n: 128, k: 14, a: 12 }).sizes.fors), 2912);
});

test('SHRINCS reproduces its published key and signature sizes', () => {
  const d = derive(shrincs);
  assert.equal(bytes(d.sizes.pk), 48, 'public key');
  assert.equal(bytes(d.sizes.sk), 82, 'serialized secret key');
  assert.equal(bytes(d.sl.sizes.sig), 5777, 'SHRINCS_SL_SIGNATURE_SIZE');
  assert.equal(bytes(d.sl.sizes.fors), 2240, 'FORS_SIGNATURE_SIZE');
  assert.equal(bytes(d.sl.sizes.ht), 3520, 'HYPERTREE_SIGNATURE_SIZE');
  assert.equal(bytes(d.sf.sizes.chains), 512, 'WOTS_C_CHAINS_SIZE');

  // FXMSS_SIGNATURE_SIZE_MIN and SHRINCS_SF_SIGNATURE_SIZE_MIN, at depth 1.
  const shallow = derive(shrincs, { depth: 1 });
  const fxmss = (x) => bytes(x.sf.sizes.counter + x.sf.sizes.chains + x.sf.sizes.authPath);
  assert.equal(fxmss(shallow), 530, 'FXMSS_SIGNATURE_SIZE_MIN');
  assert.equal(bytes(shallow.sf.sizes.sig), 548, 'SHRINCS_SF_SIGNATURE_SIZE_MIN');
  assert.equal(fxmss(d), 4594, 'FXMSS_SIGNATURE_SIZE_MAX');
});

test('SHRINCS matches the size ratio the BIP quotes against SLH-DSA-SHA2-128s', () => {
  // The BIP: a SHRINCS public key plus its smallest stateful signature is
  // about 13.23x smaller than an SLH-DSA-SHA2-128s public key plus signature.
  const shallow = derive(shrincs, { depth: 1 });
  const ratio = (7856 + 32) / (bytes(shallow.sizes.pk) + bytes(shallow.sf.sizes.sig));
  assert.equal(ratio.toFixed(2), '13.23');
});
