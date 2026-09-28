import test from 'node:test';
import assert from 'node:assert/strict';

import shrimps from '../js/schemes/shrimps.js';
import sphincs from '../js/schemes/sphincs.js';
import * as merkleTree from '../js/primitives/merkle-tree.js';
import * as porsFp from '../js/primitives/pors-fp.js';
import * as wotsC from '../js/primitives/wots-c.js';
import { compressions } from '../js/sha256.js';
import { initialState } from '../js/scheme.js';
import { bytes, derive } from './helpers.js';
import { fixtures } from './reference/load.js';
import { MIDSTATE, THEIR_HMSG, THEIR_PRFMSG, hmsg } from './reference/conventions.js';

// SHRIMPS against Jonas Nick's Delving Bitcoin post, and its PORS+FP compact
// instance against the SPHINCS-Parameters fixtures vendored in test/reference.

const N = 128;
const lg = (w) => Math.log2(w);

// A compact instance in the post's notation, (k, a, h, d), w and S_{w,n}, with
// the WOTS+C counter of SPHINCS-Parameters (4 bytes). m_max is the default the
// parameters panel would give it, the value costs.sage picks.
const mmaxParam = shrimps.parameters.find((p) => p.key === 'mmax');
const compactState = ({ k, a, h, d, w, swn }) => {
  const state = { ...initialState(shrimps.parameters), n: N, k, a, hp: h / d, d, b: lg(w), z: 0, S: swn, r: 32 };
  return { ...state, mmax: mmaxParam.default(state) };
};

// The PORS+FP digest as js/schemes/shrimps.js charges it, restated so that a
// change there fails here.
const porsDigestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * Math.ceil(Math.log2(k * 2 ** a))) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// The verifier's hash of the two public keys, PK.seed || PK.root each.
const pkHash = compressions((4 * N) / 8);

// variant key: W+C_P+FP, then h, d, k, a, w, S_{w,n}.
const porsVariants = Object.entries(fixtures.variants)
  .filter(([key]) => key.startsWith('W+C_P+FP|'))
  .map(([key, want]) => {
    const [h, d, k, a, w, swn] = key.split('|')[1].split(',').map(Number);
    return { key, want, v: { h, d, k, a, w, swn } };
  });

test('the compact instance matches the PORS+FP reference variants', () => {
  assert.equal(porsVariants.length, 3, 'three PORS+FP variants are vendored');
  for (const { key, want, v } of porsVariants) {
    const state = compactState(v);
    const d0 = derive(shrimps, state);
    // The default m_max is the one costs.sage picks, which fixes the size.
    assert.equal(bytes(d0.cp.sizes.sig - d0.cp.sizes.sibling), want.size, `${key} signature`);
    // Verification differs by the midstate, by how H_msg is costed, and by the
    // hash of the two public keys, which a lone SPHINCS+ instance does not have.
    const offset = MIDSTATE + hmsg(N, porsDigestBits(state)) - THEIR_HMSG + pkHash;
    assert.equal(d0.verifyCompressions - offset, want.sv_worst, `${key} worst-case verification`);
  }
});

test('the compact instance reproduces the reference signing cost once its parts are named', () => {
  // The reference signs by building the PORS+FP tree and every hypertree
  // layer, with the expected number of trials for each search: 1 / p_nu per
  // WOTS+C layer at one compression each, and the PORS+FP expectation at one
  // H_msg and one PRF_msg each. The site's own figure uses the WC search.
  for (const { key, want, v } of porsVariants) {
    const state = compactState(v);
    const s = derive(shrimps, state);
    const ots = wotsC.model({ ...state, compressed: true });
    const tree = merkleTree.model({ h: state.hp, n: N }, ots);
    assert.equal(
      s.cp.pors.keygen.compressions + s.cp.pors.expected * (THEIR_HMSG + THEIR_PRFMSG)
        + v.d * tree.keygen.compressions + v.d * Math.ceil(1 / ots.p),
      want.sg,
      `${key} signing, reference composition`,
    );
  }
});

// The post's table of compact-path parameter sets: (k, a, h, d) with w = 16
// and S_{w,n} = 240, the size as SPHINCS+ signature plus the 16-byte sibling
// public key, and the signing cost in millions of compressions.
const POST_ROWS = [
  { k: 10, a: 12, h: 12, d: 1, size: 2324, sign: 2.5 },
  { k: 8, a: 17, h: 12, d: 1, size: 2564, sign: 6.8 },
  { k: 12, a: 12, h: 12, d: 1, size: 2708, sign: 2.4 },
  { k: 10, a: 14, h: 14, d: 1, size: 2628, sign: 9.9 },
  { k: 12, a: 13, h: 12, d: 1, size: 2884, sign: 2.7 },
  { k: 8, a: 17, h: 16, d: 1, size: 2580, sign: 41.0 },
  { k: 10, a: 15, h: 14, d: 1, size: 2772, sign: 10.9 },
  { k: 10, a: 12, h: 22, d: 2, size: 3000, sign: 2.5 },
];

test('the compact path reproduces every row of the post\'s table', () => {
  // The post ran costs.sage at commit f2ea2a2, where R is 32 bytes and each
  // two-block Th costs 2 compressions. Here R is n = 16 bytes, as in FIPS 205,
  // so every size is 16 bytes smaller. The signing cost is rebuilt under that
  // commit's constants from the parts the site computes.
  const R_GAP = 16;
  for (const row of POST_ROWS) {
    const v = { ...row, w: 16, swn: 240 };
    const state = compactState(v);
    const d0 = derive(shrimps, state);
    const where = `(k, a, h, d) = (${row.k}, ${row.a}, ${row.h}, ${row.d})`;
    assert.equal(bytes(d0.cp.sizes.sig) + R_GAP, row.size, `${where} size`);

    const ots = wotsC.model({ ...state, compressed: true });
    const t = row.k * 2 ** row.a;
    const th = (x) => Math.ceil((128 + 96 + 128 * x + 65) / 512);
    const merkle = 2 ** state.hp * (ots.l + ots.l * 15 + th(ots.l)) + (2 ** state.hp - 1) * 2;
    const sign = row.d * merkle + row.d * Math.ceil(1 / ots.p)
      + 2 * t + (t - 1) * 2 + d0.cp.pors.expected * (THEIR_HMSG + THEIR_PRFMSG);
    assert.equal((sign / 1e6).toFixed(1), row.sign.toFixed(1), `${where} signing cost`);
  }
});

test('security at the compact budget and past it matches the post', () => {
  // The post's table for (k, a, h, d) = (8, 17, 12, 1) as the total number of
  // compact-path signatures grows past q_s = 2^10.
  const want = { 10: 128.0, 11: 128.0, 12: 125.1, 13: 120.4, 14: 115.0, 15: 108.9 };
  for (const [log2q, bits] of Object.entries(want)) {
    const got = porsFp.securityBits({ n: N, k: 8, a: 17, h: 12 }, 2 ** Number(log2q));
    assert.equal(got.toFixed(1), bits.toFixed(1), `2^${log2q} signatures`);
  }
});

test('the fallback instance at its defaults is SLH-DSA-SHA2-128s plus the sibling public key', () => {
  const d0 = derive(shrimps);
  const slh = derive(sphincs);
  assert.equal(bytes(slh.sizes.sig), 7856);
  assert.equal(d0.fp.sizes.sig, slh.sizes.sig + N);
  assert.equal(d0.fp.keygen.compressions, slh.calls.keygen.compressions);
});
