import test from 'node:test';
import assert from 'node:assert/strict';

import sphincs from '../js/schemes/sphincs.js';
import xmssMt from '../js/schemes/xmss-mt.js';
import fxmss from '../js/schemes/fxmss.js';
import * as plainWots from '../js/primitives/wots.js';
import * as wotsC from '../js/primitives/wots-c.js';
import * as forsP from '../js/primitives/fors.js';
import * as merkleTree from '../js/primitives/merkle-tree.js';
import * as messageHash from '../js/primitives/message-hash.js';
import { bytes, derive } from './helpers.js';
import { fixtures, formulas } from './reference/load.js';
import {
  MIDSTATE, THEIR_HMSG, THEIR_PRFMSG, digestBits, verifyOffset,
} from './reference/conventions.js';

// Figures from BlockstreamResearch/SPHINCS-Parameters, the scripts behind
// Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin". See
// test/reference/README.md for the source and commit, and
// test/reference/conventions.js for the offsets applied below.

const N = 128; // the reference model is fixed at n = 128.
const lg = (w) => Math.log2(w);

// Rows the site cannot express. Each is skipped with its reason.
const inRange = (w) => Number.isInteger(lg(w)) && lg(w) <= 8;

test('WOTS chain counts match across the w grid', () => {
  for (const [w, len] of Object.entries(fixtures.wots_len)) {
    if (!inRange(Number(w))) continue; // b stops at 8, so w stops at 256
    assert.equal(plainWots.lengths(N, lg(w)).len, len, `w=${w} chains in total`);
  }
  for (const [w, len1] of Object.entries(fixtures.wots_len_wc)) {
    if (!inRange(Number(w))) continue;
    assert.equal(wotsC.model({ n: N, b: lg(w), z: 0, S: 0, r: 32 }).l, len1, `w=${w} signed chains`);
  }
});

test('the default WOTS+C target sum matches wherever the two definitions agree', () => {
  // S_{w,n} is ceil(l(w-1)/2) here and floor(l(w-1)/2) in the reference, so
  // the two agree unless l(w-1) is odd. The odd case is asserted as it stands,
  // unresolved, rather than left to drift.
  for (const [w, swn] of Object.entries(fixtures.swn)) {
    if (!inRange(Number(w))) continue;
    const l = wotsC.model({ n: N, b: lg(w), z: 0, S: 0, r: 32 }).l;
    const product = l * (Number(w) - 1);
    const ours = Math.ceil(product / 2);
    if (product % 2 === 0) assert.equal(ours, swn, `w=${w} target sum`);
    else assert.equal(ours, swn + 1, `w=${w} target sum, the odd case the definitions split on`);
  }
});

// h, d, k, a, w of each reference parameter tuple.
const tuple = (key) => {
  const [h, d, k, a, w] = key.split(',').map(Number);
  return { h, d, k, a, w, hp: h / d };
};

test('SPHINCS+ matches every reference parameter tuple', () => {
  let pinned = 0;
  for (const [key, want] of Object.entries(fixtures.stateless)) {
    const { h, d, k, a, w, hp } = tuple(key);
    if (!inRange(w) || h % d) continue;
    const d0 = derive(sphincs, { n: N, b: lg(w), hp, d, a, k });

    assert.equal(bytes(d0.sizes.sig), want.size, `${key} signature`);
    assert.equal(d0.keygenCompressions - MIDSTATE, want.kg, `${key} key generation`);
    assert.equal(
      d0.verifyCompressions - verifyOffset(N, digestBits({ k, a, hp, d })),
      want.sv_worst,
      `${key} worst-case verification`,
    );
    pinned += 3;
  }
  assert.equal(pinned, 51, 'every tuple pinned on three figures');
});

test('SPHINCS+ signing reproduces the reference once its parts are named', () => {
  for (const [key, want] of Object.entries(fixtures.stateless)) {
    const { h, d, k, a, w, hp } = tuple(key);
    if (!inRange(w) || h % d) continue;
    const state = { n: N, b: lg(w) };
    const ots = plainWots.model(state);
    const tree = merkleTree.model({ h: hp, n: N }, ots);
    const msg = messageHash.model(state, { digestBits: digestBits({ k, a, hp, d }) });
    const f = forsP.model({ ...state, k, a, plusC: false, r: 32 }, msg.mgf1);

    // The reference signs by building the FORS trees and every layer of the
    // hypertree, and reads the signatures out of that work.
    assert.equal(
      f.keygen.compressions + THEIR_HMSG + THEIR_PRFMSG + d * tree.keygen.compressions,
      want.sg,
      `${key} signing, reference composition`,
    );

    // The site costs the same build, then adds the message hash as it models
    // it, the FORS leaf secrets the signature reveals, and the OTS chain walk
    // at each layer.
    const extra = (msg.sign.compressions - THEIR_HMSG - THEIR_PRFMSG)
      + (f.sign.compressions - f.keygen.compressions)
      + d * ots.sign.compressions;
    assert.equal(
      derive(sphincs, { n: N, b: lg(w), hp, d, a, k }).signCompressions,
      want.sg + extra + MIDSTATE,
      `${key} signing, site composition`,
    );
  }
});

// variant key: W+C or W+C_F+C, then h, d, k, a, w, S_{w,n}.
const variant = (key) => {
  const [scheme, rest] = key.split('|');
  const [h, d, k, a, w, swn] = rest.split(',').map(Number);
  return { scheme, h, d, k, a, w, swn, hp: h / d };
};

const variantState = ({ h, d, k, a, w, swn, hp, scheme }) => ({
  n: N, b: lg(w), hp, d, a, k,
  wotsPlusC: true, z: 0, S: swn, wotsR: 32,
  forsPlusC: scheme.includes('F+C'), forsR: 32,
});

test('SPHINCS+ with WOTS+C matches the reference variants', () => {
  for (const [key, want] of Object.entries(fixtures.variants)) {
    const v = variant(key);
    if (v.scheme !== 'W+C' || !inRange(v.w)) continue; // PORS+FP is not built
    const d0 = derive(sphincs, variantState(v));
    assert.equal(bytes(d0.sizes.sig), want.size, `${key} signature`);
    assert.equal(d0.keygenCompressions - MIDSTATE, want.kg, `${key} key generation`);
    assert.equal(
      d0.verifyCompressions - verifyOffset(N, digestBits(v)),
      want.sv_worst,
      `${key} worst-case verification`,
    );
  }
});

test('SPHINCS+ with FORS+C differs from the reference by the last tree leaf and counter', () => {
  // Here a FORS+C signature keeps the revealed leaf of the omitted tree and
  // carries its own counter (js/primitives/fors.js). The reference drops the
  // tree whole and carries no FORS counter (costs.sage, compute_size). The gap
  // is n + r bits either way, and is asserted as it stands, unresolved.
  for (const [key, want] of Object.entries(fixtures.variants)) {
    const v = variant(key);
    if (v.scheme !== 'W+C_F+C' || !inRange(v.w)) continue;
    const state = variantState(v);
    const d0 = derive(sphincs, state);
    assert.equal(bytes(d0.sizes.sig), want.size + bytes(N + state.forsR), `${key} signature`);
    assert.equal(d0.keygenCompressions - MIDSTATE, want.kg, `${key} key generation`);
    // Verification hashes that revealed leaf too, so the FORS+C term differs.
    // Both sides are written out rather than folded into a constant.
    const msg = messageHash.model(state, { digestBits: 256, counterBits: state.forsR });
    const ours = forsP.model({ ...state, plusC: true }, msg.mgf1).verify.compressions;
    const theirs = (v.k - 1) + (v.k - 1) * v.a + formulas.computeTh(v.k - 1);
    assert.equal(
      d0.verifyCompressions - verifyOffset(N, digestBits(v), state.forsR) - (ours - theirs),
      want.sv_worst,
      `${key} worst-case verification`,
    );
  }
});

// stateful key: WC or TW, then w for uxmss, or h, d, w for xmssmt.
const statefulRows = (block, parse) => Object.entries(block)
  .map(([key, want]) => ({ key, want, ...parse(key) }))
  .filter((r) => r.ots === 'WC' && inRange(r.w)); // both tabs are WOTS+C only

test('FXMSS matches the reference UXMSS rows', () => {
  const rows = statefulRows(fixtures.stateful.uxmss, (key) => {
    const [ots, w] = key.split(',');
    return { ots, w: Number(w) };
  });
  assert.equal(rows.length, 5, 'rows the tab can express');

  for (const { key, want, w } of rows) {
    const d0 = derive(fxmss, {
      n: N, b: lg(w), shape: 'UXMSS', depth: want.hsf, z: 0, S: fixtures.swn[w], r: 32,
    });
    assert.equal(bytes(d0.sizes.sig), want.sz_max, `${key} deepest signature`);
    assert.equal(d0.keygenCompressions - MIDSTATE, want.kg, `${key} key generation`);
    assert.equal(
      d0.verifyCompressions - verifyOffset(N),
      want.sv_max_worst,
      `${key} worst-case verification`,
    );
  }
});

test('XMSS^MT matches the reference rows', () => {
  const rows = statefulRows(fixtures.stateful.xmssmt, (key) => {
    const [ots, h, d, w] = key.split(',');
    return { ots, h: Number(h), d: Number(d), w: Number(w) };
  });
  assert.equal(rows.length, 3, 'rows the tab can express');

  for (const { key, want, h, d, w } of rows) {
    const d0 = derive(xmssMt, {
      n: N, b: lg(w), hp: h / d, d, z: 0, S: fixtures.swn[w], r: 32,
    });
    assert.equal(bytes(d0.sizes.sig), want.size, `${key} signature`);
    assert.equal(d0.keygenCompressions - MIDSTATE, want.kg, `${key} key generation`);
    assert.equal(
      d0.verifyCompressions - verifyOffset(N),
      want.sv_worst,
      `${key} worst-case verification`,
    );
  }
});
