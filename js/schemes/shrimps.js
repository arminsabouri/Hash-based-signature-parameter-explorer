import * as fors from '../primitives/fors.js';
import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as porsFp from '../primitives/pors-fp.js';
import * as wotsC from '../primitives/wots-c.js';
import * as plainWots from '../primitives/wots.js';
import { compressions } from '../sha256.js';
import { approx, bytes, num } from '../scheme.js';
import { blockSpace, hashCalls, hashCallsNote, messageHashNote, probability, withMidstate } from '../common-results.js';
import { axisSpans, hashCallCount, tradeoffGroup } from '../tradeoff.js';
import { bracket, drawForest, drawHypertree, svg } from '../draw.js';

// SHRIMPS, from Jonas Nick's Delving Bitcoin post "SHRIMPS: 2.5 KB post-quantum
// signatures across multiple stateful devices": two SPHINCS+ instances under
// one public key. The compact instance has q_s = n_dev * n_dsig, where n_dev
// bounds the number of device initializations and n_dsig the compact-path
// signatures per device; the fallback instance has a large q_s. A signature is
// a SPHINCS+ signature from one instance and the public key of the other.
// The compact defaults are the post's (k, a, h, d) = (8, 17, 12, 1), w = 16,
// S_{w,n} = 240 with WOTS+C and PORS+FP; the fallback defaults are SLH-DSA-SHA2-128s.

const CP = 'Compact path';
const FP = 'Fallback path';

const pick = (params, keys) => keys.map((key) => params.find((p) => p.key === key));
const wotsCParams = wotsC.parameters(CP);
const porsParams = porsFp.parameters(CP);
const forsParams = fors.parameters(FP);

// FIPS 205 message digest: ka bits for the FORS indices, h - h' bits for the
// tree index, and h' bits for the leaf index, each padded to whole bytes.
const forsDigestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * a) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// Neither the post nor SPHINCS-Parameters gives a digest layout for PORS+FP.
// This charges k indices of ceil(log2 t) bits each, in place of FIPS 205's ka
// bits, with the tree and leaf index as there.
const porsDigestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * Math.ceil(Math.log2(k * 2 ** a))) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// The verifier hashes both public keys, PK.seed || PK.root each, to rebuild
// the SHRIMPS public key.
const pkHash = (n) => ({ th: 1, compressions: compressions((4 * n) / 8) });

const otsOf = (state) => wotsC.model({ n: state.n, b: state.b, z: state.z, S: state.S, r: state.r, compressed: true });

// The compact instance: SPHINCS+ with WOTS+C and PORS+FP.
function compact(state) {
  const { n, d, hp } = state;
  const ots = otsOf(state);
  const tree = merkleTree.model({ h: hp, n }, ots);
  const msg = messageHash.model(state, { digestBits: porsDigestBits(state) });
  const pors = porsFp.model(state, msg.sign.compressions);

  const sizes = {
    R: msg.sizes.R,
    fts: pors.sizes.sig,
    ots: d * ots.sizes.sig,
    authPath: d * tree.sizes.authPath,
    sibling: n,
  };
  sizes.sig = sizes.R + sizes.fts + sizes.ots + sizes.authPath + sizes.sibling;

  return {
    leaves: 2 ** (d * hp), h: d * hp, t: pors.t, pors, wots: { p: ots.p, wcSearch: ots.wcSearch },
    sizes,
    keygen: tree.keygen,
    sign: {
      prf: pors.sign.prf + d * (tree.keygen.prf + ots.sign.prf),
      th: pors.sign.th + d * (tree.keygen.th + ots.sign.th),
      compressions: msg.sign.compressions + pors.sign.compressions
        + d * (tree.keygen.compressions + ots.sign.compressions),
    },
    verify: {
      th: pors.verify.th + d * (ots.verify.th + tree.verify.th) + pkHash(n).th,
      compressions: msg.verify.compressions + pors.verify.compressions
        + d * (ots.verify.compressions + tree.verify.compressions) + pkHash(n).compressions,
    },
  };
}

// The fallback instance: SLH-DSA, WOTS and FORS.
function fallback(state) {
  const { n } = state;
  const s = { n, hp: state.fHp, d: state.fD, k: state.fK, a: state.fA };
  const ots = plainWots.model({ n, b: state.fB, compressed: true });
  const tree = merkleTree.model({ h: s.hp, n }, ots);
  const msg = messageHash.model(s, { digestBits: forsDigestBits(s) });
  const f = fors.model({ ...s, plusC: false }, msg.mgf1);

  const sizes = {
    R: msg.sizes.R,
    fts: f.sizes.sig,
    ots: s.d * ots.sizes.sig,
    authPath: s.d * tree.sizes.authPath,
    sibling: n,
  };
  sizes.sig = sizes.R + sizes.fts + sizes.ots + sizes.authPath + sizes.sibling;

  return {
    leaves: 2 ** (s.d * s.hp), h: s.d * s.hp, t: f.t,
    sizes,
    keygen: tree.keygen,
    sign: {
      prf: f.sign.prf + s.d * (tree.keygen.prf + ots.sign.prf),
      th: f.sign.th + s.d * (tree.keygen.th + ots.sign.th),
      compressions: msg.sign.compressions + f.sign.compressions
        + s.d * (tree.keygen.compressions + ots.sign.compressions),
    },
    verify: {
      th: f.verify.th + s.d * (ots.verify.th + tree.verify.th) + pkHash(n).th,
      compressions: msg.verify.compressions + f.verify.compressions
        + s.d * (ots.verify.compressions + tree.verify.compressions) + pkHash(n).compressions,
    },
  };
}

// The m_max SPHINCS-Parameters picks for the compact instance's parameters.
// The counter size does not enter p_nu, so r is left out.
const defaultMmax = (s) => {
  const ots = wotsC.model({ n: s.n, b: s.b, z: s.z, S: s.S, r: 0, compressed: true });
  return porsFp.referenceMmax({ k: s.k, a: s.a, hp: s.hp, d: s.d, w: ots.w, l: ots.l, wotsP: ots.p });
};

const qs = (d) => 2 ** (d.devLog2 + d.dsigLog2);

const dash = () => '—';

// The tradeoff diagram, one series per signing path, drawn on shared axes.
// Key generation derives both instances, so that figure is the same on either
// path. The axis endpoints are pinned; `test/tradeoff.test.js` checks them
// against a fresh walk of the parameter corners.
const path = (name, color, of) => ({
  name,
  color,
  metrics: (d) => {
    const c = of(d);
    return {
      blockSpace: (c.sizes.sig + d.sizes.pk) / 8,
      signCalls: hashCallCount(c.sign),
      verifyCalls: hashCallCount(c.verify),
      keygenCalls: hashCallCount(d.keygen),
      budget: c.leaves,
    };
  },
});

const SERIES = [
  path(CP, 'var(--c-0a9396)', (d) => d.cp),
  path(FP, 'var(--c-ca6702)', (d) => d.fp),
];

// The knobs that tune a search, and n_dev and n_dsig, which no axis reads,
// held at their defaults when the endpoints are worked out.
export const SEARCH_KEYS = ['z', 'S', 'r', 'mmax', 'devLog2', 'dsigLog2'];

const AXIS_SPANS = [
  [8, 343136],
  [3.3858550252753835e-12, 0.012987012987012988],
  [0.000003682508819608623, 0.1],
  [5.643043292663114e-11, 0.011494252873563218],
  [2, 4.562440617622195e+192],
];

export const spans = () => axisSpans(scheme, SERIES, SEARCH_KEYS);

const scheme = {
  id: 'shrimps',
  title: 'SHRIMPS',
  columns: [CP, FP],
  groups: { [CP]: 'var(--c-0a9396)', [FP]: 'var(--c-ca6702)' },

  parameters: [
    { ...pick(wotsCParams, ['n'])[0], group: undefined },
    {
      key: 'devLog2', type: 'range', min: 0, max: 20, step: 1, default: 10, group: CP,
      display: (v) => `2^${v}`,
      label: '\\(n_{\\text{dev}}\\) (upper bound on device initializations)',
      tooltip: 'Each device signs through the compact instance at most \\(n_{\\text{dsig}}\\) times, so the compact instance is parameterized for \\(q_s = n_{\\text{dev}} \\cdot n_{\\text{dsig}}\\) signatures. A device that loses its state and is initialized again from the seed counts again.',
    },
    {
      key: 'dsigLog2', type: 'range', min: 0, max: 8, step: 1, default: 0, group: CP,
      display: (v) => `2^${v}`,
      label: '\\(n_{\\text{dsig}}\\) (compact-path signatures per device)',
      tooltip: 'Signatures each device makes through the compact instance before it switches to the fallback instance.',
    },
    {
      key: 'hp', type: 'range', min: 1, max: 20, step: 1, default: 12, group: CP,
      label: '\\(h\'\\) (height of each XMSS tree)',
      tooltip: 'Each tree has \\(2^{h\'}\\) WOTS+C leaves. Key generation builds the top-layer tree, and each layer adds \\(h\'\\) nodes to the signature.',
    },
    {
      key: 'd', type: 'range', min: 1, max: 32, step: 1, default: 1, group: CP,
      label: '\\(d\\) (number of layers)',
      tooltip: 'The hypertree has total height \\(h = d \\cdot h\'\\) and \\(2^h\\) bottom-layer leaves, one PORS+FP key pair each.',
    },
    ...pick(wotsCParams, ['b', 'z', 'S', 'r']),
    ...pick(porsParams, ['k', 'a']),
    {
      ...pick(porsParams, ['mmax'])[0], default: defaultMmax, resetOn: ['n', 'k', 'a', 'hp', 'd', 'b', 'z', 'S'],
    },
    { ...pick(wotsCParams, ['b'])[0], key: 'fB', group: FP },
    {
      key: 'fHp', type: 'range', min: 1, max: 20, step: 1, default: 9, group: FP,
      label: '\\(h\'\\) (height of each XMSS tree)',
      tooltip: 'Each tree of the hypertree has \\(2^{h\'}\\) WOTS leaves. Key generation builds the top-layer tree.',
    },
    {
      key: 'fD', type: 'range', min: 1, max: 32, step: 1, default: 7, group: FP,
      label: '\\(d\\) (number of layers)',
      tooltip: 'The hypertree has total height \\(h = d \\cdot h\'\\). Each layer adds one WOTS signature and one authentication path to the fallback signature.',
    },
    { ...pick(forsParams, ['k'])[0], key: 'fK' },
    { ...pick(forsParams, ['a'])[0], key: 'fA' },
  ],

  derive(state) {
    const cp = compact(state);
    const fp = fallback(state);
    // Loading the seed derives both key pairs, and the public key is a hash
    // of the two instances' public keys.
    const hash = pkHash(state.n);
    const keygen = {
      prf: cp.keygen.prf + fp.keygen.prf,
      th: cp.keygen.th + fp.keygen.th + hash.th,
      compressions: cp.keygen.compressions + fp.keygen.compressions + hash.compressions,
    };
    return {
      cp, fp, keygen, n: state.n, k: state.k, a: state.a,
      devLog2: state.devLog2, dsigLog2: state.dsigLog2,
      sizes: { pk: state.n },
      ...withMidstate({ keygen, sign: cp.sign, verify: cp.verify }),
    };
  },

  results: [
    tradeoffGroup({ spans: AXIS_SPANS, series: SERIES, hold: ['n', ...SEARCH_KEYS] }),
    {
      rows: [
        {
          label: 'Public key',
          tooltip: 'A hash of the public keys of both instances. The verifier rebuilds the signing instance\'s public key from the signature and hashes it with the other one, which the signature carries.',
          value: (d) => bytes(d.sizes.pk),
        },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'A SPHINCS+ signature under the selected instance, followed by the public key of the other instance. Both instances share \\(\\mathrm{PK.seed}\\), so that public key is its \\(\\mathrm{PK.root}\\) alone.',
      rows: [
        { label: 'Randomness \\(R\\)', values: [(d) => bytes(d.cp.sizes.R), (d) => bytes(d.fp.sizes.R)] },
        { label: 'PORS+FP signature', values: [(d) => bytes(d.cp.sizes.fts), dash] },
        { label: 'FORS signature', values: [dash, (d) => bytes(d.fp.sizes.fts)] },
        { label: 'OTS signatures (\\(d \\times \\sigma_{\\mathrm{OTS}}\\))', values: [(d) => bytes(d.cp.sizes.ots), (d) => bytes(d.fp.sizes.ots)] },
        { label: '\\(d \\times \\mathrm{AuthPath}\\)', values: [(d) => bytes(d.cp.sizes.authPath), (d) => bytes(d.fp.sizes.authPath)] },
        { label: 'Sibling public key', values: [(d) => bytes(d.cp.sizes.sibling), (d) => bytes(d.fp.sizes.sibling)] },
        { label: 'Total', values: [(d) => bytes(d.cp.sizes.sig), (d) => bytes(d.fp.sizes.sig)] },
      ],
    },
    {
      heading: 'Search',
      tooltip: 'The compact instance grinds twice: the WOTS+C counter at each of the \\(d\\) layers, and the digest until the PORS+FP authentication set has at most \\(m_{\\max}\\) nodes. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        { label: 'PORS+FP leaves (\\(t = k \\cdot 2^a\\))', values: [(d) => approx(d.cp.t), dash] },
        { label: 'PORS+FP success probability per trial', values: [(d) => probability(d.cp.pors.p), dash] },
        { label: 'PORS+FP WC search', values: [(d) => approx(d.cp.pors.wcSearch), dash] },
        { label: 'WOTS+C success probability per trial (\\(p_\\nu\\))', values: [(d) => probability(d.cp.wots.p), dash] },
        { label: 'WOTS+C WC search', values: [(d) => approx(d.cp.wots.wcSearch), dash] },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: `Key generation derives both instances, building each top-layer tree, and hashes their public keys. Signing builds the few-time signature trees and the \\(d\\) hypertree trees on the path; compact-path signing includes the PORS+FP WC search. Verification includes hashing the two public keys. ${messageHashNote} ${hashCallsNote}`,
      rows: [
        { label: 'Key generation (both instances)', value: (d) => hashCalls(d.keygen) },
        { label: 'Signing', values: [(d) => hashCalls(d.cp.sign), (d) => hashCalls(d.fp.sign)] },
        { label: 'Verification', values: [(d) => hashCalls(d.cp.verify, num), (d) => hashCalls(d.fp.verify, num)] },
      ],
    },
    {
      heading: 'Signature budget',
      rows: [
        {
          label: '\\(q_s = n_{\\text{dev}} \\cdot n_{\\text{dsig}}\\)',
          tooltip: 'The number of signatures the compact instance is parameterized to support. Each device signs through it at most \\(n_{\\text{dsig}}\\) times.',
          values: [(d) => approx(qs(d)), dash],
        },
        {
          label: 'Security',
          tooltip: 'At \\(q_s\\) compact-path signatures, as security.sage in SPHINCS-Parameters computes it for PORS+FP: \\(-\\log_2 \\max(2^{-n}, \\sigma)\\), where \\(\\sigma\\) sums, over \\(r\\), the probability that \\(r\\) signatures hit one of the \\(2^h\\) instances times the probability that a fresh digest selects only leaves they revealed.',
          values: [(d) => `${porsFp.securityBits({ n: d.n, k: d.k, a: d.a, h: d.cp.h }, qs(d)).toFixed(1)} bits`, dash],
        },
        {
          label: 'State counter',
          tooltip: 'Per key, the device stores the number of compact-path signatures made, \\(\\lceil \\log_2(n_{\\text{dsig}} + 1) \\rceil\\) bits. With keys derived from one seed, it keeps this for every derived key.',
          values: [(d) => {
            const bits = Math.ceil(Math.log2(2 ** d.dsigLog2 + 1));
            return `${num(bits)} ${bits === 1 ? 'bit' : 'bits'}`;
          }, dash],
        },
        {
          label: 'Hypertree leaves (\\(2^h\\))',
          tooltip: 'Each bottom-layer leaf carries one few-time key pair, selected by the message digest.',
          values: [(d) => approx(d.cp.leaves), (d) => approx(d.fp.leaves)],
        },
      ],
    },
    {
      ...blockSpace,
      rows: [
        {
          ...blockSpace.rows[0],
          values: [
            (d) => num(Math.floor(4000000 / ((d.cp.sizes.sig + d.sizes.pk) / 8))),
            (d) => num(Math.floor(4000000 / ((d.fp.sizes.sig + d.sizes.pk) / 8))),
          ],
        },
      ],
    },
  ],
};

export default scheme;

// The PORS+FP tree: one tree of t leaves with k of them revealed.
function drawPors(g, { k, t, left, right, top, bx }) {
  const rootY = top, baseY = top + 110, size = 10;
  const cx = (left + right) / 2;
  const hw = (right - left) / 2 - 8;
  g.line(cx, rootY, cx - hw, baseY, 'edge');
  g.line(cx, rootY, cx + hw, baseY, 'edge');
  g.line(cx - hw, baseY, cx + hw, baseY, 'edge');
  g.circle(cx, rootY, 7, 'tree-node');
  const shown = Math.min(k, 12);
  for (let j = 0; j < shown; j++) {
    const x = cx - hw + (2 * hw) * ((j * 0.37 + 0.13) % 1);
    g.rect(x - size / 2, baseY + 6, size, size, 'ots-node');
  }
  bracket(g, bx, rootY, baseY, [`t = ${t.toLocaleString()}`]);
  g.text(bx + 8, baseY + 16, 'leaves', 'start', 'label ots-label');
  g.text(cx, baseY + 40, `k = ${k} leaves revealed`, 'middle');
  return { rootX: cx, rootY, bottom: baseY + 50 };
}

// Structure diagram: the two instances stacked, each a hypertree over its
// few-time signature.
function shrimpsSvg(state) {
  const W = 620;
  const g = svg();
  const left = 120, right = W - 160, bx = W - 142;

  g.text(W / 2, 20, 'SHRIMPS public key = hash of both instances\' public keys');

  // Compact instance.
  g.text(40, 50, CP, 'start');
  const cLeaf = drawHypertree(g, {
    hp: state.hp, d: state.d, left, right, bx, top: 96, otsLabel: 'WOTS+C', rootLabel: 'compact PK.root',
  });
  const poTop = cLeaf.y + 96;
  const pkX = (left + right) / 2;
  g.line(cLeaf.x, cLeaf.y + 7, cLeaf.x, cLeaf.y + 56, 'ots-edge');
  g.line(cLeaf.x, cLeaf.y + 56, pkX, cLeaf.y + 56, 'ots-edge');
  g.line(pkX, cLeaf.y + 56, pkX, poTop - 7, 'ots-edge');
  g.text(cLeaf.x + 10, cLeaf.y + 30, 'WOTS+C key signs the PORS+FP public key', 'start', 'label ots-label');
  const pors = drawPors(g, { k: state.k, t: state.k * 2 ** state.a, left: 70, right: W - 150, top: poTop, bx: W - 130 });

  // Fallback instance.
  const fTop = pors.bottom + 40;
  g.text(40, fTop, FP, 'start');
  const fLeaf = drawHypertree(g, {
    hp: state.fHp, d: state.fD, left, right, bx, top: fTop + 46, otsLabel: 'WOTS', rootLabel: 'fallback PK.root',
  });
  const forestTop = fLeaf.y + 96;
  g.line(fLeaf.x, fLeaf.y + 7, fLeaf.x, fLeaf.y + 56, 'ots-edge');
  g.line(fLeaf.x, fLeaf.y + 56, pkX, fLeaf.y + 56, 'ots-edge');
  g.line(pkX, fLeaf.y + 56, pkX, forestTop - 7, 'ots-edge');
  g.text(fLeaf.x + 10, fLeaf.y + 30, 'WOTS key signs the FORS public key', 'start', 'label ots-label');
  const forest = drawForest(g, {
    k: state.fK, a: state.fA, plusC: false, left: 70, right: W - 150, top: forestTop, bx: W - 130, pkLabel: '',
  });
  g.text(pkX + 16, forestTop + 4, 'FORS public key', 'start');

  return { svg: g.toString(), width: W, height: forest.bottom + 10 };
}

// Visualization state, nested inside the scheme component.
export function shrimpsDiagram() {
  return {
    get drawing() {
      return shrimpsSvg(this.state);
    },
  };
}
