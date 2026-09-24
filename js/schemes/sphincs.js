import * as fors from '../primitives/fors.js';
import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wotsC from '../primitives/wots-c.js';
import * as plainWots from '../primitives/wots.js';
import { approx, bytes, num } from '../scheme.js';
import {
  blockSpace, exhaustProbability, hashCalls, hashCallsNote, messageCompressionsTooltip, messageHashNote,
  probability, sigPart, signatureBudget, withMidstate,
} from '../common-results.js';
import { drawForest, drawHypertree, svg, tradeoffSvg } from '../draw.js';

// SPHINCS+, the structure standardized as SLH-DSA in FIPS 205: a FORS key
// pair at every bottom-layer leaf of an XMSS^MT hypertree. The message digest
// selects the leaf, so the signer keeps no state. The OTS of the hypertree is
// WOTS or WOTS+C, and the few-time signature is FORS or FORS+C.
// Defaults are the parameters of SLH-DSA-SHA2-128s.

const HT = 'Hypertree';
const OTS = 'OTS';
const FORS = 'FORS';

// The WOTS+C and FORS+C counters are separate, so their parameters are kept
// under separate keys and passed to each primitive under its own name.
const pick = (params, keys) => keys.map((key) => params.find((p) => p.key === key));
const wotsParams = wotsC.parameters(OTS);
const forsParams = fors.parameters(FORS);

const otsModel = (state) => (state.wotsPlusC
  ? wotsC.model({ ...state, r: state.wotsR, compressed: true })
  : plainWots.model({ ...state, compressed: true }));

// FIPS 205 message digest: ka bits for the FORS indices, h - h' bits for the
// tree index, and h' bits for the leaf index, each padded to whole bytes.
const digestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * a) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// The tradeoff diagram's five axes. Each reads a figure off the derived values;
// `up` says which direction the axis grows in, so that a cost becomes a speed.
const calls = (c) => (c.prf ?? 0) + (c.th ?? 0);
const AXES = [
  {
    label: ['Block space', 'consumption'],
    of: (d) => (d.sizes.sig + d.sizes.pk) / 8,
  },
  {
    label: ['Signature', 'generation speed'],
    of: (d) => 1 / calls(d.calls.sign),
  },
  { label: ['Verification', 'speed'], of: (d) => 1 / calls(d.calls.verify) },
  { label: ['Key generation', 'speed'], of: (d) => 1 / calls(d.calls.keygen) },
  { label: ['Signing budget'], of: (d) => d.leaves },
];

const resolve = (value, state) => (typeof value === 'function' ? value(state) : value);

// The knobs that tune a counter search rather than the structure. Their
// extremes are not useful as axis endpoints: a target sum of 0 asks every
// digest digit to be zero, which at w = 256 is a 2^261 search, and that one
// corner would stretch the signing axis past every realistic setting. They are
// held at their defaults instead.
const SEARCH_KEYS = new Set(['z', 'S', 'wotsR', 'forsR']);

// Every corner of the structural parameter ranges: each slider at its minimum
// or its maximum, and each toggle both ways. A slider whose bounds depend on
// other parameters is resolved against the corner being built, which is why
// the parameter order matters here.
function cornerStates(parameters) {
  const ranges = parameters.filter((p) => p.type === 'range' && !SEARCH_KEYS.has(p.key));
  const held = parameters.filter((p) => p.type === 'range' && SEARCH_KEYS.has(p.key));
  const flags = parameters.filter((p) => p.type === 'checkbox');
  const states = [];
  for (let f = 0; f < 2 ** flags.length; f++) {
    for (let m = 0; m < 2 ** ranges.length; m++) {
      const state = {};
      flags.forEach((p, i) => { state[p.key] = Boolean(f & (1 << i)); });
      ranges.forEach((p, i) => {
        const lo = resolve(p.min, state);
        const hi = resolve(p.max, state);
        state[p.key] = (m & (1 << i)) ? hi : lo;
      });
      held.forEach((p) => { state[p.key] = resolve(p.default, state); });
      states.push(state);
    }
  }
  return states;
}

// The span of each axis over those corners. Each axis takes its own minimum
// and maximum, since the corner that makes a signature largest is not the one
// that makes key generation slowest. Computing this walks every corner, which
// is too slow to do on first paint, so the result is pinned here and a test
// checks it against a fresh computation.
const AXIS_SPANS = [
  [8, 343136],
  [3.3858550252753835e-12, 0.013513513513513514],
  [0.0000036825223805297676, 0.1111111111111111],
  [1.0954219119121497e-10, 0.02857142857142857],
  [2, 4.562440617622195e+192],
];

export function axisSpans(config) {
  const spans = AXES.map(() => ({ min: Infinity, max: -Infinity }));
  for (const state of cornerStates(config.parameters)) {
    const derived = config.derive(state);
    AXES.forEach((axis, i) => {
      const v = axis.of(derived);
      if (!Number.isFinite(v) || v <= 0) return;
      spans[i].min = Math.min(spans[i].min, v);
      spans[i].max = Math.max(spans[i].max, v);
    });
  }
  return spans.map((s) => [s.min, s.max]);
}

// Axis positions for the current parameters. The figures span many orders of
// magnitude, so each is placed on a log scale between the two extremes.
function tradeoff(derived) {
  return tradeoffSvg(AXES.map((axis, i) => {
    const [min, max] = AXIS_SPANS[i];
    const v = axis.of(derived);
    const t = max > min ? (Math.log(v) - Math.log(min)) / (Math.log(max) - Math.log(min)) : 0.5;
    return { label: axis.label, value: Math.min(1, Math.max(0, t)) };
  }));
}


const scheme = {
  id: 'sphincs',
  title: 'SPHINCS+',

  groups: { [HT]: 'var(--c-0a9396)', [OTS]: 'var(--c-ca6702)', [FORS]: 'var(--c-9b2226)' },

  parameters: [
    { ...pick(wotsParams, ['n'])[0], group: undefined },
    {
      key: 'hp', type: 'range', min: 1, max: 20, step: 1, default: 9, group: HT,
      ticks: [4, 8, 16],
      label: '\\(h\'\\) (height of each XMSS tree)',
      tooltip: 'Each tree has \\(2^{h\'}\\) OTS leaves. Key generation builds the top-layer tree, signing builds the \\(d\\) trees on the path to the selected leaf, and each layer adds \\(h\'\\) nodes to the signature.',
    },
    {
      key: 'd', type: 'range', min: 1, max: 32, step: 1, default: 7, group: HT,
      label: '\\(d\\) (number of layers)',
      tooltip: 'The hypertree has total height \\(h = d \\cdot h\'\\) and \\(2^h\\) bottom-layer leaves, one FORS key pair each. Each layer adds one OTS signature and one authentication path to the signature.',
    },
    ...pick(forsParams, ['k', 'a']),
    {
      ...pick(forsParams, ['plusC'])[0], key: 'forsPlusC',
      tooltip: 'The signer grinds a counter until the last \\(a\\) bits of the FORS part of the digest are zero, so the last tree always opens its first leaf. That tree carries no authentication path, and the signer never builds it.',
    },
    { ...pick(forsParams, ['r'])[0], key: 'forsR', show: (s) => s.forsPlusC },
    ...pick(wotsParams, ['b']),
    {
      key: 'wotsPlusC', type: 'checkbox', default: false, group: OTS,
      label: 'WOTS+C',
      tooltip: 'The signer grinds a counter until the digits of the signed value sum to \\(S_{w,n}\\), which replaces the checksum chains. Each of the \\(d\\) OTS signatures carries its own counter.',
    },
    ...pick(wotsParams, ['z', 'S']).map((p) => ({ ...p, show: (s) => s.wotsPlusC })),
    { ...pick(wotsParams, ['r'])[0], key: 'wotsR', show: (s) => s.wotsPlusC },
  ],

  derive(state) {
    const { n, d, hp, k, a } = state;
    const h = d * hp;
    const ots = otsModel(state);
    const tree = merkleTree.model({ h: hp, n }, ots);
    const msg = messageHash.model(state, {
      digestBits: digestBits(state),
      counterBits: state.forsPlusC ? state.forsR : 0,
    });
    const f = fors.model({ ...state, plusC: state.forsPlusC, r: state.forsR }, msg.mgf1);

    // Signature (R, sigma_FORS, then sigma_OTS and AuthPath for each layer).
    const sizes = {
      sk: 4 * n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * n, // PK.seed and root
      R: msg.sizes.R,
      fors: f.sizes.sig,
      ots: d * ots.sizes.sig,
      authPath: d * tree.sizes.authPath,
    };
    sizes.ht = sizes.ots + sizes.authPath;
    sizes.sig = sizes.R + sizes.fors + sizes.ht;

    // Key generation builds the top-layer tree. The digest picks a different
    // path for every message, so signing builds the FORS trees and the d
    // hypertree trees on that path.
    const ops = {
      keygen: tree.keygen,
      sign: {
        prf: f.sign.prf + d * (tree.keygen.prf + ots.sign.prf),
        th: f.sign.th + d * (tree.keygen.th + ots.sign.th),
        compressions: msg.sign.compressions + f.sign.compressions
          + d * (tree.keygen.compressions + ots.sign.compressions),
      },
      verify: {
        th: f.verify.th + d * (ots.verify.th + tree.verify.th),
        compressions: msg.verify.compressions + f.verify.compressions
          + d * (ots.verify.compressions + tree.verify.compressions),
      },
    };

    return {
      h, k, leaves: 2 ** h, t: f.t, built: f.built, l: ots.l ?? ots.len, w: ots.w,
      wotsPlusC: state.wotsPlusC, forsPlusC: state.forsPlusC,
      wots: { p: ots.p, wcSearch: ots.wcSearch, exhaustLog2: ots.exhaustLog2 },
      fors: { p: f.p, wcSearch: f.wcSearch, exhaustLog2: f.exhaustLog2 },
      sizes, calls: ops, ...withMidstate(ops),
    };
  },

  results: [
    {
      heading: 'Tradeoff diagram',
      tradeoff,
      rows: [],
    },
    {
      heading: 'Hypertree',
      group: HT,
      rows: [
        { label: 'Total height (\\(h = d \\cdot h\'\\))', value: (d) => num(d.h) },
        { label: 'Bottom-layer leaves (\\(2^h\\))', value: (d) => approx(d.leaves) },
      ],
    },
    {
      heading: 'FORS',
      group: FORS,
      rows: [
        { label: 'Leaves per tree (\\(2^a\\))', value: (d) => approx(d.t) },
        {
          label: 'Trees with an authentication path',
          tooltip: 'All \\(k\\) trees for FORS. FORS+C leaves out the last tree, which always opens its first leaf.',
          value: (d) => num(d.built),
        },
      ],
    },
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.sizes.sk) },
        { label: 'Public key', value: (d) => bytes(d.sizes.pk) },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'The tuple \\((R, \\sigma_{\\mathrm{FORS}}, \\sigma_{\\mathrm{HT}})\\). The leaf index is derived from the digest, so it is not carried in the signature.',
      bar: true,
      rows: [
        sigPart('Randomness \\(R\\)', 'R'),
        sigPart('FORS signature (\\(\\sigma_{\\mathrm{FORS}}\\))', 'fors', FORS),
        sigPart('OTS signatures (\\(d \\times \\sigma_{\\mathrm{OTS}}\\))', 'ots', OTS),
        sigPart('\\(d \\times \\mathrm{AuthPath}\\)', 'authPath', HT),
        { label: 'Total', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Search',
      group: OTS,
      show: (d) => d.wotsPlusC,
      tooltip: 'The WOTS+C counter search, run for each of the \\(d\\) OTS signatures: on the FORS public key at the bottom layer and on a tree root at every other layer. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        { label: 'Success probability per trial (\\(p_\\nu\\))', value: (d) => probability(d.wots.p) },
        { label: 'WC search', value: (d) => approx(d.wots.wcSearch) },
        {
          label: 'Counter exhaustion probability',
          tooltip: 'Probability that none of the \\(2^r\\) counter values meets the conditions, \\((1 - p_\\nu)^{2^r}\\).',
          value: (d) => exhaustProbability(d.wots.exhaustLog2),
        },
      ],
    },
    {
      heading: 'Search',
      group: FORS,
      show: (d) => d.forsPlusC,
      tooltip: 'The FORS+C counter search on the message digest. Each trial recomputes the MGF1 part of \\(\\mathbf{H}_{\\mathbf{msg}}\\) with the counter and succeeds when the last \\(a\\) bits of the FORS part are zero, with probability \\(2^{-a}\\). WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        { label: 'Success probability per trial', value: (d) => probability(d.fors.p) },
        { label: 'WC search', value: (d) => approx(d.fors.wcSearch) },
        {
          label: 'Counter exhaustion probability',
          tooltip: 'Probability that none of the \\(2^r\\) counter values meets the condition, \\((1 - 2^{-a})^{2^r}\\).',
          value: (d) => exhaustProbability(d.fors.exhaustLog2),
        },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: `Key generation builds the top-layer tree. The digest selects a different leaf for every message, so signing builds the \\(k\\) FORS trees and the \\(d\\) hypertree trees on the path to that leaf. With WOTS, signing and verification are the worst case over all messages. ${messageHashNote} ${hashCallsNote}`,
      rows: [
        { label: 'Key generation', value: (d) => hashCalls(d.calls.keygen) },
        { label: 'Signing', value: (d) => hashCalls(d.calls.sign) },
        { label: 'Verification', value: (d) => hashCalls(d.calls.verify, num) },
      ],
    },
    // The SHA-256 compressions group, hidden for now.
    /*
    {
      heading: 'SHA-256 compressions',
      tooltip: `${messageCompressionsTooltip(' and a \\(ka + h\\) bit digest')} Signing includes the WC search of each counter that is in use.`,
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: 'Signing', value: (d) => approx(d.signCompressions) },
        { label: 'Verification', value: (d) => approx(d.verifyCompressions) },
      ],
    },
    */
    signatureBudget(
      {
        label: 'Secret FORS leaves revealed per signature',
        group: FORS,
        value: (d) => num(d.k),
      },
      {
        label: 'FORS key pairs (\\(2^h\\))',
        group: HT,
        tooltip: 'The message digest selects a bottom-layer leaf, and that leaf\'s FORS key pair signs the digest. The signer keeps no state, so two messages can select the same FORS key pair.',
        value: (d) => approx(d.leaves),
      },
    ),
    blockSpace,
  ],
};

export default scheme;

// Structure diagram: the d layers of the hypertree, with the FORS forest of
// the selected bottom-layer leaf drawn beneath it.
function sphincsSvg(hp, d, k, a, forsPlusC, otsLabel) {
  const W = 560;
  const g = svg();
  const leaf = drawHypertree(g, { hp, d, left: 90, right: W - 130, bx: W - 112, top: 30, otsLabel });
  const left = 40, right = W - 120;
  const pkX = (left + right) / 2;
  const busY = leaf.y + 62;
  const top = leaf.y + 104;

  // The selected leaf's OTS key signs the FORS public key. The connector runs
  // down, across, and into the node so that it crosses no label.
  g.line(leaf.x, leaf.y + 7, leaf.x, busY, 'ots-edge');
  g.line(leaf.x, busY, pkX, busY, 'ots-edge');
  g.line(pkX, busY, pkX, top - 7, 'ots-edge');
  g.text(leaf.x + 10, leaf.y + 28, `${otsLabel} key signs the`, 'start', 'label ots-label');
  g.text(leaf.x + 10, leaf.y + 42, 'FORS public key', 'start', 'label ots-label');

  const forest = drawForest(g, { k, a, plusC: forsPlusC, left, right, top, bx: W - 100, pkLabel: '' });
  g.text(pkX + 16, top + 4, 'FORS public key', 'start');
  g.text(pkX, forest.baseY + 84, 'FORS signs the message digest', 'middle', 'label ots-label');
  return { svg: g.toString(), width: W, height: forest.bottom + 20 };
}

// Visualization state, nested inside the scheme component.
export function sphincsDiagram() {
  return {
    get drawing() {
      const { hp, d, k, a, forsPlusC, wotsPlusC } = this.state;
      return sphincsSvg(hp, d, k, a, forsPlusC, wotsPlusC ? 'WOTS+C' : 'WOTS');
    },
  };
}
