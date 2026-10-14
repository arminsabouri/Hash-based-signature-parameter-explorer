import * as fors from '../primitives/fors.js';
import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wots from '../primitives/wots.js';
import { approx, bytes, num } from '../scheme.js';
import {
  blockSpace, hashCalls, hashCallsNote, messageCompressionsTooltip, messageHashNote,
  sigPart, signatureBudget, withMidstate,
} from '../common-results.js';
import { drawForest, drawHypertree, svg } from '../draw.js';
import { axisSpans, hashCallCount, tradeoffGroup } from '../tradeoff.js';

// SPHINCS+, the structure standardized as SLH-DSA in FIPS 205: a FORS key
// pair at every bottom-layer leaf of an XMSS^MT hypertree. The message digest
// selects the leaf, so the signer keeps no state. The OTS of the hypertree is
// WOTS, and the few-time signature is FORS.
// Defaults are the parameters of SLH-DSA-SHA2-128s.

const HT = 'Hypertree';
const OTS = 'OTS';
const FORS = 'FORS';

const pick = (params, keys) => keys.map((key) => params.find((p) => p.key === key));
const wotsParams = wots.parameters(OTS);
const forsParams = fors.parameters(FORS);

// FIPS 205 message digest: ka bits for the FORS indices, h - h' bits for the
// tree index, and h' bits for the leaf index, each padded to whole bytes.
const digestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * a) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// The tradeoff diagram. One series, since a SPHINCS+ signature has only the
// one shape. The axis endpoints are pinned; `test/tradeoff.test.js` checks
// them against a fresh walk of the parameter corners.
const SERIES = [{
  metrics: (d) => ({
    blockSpace: (d.sizes.sig + d.sizes.pk) / 8,
    signCalls: hashCallCount(d.calls.sign),
    verifyCalls: hashCallCount(d.calls.verify),
    keygenCalls: hashCallCount(d.calls.keygen),
    budget: d.leaves,
  }),
}];

// SPHINCS+ has no counter search, so no knob is held when the endpoints are
// worked out.
export const SEARCH_KEYS = [];

const AXIS_SPANS = [
  [8, 343136],
  [3.3858550252753835e-12, 0.012987012987012988],
  [0.0000036825223805297676, 0.0625],
  [1.0954219119121497e-10, 0.0196078431372549],
  [2, 4.562440617622195e+192],
];

export const spans = () => axisSpans(scheme, SERIES, SEARCH_KEYS);

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
    ...pick(wotsParams, ['b']),
  ],

  derive(state) {
    const { n, d, hp, k, a } = state;
    const h = d * hp;
    const ots = wots.model({ ...state, compressed: true });
    const tree = merkleTree.model({ h: hp, n }, ots);
    const msg = messageHash.model(state, { digestBits: digestBits(state) });
    const f = fors.model({ ...state, plusC: false }, msg.mgf1);

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
      h, k, leaves: 2 ** h, t: f.t, l: ots.len, w: ots.w,
      sizes, calls: ops, ...withMidstate(ops),
    };
  },

  results: [
    tradeoffGroup({ spans: AXIS_SPANS, series: SERIES, hold: ['n', ...SEARCH_KEYS] }),
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
      heading: 'Hash calls',
      tooltip: `Key generation builds the top-layer tree. The digest selects a different leaf for every message, so signing builds the \\(k\\) FORS trees and the \\(d\\) hypertree trees on the path to that leaf. Signing and verification are the worst case over all messages. ${messageHashNote} ${hashCallsNote}`,
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
      tooltip: `${messageCompressionsTooltip(' and a \\(ka + h\\) bit digest')}`,
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
function sphincsSvg(hp, d, k, a) {
  const W = 560;
  const g = svg();
  const leaf = drawHypertree(g, { hp, d, left: 90, right: W - 130, bx: W - 112, top: 30, otsLabel: 'WOTS' });
  const left = 40, right = W - 120;
  const pkX = (left + right) / 2;
  const busY = leaf.y + 62;
  const top = leaf.y + 104;

  // The selected leaf's OTS key signs the FORS public key. The connector runs
  // down, across, and into the node so that it crosses no label.
  g.line(leaf.x, leaf.y + 7, leaf.x, busY, 'ots-edge');
  g.line(leaf.x, busY, pkX, busY, 'ots-edge');
  g.line(pkX, busY, pkX, top - 7, 'ots-edge');
  g.text(leaf.x + 10, leaf.y + 28, 'WOTS key signs the', 'start', 'label ots-label');
  g.text(leaf.x + 10, leaf.y + 42, 'FORS public key', 'start', 'label ots-label');

  const forest = drawForest(g, { k, a, plusC: false, left, right, top, bx: W - 100, pkLabel: '' });
  g.text(pkX + 16, top + 4, 'FORS public key', 'start');
  g.text(pkX, forest.baseY + 84, 'FORS signs the message digest', 'middle', 'label ots-label');
  return { svg: g.toString(), width: W, height: forest.bottom + 20 };
}

// Visualization state, nested inside the scheme component.
export function sphincsDiagram() {
  return {
    get drawing() {
      const { hp, d, k, a } = this.state;
      return sphincsSvg(hp, d, k, a);
    },
  };
}
