import * as fors from '../primitives/fors.js';
import * as merkleTree from '../primitives/merkle-tree.js';
import * as wotsC from '../primitives/wots-c.js';
import * as wotsTw from '../primitives/wots-tw.js';
import { compressions } from '../sha256.js';
import { approx, bytes, num } from '../scheme.js';
import { blockSpace, hashCalls, hashCallsNote, withMidstate } from '../common-results.js';
import { drawForest, drawHypertree, drawTree, annotateTree, bracket, svg } from '../draw.js';

// SHRINCS, which combines a stateful component (an FXMSS tree of WOTS+C
// leaves) with a stateless one (SLH-DSA with a non-standard parameter set).
// A signature from either component passes verification. Defaults are the
// parameter values given in the SHRINCS specification.

const SF = 'Stateful';
const SL = 'Stateless';

const MAX_DEPTH = { UXMSS: 255, BXMSS: 64 };

const pick = (params, keys) => keys.map((key) => params.find((p) => p.key === key));
const wotsCParams = wotsC.parameters(SF);
const forsParams = fors.parameters(SL);

// The indicator byte tells the verifier which component produced the signature.
const INDICATOR = 8;

// H_msg_sf: sha256(R || pk_seed || sha256(R || pk_seed || sf_root || ADRS[:9] || M) || ADRS[:9]).
const statefulDigest = (nb) => compressions(3 * nb + 9 + 32) + compressions(2 * nb + 32 + 9);
// H_msg_sl: the inner hash, then MGF1-SHA-256 blocks over R || pk_seed || inner.
const statelessDigest = (nb, digestBits) =>
  compressions(3 * nb + 32) + Math.ceil(digestBits / 256) * compressions(2 * nb + 32 + 4);
// PRF_msg_sf and PRF_msg_sl, both HMAC-SHA-256 over a 32-byte message.
const statefulPrfMsg = (nb) => compressions(64 + nb + 9 + 32) + compressions(64 + 32);
const statelessPrfMsg = (nb) => compressions(64 + nb + 32) + compressions(64 + 32);

// FIPS 205 message digest: ka bits of FORS indices, h - h' of tree index and
// h' of leaf index, each padded to whole bytes.
const digestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * a) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// The stateful component: an FXMSS tree of WOTS+C leaves. Sizes and
// verification are for the deepest leaf.
function stateful(state) {
  const { n, depth, shape } = state;
  const ots = wotsC.model({ n, b: state.sfB, z: state.sfZ, S: state.sfS, r: state.sfR, compressed: true });
  const tree = shape === 'UXMSS'
    ? merkleTree.unbalancedModel({ depth, n }, ots)
    : merkleTree.model({ h: depth, n }, ots);
  const msgVerify = statefulDigest(n / 8);
  const msgSign = msgVerify + statefulPrfMsg(n / 8);

  const sizes = {
    index: 8 * Math.ceil(Math.ceil(Math.log2(tree.leaves)) / 8),
    R: n,
    counter: state.sfR,
    chains: ots.l * n,
    authPath: tree.sizes.authPath,
  };
  sizes.sig = INDICATOR + sizes.R + sizes.index + sizes.counter + sizes.chains + sizes.authPath;

  const signCached = {
    prf: ots.sign.prf, th: ots.sign.th, compressions: msgSign + ots.sign.compressions,
  };
  const ops = {
    keygen: tree.keygen,
    sign: {
      prf: tree.keygen.prf + signCached.prf,
      th: tree.keygen.th + signCached.th,
      compressions: tree.keygen.compressions + signCached.compressions,
    },
    signCached,
    verify: {
      prf: 0,
      th: ots.verify.th + tree.verify.th,
      compressions: msgVerify + ots.verify.compressions + tree.verify.compressions,
    },
  };
  return { leaves: tree.leaves, l: ots.l, w: ots.w, p: ots.p, wcSearch: ots.wcSearch, sizes, ...ops };
}

// The stateless component: SLH-DSA, a FORS key pair under every bottom-layer
// leaf of a hypertree of d layers of height h'.
function stateless(state) {
  const { n, d, hp } = state;
  const ots = wotsTw.model({ n, b: state.slB, compressed: true });
  const tree = merkleTree.model({ h: hp, n }, ots);
  const f = fors.model({ ...state, plusC: false }, 0);
  const msgVerify = statelessDigest(n / 8, digestBits(state));
  const msgSign = msgVerify + statelessPrfMsg(n / 8);

  const sizes = { R: n, fors: f.sizes.sig, ht: d * (ots.sizes.sig + tree.sizes.authPath) };
  sizes.sig = INDICATOR + sizes.R + sizes.fors + sizes.ht;

  const ops = {
    keygen: tree.keygen,
    sign: {
      prf: f.sign.prf + d * (tree.keygen.prf + ots.sign.prf),
      th: f.sign.th + d * (tree.keygen.th + ots.sign.th),
      compressions: msgSign + f.sign.compressions
        + d * (tree.keygen.compressions + ots.sign.compressions),
    },
    verify: {
      prf: 0,
      th: f.verify.th + d * (ots.verify.th + tree.verify.th),
      compressions: msgVerify + f.verify.compressions
        + d * (ots.verify.compressions + tree.verify.compressions),
    },
  };
  return { leaves: 2 ** (d * hp), h: d * hp, t: f.t, k: state.k, sizes, ...ops };
}

const dash = () => '—';

export default {
  id: 'shrincs',
  title: 'SHRINCS',
  columns: [SF, SL],
  groups: { [SF]: 'var(--c-0a9396)', [SL]: 'var(--c-ca6702)' },

  parameters: [
    { ...pick(wotsCParams, ['n'])[0], group: undefined },
    {
      key: 'shape', type: 'select', options: ['UXMSS', 'BXMSS'], default: 'UXMSS', group: SF,
      label: 'Shape',
      tooltip: 'UXMSS places one leaf at each depth from 1 to \\(\\mathrm{depth}\\), plus a second leaf at the deepest level, so signatures grow by one node each. BXMSS places all \\(2^{\\mathrm{depth}}\\) leaves at the same depth, so every signature has the same size.',
    },
    {
      key: 'depth', type: 'range', min: 1, max: (s) => MAX_DEPTH[s.shape], step: 1, group: SF,
      default: (s) => (s.shape === 'UXMSS' ? 255 : 8), resetOn: ['shape'],
      label: 'Depth',
      tooltip: 'Distance from the root to the deepest leaf. SHRINCS sets the maximum depth of a WOTS+C leaf to 255 and encodes the shape and depth in the secret key.',
    },
    { ...pick(wotsCParams, ['b'])[0], key: 'sfB' },
    { ...pick(wotsCParams, ['z'])[0], key: 'sfZ', max: (s) => Math.min(8, Math.ceil(s.n / s.sfB) - 1) },
    {
      ...pick(wotsCParams, ['S'])[0], key: 'sfS', resetOn: ['n', 'sfB', 'sfZ'],
      max: (s) => (Math.ceil(s.n / s.sfB) - s.sfZ) * (2 ** s.sfB - 1),
      default: (s) => Math.ceil(((Math.ceil(s.n / s.sfB) - s.sfZ) * (2 ** s.sfB - 1)) / 2),
    },
    {
      ...pick(wotsCParams, ['r'])[0], key: 'sfR', min: 8, max: 64, step: 8, default: 16,
      tooltip: 'Size of the WOTS+C counter carried in the signature. SHRINCS uses 16 bits.',
    },
    { ...pick(wotsCParams, ['b'])[0], key: 'slB', group: SL },
    {
      key: 'd', type: 'range', min: 1, max: 32, step: 1, default: 5, group: SL,
      label: '\\(d\\) (number of layers)',
      tooltip: 'The hypertree has total height \\(h = d \\cdot h\'\\). Each layer adds one WOTS-TW signature and one authentication path to the stateless signature.',
    },
    {
      key: 'hp', type: 'range', min: 1, max: 20, step: 1, default: 9, group: SL,
      label: '\\(h\'\\) (height of each XMSS tree)',
      tooltip: 'Each tree of the hypertree has \\(2^{h\'}\\) WOTS-TW leaves. Key generation builds the top-layer tree.',
    },
    { ...pick(forsParams, ['a'])[0], default: 13 },
    { ...pick(forsParams, ['k'])[0], default: 10 },
  ],

  derive(state) {
    const sf = stateful(state);
    const sl = stateless(state);
    // Key generation builds both components.
    const keygen = {
      prf: sf.keygen.prf + sl.keygen.prf,
      th: sf.keygen.th + sl.keygen.th,
      compressions: sf.keygen.compressions + sl.keygen.compressions,
    };
    return {
      sf, sl, keygen,
      // sk_seed, sk_prf, pk_seed, sl_root, the 2-byte tree structure, sf_root.
      sizes: { sk: 5 * state.n + 16, pk: 3 * state.n },
      ...withMidstate({ keygen, sign: sf.sign, verify: sf.verify }),
      keygenBoth: keygen.compressions + 1,
    };
  },

  results: [
    {
      rows: [
        {
          label: 'Secret key',
          tooltip: '\\(\\mathrm{sk\\_seed} \\,\\|\\, \\mathrm{sk\\_prf} \\,\\|\\, \\mathrm{pk\\_seed} \\,\\|\\, \\mathrm{sl\\_root} \\,\\|\\, \\mathrm{sf\\_structure} \\,\\|\\, \\mathrm{sf\\_root}\\), where \\(\\mathrm{sf\\_structure}\\) is the shape byte and the depth byte. It is generated from a 48-byte seed.',
          value: (d) => bytes(d.sizes.sk),
        },
        {
          label: 'Public key',
          tooltip: '\\(\\mathrm{pk\\_seed} \\,\\|\\, \\mathrm{sl\\_root} \\,\\|\\, \\mathrm{sf\\_root}\\). A stateful signature is checked against \\(\\mathrm{sf\\_root}\\), a stateless one against \\(\\mathrm{sl\\_root}\\).',
          value: (d) => bytes(d.sizes.pk),
        },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'Both signatures start with the indicator byte, which tells the verifier which component signed. The stateful figures are for a leaf at the full depth, which has the longest authentication path.',
      rows: [
        { label: 'Indicator byte', values: [(d) => bytes(INDICATOR), (d) => bytes(INDICATOR)] },
        { label: 'Randomness \\(R\\)', values: [(d) => bytes(d.sf.sizes.R), (d) => bytes(d.sl.sizes.R)] },
        { label: 'Leaf index', values: [(d) => bytes(d.sf.sizes.index), dash] },
        { label: 'WOTS+C counter', values: [(d) => bytes(d.sf.sizes.counter), dash] },
        { label: 'WOTS+C chains', values: [(d) => bytes(d.sf.sizes.chains), dash] },
        { label: '\\(\\mathrm{AuthPath}\\)', values: [(d) => bytes(d.sf.sizes.authPath), dash] },
        { label: 'FORS signature', values: [dash, (d) => bytes(d.sl.sizes.fors)] },
        { label: 'Hypertree signature', values: [dash, (d) => bytes(d.sl.sizes.ht)] },
        { label: 'Total', values: [(d) => bytes(d.sf.sizes.sig), (d) => bytes(d.sl.sizes.sig)] },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: `Key generation builds both components, so its cost is shared. Stateful signing without a cache rebuilds the FXMSS tree; stateless signing builds the FORS trees and the \\(d\\) hypertree trees on the path. Verification is for the deepest stateful leaf and, on the stateless path, the worst case over all messages. ${hashCallsNote}`,
      rows: [
        { label: 'Key generation', values: [(d) => hashCalls(d.sf.keygen), (d) => hashCalls(d.sl.keygen)] },
        { label: 'Key generation (both components)', value: (d) => hashCalls(d.keygen) },
        {
          label: 'Signing',
          values: [(d) => hashCalls(d.sf.sign), (d) => hashCalls(d.sl.sign)],
        },
        {
          label: 'Signing (cached tree)',
          values: [(d) => hashCalls(d.sf.signCached, num), dash],
        },
        { label: 'Verification', values: [(d) => hashCalls(d.sf.verify, num), (d) => hashCalls(d.sl.verify, num)] },
      ],
    },
    {
      heading: 'Signature budget',
      rows: [
        {
          label: 'Signatures per key pair',
          tooltip: 'One per FXMSS leaf: \\(\\mathrm{depth} + 1\\) for UXMSS and \\(2^{\\mathrm{depth}}\\) for BXMSS. The stateless component keeps no state, so the digest selects its leaf.',
          values: [(d) => approx(d.sf.leaves), dash],
        },
        {
          label: 'State counter',
          tooltip: 'The signer stores the number of stateful signatures issued and increments it before releasing each one. SHRINCS requires that it never decrements and is never restored from a backup.',
          values: [(d) => `${num(Math.ceil(Math.log2(d.sf.leaves)) || 1)} bits`, dash],
        },
        {
          label: 'Hypertree leaves (\\(2^h\\))',
          tooltip: 'Each bottom-layer leaf of the hypertree carries one FORS key pair, selected by the message digest.',
          values: [dash, (d) => approx(d.sl.leaves)],
        },
      ],
    },
    {
      ...blockSpace,
      rows: [
        {
          ...blockSpace.rows[0],
          values: [
            (d) => num(Math.floor(4000000 / ((d.sf.sizes.sig + d.sizes.pk) / 8))),
            (d) => num(Math.floor(4000000 / ((d.sl.sizes.sig + d.sizes.pk) / 8))),
          ],
        },
      ],
    },
  ],
};

// Structure diagram: the two components stacked, each under its own root, with
// a bracket down the left spanning both to show that either one verifies.
function shrincsSvg(state) {
  const W = 620;
  const g = svg();
  const { shape, depth, d, hp, k, a } = state;

  g.text(W / 2, 20, 'SHRINCS public key = pk_seed || sl_root || sf_root');

  // Stateful component.
  const sfTop = 76;
  let sfBottom, rootX;
  if (shape === 'UXMSS') {
    const spine = drawSpine(g, depth, sfTop);
    sfBottom = spine.bottom;
    rootX = spine.rootX;
  } else {
    const tree = drawTree(g, { h: depth, left: 80, right: W - 150, top: sfTop, level: 30 });
    annotateTree(g, tree, W - 130, [`depth = ${depth}`]);
    sfBottom = tree.leafY + 30;
    rootX = tree.rootX;
  }
  g.text(rootX, sfTop - 14, 'sf_root');
  g.text(80, sfBottom + 4, 'leaves are WOTS+C public keys', 'start', 'label ots-label');

  // Stateless component.
  const slTop = sfBottom + 54;
  const leaf = drawHypertree(g, {
    hp, d, left: 120, right: W - 160, bx: W - 142, top: slTop, otsLabel: 'WOTS-TW', rootLabel: 'sl_root',
  });
  const forestTop = leaf.y + 96;
  const left = 70, right = W - 150;
  const pkX = (left + right) / 2;
  g.line(leaf.x, leaf.y + 7, leaf.x, leaf.y + 56, 'ots-edge');
  g.line(leaf.x, leaf.y + 56, pkX, leaf.y + 56, 'ots-edge');
  g.line(pkX, leaf.y + 56, pkX, forestTop - 7, 'ots-edge');
  g.text(leaf.x + 10, leaf.y + 30, 'WOTS-TW key signs the FORS public key', 'start', 'label ots-label');
  const forest = drawForest(g, {
    k, a, plusC: false, left, right, top: forestTop, bx: W - 130, pkLabel: '',
  });
  g.text(pkX + 16, forestTop + 4, 'FORS public key', 'start');

  bracket(g, 40, 60, forest.baseY, ['either root', 'verifies']);
  return { svg: g.toString(), width: W, height: forest.bottom + 10 };
}

// The left spine of a UXMSS tree, with a leaf to the right at each depth.
// Leaves between the fifth and the deepest are elided.
function drawSpine(g, depth, top) {
  const dx = 26, dy = 30, rootX = 300, size = 12;
  const rows = depth > 6 ? [0, 1, 2, 3, null, depth - 1] : [...Array(depth).keys()];
  const X = (r) => rootX - r * dx;
  const Y = (r) => top + r * dy;

  rows.forEach((kRow, r) => {
    const x = X(r), y = Y(r);
    if (kRow === null) {
      g.text(x, y + 4, '⋮', 'middle');
      return;
    }
    const last = r === rows.length - 1;
    if (!last && rows[r + 1] !== null) g.line(x, y, X(r + 1), Y(r + 1));
    if (!last && rows[r + 1] === null) g.line(x, y, X(r + 1) + 6, Y(r + 1) - 10);
    if (r > 0 && rows[r - 1] === null) g.line(X(r - 1) + 6, Y(r - 1) + 10, x, y);
    g.line(x, y, x + dx, y + dy);
    g.rect(x + dx - size / 2, y + dy - size / 2, size, size, 'ots-node');
  });
  for (const r of rows.keys()) if (rows[r] !== null) g.circle(X(r), Y(r), 7, 'tree-node');
  const leafY = Y(rows.length);
  g.rect(X(rows.length) - size / 2, leafY - size / 2, size, size, 'ots-node');
  bracket(g, rootX + 30, top, leafY, [`depth = ${depth}`]);
  return { bottom: leafY + 20, rootX };
}

// Visualization state, nested inside the scheme component.
export function shrincsDiagram() {
  return {
    get drawing() {
      return shrincsSvg(this.state);
    },
  };
}
