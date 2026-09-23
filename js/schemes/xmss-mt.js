import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wotsC from '../primitives/wots-c.js';
import { bytes } from '../scheme.js';
import {
  OTS, TREE, blockSpace, otsSearch, treeBudget, treeCosts, treeGroups, treeKeys, withMidstate,
} from '../common-results.js';
import { drawHypertree, drawLeafChains, svg } from '../draw.js';

// XMSS^MT with WOTS+C leaves, Section 8 of Kudinov and Nick, "Hash-based
// Signature Schemes for Bitcoin". A hypertree of d layers of XMSS trees of
// height h', total height h = d * h'.

export default {
  id: 'xmss-mt',
  title: 'XMSS<sup>MT</sup> + WOTS+C',

  groups: treeGroups,

  parameters: [
    {
      key: 'hp', type: 'range', min: 1, max: 20, step: 1, default: 10, group: TREE,
      ticks: [4, 8, 16],
      label: '\\(h\'\\) (height of each XMSS tree)',
      tooltip: 'Each tree has \\(2^{h\'}\\) WOTS+C leaves. Key generation builds one tree, signing without a cache builds \\(d\\) trees, and each layer adds \\(h\'\\) nodes to the signature.',
    },
    {
      key: 'd', type: 'range', min: 1, max: 16, step: 1, default: 2, group: TREE,
      label: '\\(d\\) (number of layers)',
      tooltip: 'The hypertree has total height \\(h = d \\cdot h\'\\) and \\(2^h\\) bottom-layer leaves. Each layer adds one WOTS+C signature and one authentication path to the signature.',
    },
    ...wotsC.parameters(OTS),
  ],

  derive(state) {
    const { d, hp } = state;
    const h = d * hp;
    const ots = wotsC.model({ ...state, compressed: true });
    const tree = merkleTree.model({ h: hp, n: state.n }, ots);
    const msg = messageHash.model(state);

    // Signature (i, R, then sigma_OTS and AuthPath for each of the d layers).
    const sizes = {
      sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * state.n, // PK.seed and root
      // The d trees on the current path and the d - 1 upper-layer WOTS+C
      // signatures on their roots.
      cache: d * tree.sizes.cache + (d - 1) * ots.sizes.sig,
      index: 8 * Math.ceil(h / 8),
      R: msg.sizes.R,
      ots: d * ots.sizes.sig,
      authPath: d * tree.sizes.authPath,
    };
    sizes.sig = sizes.index + sizes.R + sizes.ots + sizes.authPath;

    // Without a cache, signing builds the d trees on the path and signs the
    // message and the d - 1 lower roots. With the trees and upper signatures
    // cached, it signs the message alone.
    const signCached = {
      prf: ots.sign.prf,
      th: ots.sign.th,
      compressions: msg.sign.compressions + ots.sign.compressions,
    };
    const ops = {
      keygen: tree.keygen,
      sign: {
        prf: d * (tree.keygen.prf + ots.sign.prf),
        th: d * (tree.keygen.th + ots.sign.th),
        compressions: msg.sign.compressions + d * (tree.keygen.compressions + ots.sign.compressions),
      },
      signCached,
      verify: {
        th: d * (ots.verify.th + tree.verify.th),
        compressions: msg.verify.compressions + d * (ots.verify.compressions + tree.verify.compressions),
      },
    };
    return {
      p: ots.p, wcSearch: ots.wcSearch, leaves: 2 ** h, l: ots.l, w: ots.w,
      sizes, calls: ops, ...withMidstate(ops),
    };
  },

  results: [
    treeKeys('The \\(d\\) trees on the path to the current leaf, \\(2^{h\'+1} - 1\\) nodes each, and the \\(d - 1\\) WOTS+C signatures on their roots. A signer that keeps them signs with the bottom-layer WOTS+C key alone.'),
    {
      heading: 'Signature',
      tooltip: 'The leaf index \\(i\\), the message randomness \\(R\\), and for each of the \\(d\\) layers a WOTS+C signature with its counter and the \\(h\'\\) sibling nodes of its authentication path.',
      rows: [
        { label: 'Leaf index \\(i\\)', group: TREE, value: (d) => bytes(d.sizes.index) },
        { label: 'Randomness \\(R\\)', value: (d) => bytes(d.sizes.R) },
        { label: 'WOTS+C signatures (\\(d \\times \\sigma_{\\mathrm{OTS}}\\))', group: OTS, value: (d) => bytes(d.sizes.ots) },
        { label: '\\(d \\times \\mathrm{AuthPath}\\)', group: TREE, value: (d) => bytes(d.sizes.authPath) },
        { label: 'Total', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    otsSearch('The WOTS+C counter search, run for each WOTS+C signature: on the message digest at the bottom layer and on a tree root at every other layer. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).'),
    ...treeCosts('Key generation builds the top-layer tree. Without a cache, signing builds the \\(d\\) trees on the path and computes \\(d\\) WOTS+C signatures. With the trees and upper-layer signatures cached, signing is the bottom-layer WOTS+C signature alone.', 'trees'),
    treeBudget(
      'One per bottom-layer leaf, \\(2^h\\) with \\(h = d \\cdot h\'\\). Reusing a leaf for a second message breaks the security of its WOTS+C key.',
      'The signer stores the index of the next unused bottom-layer leaf and increments it before releasing each signature. SHRINCS requires that it never decrements and is never restored from a backup.',
    ),
    blockSpace,
  ],
};

// Structure diagram: the d layers of the hypertree, with a bottom-layer leaf
// opened up into its chains to sign the message digest.
function hypertreeSvg(hp, d, l, w) {
  const W = 560;
  const g = svg();
  const from = drawHypertree(g, { hp, d, left: 90, right: W - 130, bx: W - 112, top: 30, otsLabel: 'WOTS+C' });
  const leaf = drawLeafChains(g, { leafX: from.x, leafY: from.y, l, w, notes: ['signs the message digest'], compact: true });
  return { svg: g.toString(), width: W, height: leaf.bottom };
}

// Visualization state, nested inside the scheme component.
export function xmssMtTree() {
  return {
    get drawing() {
      const { l, w } = this.derived;
      return hypertreeSvg(this.state.hp, this.state.d, l, w);
    },
  };
}
