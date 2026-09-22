import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wotsC from '../primitives/wots-c.js';
import { approx, bytes, num } from '../scheme.js';
import { blockSpace, signatureBudget, successProbability, wcSearch } from '../common-results.js';
import { drawLeafChains, drawTree, svg } from '../draw.js';

// XMSS^MT with WOTS+C leaves, Section 8 of Kudinov and Nick, "Hash-based
// Signature Schemes for Bitcoin". A hypertree of d layers of XMSS trees of
// height h', total height h = d * h'.

export default {
  id: 'xmss-mt',
  title: 'XMSS<sup>MT</sup> + WOTS+C',

  // Colors for the parameter groups.
  groups: {
    'Tree': 'var(--c-0a9396)',
    'OTS (WOTS+C)': 'var(--c-ca6702)',
  },

  parameters: [
    {
      key: 'hp', type: 'range', min: 1, max: 20, step: 1, default: 10, group: 'Tree',
      ticks: [4, 8, 16],
      label: '\\(h\'\\) (height of each XMSS tree)',
      tooltip: 'Each tree has \\(2^{h\'}\\) WOTS+C leaves. Key generation builds one tree, signing without a cache builds \\(d\\) trees, and each layer adds \\(h\'\\) nodes to the signature.',
    },
    {
      key: 'd', type: 'range', min: 1, max: 16, step: 1, default: 2, group: 'Tree',
      label: '\\(d\\) (number of layers)',
      tooltip: 'The hypertree has total height \\(h = d \\cdot h\'\\) and \\(2^h\\) bottom-layer leaves. Each layer adds one WOTS+C signature and one authentication path to the signature.',
    },
    ...wotsC.parameters('OTS (WOTS+C)'),
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
    // message and the d - 1 lower roots. Each operation also computes the
    // cached PK.seed midstate once.
    const layerCompressions = tree.keygen.compressions + ots.sign.compressions;
    return {
      h, p: ots.p, wcSearch: ots.wcSearch, leaves: 2 ** h,
      sizes,
      treePrf: tree.keygen.prf, treeTh: tree.keygen.th,
      signPrf: d * (tree.keygen.prf + ots.sign.prf), signTh: d * (tree.keygen.th + ots.sign.th),
      signCachedPrf: ots.sign.prf, signCachedTh: ots.sign.th,
      verifyTh: d * (ots.verify.th + tree.verify.th),
      keygenCompressions: tree.keygen.compressions + 1,
      signCompressions: msg.sign.compressions + d * layerCompressions + 1,
      signCachedCompressions: msg.sign.compressions + ots.sign.compressions + 1,
      verifyCompressions: msg.verify.compressions + d * (ots.verify.compressions + tree.verify.compressions) + 1,
    };
  },

  results: [
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.sizes.sk) },
        { label: 'Public key', group: 'Tree', value: (d) => bytes(d.sizes.pk) },
        {
          label: 'Tree cache',
          group: 'Tree',
          tooltip: 'The \\(d\\) trees on the path to the current leaf, \\(2^{h\'+1} - 1\\) nodes each, and the \\(d - 1\\) WOTS+C signatures on their roots. A signer that keeps them signs with the bottom-layer WOTS+C key alone.',
          value: (d) => bytes(d.sizes.cache),
        },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'The leaf index \\(i\\), the message randomness \\(R\\), and for each of the \\(d\\) layers a WOTS+C signature with its counter and the \\(h\'\\) sibling nodes of its authentication path.',
      rows: [
        { label: 'Leaf index \\(i\\)', group: 'Tree', value: (d) => bytes(d.sizes.index) },
        { label: 'Randomness \\(R\\)', value: (d) => bytes(d.sizes.R) },
        { label: 'WOTS+C signatures (\\(d \\times \\sigma_{\\mathrm{OTS}}\\))', group: 'OTS (WOTS+C)', value: (d) => bytes(d.sizes.ots) },
        { label: '\\(d \\times \\mathrm{AuthPath}\\)', group: 'Tree', value: (d) => bytes(d.sizes.authPath) },
        { label: 'Total', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Search',
      group: 'OTS (WOTS+C)',
      tooltip: 'The WOTS+C counter search, run for each WOTS+C signature: on the message digest at the bottom layer and on a tree root at every other layer. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        successProbability,
        wcSearch,
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation builds the top-layer tree. Without a cache, signing builds the \\(d\\) trees on the path and computes \\(d\\) WOTS+C signatures. With the trees and upper-layer signatures cached, signing is the bottom-layer WOTS+C signature alone. Signing also computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\); verification computes \\(\\mathbf{H}_{\\mathbf{msg}}\\).',
      rows: [
        { label: 'Key generation', value: (d) => `${approx(d.treePrf)} \\(\\mathbf{PRF}\\) + ${approx(d.treeTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (no cache, WC search)', value: (d) => `${approx(d.signPrf)} \\(\\mathbf{PRF}\\) + ${approx(d.signTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (cached trees, WC search)', value: (d) => `${num(d.signCachedPrf)} \\(\\mathbf{PRF}\\) + ${approx(d.signCachedTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification', value: (d) => `${num(d.verifyTh)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. \\(\\mathrm{Th}\\) and \\(\\mathbf{PRF}\\) follow FIPS 205 with a cached \\(\\mathrm{PK.seed}\\) block, adding one compression per operation. \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\) follow FIPS 205 for a 32-byte message.',
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: 'Signing (no cache, WC search)', value: (d) => approx(d.signCompressions) },
        { label: 'Signing (cached trees, WC search)', value: (d) => approx(d.signCachedCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    {
      ...signatureBudget(
        {
          label: 'Signatures per key pair',
          tooltip: 'One per bottom-layer leaf, \\(2^h\\) with \\(h = d \\cdot h\'\\). Reusing a leaf for a second message breaks the security of its WOTS+C key.',
          value: (d) => approx(d.leaves),
        },
        {
          label: 'State counter',
          tooltip: 'The signer stores the index of the next unused bottom-layer leaf and increments it before releasing each signature. SHRINCS requires that it never decrements and is never restored from a backup.',
          value: (d) => `${num(d.h)} bits`,
        },
      ),
      group: 'Tree',
    },
    blockSpace,
  ],
};

// Structure diagram: the d layers stacked with the top layer first. A WOTS+C
// leaf of each tree signs the root of the tree below it, and a bottom-layer
// leaf, opened up into its chains, signs the message digest. Layers between the top and bottom are
// elided when d > 3.
function hypertreeSvg(hp, d, l, w) {
  const W = 560;
  const left = 90, right = W - 130, bx = W - 112;
  const g = svg();
  const layers = d <= 3 ? [...Array(d).keys()].reverse() : [d - 1, null, 0];
  const gap = 56;
  let top = 30;
  let from = null; // leaf position of the layer above

  const connect = (x, y) => {
    g.line(from.x, from.y + 7, x, y, 'ots-edge');
  };

  g.text((left + right) / 2, top - 14, 'Public key (root)');
  for (const layer of layers) {
    if (layer === null) {
      const y = top + 8;
      connect((left + right) / 2, y - 12);
      g.text((left + right) / 2, y + 4, `⋮  layers ${d - 2} to 1`);
      from = { x: (left + right) / 2, y: y + 6 };
      top += gap;
      continue;
    }
    if (from) {
      connect((left + right) / 2, top - 8);
      g.text((left + right) / 2 + 14, top - gap / 2 + 4, 'WOTS+C key signs this root', 'start', 'label ots-label');
    }
    const tree = drawTree(g, { h: hp, left, right, top, level: 30 });
    g.text(left - 16, (tree.rootY + tree.leafY) / 2 + 4, `layer ${layer}`, 'end');

    g.line(bx, tree.rootY, bx, tree.leafY, 'bracket');
    g.line(bx - 4, tree.rootY, bx, tree.rootY, 'bracket');
    g.line(bx - 4, tree.leafY, bx, tree.leafY, 'bracket');
    g.text(bx + 8, (tree.rootY + tree.leafY) / 2 + 4, `h' = ${hp}`, 'start');
    g.text(bx + 8, tree.leafY + 4, `${tree.leafCount.toLocaleString()} leaves`, 'start', 'label ots-label');

    from = { x: tree.slotX(0), y: tree.leafY };
    top = tree.leafY + gap;
  }

  // A bottom-layer leaf opened up into its chains. It signs the message digest.
  const leaf = drawLeafChains(g, { leafX: from.x, leafY: from.y, l, w, notes: ['signs the message digest'], compact: true });

  return { svg: g.toString(), width: W, height: leaf.bottom };
}

// Visualization state, nested inside the scheme component.
export function xmssMtTree() {
  return {
    get drawing() {
      const { l, w } = wotsC.model({ ...this.state, compressed: true });
      return hypertreeSvg(this.state.hp, this.state.d, l, w);
    },
  };
}
