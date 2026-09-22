import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wotsC from '../primitives/wots-c.js';
import { approx, bytes, num } from '../scheme.js';
import { blockSpace, signatureBudget, successProbability, wcSearch } from '../common-results.js';
import { drawLeafChains, drawTree, svg } from '../draw.js';

// FXMSS with WOTS+C leaves, the stateful component of SHRINCS. The tree
// structure is a shape, UXMSS (unbalanced, left-leaning) or BXMSS (balanced),
// and a depth: the distance from the root to the deepest leaf.

const MAX_DEPTH = { UXMSS: 255, BXMSS: 64 };

export default {
  id: 'fxmss',
  title: 'FXMSS + WOTS+C',

  // Colors for the parameter groups.
  groups: {
    'Tree': 'var(--c-0a9396)',
    'OTS (WOTS+C)': 'var(--c-ca6702)',
  },

  parameters: [
    {
      key: 'shape', type: 'select', options: ['UXMSS', 'BXMSS'], default: 'UXMSS', group: 'Tree',
      label: 'Shape',
      tooltip: 'UXMSS places one leaf at each depth from 1 to \\(\\mathrm{depth}\\), plus a second leaf at the deepest level, so signatures grow by one node each. BXMSS places all \\(2^{\\mathrm{depth}}\\) leaves at the same depth, so every signature has the same size.',
    },
    {
      key: 'depth', type: 'range', min: 1, max: (s) => MAX_DEPTH[s.shape], step: 1, group: 'Tree',
      default: (s) => (s.shape === 'UXMSS' ? 255 : 8), resetOn: ['shape'],
      label: 'Depth',
      tooltip: 'Distance from the root to the deepest leaf. SHRINCS encodes it in one byte, up to 255, and leaf indexes in 64 bits.',
    },
    ...wotsC.parameters('OTS (WOTS+C)'),
  ],

  derive(state) {
    const { depth, shape } = state;
    const ots = wotsC.model({ ...state, compressed: true });
    const tree = shape === 'UXMSS'
      ? merkleTree.unbalancedModel({ depth, n: state.n }, ots)
      : merkleTree.model({ h: depth, n: state.n }, ots);
    const msg = messageHash.model(state);

    // Signature (i, R, sigma_OTS, AuthPath_i) for the deepest leaf.
    const sizes = {
      sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * state.n, // PK.seed and root
      cache: tree.sizes.cache,
      // Enough bytes to number every leaf, ceil(depth / 8) for BXMSS.
      index: 8 * Math.ceil(Math.ceil(Math.log2(tree.leaves)) / 8),
      R: msg.sizes.R,
      ots: ots.sizes.sig,
      authPath: tree.sizes.authPath,
    };
    sizes.sig = sizes.index + sizes.R + sizes.ots + sizes.authPath;
    // Signature size for a leaf at a given depth.
    const sigAt = (leafDepth) => sizes.index + sizes.R + sizes.ots + leafDepth * state.n;

    // Each operation also computes the cached PK.seed midstate once.
    const otsSign = msg.sign.compressions + ots.sign.compressions;
    return {
      p: ots.p, wcSearch: ots.wcSearch, leaves: tree.leaves,
      sizes, sigAt,
      treePrf: tree.keygen.prf, treeTh: tree.keygen.th,
      signPrf: ots.sign.prf, signTh: ots.sign.th,
      verifyTh: ots.verify.th + tree.verify.th,
      keygenCompressions: tree.keygen.compressions + 1,
      signCompressions: tree.keygen.compressions + otsSign + 1,
      signCachedCompressions: otsSign + 1,
      verifyCompressions: msg.verify.compressions + ots.verify.compressions + tree.verify.compressions + 1,
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
          tooltip: 'Every node of the tree, kept by a signer that avoids rebuilding it on each signature.',
          value: (d) => bytes(d.sizes.cache),
        },
      ],
    },
    {
      heading: 'Signature (deepest leaf)',
      tooltip: 'The tuple \\((i, R, \\sigma_{\\mathrm{OTS}}, \\mathrm{AuthPath}_i)\\) for a leaf at the full depth, which has the longest authentication path. In UXMSS, shallower leaves have one \\(n\\)-bit node less per level; the visualization gives the size for each signature.',
      rows: [
        { label: 'Leaf index \\(i\\)', group: 'Tree', value: (d) => bytes(d.sizes.index) },
        { label: 'Randomness \\(R\\)', value: (d) => bytes(d.sizes.R) },
        { label: 'WOTS+C signature (\\(\\sigma_{\\mathrm{OTS}}\\))', group: 'OTS (WOTS+C)', value: (d) => bytes(d.sizes.ots) },
        { label: '\\(\\mathrm{AuthPath}_i\\)', group: 'Tree', value: (d) => bytes(d.sizes.authPath) },
        { label: 'Total', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Search',
      group: 'OTS (WOTS+C)',
      tooltip: 'The WOTS+C counter search on the message digest. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        successProbability,
        wcSearch,
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation builds every WOTS+C leaf and hashes the tree up to the root. Without a cache, signing rebuilds the tree to get the authentication path. With the tree cached, signing is the WOTS+C signature alone. Verification is for the deepest leaf. Signing also computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\); verification computes \\(\\mathbf{H}_{\\mathbf{msg}}\\).',
      rows: [
        { label: 'Key generation', value: (d) => `${approx(d.treePrf)} \\(\\mathbf{PRF}\\) + ${approx(d.treeTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (no cache, WC search)', value: (d) => `${approx(d.treePrf + d.signPrf)} \\(\\mathbf{PRF}\\) + ${approx(d.treeTh + d.signTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (cached tree, WC search)', value: (d) => `${num(d.signPrf)} \\(\\mathbf{PRF}\\) + ${approx(d.signTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification', value: (d) => `${num(d.verifyTh)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. \\(\\mathrm{Th}\\) and \\(\\mathbf{PRF}\\) follow FIPS 205 with a cached \\(\\mathrm{PK.seed}\\) block, adding one compression per operation. \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\) follow FIPS 205 for a 32-byte message.',
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: 'Signing (no cache, WC search)', value: (d) => approx(d.signCompressions) },
        { label: 'Signing (cached tree, WC search)', value: (d) => approx(d.signCachedCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    {
      ...signatureBudget(
        {
          label: 'Signatures per key pair',
          tooltip: 'One per leaf: \\(\\mathrm{depth} + 1\\) for UXMSS and \\(2^{\\mathrm{depth}}\\) for BXMSS. Reusing a leaf for a second message breaks the security of its WOTS+C key.',
          value: (d) => approx(d.leaves),
        },
        {
          label: 'State counter',
          tooltip: 'The signer stores the number of signatures issued and increments it before releasing each signature. SHRINCS requires that it never decrements and is never restored from a backup.',
          value: (d) => `${num(Math.ceil(Math.log2(d.leaves)) || 1)} bits`,
        },
      ),
      group: 'Tree',
    },
    blockSpace,
  ],
};

const W = 560;

// Height bracket from y1 to y2 at x, with labels to its right.
function bracket(g, x, y1, y2, lines) {
  g.line(x, y1, x, y2, 'bracket');
  g.line(x - 4, y1, x, y1, 'bracket');
  g.line(x - 4, y2, x, y2, 'bracket');
  lines.forEach((s, k) => g.text(x + 8, (y1 + y2) / 2 + 4 + 16 * (k - (lines.length - 1) / 2), s, 'start'));
}

// BXMSS: the balanced tree, as in the XMSS diagram, with one leaf opened up.
function balancedSvg(depth, l, w) {
  const g = svg();
  const tree = drawTree(g, { h: depth, left: 40, right: W - 110, top: 30 });
  g.text(tree.rootX, tree.rootY - 14, 'Public key (root)');
  bracket(g, W - 92, tree.rootY, tree.leafY, [`depth = ${depth}`]);
  g.text(W - 84, tree.leafY + 4, `${tree.leafCount.toLocaleString()} leaves`, 'start', 'label ots-label');
  const leaf = drawLeafChains(g, { leafX: tree.slotX(0), leafY: tree.leafY, l, w, compact: true });
  return { svg: g.toString(), width: W, height: leaf.bottom };
}

// UXMSS: the left spine of inner nodes, with a leaf to the right at each
// depth and a second leaf at the deepest level. Each leaf is labeled with
// the signature that uses it and that signature's size. Leaves at depths 6
// to depth - 1 are elided when depth > 7.
function unbalancedSvg(depth, l, w, sigAt) {
  const g = svg();
  const dx = 26, dy = 34, rootX = 290, top = 30, size = 14;
  const elided = depth > 7;
  // Rows of the spine: depth values drawn, with null for the elided gap.
  const rows = elided ? [0, 1, 2, 3, 4, null, depth - 1] : [...Array(depth).keys()];
  const X = (r) => rootX - r * dx;
  const Y = (r) => top + r * dy;
  const sizeLabel = (q, leafDepth) => `signature ${q}: ${bytes(sigAt(leafDepth))}`;

  g.text(rootX, top - 14, 'Public key (root)');
  rows.forEach((k, r) => {
    const x = X(r), y = Y(r);
    if (k === null) {
      g.text(x, y + 4, '⋮', 'middle');
      g.text(x + dx + size, y + dy / 2 + 4, `signatures 6 to ${depth - 1}`, 'start', 'label ots-label');
      return;
    }
    // Edge down to the next spine node (or the deepest left leaf).
    const last = r === rows.length - 1;
    if (!last && rows[r + 1] !== null) g.line(x, y, X(r + 1), Y(r + 1));
    if (!last && rows[r + 1] === null) g.line(x, y, X(r + 1) + 6, Y(r + 1) - 10);
    if (last) g.line(x, y, X(r + 1), Y(r + 1));
    // Right child leaf at depth k + 1.
    g.line(x, y, x + dx, y + dy);
    const q = k + 1;
    g.rect(x + dx - size / 2, y + dy - size / 2, size, size, 'ots-node');
    const label = q === depth ? `signatures ${q}, ${q + 1}: ${bytes(sigAt(q))}` : sizeLabel(q, q);
    g.text(x + dx + size, y + dy + 4, label, 'start', 'label ots-label');
    if (r > 0 && rows[r - 1] === null) g.line(X(r - 1) + 6, Y(r - 1) + 10, x, y);
  });
  for (const r of rows.keys()) if (rows[r] !== null) g.circle(X(r), Y(r), 7, 'tree-node');

  // Deepest left leaf.
  const leafX = X(rows.length), leafY = Y(rows.length);
  g.rect(leafX - size / 2, leafY - size / 2, size, size, 'ots-node');

  bracket(g, 40, top, leafY, [`depth = ${depth}`]);
  const leaf = drawLeafChains(g, { leafX, leafY, l, w, compact: true });
  return { svg: g.toString(), width: W, height: leaf.bottom };
}

// Visualization state, nested inside the scheme component.
export function fxmssTree() {
  return {
    get drawing() {
      const { l, w } = wotsC.model({ ...this.state, compressed: true });
      return this.state.shape === 'UXMSS'
        ? unbalancedSvg(this.state.depth, l, w, this.derived.sigAt)
        : balancedSvg(this.state.depth, l, w);
    },
  };
}
