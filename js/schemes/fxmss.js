import * as merkleTree from '../primitives/merkle-tree.js';
import * as wotsC from '../primitives/wots-c.js';
import { bytes } from '../scheme.js';
import {
  OTS, TREE, blockSpace, otsSearch, treeBudget, treeCosts, treeGroups, treeKeys,
} from '../common-results.js';
import { bracket, drawLeafChains, svg } from '../draw.js';
import { deriveSingleTree, singleTreeHashTooltip, singleTreeSignature } from './xmss.js';

// FXMSS with WOTS+C leaves, the stateful component of SHRINCS, in its UXMSS
// shape (unbalanced, left-leaning). The depth is the distance from the root
// to the deepest leaf.

export default {
  id: 'fxmss',
  title: 'FXMSS + WOTS+C',

  groups: treeGroups,

  parameters: [
    {
      key: 'depth', type: 'range', min: 1, max: 255, step: 1, default: 255, group: TREE,
      label: 'Depth',
      tooltip: 'Distance from the root to the deepest leaf, encoded in one byte, up to 255. UXMSS places one leaf at each depth from 1 to \\(\\mathrm{depth}\\), plus a second leaf at the deepest level, so signatures grow by one node each. Leaf indexes are encoded in 64 bits.',
    },
    ...wotsC.parameters(OTS),
  ],

  // Sizes and verification are for the deepest leaf. `sigAt` gives the
  // signature size for a leaf at a given depth.
  derive(state) {
    const { depth, n } = state;
    const ots = wotsC.model({ ...state, compressed: true });
    const tree = merkleTree.unbalancedModel({ depth, n }, ots);
    const d = deriveSingleTree(state, tree);
    const { index, R, ots: otsBits } = d.sizes;
    return { ...d, sigAt: (leafDepth) => index + R + otsBits + leafDepth * n };
  },

  results: [
    treeKeys('Every node of the tree, kept by a signer that avoids rebuilding it on each signature.'),
    {
      ...singleTreeSignature('The tuple \\((i, R, \\sigma_{\\mathrm{OTS}}, \\mathrm{AuthPath}_i)\\) for a leaf at the full depth, which has the longest authentication path. Shallower leaves have one \\(n\\)-bit node less per level; the visualization gives the size for each signature.'),
      heading: 'Signature (deepest leaf)',
    },
    otsSearch('The WOTS+C counter search on the message digest. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).'),
    ...treeCosts(`${singleTreeHashTooltip} Verification is for the deepest leaf.`, 'tree'),
    treeBudget(
      'One per leaf, \\(\\mathrm{depth} + 1\\). Reusing a leaf for a second message breaks the security of its WOTS+C key.',
      'The signer stores the number of signatures issued and increments it before releasing each signature. It must never decrement and must never be restored from a backup.',
    ),
    blockSpace,
  ],
};

const W = 560;

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
      const { l, w } = this.derived;
      return unbalancedSvg(this.state.depth, l, w, this.derived.sigAt);
    },
  };
}
