import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wotsC from '../primitives/wots-c.js';
import { bytes } from '../scheme.js';
import {
  OTS, TREE, blockSpace, otsSearch, sigPart, treeBudget, treeCosts, treeGroups, treeKeys, withMidstate,
} from '../common-results.js';
import { balancedTreeSvg } from '../draw.js';

// XMSS with WOTS+C leaves, Section 7 of Kudinov and Nick, "Hash-based Signature
// Schemes for Bitcoin". Balanced tree of height h.

// Derived values for one tree of WOTS+C leaves with the signature
// (i, R, sigma_OTS, AuthPath_i). The leaf index takes enough bytes to number
// every leaf. Sizes and verification are for the tree model's authentication
// path. Also used by FXMSS.
export function deriveSingleTree(state, tree) {
  const ots = wotsC.model({ ...state, compressed: true });
  const msg = messageHash.model(state);
  const sizes = {
    sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
    pk: 2 * state.n, // PK.seed and root
    cache: tree.sizes.cache,
    index: 8 * Math.ceil(Math.ceil(Math.log2(tree.leaves)) / 8),
    R: msg.sizes.R,
    ots: ots.sizes.sig,
    authPath: tree.sizes.authPath,
  };
  sizes.sig = sizes.index + sizes.R + sizes.ots + sizes.authPath;

  // Without a cache, signing rebuilds the tree for the authentication path.
  const signCached = {
    prf: ots.sign.prf,
    th: ots.sign.th,
    compressions: msg.sign.compressions + ots.sign.compressions,
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
      th: ots.verify.th + tree.verify.th,
      compressions: msg.verify.compressions + ots.verify.compressions + tree.verify.compressions,
    },
  };
  return {
    p: ots.p, wcSearch: ots.wcSearch, leaves: tree.leaves, l: ots.l, w: ots.w,
    sizes, calls: ops, ...withMidstate(ops),
  };
}

// Rows of the (i, R, sigma_OTS, AuthPath_i) signature.
export const singleTreeSignature = (tooltip) => ({
  heading: 'Signature',
  tooltip,
  bar: true,
  rows: [
    sigPart('Leaf index \\(i\\)', 'index', TREE),
    sigPart('Randomness \\(R\\)', 'R'),
    sigPart('WOTS+C signature (\\(\\sigma_{\\mathrm{OTS}}\\))', 'ots', OTS),
    sigPart('\\(\\mathrm{AuthPath}_i\\)', 'authPath', TREE),
    { label: 'Total', value: (d) => bytes(d.sizes.sig) },
  ],
});

export const singleTreeHashTooltip = 'Key generation builds every WOTS+C leaf and hashes the tree up to the root. Without a cache, signing rebuilds the tree to get the authentication path. With the tree cached, signing is the WOTS+C signature alone.';

export const stateCounterTooltip = 'The signer stores the index of the next unused leaf and increments it before releasing each signature. SHRINCS requires that it never decrements and is never restored from a backup.';

export default {
  id: 'xmss',
  title: 'XMSS + WOTS+C',
  groups: treeGroups,

  parameters: [
    ...merkleTree.parameters(TREE).map((p) => ({
      ...p,
      tooltip: 'The tree has \\(2^h\\) WOTS+C leaves, one per signature. Each extra level doubles the signature budget and the key generation work, and adds one \\(n\\)-bit node to the authentication path.',
    })),
    ...wotsC.parameters(OTS),
  ],

  derive(state) {
    const ots = wotsC.model({ ...state, compressed: true });
    return deriveSingleTree(state, merkleTree.model(state, ots));
  },

  results: [
    treeKeys('All \\(2^{h+1} - 1\\) tree nodes, kept by a signer that avoids rebuilding the tree on each signature.'),
    singleTreeSignature('The tuple \\((i, R, \\sigma_{\\mathrm{OTS}}, \\mathrm{AuthPath}_i)\\): the leaf index, the message randomness, the WOTS+C signature with its counter, and the \\(h\\) sibling nodes from leaf to root.'),
    otsSearch('The WOTS+C counter search on the message digest. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).'),
    ...treeCosts(singleTreeHashTooltip, 'tree'),
    treeBudget(
      'One per leaf, \\(2^h\\). Reusing a leaf for a second message breaks the security of its WOTS+C key.',
      stateCounterTooltip,
    ),
    blockSpace,
  ],
};

// Visualization state, nested inside the scheme component. The tree (root =
// public key, inner nodes = Th of two children) with WOTS+C public keys as
// leaves, and one leaf opened up to show its chains.
export function xmssTree() {
  return {
    get drawing() {
      const { l, w } = this.derived;
      return balancedTreeSvg({ h: this.state.h, lines: [`h = ${this.state.h}`, 'levels'], l, w });
    },
  };
}
