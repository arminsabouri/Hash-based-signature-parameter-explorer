import * as merkleTree from '../primitives/merkle-tree.js';
import * as messageHash from '../primitives/message-hash.js';
import * as wotsC from '../primitives/wots-c.js';
import { approx, bytes, num } from '../scheme.js';
import { blockSpace, signatureBudget, successProbability, wcSearch } from '../common-results.js';
import { drawChains, drawTree, svg } from '../draw.js';

// XMSS with WOTS+C leaves, Section 7 of Kudinov and Nick, "Hash-based Signature
// Schemes for Bitcoin". Balanced tree of height h.

export default {
  id: 'xmss',
  title: 'XMSS + WOTS+C',

  // Colors for the parameter groups.
  groups: {
    'Tree': 'var(--c-0a9396)',
    'OTS (WOTS+C)': 'var(--c-ca6702)',
  },

  parameters: [
    ...merkleTree.parameters('Tree').map((p) => ({
      ...p,
      tooltip: 'The tree has \\(2^h\\) WOTS+C leaves, one per signature. Each extra level doubles the signature budget and the key generation work, and adds one \\(n\\)-bit node to the authentication path.',
    })),
    ...wotsC.parameters('OTS (WOTS+C)'),
  ],

  derive(state) {
    const ots = wotsC.model({ ...state, compressed: true });
    const tree = merkleTree.model(state, ots);
    const msg = messageHash.model(state);

    // Signature (i, R, sigma_OTS, AuthPath_i).
    const sizes = {
      sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * state.n, // PK.seed and root
      cache: tree.sizes.cache,
      index: 8 * Math.ceil(state.h / 8),
      R: msg.sizes.R,
      ots: ots.sizes.sig,
      authPath: tree.sizes.authPath,
    };
    sizes.sig = sizes.index + sizes.R + sizes.ots + sizes.authPath;

    // Each operation also computes the cached PK.seed midstate once.
    const otsSign = msg.sign.compressions + ots.sign.compressions;
    return {
      p: ots.p, wcSearch: ots.wcSearch, leaves: tree.leaves,
      sizes,
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
          tooltip: 'All \\(2^{h+1} - 1\\) tree nodes, kept by a signer that avoids rebuilding the tree on each signature.',
          value: (d) => bytes(d.sizes.cache),
        },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'The tuple \\((i, R, \\sigma_{\\mathrm{OTS}}, \\mathrm{AuthPath}_i)\\): the leaf index, the message randomness, the WOTS+C signature with its counter, and the \\(h\\) sibling nodes from leaf to root.',
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
      tooltip: 'Key generation builds every WOTS+C leaf and hashes the tree up to the root. Without a cache, signing rebuilds the tree to get the authentication path. With the tree cached, signing is the WOTS+C signature alone. Signing also computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\); verification computes \\(\\mathbf{H}_{\\mathbf{msg}}\\).',
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
          tooltip: 'One per leaf, \\(2^h\\). Reusing a leaf for a second message breaks the security of its WOTS+C key.',
          value: (d) => num(d.leaves),
        },
        {
          label: 'State counter',
          tooltip: 'The signer stores the index of the next unused leaf and increments it before releasing each signature. SHRINCS requires that it never decrements and is never restored from a backup.',
          value: (d) => `${num(Math.ceil(Math.log2(d.leaves)) || 1)} bits`,
        },
      ),
      group: 'Tree',
    },
    blockSpace,
  ],
};

// Structure diagram: the tree (root = public key, inner nodes = Th of two
// children) with WOTS+C public keys as leaves, and one leaf opened up to show
// its l chains of w values compressed into the leaf.
function treeSvg(h, l, w) {
  const W = 560;
  const g = svg();
  const tree = drawTree(g, { h, left: 40, right: W - 110, top: 30 });
  g.text(tree.rootX, tree.rootY - 14, 'Public key (root)');

  // Height and leaf count annotations.
  const bx = W - 92;
  g.line(bx, tree.rootY, bx, tree.leafY, 'bracket');
  g.line(bx - 4, tree.rootY, bx, tree.rootY, 'bracket');
  g.line(bx - 4, tree.leafY, bx, tree.leafY, 'bracket');
  g.text(bx + 8, (tree.rootY + tree.leafY) / 2 - 4, `h = ${h}`, 'start');
  g.text(bx + 8, (tree.rootY + tree.leafY) / 2 + 12, 'levels', 'start');
  g.text(bx + 8, tree.leafY + 4, `${tree.leafCount.toLocaleString()} leaves`, 'start', 'label ots-label');

  // The first leaf opened up into its chains.
  const leafX = tree.slotX(0);
  const top = tree.leafY + 46;
  const busY = top - 16;
  g.line(leafX, tree.leafY + 7, leafX, busY, 'ots-edge');
  g.text(leafX + 8, tree.leafY + 26, 'WOTS+C public key = Th(pk\u2081, \u2026, pk\u2097)', 'start', 'label ots-label');
  const chains = drawChains(g, { l, w, left: 120, top });
  const endsX = chains.right + 24;
  for (const end of chains.ends) g.line(end.x, end.y, endsX, busY, 'ots-edge faint');
  g.line(endsX, busY, leafX, busY, 'ots-edge');
  g.text(chains.right, chains.bottom + 30, `l = ${l} chains`, 'end', 'label ots-label');

  return { svg: g.toString(), width: W, height: chains.bottom + 44 };
}

// Visualization state, nested inside the scheme component.
export function xmssTree() {
  return {
    get drawing() {
      const { l, w } = wotsC.model({ ...this.state, compressed: true });
      return treeSvg(this.state.h, l, w);
    },
  };
}
