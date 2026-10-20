import * as hg from '../primitives/hg-wots.js';
import { num } from '../scheme.js';
import { hashCalls, sigPart, signatureBudget } from '../common-results.js';
import { annotateTree, drawTree, svg } from '../draw.js';
import { clampState } from '../tradeoff.js';
import hgWots, { leafOf as hgWotsLeafOf, pow2 } from './hg-wots.js';
import haggrid, { leafOf as hagGridLeafOf } from './haggrid.js';

// HGT: a Merkle tree of N HG-WOTS or HagGrid leaves. The message hash picks K
// distinct leaves, and a separate field of it must pass a grinding threshold.
// Defaults are N = 512 and K = 4, with each leaf at its own tab's defaults.

const TREE = 'HGT';
const HG_WOTS = 'HG-WOTS';
const HAGGRID = 'HagGrid';

const bitsText = (x) => (Number.isFinite(x) ? x.toFixed(1) : '?');
const perInstanceText = (r) => (r > hg.R_MAX ? `\\(\\geq ${hg.R_MAX}\\)` : num(r));

// A leaf tab's parameters, shown only while its leaf is selected. n and q
// belong to the tree here.
const leafParameters = (scheme, leaf) => scheme.parameters
  .filter((p) => p.key !== 'n' && p.key !== 'q')
  .map((p) => ({ ...p, show: (s) => s.leaf === leaf && (!p.show || p.show(s)) }));

const leafOf = (s) => (s.leaf === HAGGRID ? hagGridLeafOf(s) : hgWotsLeafOf(s));

const hgt = {
  id: 'hgt',
  title: 'HGT',
  groups: { [TREE]: 'var(--c-0a9396)', ...hgWots.groups, ...haggrid.groups },

  parameters: [
    {
      key: 'leaf', type: 'select', options: [HG_WOTS, HAGGRID], default: HG_WOTS, group: TREE,
      label: 'Leaf',
      tooltip: 'The key at each leaf of the tree.',
    },
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128, group: TREE,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Size of each hash in bits, which sets how many bytes a signature takes.',
    },
    {
      key: 'logN', type: 'range', min: 1, max: 16, step: 1, default: 9, group: TREE,
      display: (x) => (2 ** x).toLocaleString(),
      label: '\\(N\\) (leaves)',
      tooltip: 'The tree has \\(N\\) leaf keys. The signer keeps no state and rebuilds every leaf for each signature.',
    },
    {
      key: 'K', type: 'range', min: 1, max: (s) => Math.min(4, 2 ** s.logN), step: 1, default: 4, group: TREE,
      label: '\\(K\\) (leaves per signature)',
      tooltip: 'The message hash picks \\(K\\) distinct leaves, and the signature carries a leaf signature for each with one Merkle multiproof up to the root.',
    },
    {
      key: 'r', type: 'range', min: 1, max: hg.R_MAX, step: 1, default: 8, group: TREE,
      label: '\\(r\\) (signatures made)',
      tooltip: 'Signatures this tree has already made, across all of its leaves.',
    },
    {
      key: 'grind', type: 'range', min: 0, max: 40, step: 0.01, default: 16.71, group: TREE,
      label: 'Grinding (bits)',
      tooltip: 'Grinding for the signatures per instance result. A field of the message hash must pass a threshold, which adds this many bits.',
    },
    ...leafParameters(hgWots, HG_WOTS),
    ...leafParameters(haggrid, HAGGRID),
  ],

  // Clamped, since a state can hold values its own bounds rule out before the
  // parameters panel clamps it.
  derive(state) {
    const s = clampState(this.parameters, state);
    const leaf = leafOf(s);
    const N = 2 ** s.logN;
    const bits = hg.forgeryBits(leaf, N, s.K);
    const bitsAtR = bits[s.r];
    const grinding = Math.max(0, hg.TARGET_BITS - bitsAtR);
    const p = 2 ** -grinding;
    const wcSearch = p >= 1 ? 1 : Math.ceil((-30 * Math.LN2) / Math.log1p(-p));
    const keygen = hg.keygen(leaf);
    const nodes = hg.nodes(leaf);
    return {
      leaf: s.leaf, nodes, bitsAtR, grinding,
      perInstance: hg.signaturesPerInstance(bits, s.grind),
      sizes: { leaves: s.K * nodes * s.n },
      calls: {
        keygen: { th: keygen },
        verify: { th: hg.verify(leaf) },
        // Every leaf, the N - 1 inner nodes, and one hash call per grinding trial.
        sign: { th: N * keygen + (N - 1) + wcSearch },
      },
    };
  },

  results: [
    {
      rows: [
        { label: 'Nodes per leaf signature', value: (d) => num(d.nodes) },
      ],
    },
    {
      heading: 'Witness',
      tooltip: 'The \\(K\\) leaf signatures of \\(n\\)-bit nodes, and one Merkle multiproof for the \\(K\\) leaves. The multiproof size is not modeled, so it and the total show ?.',
      rows: [
        sigPart('Leaf signatures (\\(K\\))', 'leaves'),
        { label: 'Merkle multiproof', value: () => '?' },
        { label: 'Total', value: () => '?' },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Keygen and verify per leaf are the key generation and verification of the leaf key on its own tab. Signing rebuilds every leaf and the tree, then grinds the message hash: the WC search, the number of trials that suffices except with probability \\(2^{-30}\\) at the grinding to 128 bits, one hash call each. Mapping the message hash to positions with the fixed sums is not counted. Verification also hashes the Merkle multiproof, which is not modeled.',
      rows: [
        { label: 'Keygen per leaf', value: (d) => hashCalls(d.calls.keygen, num) },
        { label: 'Verify per leaf', value: (d) => hashCalls(d.calls.verify, num) },
        { label: 'Signing (WC search)', value: (d) => hashCalls(d.calls.sign) },
        { label: 'Verification', value: () => '?' },
      ],
    },
    {
      ...signatureBudget(
        {
          label: 'Forgery probability after \\(r\\) signatures',
          tooltip: '\\(2^{-b}\\), with \\(b\\) the bits at \\(r\\). Grinding is not included.',
          value: (d) => pow2(d.bitsAtR),
        },
        {
          label: 'Bits at \\(r\\)',
          tooltip: '\\(-\\log_2\\) of the probability that a fresh message hash gives a signature an attacker can compute by hashing forward from the nodes in \\(r\\) past signatures. Each signature picks \\(K\\) distinct leaves, and every picked leaf must be covered by the past signatures that picked it. Grinding is not included.',
          value: (d) => bitsText(d.bitsAtR),
        },
        {
          label: 'Grinding to 128 bits',
          tooltip: '128 minus the bits at \\(r\\).',
          value: (d) => `${d.grinding.toFixed(2)} bits`,
        },
        {
          label: 'Signatures per instance',
          tooltip: `The largest \\(r\\), up to ${hg.R_MAX}, whose bits plus the grinding parameter reach 128.`,
          value: (d) => perInstanceText(d.perInstance),
        },
      ),
      group: TREE,
    },
  ],
};

export default hgt;

// The tree, with its root as the public key.
function treeSvg({ logN, K, leaf }) {
  const W = 560;
  const g = svg();
  const tree = drawTree(g, { h: logN, left: 40, right: W - 110, top: 30 });
  g.text(tree.rootX, tree.rootY - 14, 'Public key (root)');
  annotateTree(g, tree, W - 92, [`log\u2082 N = ${logN}`]);
  g.text((40 + W - 110) / 2, tree.leafY + 30, `leaves are ${leaf} keys; a signature picks K = ${K}`, 'middle', 'label ots-label');
  return { svg: g.toString(), width: W, height: tree.leafY + 44 };
}

// Visualization state, nested inside the scheme component.
export function hgtTree() {
  return {
    get drawing() {
      return treeSvg(clampState(hgt.parameters, this.state));
    },
  };
}
