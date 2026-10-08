import * as hg from '../primitives/hg-wots.js';
import { bytes, num } from '../scheme.js';
import { hashCalls, sigPart, signatureBudget } from '../common-results.js';
import { CHAIN_CELL, svg, verticalChain } from '../draw.js';
import { clampState } from '../tradeoff.js';

// An HGT tree of HG-WOTS leaves. Defaults are the HGT baseline
// (k, s, chain length, d_g, j, group chain length, d_h) = (7, 4, 16, 20, 5, 8, 11),
// N = 512 and K = 4.

const KEY = 'HG-WOTS';
const TREE = 'HGT';

// A leaf in the shape js/primitives/hg-wots.js takes: one level of k groups
// that opens the k - j revealed ones.
export const leafOf = (s) => ({
  levels: [{ units: s.k, open: s.k - s.j, length: s.gl, sum: s.dh }],
  bottom: { chains: s.s, length: s.w, sum: s.dg },
});

export const bitsText = (x) => (Number.isFinite(x) ? x.toFixed(1) : '?');
export const perInstanceText = (r) => (r > hg.R_MAX ? `\\(\\geq ${hg.R_MAX}\\)` : num(r));

// Parameters of the tree, shared with HagGrid.
export function treeParameters(group) {
  return [
    {
      key: 'logN', type: 'range', min: 1, max: 16, step: 1, default: 9, group,
      display: (x) => (2 ** x).toLocaleString(),
      label: '\\(N\\) (leaves)',
      tooltip: 'The HGT tree is a Merkle tree of \\(N\\) leaf keys. The signer keeps no state and rebuilds every leaf for each signature.',
    },
    {
      key: 'K', type: 'range', min: 1, max: (s) => Math.min(4, 2 ** s.logN), step: 1, default: 4, group,
      label: '\\(K\\) (leaves per signature)',
      tooltip: 'The message hash picks \\(K\\) distinct leaves, and the signature carries a leaf signature for each with one Merkle multiproof up to the root.',
    },
    {
      key: 'r', type: 'range', min: 1, max: hg.R_MAX, step: 1, default: 8, group,
      label: '\\(r\\) (signatures made)',
      tooltip: 'Signatures this tree instance has already made, across all of its leaves.',
    },
    {
      key: 'grind', type: 'range', min: 0, max: 40, step: 0.01, default: 16.71, group,
      label: 'Grinding (bits)',
      tooltip: 'Grinding for the signatures per instance result. A field of the message hash must pass a threshold, which adds this many bits.',
    },
  ];
}

// Figures shared with HagGrid, for a leaf in the primitive's shape.
export function treeModel(state, leaf) {
  const N = 2 ** state.logN;
  const bits = hg.forgeryBits(leaf, N, state.K);
  const bitsAtR = bits[state.r];
  const grinding = Math.max(0, hg.TARGET_BITS - bitsAtR);
  const p = 2 ** -grinding;
  const wcSearch = p >= 1 ? 1 : Math.ceil((-30 * Math.LN2) / Math.log1p(-p));
  const keygen = hg.keygen(leaf);
  const nodes = hg.nodes(leaf);
  return {
    N, K: state.K, nodes, wcSearch,
    bitsAtR,
    grinding,
    perInstance: hg.signaturesPerInstance(bits, state.grind),
    sizes: { leaves: state.K * nodes * state.n },
    calls: {
      keygen: { th: keygen },
      verify: { th: hg.verify(leaf) },
      // Every leaf, the N - 1 inner nodes, and one hash call per grinding trial.
      sign: { th: N * keygen + (N - 1) + wcSearch },
    },
  };
}

// Result groups shared with HagGrid. `leafName` names the leaf signatures.
export function treeResults({ leafName, keygenTooltip, verifyTooltip }) {
  return [
    {
      rows: [
        { label: 'Nodes per leaf signature', value: (d) => num(d.nodes) },
      ],
    },
    {
      heading: 'Witness',
      tooltip: `The \\(K\\) leaf signatures of \\(n\\)-bit nodes, and one Merkle multiproof for the \\(K\\) leaves. The multiproof size is not modeled, so it and the total show ?.`,
      rows: [
        sigPart(`${leafName} signatures (\\(K\\))`, 'leaves'),
        { label: 'Merkle multiproof', value: () => '?' },
        { label: 'Total', value: () => '?' },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Signing rebuilds every leaf and the tree, then grinds the message hash: the WC search, the number of trials that suffices except with probability \\(2^{-30}\\) at the grinding to 128 bits, one hash call each. Mapping the message hash to positions with the fixed sums is not counted. Verification also hashes the Merkle multiproof, which is not modeled.',
      rows: [
        { label: 'Keygen per leaf', tooltip: keygenTooltip, value: (d) => hashCalls(d.calls.keygen, num) },
        { label: 'Verify per leaf', tooltip: verifyTooltip, value: (d) => hashCalls(d.calls.verify, num) },
        { label: 'Signing (WC search)', value: (d) => hashCalls(d.calls.sign) },
        { label: 'Verification', value: () => '?' },
      ],
    },
    {
      ...signatureBudget(
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
  ];
}

const hgWots = {
  id: 'hg-wots',
  title: 'HGT + HG-WOTS',
  groups: { [KEY]: 'var(--c-ca6702)', [TREE]: 'var(--c-0a9396)' },

  parameters: [
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128, group: KEY,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Every chain value, and so every node in a signature, is \\(n\\) bits.',
    },
    {
      key: 'k', type: 'range', min: 2, max: 8, step: 1, default: 7, group: KEY,
      label: '\\(k\\) (groups)',
      tooltip: 'The chain ends of each group hash into the start of its group chain, and the ends of the \\(k\\) group chains hash into the leaf key.',
    },
    {
      key: 'j', type: 'range', step: 1, default: 5, group: KEY,
      min: (s) => Math.max(1, s.k - 3),
      max: (s) => Math.min(s.k - 1, hg.maxCount(s.gl)),
      label: '\\(j\\) (hidden groups)',
      tooltip: 'A signature hides \\(j\\) of the \\(k\\) groups and sends one node on each hidden group chain. It reveals the other \\(k - j\\) groups and sends one node on each of their chains.',
    },
    {
      key: 's', type: 'range', min: 1, step: 1, default: 4, group: KEY,
      max: (s) => Math.min(6, hg.maxCount(s.w)),
      label: '\\(s\\) (chains per group)',
      tooltip: 'Chains in each group. A revealed group sends one node on each of its \\(s\\) chains.',
    },
    {
      key: 'w', type: 'range', min: 2, max: 16, step: 1, default: 16, group: KEY,
      label: 'Chain length',
      tooltip: 'Values on each chain, its end included.',
    },
    {
      key: 'dg', type: 'range', min: 0, step: 1, default: 20, group: KEY,
      max: (s) => s.s * (s.w - 1),
      label: '\\(d_g\\) (distance sum per revealed group)',
      tooltip: 'The distances from the nodes of a revealed group to their chain ends sum to \\(d_g\\). The verifier walks them.',
    },
    {
      key: 'gl', type: 'range', min: 2, max: 16, step: 1, default: 8, group: KEY,
      label: 'Group chain length',
      tooltip: 'Values on each group chain, its end included. The verifier walks a revealed group\'s group chain from its start.',
    },
    {
      key: 'dh', type: 'range', min: 0, step: 1, default: 11, group: KEY,
      max: (s) => s.j * (s.gl - 1),
      label: '\\(d_h\\) (distance sum over hidden groups)',
      tooltip: 'The distances from the nodes of the \\(j\\) hidden groups to their group chain ends sum to \\(d_h\\). The verifier walks them.',
    },
    ...treeParameters(TREE),
  ],

  // Clamped, since a state can hold values its own bounds rule out, such as
  // j >= k, before the parameters panel clamps it.
  derive(state) {
    const s = clampState(this.parameters, state);
    return treeModel(s, leafOf(s));
  },

  results: treeResults({
    leafName: 'HG-WOTS',
    keygenTooltip: 'Every chain and group chain to its end, one hash call per group on its chain ends, and one on the group chain ends for the leaf key.',
    verifyTooltip: 'The walks from the revealed nodes to their chain ends, \\(k - j\\) hash calls on chain ends, every revealed group chain from its start, and the hash call for the leaf key.',
  }),
};

export default hgWots;

// One leaf signing a sampled message.
function leafSvg(s, sample) {
  const W = 560;
  const g = svg();
  const { width, height, gap } = CHAIN_CELL;
  const keyX = W / 2, keyY = 28;
  const groupW = (W - 40) / s.k;
  const groupTop = 76;
  const groupBottom = groupTop + s.gl * (height + gap);
  const chainsTop = groupBottom + 34;

  g.text(keyX, keyY - 14, 'Leaf key = hash call on the k group chain ends');
  for (let i = 0; i < s.k; i++) {
    const cx = 20 + (i + 0.5) * groupW;
    const hidden = sample.hidden.includes(i);
    const group = hidden
      ? verticalChain(g, cx, groupTop, s.gl, { reveal: s.gl - 1 - sample.dh[sample.hidden.indexOf(i)] })
      : verticalChain(g, cx, groupTop, s.gl, { walked: true });
    g.line(keyX, keyY + 7, cx, groupTop - 2, 'edge faint');
    const span = (s.s - 1) * (width + 3);
    let bottom = 0;
    for (let c = 0; c < s.s; c++) {
      const x = cx - span / 2 + c * (width + 3);
      const opts = hidden ? {} : { reveal: s.w - 1 - sample.dg[sample.revealed.indexOf(i)][c] };
      const chain = verticalChain(g, x, chainsTop, s.w, opts);
      g.line(x, chainsTop - 2, cx, group.bottom + 2, hidden ? 'edge faint dashed' : 'edge faint');
      bottom = chain.bottom;
    }
    g.text(cx, bottom + 16, hidden ? 'hidden' : 'revealed', 'middle', hidden ? 'label' : 'label ots-label');
  }
  g.circle(keyX, keyY, 7, 'tree-node');
  const bottom = chainsTop + s.w * (height + gap) + 16;
  g.text(W / 2, bottom + 22, `k = ${s.k} groups, j = ${s.j} hidden`);
  return { svg: g.toString(), width: W, height: bottom + 34 };
}

// A message sampled from `seed`: the hidden groups, and every distance.
function sampleLeaf(s, seed) {
  const random = seeded(seed);
  const order = shuffled(s.k, random);
  const hidden = order.slice(0, s.j).sort((a, b) => a - b);
  const revealed = order.slice(s.j).sort((a, b) => a - b);
  return {
    hidden,
    revealed,
    dh: hg.sampleDistances(s.j, s.dh, s.gl - 1, random),
    dg: revealed.map(() => hg.sampleDistances(s.s, s.dg, s.w - 1, random)),
  };
}

// Visualization state, nested inside the scheme component. A new seed draws
// another message.
export function hgWotsLeaf() {
  return {
    seed: newSeed(),

    resample() {
      this.seed = newSeed();
    },

    // Clamped, as the state can briefly hold values out of bounds.
    get drawing() {
      const s = clampState(hgWots.parameters, this.state);
      return leafSvg(s, sampleLeaf(s, this.seed));
    },
  };
}

export const newSeed = () => Math.floor(Math.random() * 2 ** 32);

// Mulberry32, so that a seed gives the same message while the parameters it
// does not depend on change.
export function seeded(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 2 ** 32;
  };
}

// 0..count-1 in a uniform random order.
export function shuffled(count, random) {
  const out = [...Array(count).keys()];
  for (let i = count - 1; i > 0; i--) {
    const k = Math.floor(random() * (i + 1));
    [out[i], out[k]] = [out[k], out[i]];
  }
  return out;
}
