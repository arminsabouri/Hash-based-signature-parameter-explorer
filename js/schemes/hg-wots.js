import * as hg from '../primitives/hg-wots.js';
import { bytes, num } from '../scheme.js';
import { hashCalls, signatureBudget } from '../common-results.js';
import { CHAIN_CELL, svg, verticalChain } from '../draw.js';
import { clampState } from '../tradeoff.js';

// HG-WOTS as a few-time signature on its own. Defaults are the HGT baseline
// leaf (k, s, chain length, d_g, j, group chain length, d_h) =
// (7, 4, 16, 20, 5, 8, 11).

const KEY = 'HG-WOTS';

// A key in the shape js/primitives/hg-wots.js takes: one level of k groups
// that opens the k - j revealed ones.
export const leafOf = (s) => ({
  levels: [{ units: s.k, open: s.k - s.j, length: s.gl, sum: s.dh }],
  bottom: { chains: s.s, length: s.w, sum: s.dg },
});

export const pow2 = (x) => (Number.isFinite(x) ? `\\(2^{-${x.toFixed(1)}}\\)` : '?');

// The q parameter, shared with HagGrid.
export const qParameter = {
  key: 'q', type: 'range', min: 1, max: hg.Q_MAX, step: 1, default: 1,
  label: '\\(q\\) (signatures on this key)',
  tooltip: 'Signatures this key has already made, each on a different message. The forgery probability below is after \\(q\\) signatures.',
};

// Figures shared with HagGrid, for a key in the primitive's shape.
export function keyModel(state, leaf) {
  const nodes = hg.nodes(leaf);
  return {
    nodes,
    forgeryLog2: hg.keyForgeryBits(leaf)[state.q],
    sizes: { sig: nodes * state.n },
    calls: {
      keygen: { th: hg.keygen(leaf) },
      sign: { th: hg.sign(leaf) },
      verify: { th: hg.verify(leaf) },
    },
  };
}

// Result groups shared with HagGrid.
export function keyResults({ keygenTooltip, signTooltip, verifyTooltip }) {
  return [
    {
      rows: [
        { label: 'Nodes per signature', value: (d) => num(d.nodes) },
        { label: 'Signature', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Hash calls',
      rows: [
        { label: 'Key generation', tooltip: keygenTooltip, value: (d) => hashCalls(d.calls.keygen, num) },
        { label: 'Signing', tooltip: signTooltip, value: (d) => hashCalls(d.calls.sign, num) },
        { label: 'Verification', tooltip: verifyTooltip, value: (d) => hashCalls(d.calls.verify, num) },
      ],
    },
    signatureBudget({
      label: 'Forgery probability after \\(q\\) signatures',
      tooltip: 'Probability that a new message gets a signature an attacker can compute by hashing forward from the nodes of \\(q\\) past signatures on this key. Each message an attacker tries succeeds with this probability.',
      value: (d) => pow2(d.forgeryLog2),
    }),
  ];
}

const hgWots = {
  id: 'hg-wots',
  title: 'HG-WOTS',
  groups: { [KEY]: 'var(--c-ca6702)' },

  parameters: [
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128, group: KEY,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Size of each hash in bits, which sets how many bytes a signature takes.',
    },
    {
      key: 'k', type: 'range', min: 2, max: 8, step: 1, default: 7, group: KEY,
      label: '\\(k\\) (groups)',
      tooltip: 'The chain ends of each group hash into the start of its group chain, and the ends of the \\(k\\) group chains hash into the public key.',
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
    qParameter,
  ],

  // Clamped, since a state can hold values its own bounds rule out, such as
  // j >= k, before the parameters panel clamps it.
  derive(state) {
    const s = clampState(this.parameters, state);
    return keyModel(s, leafOf(s));
  },

  results: keyResults({
    keygenTooltip: 'Every chain and group chain to its end, one hash call per group on its chain ends, and one on the group chain ends for the public key.',
    signTooltip: 'Every chain from its start up to the node the signature sends. A hidden group\'s group chain starts from its chain ends, so the signer builds that group in full. The fixed sums make this the same for every message.',
    verifyTooltip: 'The walks from the sent nodes to their chain ends, \\(k - j\\) hash calls on chain ends, every revealed group chain from its start, and the hash call for the public key.',
  }),
};

export default hgWots;

// One key signing a sampled message.
function leafSvg(s, sample) {
  const W = 560;
  const g = svg();
  const { width, height, gap } = CHAIN_CELL;
  const keyX = W / 2, keyY = 28;
  const groupW = (W - 40) / s.k;
  const groupTop = 76;
  const groupBottom = groupTop + s.gl * (height + gap);
  const chainsTop = groupBottom + 34;

  g.text(keyX, keyY - 14, 'Public key = hash call on the k group chain ends');
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
