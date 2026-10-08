import * as hg from '../primitives/hg-wots.js';
import { CHAIN_CELL, svg, verticalChain } from '../draw.js';
import { clampState } from '../tradeoff.js';
import { keyModel, keyResults, newSeed, qParameter, seeded } from './hg-wots.js';

// HagGrid, nested HG-WOTS, as a few-time signature on its own. Defaults are
// (4, 3, 16, 15) three times over a (4, 4, 16, 20) bottom group, 13 nodes per
// signature.

const LEAF = 'HagGrid';
const BOTTOM = 'Bottom group';

// A key in the shape js/primitives/hg-wots.js takes: `levels` levels of the
// same shape over a bottom group.
export const leafOf = (s) => ({
  levels: Array.from({ length: s.levels }, () => ({ units: s.u, open: 1, length: s.l, sum: s.h })),
  bottom: { chains: s.c, length: s.bw, sum: s.bs },
});

const haggrid = {
  id: 'haggrid',
  title: 'HagGrid',
  groups: { [LEAF]: 'var(--c-ca6702)', [BOTTOM]: 'var(--c-94d2bd)' },

  parameters: [
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128, group: LEAF,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Size of each hash in bits, which sets how many bytes a signature takes.',
    },
    {
      key: 'levels', type: 'range', min: 1, max: 4, step: 1, default: 3, group: LEAF,
      label: 'Levels',
      tooltip: 'Levels of units above the bottom group, all with the units, chain length and distance sum below. The top level\'s chain ends hash into the public key.',
    },
    {
      key: 'u', type: 'range', min: 2, step: 1, default: 4, group: LEAF,
      max: (s) => Math.min(8, hg.maxCount(s.l) + 1),
      label: 'Units',
      tooltip: 'Units at each level. The signature opens one and sends one node on the chain of each of the others.',
    },
    {
      key: 'l', type: 'range', min: 2, max: 16, step: 1, default: 16, group: LEAF,
      label: 'Chain length',
      tooltip: 'Values on the chain of each unit, its end included. The verifier walks the opened unit\'s chain from its start.',
    },
    {
      key: 'h', type: 'range', min: 0, step: 1, default: 15, group: LEAF,
      max: (s) => (s.u - 1) * (s.l - 1),
      label: 'Distance sum over hidden units',
      tooltip: 'At each level, the distances from the nodes of the hidden units to their chain ends sum to this. The verifier walks them.',
    },
    {
      key: 'c', type: 'range', min: 1, step: 1, default: 4, group: BOTTOM,
      max: (s) => Math.min(6, hg.maxCount(s.bw)),
      label: 'Chains',
      tooltip: 'Chains in each bottom group. The opened bottom group sends one node on each.',
    },
    {
      key: 'bw', type: 'range', min: 2, max: 16, step: 1, default: 16, group: BOTTOM,
      label: 'Chain length',
      tooltip: 'Values on each chain of a bottom group, its end included.',
    },
    {
      key: 'bs', type: 'range', min: 0, step: 1, default: 20, group: BOTTOM,
      max: (s) => s.c * (s.bw - 1),
      label: 'Distance sum',
      tooltip: 'The distances from the nodes of the opened bottom group to their chain ends sum to this. The verifier walks them.',
    },
    qParameter,
  ],

  // Clamped, since a state can hold values its own bounds rule out before the
  // parameters panel clamps it.
  derive(state) {
    const s = clampState(this.parameters, state);
    return keyModel(s, leafOf(s));
  },

  results: keyResults({
    keygenTooltip: 'Every chain to its end, one hash call per unit and per bottom group on the chain ends under it, and one on the top level\'s chain ends for the public key.',
    signTooltip: 'Every chain from its start up to the node the signature sends. A hidden unit\'s chain starts from the ends of everything under it, so the signer builds that unit in full. The fixed sums make this the same for every message.',
    verifyTooltip: 'The walks from the sent nodes to their chain ends, the opened unit\'s chain from its start at every level, and one hash call per level on chain ends, plus one for the bottom group.',
  }),
};

export default haggrid;

// A message sampled from `seed`: at every level the opened unit and the
// distances of the others, and the distances of the bottom group.
function sampleLeaf(leaf, seed) {
  const random = seeded(seed);
  return {
    levels: leaf.levels.map(({ units, length, sum }) => ({
      opened: Math.floor(random() * units),
      distances: hg.sampleDistances(units - 1, sum, length - 1, random),
    })),
    bottom: hg.sampleDistances(leaf.bottom.chains, leaf.bottom.sum, leaf.bottom.length - 1, random),
  };
}

// One key signing a sampled message, levels top first. Only the units under
// the opened ones are drawn.
function leafSvg(leaf, sample) {
  const W = 560;
  const g = svg();
  const { height, gap } = CHAIN_CELL;
  const cx = W / 2, spacing = 26;
  let anchor = { x: cx, y: 35 };
  let y = 76;

  g.text(cx, 14, 'Public key = hash call on the level 1 chain ends');
  leaf.levels.forEach(({ units, length }, i) => {
    const { opened, distances } = sample.levels[i];
    let next = null;
    let hidden = 0;
    for (let u = 0; u < units; u++) {
      const x = cx + (u - (units - 1) / 2) * spacing;
      g.line(anchor.x, anchor.y, x, y - 2, 'edge faint');
      if (u === opened) {
        const chain = verticalChain(g, x, y, length, { walked: true });
        next = { x, y: chain.bottom + 2 };
      } else {
        verticalChain(g, x, y, length, { reveal: length - 1 - distances[hidden++] });
      }
    }
    g.text(cx - (units / 2) * spacing - 16, y + (length * (height + gap)) / 2 + 4, `level ${i + 1}`, 'end');
    anchor = next;
    y += length * (height + gap) + 34;
  });

  const { chains, length } = leaf.bottom;
  for (let c = 0; c < chains; c++) {
    const x = cx + (c - (chains - 1) / 2) * 12;
    g.line(anchor.x, anchor.y, x, y - 2, 'edge faint');
    verticalChain(g, x, y, length, { reveal: length - 1 - sample.bottom[c] });
  }
  g.text(cx - (chains / 2) * 12 - 16, y + (length * (height + gap)) / 2 + 4, 'bottom group', 'end', 'label ots-label');
  g.circle(cx, 28, 7, 'tree-node');
  const bottom = y + length * (height + gap);
  return { svg: g.toString(), width: W, height: bottom + 12 };
}

// Visualization state, nested inside the scheme component. A new seed draws
// another message.
export function hagGridLeaf() {
  return {
    seed: newSeed(),

    resample() {
      this.seed = newSeed();
    },

    // Clamped, as the state can briefly hold values out of bounds.
    get drawing() {
      const leaf = leafOf(clampState(haggrid.parameters, this.state));
      return leafSvg(leaf, sampleLeaf(leaf, this.seed));
    },
  };
}
