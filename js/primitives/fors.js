import { tweakedCompressions } from '../sha256.js';

// FORS and FORS+C, Section 9 of Kudinov and Nick, "Hash-based Signature
// Schemes for Bitcoin". k trees of height a; each signature opens one leaf
// per tree. FORS+C grinds a counter until the last tree's index is 0, so that
// tree only reveals its first leaf and carries no authentication path.

export function parameters(group) {
  return [
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128, group,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Hash output length in bits. Every secret leaf, tree node, and root is \\(n\\) bits.',
    },
    {
      key: 'k', type: 'range', min: 1, max: 64, step: 1, default: 14, group,
      label: '\\(k\\) (number of trees)',
      tooltip: 'The message digest is split into \\(k\\) indices of \\(a\\) bits, one per tree. Each tree adds one revealed leaf and one authentication path to the signature.',
    },
    {
      key: 'a', type: 'range', min: 1, max: 24, step: 1, default: 12, group,
      label: '\\(a\\) (tree height)',
      tooltip: 'Each tree has \\(2^a\\) secret leaves. Each extra level doubles the key generation work and adds one \\(n\\)-bit node to every authentication path.',
    },
    {
      key: 'plusC', type: 'checkbox', default: false, group,
      label: 'FORS+C',
      tooltip: 'The signer grinds a counter until the last \\(a\\) digest bits are zero, so the last tree always opens its first leaf. That tree carries no authentication path, and the signer never builds it.',
    },
    {
      key: 'r', type: 'range', min: 8, max: 64, step: 8, default: 32, group,
      show: (s) => s.plusC,
      label: '\\(r\\) (counter bits)',
      tooltip: 'Size of the grinding counter carried in the signature.',
    },
  ];
}

// Signing uses the WC search: the number of trials that suffices except
// with probability 2^-30. `grindCall` is the compression cost of one trial.
export function model({ n, k, a, plusC, r }, grindCall = 0) {
  const t = 2 ** a;
  const built = plusC ? k - 1 : k; // trees with a full authentication path
  const call = tweakedCompressions(n / 8);
  const nodeCall = tweakedCompressions((2 * n) / 8);
  const rootsCall = tweakedCompressions((k * n) / 8);

  // FORS+C search: success probability 2^-a per trial.
  const p = plusC ? 2 ** -a : 1;
  const wcSearch = plusC ? Math.ceil((-30 * Math.LN2) / Math.log1p(-p)) : 1;
  const exhaustLog2 = plusC ? (2 ** r * Math.log1p(-p)) / Math.LN2 : -Infinity;

  // Every leaf of the built trees is PRF then Th; inner nodes are Th of two
  // children; the roots are compressed with one Th. FORS+C adds the last
  // tree's first leaf.
  const leaves = built * t + (plusC ? 1 : 0);
  const nodes = built * (t - 1);
  const keygen = {
    prf: leaves,
    th: leaves + nodes + 1,
    compressions: 2 * leaves * call + nodes * nodeCall + rootsCall,
  };

  return {
    t, built, p, wcSearch, exhaustLog2,
    sizes: {
      // Revealed leaf and authentication path per built tree, plus the first
      // leaf and the counter for FORS+C.
      sig: built * (a + 1) * n + (plusC ? n + r : 0),
      root: n,
    },
    keygen,
    // Without a cache: rebuild the trees, then PRF for the k revealed leaves.
    sign: {
      prf: keygen.prf + k,
      th: keygen.th - 1,
      compressions: keygen.compressions - rootsCall + k * call + (wcSearch - 1) * grindCall,
    },
    signCached: { prf: k, th: 0, compressions: k * call + (wcSearch - 1) * grindCall },
    // Th on each revealed leaf, a Th up each path, then the roots.
    verify: {
      th: built * (1 + a) + (plusC ? 1 : 0) + 1,
      compressions: (built + (plusC ? 1 : 0)) * call + built * a * nodeCall + rootsCall,
    },
  };
}

// log2 of the probability that a fresh digest opens only leaves already
// revealed by q signatures: each tree's index was hit with probability
// 1 - (1 - 2^-a)^q. For FORS+C the last tree is fixed, and the digest must
// also end in a zero bits.
export function forgeryLog2({ k, a, plusC }, q) {
  const hit = -Math.expm1(q * Math.log1p(-(2 ** -a)));
  return plusC ? (k - 1) * Math.log2(hit) - a : k * Math.log2(hit);
}
