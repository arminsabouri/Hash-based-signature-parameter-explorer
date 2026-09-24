import { tweakedCompressions } from '../sha256.js';

// WOTS, Section 4 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".
// The message length m equals n, as in SPHINCS+.

const bitLength = (x) => (x === 0 ? 0 : Math.floor(Math.log2(x)) + 1);

// len1, len2, and the width in bits of the most significant message digit.
export function lengths(n, b) {
  const w = 2 ** b;
  const len1 = Math.ceil(n / b);
  // As in SHRINCS: ceildiv(bit_length(len1 * (w - 1)), log2 w).
  const len2 = Math.ceil(bitLength(len1 * (w - 1)) / b);
  const topBits = n - (len1 - 1) * b;
  return { w, len1, len2, len: len1 + len2, topBits };
}

// Base-w digits of x, most significant first.
export function digits(x, w, count) {
  const out = new Array(count);
  for (let j = count - 1; j >= 0; j--) {
    out[j] = x % w;
    x = Math.floor(x / w);
  }
  return out;
}

// Distribution of the digit sum of len1 digits: the first uniform over
// 2^topBits values, the rest uniform over w values. The same distribution is
// asked for repeatedly, so results are kept. Callers only read from them.
const distributions = new Map();

export function digitSumDistribution(w, len1, topBits) {
  const key = `${w}|${len1}|${topBits}`;
  const hit = distributions.get(key);
  if (hit) return hit;
  const dist = compute(w, len1, topBits);
  distributions.set(key, dist);
  return dist;
}

function compute(w, len1, topBits) {
  let dist = [1];
  const ranges = [2 ** topBits, ...new Array(len1 - 1).fill(w)];
  for (const r of ranges) {
    const next = new Array(dist.length + r - 1).fill(0);
    // Sliding window sum of the previous distribution over r values.
    let window = 0;
    for (let s = 0; s < next.length; s++) {
      if (s < dist.length) window += dist[s];
      if (s - r >= 0) window -= dist[s - r];
      next[s] = window / r;
    }
    dist = next;
  }
  return dist;
}

export function parameters(group) {
  return [
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128, group,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Hash output length in bits, which is also the length of the signed message. Every chain value is \\(n\\) bits.',
    },
    {
      key: 'b', type: 'range', min: 1, max: 8, step: 1, default: 4, group,
      display: (b) => 2 ** b,
      label: '\\(w\\) (Winternitz parameter)',
      tooltip: 'Each chain has \\(w\\) values and encodes \\(\\log_2 w\\) message bits. A larger \\(w\\) gives fewer, longer chains.',
    },
  ];
}

// Worst-case signing and verification over all messages.
export function model({ n, b, compressed = true }) {
  const { w, len1, len2, len, topBits } = lengths(n, b);
  const chainSteps = len * (w - 1);

  // Verification steps for checksum value C: the message chains need
  // sum(w - 1 - a_i) = C steps, the checksum chains need sum(w - 1 - c_j).
  const verifySteps = (C) => C + len2 * (w - 1) - digits(C, w, len2).reduce((a, x) => a + x, 0);

  const maxS = (len1 - 1) * (w - 1) + 2 ** topBits - 1;
  let worstVerify = 0, worstSign = 0;
  for (let S = 0; S <= maxS; S++) {
    const v = verifySteps(len1 * (w - 1) - S);
    worstVerify = Math.max(worstVerify, v);
    worstSign = Math.max(worstSign, chainSteps - v);
  }

  // Chain steps and PRF calls take an n-bit input; the public key
  // compression call takes all len chain ends.
  const call = tweakedCompressions(n / 8);
  const pkCalls = compressed ? 1 : 0;
  const pkCall = compressed ? tweakedCompressions(len * n / 8) : 0;
  const pBits = n;

  return {
    w, len1, len2, len,
    sizes: {
      sk: n + pBits, // SK.seed and P
      pk: (compressed ? n : len * n) + pBits,
      sig: len * n,
    },
    keygen: { prf: len, th: chainSteps + pkCalls, compressions: (len + chainSteps) * call + pkCall },
    sign: { prf: len, th: worstSign, compressions: (len + worstSign) * call },
    verify: { th: worstVerify + pkCalls, compressions: worstVerify * call + pkCall },
  };
}
