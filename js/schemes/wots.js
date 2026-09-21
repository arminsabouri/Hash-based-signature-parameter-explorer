import { compressions, tweakedCompressions } from '../sha256.js';
import { bytes, num } from '../scheme.js';

// WOTS-TW, Section 4 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".
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

// Distribution of the message digit sum S for a uniformly random n-bit message.
function digitSumDistribution(w, len1, topBits) {
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

export default {
  id: 'wots',
  title: 'WOTS-TW',

  parameters: [
    {
      key: 'n', type: 'range', min: 8, max: 256, step: 8, default: 128,
      ticks: [32, 64, 128, 256],
      label: '\\(n\\) (hash output bits)',
      tooltip: 'Hash output length in bits, which is also the length of the signed message. Every chain value is \\(n\\) bits.',
    },
    {
      key: 'b', type: 'range', min: 1, max: 8, step: 1, default: 4,
      display: (b) => 2 ** b,
      label: '\\(w\\) (Winternitz parameter)',
      tooltip: 'Each chain has \\(w\\) values and encodes \\(\\log_2 w\\) message bits. A larger \\(w\\) gives fewer, longer chains.',
    },
    {
      key: 'compressed', type: 'checkbox', default: true,
      label: 'Public key compression',
      tooltip: 'The \\(\\mathrm{len}\\) chain ends are hashed into one \\(n\\)-bit public key. The verifier recomputes every chain end from the signature, so the signature size is unchanged.',
    },
  ],

  derive({ n, b, compressed }) {
    const { w, len1, len2, len, topBits } = lengths(n, b);
    const chainSteps = len * (w - 1);

    // Verification steps for checksum value C: the message chains need
    // sum(w - 1 - a_i) = C steps, the checksum chains need sum(w - 1 - c_j).
    const verifySteps = (C) => C + len2 * (w - 1) - digits(C, w, len2).reduce((a, x) => a + x, 0);

    const maxS = (len1 - 1) * (w - 1) + 2 ** topBits - 1;
    const dist = digitSumDistribution(w, len1, topBits);
    let avgVerify = 0, worstVerify = 0, worstSign = 0;
    for (let S = 0; S <= maxS; S++) {
      const v = verifySteps(len1 * (w - 1) - S);
      avgVerify += dist[S] * v;
      worstVerify = Math.max(worstVerify, v);
      worstSign = Math.max(worstSign, chainSteps - v);
    }
    const avgSign = chainSteps - avgVerify;

    const pBits = n;
    const skBits = n + pBits; // SK.seed and P
    const pkBits = (compressed ? n : len * n) + pBits;
    const sigBits = len * n;

    // SHA-256 compressions: chain steps and PRF calls take an n-bit input;
    // the public key compression call takes all len chain ends.
    const call = tweakedCompressions(n / 8);
    const pkCall = compressed ? tweakedCompressions(len * n / 8) : 0;
    const pkCalls = compressed ? 1 : 0;

    return {
      w, len1, len2, len,
      skBits, pkBits, sigBits,
      pkCalls,
      keygenPrf: len, keygenSteps: chainSteps,
      avgSign, worstSign, avgVerify, worstVerify,
      keygenCompressions: (len + chainSteps) * call + pkCall + 1,
      avgSignCompressions: (len + avgSign) * call + 1,
      worstSignCompressions: (len + worstSign) * call + 1,
      avgVerifyCompressions: avgVerify * call + pkCall + 1,
      worstVerifyCompressions: worstVerify * call + pkCall + 1,
      perBlock: Math.floor(4000000 / ((sigBits + pkBits) / 8)),
    };
  },

  results: [
    {
      heading: 'Chains',
      tooltip: '\\(\\mathrm{len}_1 = \\lceil n / \\log_2 w \\rceil\\) chains sign the message and \\(\\mathrm{len}_2\\) chains sign the checksum, whose maximum is \\(\\mathrm{len}_1 (w-1)\\).',
      rows: [
        { label: '\\(\\mathrm{len}_1\\)', value: (d) => num(d.len1) },
        { label: '\\(\\mathrm{len}_2\\)', value: (d) => num(d.len2) },
        { label: '\\(\\mathrm{len}\\)', value: (d) => num(d.len) },
      ],
    },
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.skBits) },
        { label: 'Public key', value: (d) => bytes(d.pkBits) },
        { label: 'Signature', value: (d) => bytes(d.sigBits) },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation computes every chain to its end. Signing computes chain \\(i\\) up to position \\(b_i\\) and verification finishes it, so together they take \\(\\mathrm{len}(w-1)\\) steps. Worst case is the maximum over all messages.',
      rows: [
        {
          label: 'Key generation',
          value: (d) => `${num(d.keygenPrf)} \\(\\mathbf{PRF}\\) + ${num(d.keygenSteps + d.pkCalls)} \\(\\mathrm{Th}\\)`,
        },
        { label: 'Signing (average)', value: (d) => `${num(d.len)} \\(\\mathbf{PRF}\\) + ${num(Math.round(d.avgSign))} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (worst case)', value: (d) => `${num(d.len)} \\(\\mathbf{PRF}\\) + ${num(d.worstSign)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification (average)', value: (d) => `${num(Math.round(d.avgVerify + d.pkCalls))} \\(\\mathrm{Th}\\)` },
        { label: 'Verification (worst case)', value: (d) => `${num(d.worstVerify + d.pkCalls)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. Calls follow FIPS 205: a cached \\(\\mathrm{PK.seed}\\) block, then a 22-byte \\(\\mathrm{ADRS}^c\\) and the input. The cached block adds one compression per operation.',
      rows: [
        { label: 'Key generation', value: (d) => num(d.keygenCompressions) },
        { label: 'Signing (average)', value: (d) => num(Math.round(d.avgSignCompressions)) },
        { label: 'Signing (worst case)', value: (d) => num(d.worstSignCompressions) },
        { label: 'Verification (average)', value: (d) => num(Math.round(d.avgVerifyCompressions)) },
        { label: 'Verification (worst case)', value: (d) => num(d.worstVerifyCompressions) },
      ],
    },
    {
      heading: 'Signature budget',
      rows: [
        {
          label: 'Signatures per key pair',
          tooltip: 'Two signatures on different messages reveal, in each chain, the lower of the two positions. Any message whose digits are all at or above those positions can then be signed.',
          value: () => '1',
        },
      ],
    },
    {
      heading: 'Block space',
      rows: [
        {
          label: 'Signature + public key per 4,000,000 WU block',
          tooltip: 'The BIP 141 block weight limit divided by signature plus public key bytes, counted as witness data at 1 WU per byte. Transaction overhead is not included.',
          value: (d) => num(d.perBlock),
        },
      ],
    },
  ],
};

// Visualization state, nested inside the scheme component.
export function wotsChains() {
  return {
    // Random message bits for the largest n; the first n are used.
    bits: Array.from({ length: 256 }, () => (Math.random() < 0.5 ? 1 : 0)),

    get lengths() {
      return lengths(this.state.n, this.state.b);
    },

    // Message digits b_1..b_len1: the n-bit message as a base-w integer.
    get messageDigits() {
      const { len1, topBits } = this.lengths;
      const b = this.state.b;
      const out = [];
      let pos = 0;
      for (let i = 0; i < len1; i++) {
        const width = i === 0 ? topBits : b;
        let v = 0;
        for (let k = 0; k < width; k++) v = v * 2 + this.bits[pos++];
        out.push(v);
      }
      return out;
    },

    get checksum() {
      const w = this.lengths.w;
      return this.messageDigits.reduce((a, x) => a + (w - 1 - x), 0);
    },

    get checksumDigits() {
      return digits(this.checksum, this.lengths.w, this.lengths.len2);
    },

    // Increment message digit i, wrapping within its range.
    bump(i) {
      const { topBits } = this.lengths;
      const b = this.state.b;
      const width = i === 0 ? topBits : b;
      const start = i === 0 ? 0 : topBits + (i - 1) * b;
      const v = (this.messageDigits[i] + 1) % 2 ** width;
      for (let k = 0; k < width; k++) this.bits[start + k] = (v >> (width - 1 - k)) & 1;
    },

    // Message chain indexes to draw; null marks the ellipsis.
    get messageRows() {
      const len1 = this.lengths.len1;
      if (len1 <= 6) return [...Array(len1).keys()];
      return [0, 1, 2, null, len1 - 1];
    },

    // Chain positions 0..w-1 drawn as cells when w <= 16.
    get positions() {
      return [...Array(this.lengths.w).keys()];
    },

    // DOM for one chain with the value at position `digit` revealed. Positions
    // are cells when w <= 16 and a proportional bar otherwise.
    chainCells(digit) {
      const w = this.lengths.w;
      const el = (cls, style) => {
        const d = document.createElement('div');
        d.className = cls;
        if (style) d.style.cssText = style;
        return d;
      };
      if (w <= 16) {
        return Array.from({ length: w }, (_, j) =>
          el('chain-cell ' + (j < digit ? 'signer' : j === digit ? 'revealed' : 'verifier')));
      }
      const pct = (x) => (100 * x) / (w - 1);
      return [
        el('chain-bar signer', `width: ${pct(digit)}%`),
        el('chain-bar-marker', `left: ${pct(digit)}%`),
        el('chain-bar verifier', `left: ${pct(digit)}%; width: ${100 - pct(digit)}%`),
      ];
    },
  };
}
