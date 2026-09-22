import * as wotsTw from '../primitives/wots-tw.js';
import * as wotsC from '../primitives/wots-c.js';
import { chainsOf } from '../primitives/wots-c.js';
import { digitSumDistribution, digits, lengths } from '../primitives/wots-tw.js';
import { approx, bytes, num } from '../scheme.js';
import {
  blockSpace, compressionsTooltip, counterExhaustion, oneTime, signatureBudget, successProbability, wcSearch,
  withMidstate,
} from '../common-results.js';
import { chainCells } from '../draw.js';

// WOTS-TW, with a toggle to WOTS+C. The WOTS+C parameters z, S, and r are
// shown only when it is on.

const tw = (d) => !d.plusC;
const plusC = (d) => d.plusC;

export default {
  id: 'wots',
  title: (s) => (s.plusC ? 'WOTS+C' : 'WOTS-TW'),

  parameters: [
    ...wotsTw.parameters(),
    {
      key: 'plusC', type: 'checkbox', default: false,
      label: 'WOTS+C',
      tooltip: 'The signer grinds a counter until the digest digits sum to \\(S_{w,n}\\), which replaces the checksum chains. The signature carries the counter instead.',
    },
    ...wotsC.parameters().filter((p) => ['z', 'S', 'r'].includes(p.key)).map((p) => ({ ...p, show: (s) => s.plusC })),
    {
      key: 'compressed', type: 'checkbox', default: true,
      label: 'Public key compression',
      tooltip: 'The chain ends are hashed into one \\(n\\)-bit public key. The verifier recomputes every chain end from the signature, so the signature size is unchanged.',
    },
  ],

  derive(state) {
    const m = state.plusC ? wotsC.model(state) : wotsTw.model(state);
    return { ...m, plusC: state.plusC, ...withMidstate(m) };
  },

  results: [
    {
      heading: 'Chains',
      show: tw,
      tooltip: '\\(\\mathrm{len}_1 = \\lceil n / \\log_2 w \\rceil\\) chains sign the message and \\(\\mathrm{len}_2\\) chains sign the checksum, whose maximum is \\(\\mathrm{len}_1 (w-1)\\).',
      rows: [
        { label: 'Message chains (\\(\\mathrm{len}_1\\))', value: (d) => num(d.len1) },
        { label: 'Checksum chains (\\(\\mathrm{len}_2\\))', value: (d) => num(d.len2) },
        { label: 'Total chains (\\(\\mathrm{len}\\))', value: (d) => num(d.len) },
      ],
    },
    {
      heading: 'Chains',
      show: plusC,
      tooltip: '\\(\\mathrm{len}_1 = \\lceil n / \\log_2 w \\rceil\\) digest digits, of which the last \\(z\\) are zero. Only \\(l = \\mathrm{len}_1 - z\\) chains are signed, and there are no checksum chains.',
      rows: [
        { label: 'Digest digits (\\(\\mathrm{len}_1\\))', value: (d) => num(d.len1) },
        { label: 'Signed chains (\\(l\\))', value: (d) => num(d.l) },
      ],
    },
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.sizes.sk) },
        { label: 'Public key', value: (d) => bytes(d.sizes.pk) },
        { label: 'Signature', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Search',
      show: plusC,
      tooltip: 'Each trial hashes \\(m \\,\\|\\, \\mathrm{count}\\) once and succeeds with probability \\(p_\\nu = \\nu / w^{\\mathrm{len}_1}\\), where \\(\\nu\\) counts the digit tuples summing to \\(S_{w,n}\\). WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        successProbability,
        wcSearch,
        counterExhaustion('Probability that none of the \\(2^r\\) counter values meets the conditions, \\((1 - p_\\nu)^{2^r}\\).'),
      ],
    },
    {
      heading: 'Hash calls',
      show: tw,
      tooltip: 'Key generation computes every chain to its end. Signing computes chain \\(i\\) up to position \\(b_i\\) and verification finishes it, so together they take \\(\\mathrm{len}(w-1)\\) steps. Worst case is the maximum over all messages.',
      rows: [
        { label: 'Key generation', value: (d) => `${num(d.keygen.prf)} \\(\\mathbf{PRF}\\) + ${num(d.keygen.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (worst case)', value: (d) => `${num(d.sign.prf)} \\(\\mathbf{PRF}\\) + ${num(d.sign.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification (worst case)', value: (d) => `${num(d.verify.th)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'Hash calls',
      show: plusC,
      tooltip: 'Signing computes chain \\(i\\) up to position \\(a_i\\), \\(S_{w,n}\\) steps in total, plus one \\(\\mathrm{Th}\\) per search trial. Verification recomputes the digest once and takes \\(l(w-1) - S_{w,n}\\) steps for every message.',
      rows: [
        { label: 'Key generation', value: (d) => `${num(d.keygen.prf)} \\(\\mathbf{PRF}\\) + ${num(d.keygen.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (WC search)', value: (d) => `${num(d.sign.prf)} \\(\\mathbf{PRF}\\) + ${approx(d.sign.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification', value: (d) => `${num(d.verify.th)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: compressionsTooltip,
      rows: [
        { label: 'Key generation', value: (d) => num(d.keygenCompressions) },
        { label: 'Signing (worst case)', show: tw, value: (d) => num(d.signCompressions) },
        { label: 'Verification (worst case)', show: tw, value: (d) => num(d.verifyCompressions) },
        { label: 'Signing (WC search)', show: plusC, value: (d) => approx(d.signCompressions) },
        { label: 'Verification', show: plusC, value: (d) => num(d.verifyCompressions) },
      ],
    },
    signatureBudget(oneTime('Two signatures on different messages reveal, in each chain, the lower of the two positions. Any message (for WOTS+C, any digest) whose digits are all at or above those positions can then be signed.')),
    blockSpace,
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

    chainCells(digit) {
      return chainCells(this.lengths.w, digit);
    },
  };
}

// Visualization state, nested inside the scheme component. Shows one digest
// that meets the conditions, sampled uniformly among those that do.
export function wotsCChains() {
  return {
    digits: [],

    init() {
      this.resample();
      this.$watch('state', () => this.resample());
    },

    get w() { return 2 ** this.state.b; },
    get l() { return chainsOf(this.state); },

    // Sample l digits in [0, w-1] summing to S, uniformly among such tuples.
    resample() {
      const w = this.w, l = this.l, S = Math.min(this.state.S, l * (w - 1));
      const tables = [[1]];
      for (let k = 1; k <= l; k++) tables.push(digitSumDistribution(w, k, this.state.b));
      const out = [];
      let s = S;
      for (let i = 0; i < l; i++) {
        const rest = tables[l - i - 1];
        const weights = [];
        for (let a = 0; a <= Math.min(w - 1, s); a++) weights.push(rest[s - a] ?? 0);
        let u = Math.random() * weights.reduce((x, y) => x + y, 0);
        let a = 0;
        while (a < weights.length - 1 && (u -= weights[a]) > 0) a++;
        out.push(a);
        s -= a;
      }
      this.digits = out;
    },

    get rows() {
      const l = this.l;
      if (l <= 6) return [...Array(l).keys()];
      return [0, 1, 2, null, l - 1];
    },

    get zeroRows() {
      return [...Array(this.state.z).keys()];
    },

    get digitSum() {
      return this.digits.reduce((a, x) => a + x, 0);
    },

    chainCells(digit) {
      return chainCells(this.w, digit);
    },
  };
}
