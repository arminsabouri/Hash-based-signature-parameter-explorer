import * as wotsTw from '../primitives/wots-tw.js';
import { digits, lengths } from '../primitives/wots-tw.js';
import { bytes, num } from '../scheme.js';
import { blockSpace, compressionsTooltip, oneTime, signatureBudget } from '../common-results.js';
import { chainCells } from '../draw.js';

export default {
  id: 'wots',
  title: 'WOTS-TW',

  parameters: [
    ...wotsTw.parameters(),
    {
      key: 'compressed', type: 'checkbox', default: true,
      label: 'Public key compression',
      tooltip: 'The \\(\\mathrm{len}\\) chain ends are hashed into one \\(n\\)-bit public key. The verifier recomputes every chain end from the signature, so the signature size is unchanged.',
    },
  ],

  derive(state) {
    const m = wotsTw.model(state);
    // Each operation also computes the cached PK.seed midstate once.
    return {
      ...m,
      keygenCompressions: m.keygen.compressions + 1,
      signCompressions: m.sign.compressions + 1,
      verifyCompressions: m.verify.compressions + 1,
    };
  },

  results: [
    {
      heading: 'Chains',
      tooltip: '\\(\\mathrm{len}_1 = \\lceil n / \\log_2 w \\rceil\\) chains sign the message and \\(\\mathrm{len}_2\\) chains sign the checksum, whose maximum is \\(\\mathrm{len}_1 (w-1)\\).',
      rows: [
        { label: 'Message chains (\\(\\mathrm{len}_1\\))', value: (d) => num(d.len1) },
        { label: 'Checksum chains (\\(\\mathrm{len}_2\\))', value: (d) => num(d.len2) },
        { label: 'Total chains (\\(\\mathrm{len}\\))', value: (d) => num(d.len) },
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
      heading: 'Hash calls',
      tooltip: 'Key generation computes every chain to its end. Signing computes chain \\(i\\) up to position \\(b_i\\) and verification finishes it, so together they take \\(\\mathrm{len}(w-1)\\) steps. Worst case is the maximum over all messages.',
      rows: [
        { label: 'Key generation', value: (d) => `${num(d.keygen.prf)} \\(\\mathbf{PRF}\\) + ${num(d.keygen.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (worst case)', value: (d) => `${num(d.sign.prf)} \\(\\mathbf{PRF}\\) + ${num(d.sign.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification (worst case)', value: (d) => `${num(d.verify.th)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: compressionsTooltip,
      rows: [
        { label: 'Key generation', value: (d) => num(d.keygenCompressions) },
        { label: 'Signing (worst case)', value: (d) => num(d.signCompressions) },
        { label: 'Verification (worst case)', value: (d) => num(d.verifyCompressions) },
      ],
    },
    signatureBudget(oneTime('Two signatures on different messages reveal, in each chain, the lower of the two positions. Any message whose digits are all at or above those positions can then be signed.')),
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
