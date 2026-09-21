import * as wotsC from '../primitives/wots-c.js';
import { chainsOf } from '../primitives/wots-c.js';
import { digitSumDistribution } from '../primitives/wots-tw.js';
import { approx, bytes, num } from '../scheme.js';
import {
  blockSpace, compressionsTooltip, oneTime, signatureBudget, successProbability, wcSearch,
} from '../common-results.js';
import { chainCells } from '../draw.js';

export default {
  id: 'wots-c',
  title: 'WOTS+C',

  parameters: [
    ...wotsC.parameters(),
    {
      key: 'compressed', type: 'checkbox', default: true,
      label: 'Public key compression',
      tooltip: 'The \\(l\\) chain ends are hashed into one \\(n\\)-bit public key. The verifier recomputes every chain end from the signature, so the signature size is unchanged.',
    },
  ],

  derive(state) {
    const m = wotsC.model(state);
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
      tooltip: 'Each trial hashes \\(m \\,\\|\\, \\mathrm{count}\\) once and succeeds with probability \\(p_\\nu = \\nu / w^{\\mathrm{len}_1}\\), where \\(\\nu\\) counts the digit tuples summing to \\(S_{w,n}\\). WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        successProbability,
        wcSearch,
        {
          label: 'Counter exhaustion probability',
          tooltip: 'Probability that none of the \\(2^r\\) counter values meets the conditions, \\((1 - p_\\nu)^{2^r}\\).',
          value: (d) => (d.exhaustLog2 > -10
            ? (2 ** d.exhaustLog2).toFixed(4)
            : `\\(2^{${Math.round(d.exhaustLog2).toLocaleString()}}\\)`),
        },
      ],
    },
    {
      heading: 'Hash calls',
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
        { label: 'Signing (WC search)', value: (d) => approx(d.signCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    signatureBudget(oneTime('Two signatures on different messages reveal, in each chain, the lower of the two positions. Any digest whose digits are all at or above those positions can then be signed.')),
    blockSpace,
  ],
};

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
