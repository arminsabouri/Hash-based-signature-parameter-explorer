import { tweakedCompressions } from '../sha256.js';
import { approx, bytes, num } from '../scheme.js';
import { chainCells, digitSumDistribution } from './wots.js';

// WOTS+C, Section 5 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".

const len1Of = ({ n, b }) => Math.ceil(n / b);
const chainsOf = (state) => len1Of(state) - state.z;
const centerSum = (state) => Math.ceil((chainsOf(state) * (2 ** state.b - 1)) / 2);

export default {
  id: 'wots-c',
  title: 'WOTS+C',

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
      tooltip: 'Each chain has \\(w\\) values and encodes \\(\\log_2 w\\) digest bits. A larger \\(w\\) gives fewer, longer chains.',
    },
    {
      key: 'z', type: 'range', min: 0, max: (s) => Math.min(8, len1Of(s) - 1), step: 1, default: 0,
      label: '\\(z\\) (zero-chains)',
      tooltip: 'The last \\(z\\) digest digits must be zero, so those chains are left out of the signature. Each zero-chain multiplies the expected counter trials by \\(w\\).',
    },
    {
      key: 'S', type: 'range', min: 0, max: (s) => chainsOf(s) * (2 ** s.b - 1), step: 1,
      default: centerSum, resetOn: ['n', 'b', 'z'],
      label: '\\(S_{w,n}\\) (target sum)',
      tooltip: 'The signer grinds a counter until the digits of the \\(l\\) signed chains sum to \\(S_{w,n}\\), which replaces the checksum chains. Verification always takes \\(l(w-1) - S_{w,n}\\) steps, and \\(l(w-1)/2\\) needs the fewest counter trials.',
    },
    {
      key: 'r', type: 'range', min: 8, max: 64, step: 8, default: 32,
      label: '\\(r\\) (counter bits)',
      tooltip: 'Size of the counter carried in the signature. The paper counts 4 bytes and SHRINCS uses 2.',
    },
    {
      key: 'compressed', type: 'checkbox', default: true,
      label: 'Public key compression',
      tooltip: 'The \\(l\\) chain ends are hashed into one \\(n\\)-bit public key. The verifier recomputes every chain end from the signature, so the signature size is unchanged.',
    },
  ],

  derive(state) {
    const { n, b, z, S, r, compressed } = state;
    const w = 2 ** b;
    const len1 = len1Of(state);
    const l = len1 - z;

    // p_nu = nu / w^len1: the l signed digits sum to S and the z zero digits are 0.
    const dist = digitSumDistribution(w, l, b);
    const p = (dist[S] ?? 0) * w ** -z;
    const expectedSearch = 1 / p;
    // Trials that suffice except with probability 2^-30, as in the paper's tables.
    const wcSearch = Math.ceil((-30 * Math.LN2) / Math.log1p(-p));
    // log2 of the probability that all 2^r counter values fail.
    const exhaustLog2 = (2 ** r * Math.log1p(-p)) / Math.LN2;

    const pBits = n;
    const skBits = n + pBits; // SK.seed and P
    const pkBits = (compressed ? n : l * n) + pBits;
    const sigBits = l * n + r;

    const signSteps = S;
    const verifySteps = l * (w - 1) - S;
    const pkCalls = compressed ? 1 : 0;

    const call = tweakedCompressions(n / 8);
    const grindCall = tweakedCompressions((n + r) / 8);
    const pkCall = compressed ? tweakedCompressions(l * n / 8) : 0;

    return {
      w, len1, l, p,
      expectedSearch, wcSearch, exhaustLog2,
      skBits, pkBits, sigBits,
      pkCalls, signSteps, verifySteps,
      keygenSteps: l * (w - 1),
      keygenCompressions: (l + l * (w - 1)) * call + pkCall + 1,
      expSignCompressions: (l + signSteps) * call + expectedSearch * grindCall + 1,
      wcSignCompressions: (l + signSteps) * call + wcSearch * grindCall + 1,
      verifyCompressions: verifySteps * call + grindCall + pkCall + 1,
      perBlock: Math.floor(4000000 / ((sigBits + pkBits) / 8)),
    };
  },

  results: [
    {
      heading: 'Chains',
      tooltip: '\\(\\mathrm{len}_1 = \\lceil n / \\log_2 w \\rceil\\) digest digits, of which the last \\(z\\) are zero. Only \\(l = \\mathrm{len}_1 - z\\) chains are signed, and there are no checksum chains.',
      rows: [
        { label: '\\(\\mathrm{len}_1\\)', value: (d) => num(d.len1) },
        { label: '\\(l\\)', value: (d) => num(d.l) },
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
      heading: 'Search',
      tooltip: 'Each trial hashes \\(m \\,\\|\\, \\mathrm{count}\\) once and succeeds with probability \\(p_\\nu = \\nu / w^{\\mathrm{len}_1}\\), where \\(\\nu\\) counts the digit tuples summing to \\(S_{w,n}\\). WC search is the number of trials that suffices except with probability \\(2^{-30}\\), as in the paper\'s tables.',
      rows: [
        { label: '\\(p_\\nu\\)', value: (d) => (d.p >= 1e-4 ? d.p.toFixed(4) : `\\(2^{${Math.log2(d.p).toFixed(1)}}\\)`) },
        { label: 'Expected search', value: (d) => approx(d.expectedSearch) },
        { label: 'WC search', value: (d) => approx(d.wcSearch) },
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
        {
          label: 'Key generation',
          value: (d) => `${num(d.l)} \\(\\mathbf{PRF}\\) + ${num(d.keygenSteps + d.pkCalls)} \\(\\mathrm{Th}\\)`,
        },
        { label: 'Signing (expected search)', value: (d) => `${num(d.l)} \\(\\mathbf{PRF}\\) + ${approx(d.signSteps + d.expectedSearch)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (WC search)', value: (d) => `${num(d.l)} \\(\\mathbf{PRF}\\) + ${approx(d.signSteps + d.wcSearch)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification', value: (d) => `${num(d.verifySteps + 1 + d.pkCalls)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. Calls follow FIPS 205: a cached \\(\\mathrm{PK.seed}\\) block, then a 22-byte \\(\\mathrm{ADRS}^c\\) and the input. The cached block adds one compression per operation.',
      rows: [
        { label: 'Key generation', value: (d) => num(d.keygenCompressions) },
        { label: 'Signing (expected search)', value: (d) => approx(d.expSignCompressions) },
        { label: 'Signing (WC search)', value: (d) => approx(d.wcSignCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    {
      heading: 'Signature budget',
      rows: [
        {
          label: 'Signatures per key pair',
          tooltip: 'Two signatures on different messages reveal, in each chain, the lower of the two positions. Any digest whose digits are all at or above those positions can then be signed.',
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
