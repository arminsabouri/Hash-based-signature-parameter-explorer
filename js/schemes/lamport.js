import { tweakedCompressions } from '../sha256.js';
import { bytes, num } from '../scheme.js';

// Lamport OTS, Section 3 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".
export default {
  id: 'lamport',
  title: 'Lamport OTS',

  parameters: [
    {
      key: 'n', type: 'range', min: 1, max: 512, step: 1, default: 128,
      ticks: [32, 64, 128, 256, 512],
      label: '\\(n\\) (message bits)',
      tooltip: 'Length of the signed message in bits. Each bit has two secret values, so key and signature sizes grow linearly with \\(n\\).',
    },
    {
      key: 'N', type: 'range', min: 8, max: 256, step: 8, default: 256,
      ticks: [32, 64, 128, 256],
      label: '\\(N\\) (hash output bits)',
      tooltip: 'Output length of the hash function in bits. Every secret value, public key element, and signature element is \\(N\\) bits.',
    },
    {
      key: 'seedBased', type: 'checkbox', default: true,
      label: 'Seed-based generation of secret keys',
      tooltip: 'Secret values are derived from one seed with a \\(\\mathbf{PRF}\\) instead of being stored. The secret key shrinks to the seed, and signing recomputes the revealed values.',
    },
  ],

  derive({ n, N, seedBased }) {
    // The public parameter P is taken to be N bits.
    const pBits = N;
    const skBits = (seedBased ? N : 2 * n * N) + pBits;
    const pkBits = 2 * n * N + pBits;
    const sigBits = n * N;

    const keygenHashCalls = 2 * n;
    const keygenPrfCalls = seedBased ? 2 * n : 0;
    const signPrfCalls = seedBased ? n : 0;
    const verifyHashCalls = n;

    // SHA-256 compressions per Th or PRF call on an N-bit input. Each operation
    // also computes the cached PK.seed midstate once.
    const call = tweakedCompressions(N / 8);

    return {
      skBits, pkBits, sigBits,
      keygenHashCalls, keygenPrfCalls, signPrfCalls, verifyHashCalls,
      keygenCompressions: (keygenHashCalls + keygenPrfCalls) * call + 1,
      signCompressions: signPrfCalls ? signPrfCalls * call + 1 : 0,
      verifyCompressions: verifyHashCalls * call + 1,
      // BIP 141 block weight limit; witness bytes weigh 1 WU each.
      perBlock: Math.floor(4000000 / ((sigBits + pkBits) / 8)),
    };
  },

  results: [
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.skBits) },
        { label: 'Public key', value: (d) => bytes(d.pkBits) },
        { label: 'Signature', value: (d) => bytes(d.sigBits) },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation hashes all \\(2n\\) secret values. Signing only reveals values, plus \\(n\\) \\(\\mathbf{PRF}\\) calls to rederive them when seed-based. Verification hashes the \\(n\\) revealed values.',
      rows: [
        {
          label: 'Key generation',
          value: (d) => `${num(d.keygenHashCalls)} \\(\\mathrm{Th}\\)`
            + (d.keygenPrfCalls ? ` + ${num(d.keygenPrfCalls)} \\(\\mathbf{PRF}\\)` : ''),
        },
        { label: 'Signing', value: (d) => (d.signPrfCalls ? `${num(d.signPrfCalls)} \\(\\mathbf{PRF}\\)` : '0') },
        { label: 'Verification', value: (d) => `${num(d.verifyHashCalls)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. Calls follow FIPS 205: a cached \\(\\mathrm{PK.seed}\\) block, then a 22-byte \\(\\mathrm{ADRS}^c\\) and the input. The cached block adds one compression per operation.',
      rows: [
        { label: 'Key generation', value: (d) => num(d.keygenCompressions) },
        { label: 'Signing', value: (d) => num(d.signCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    {
      heading: 'Signature budget',
      rows: [
        {
          label: 'Signatures per key pair',
          tooltip: 'Signing two different messages reveals both secret values at every bit where they differ.',
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
export function lamportGrid() {
  return {
    message: Array.from({ length: 512 }, () => (Math.random() < 0.5 ? 1 : 0)),

    flip(i) {
      this.message[i] ^= 1;
    },

    // Column indexes to draw; null marks the ellipsis.
    get columns() {
      const n = this.state.n;
      if (n <= 8) return [...Array(n).keys()];
      return [0, 1, 2, 3, null, n - 2, n - 1];
    },
  };
}
