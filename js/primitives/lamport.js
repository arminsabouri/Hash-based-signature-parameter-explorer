import { tweakedCompressions } from '../sha256.js';

// Lamport OTS, Section 3 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".

export function parameters(group) {
  return [
    {
      key: 'n', type: 'range', min: 1, max: 512, step: 1, default: 128, group,
      ticks: [32, 64, 128, 256, 512],
      label: '\\(n\\) (message bits)',
      tooltip: 'Length of the signed message in bits. Each bit has two secret values, so key and signature sizes grow linearly with \\(n\\).',
    },
    {
      key: 'N', type: 'range', min: 8, max: 256, step: 8, default: 256, group,
      ticks: [32, 64, 128, 256],
      label: '\\(N\\) (hash output bits)',
      tooltip: 'Output length of the hash function in bits. Every secret value, public key element, and signature element is \\(N\\) bits.',
    },
    {
      key: 'seedBased', type: 'checkbox', default: true, group,
      label: 'Seed-based generation of secret keys',
      tooltip: 'Secret values are derived from one seed with a \\(\\mathbf{PRF}\\) instead of being stored. The secret key shrinks to the seed, and signing recomputes the revealed values.',
    },
  ];
}

export function model({ n, N, seedBased }) {
  // The public parameter P is taken to be N bits.
  const pBits = N;
  const call = tweakedCompressions(N / 8);
  const keygenPrf = seedBased ? 2 * n : 0;
  const signPrf = seedBased ? n : 0;
  return {
    sizes: {
      sk: (seedBased ? N : 2 * n * N) + pBits,
      pk: 2 * n * N + pBits,
      sig: n * N,
    },
    keygen: { prf: keygenPrf, th: 2 * n, compressions: (keygenPrf + 2 * n) * call },
    sign: { prf: signPrf, th: 0, compressions: signPrf * call },
    verify: { th: n, compressions: n * call },
  };
}
