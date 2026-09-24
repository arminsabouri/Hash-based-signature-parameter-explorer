import { tweakedCompressions } from '../sha256.js';
import { digitSumDistribution } from './wots.js';

// WOTS+C, Section 5 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".

export const len1Of = ({ n, b }) => Math.ceil(n / b);
export const chainsOf = (state) => len1Of(state) - state.z;
const centerSum = (state) => Math.ceil((chainsOf(state) * (2 ** state.b - 1)) / 2);

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
      tooltip: 'Each chain has \\(w\\) values and encodes \\(\\log_2 w\\) digest bits. A larger \\(w\\) gives fewer, longer chains.',
    },
    {
      key: 'z', type: 'range', min: 0, max: (s) => Math.min(8, len1Of(s) - 1), step: 1, default: 0, group,
      label: '\\(z\\) (zero-chains)',
      tooltip: 'The last \\(z\\) digest digits must be zero, so those chains are left out of the signature. Each zero-chain multiplies the expected counter trials by \\(w\\).',
    },
    {
      key: 'S', type: 'range', min: 0, max: (s) => chainsOf(s) * (2 ** s.b - 1), step: 1, group,
      default: centerSum, resetOn: ['n', 'b', 'z'],
      label: '\\(S_{w,n}\\) (target sum)',
      tooltip: 'The signer grinds a counter until the digits of the \\(l\\) signed chains sum to \\(S_{w,n}\\), which replaces the checksum chains. Verification always takes \\(l(w-1) - S_{w,n}\\) steps, and \\(l(w-1)/2\\) needs the fewest counter trials.',
    },
    {
      key: 'r', type: 'range', min: 8, max: 64, step: 8, default: 32, group,
      label: '\\(r\\) (counter bits)',
      tooltip: 'Size of the counter carried in the signature. SHRINCS uses 16 bits.',
    },
  ];
}

// Signing uses the WC search: the number of trials that suffices except
// with probability 2^-30.
export function model(state) {
  const { n, b, z, S: target, r, compressed = true } = state;
  const w = 2 ** b;
  const len1 = len1Of(state);
  const l = len1 - z;

  // p_nu = nu / w^len1: the l signed digits sum to S and the z zero digits are 0.
  // The target is capped at the largest sum l chains can reach, so that it
  // always has some digit tuple behind it. The parameter panel caps it the
  // same way, so this only guards states reached another way.
  const dist = digitSumDistribution(w, l, b);
  const S = Math.min(target, dist.length - 1);
  const p = dist[S] * w ** -z;
  const wcSearch = Math.ceil((-30 * Math.LN2) / Math.log1p(-p));
  // log2 of the probability that all 2^r counter values fail.
  const exhaustLog2 = (2 ** r * Math.log1p(-p)) / Math.LN2;

  const verifySteps = l * (w - 1) - S;
  const call = tweakedCompressions(n / 8);
  const grindCall = tweakedCompressions((n + r) / 8);
  const pkCalls = compressed ? 1 : 0;
  const pkCall = compressed ? tweakedCompressions(l * n / 8) : 0;
  const pBits = n;

  return {
    w, len1, l, p, wcSearch, exhaustLog2,
    sizes: {
      sk: n + pBits, // SK.seed and P
      pk: (compressed ? n : l * n) + pBits,
      sig: l * n + r,
    },
    keygen: { prf: l, th: l * (w - 1) + pkCalls, compressions: (l + l * (w - 1)) * call + pkCall },
    // One Th per search trial, then S chain steps.
    sign: { prf: l, th: S + wcSearch, compressions: (l + S) * call + wcSearch * grindCall },
    // One Th to recompute the digest, then the remaining chain steps.
    verify: { th: 1 + verifySteps + pkCalls, compressions: grindCall + verifySteps * call + pkCall },
  };
}
