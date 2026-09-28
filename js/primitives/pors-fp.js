import { tweakedCompressions } from '../sha256.js';
import { interleaveCostTable } from './octopus-pmf.js';

// PORS+FP, as costed in BlockstreamResearch/SPHINCS-Parameters (costs.sage and
// security.sage): one left-filled tree of t = k * 2^a secret leaves. The
// message digest selects k distinct leaves, and the signature reveals them with
// their Octopus authentication set. The signer grinds the digest until that set
// has at most m_max nodes, so the signature always carries k + m_max values.

export function parameters(group) {
  return [
    {
      key: 'k', type: 'range', min: 1, max: 64, step: 1, default: 8, group,
      label: '\\(k\\) (leaf indices per signature)',
      tooltip: 'The digest selects \\(k\\) distinct leaves of the one tree, and the signature reveals each of them.',
    },
    {
      key: 'a', type: 'range', min: 1, max: 24, step: 1, default: 17, group,
      label: '\\(a\\) (\\(t = k \\cdot 2^a\\) leaves)',
      tooltip: 'The tree has \\(t = k \\cdot 2^a\\) secret leaves, filled from the left. Signing builds the whole tree.',
    },
    {
      key: 'mmax', type: 'range', step: 1, group,
      min: (s) => mmaxRange(s)[0],
      max: (s) => mmaxRange(s)[1],
      default: (s) => referenceMmax(s),
      label: '\\(m_{\\max}\\) (max size of the authentication set)',
      tooltip: 'The signer grinds the digest until the Octopus authentication set of the \\(k\\) selected leaves has at most \\(m_{\\max}\\) nodes. A smaller \\(m_{\\max}\\) gives a smaller signature and more grinding trials. The default is the value SPHINCS-Parameters chooses (costs.sage, compute_mmax).',
    },
  ];
}

const leavesOf = ({ k, a }) => k * 2 ** a;

// The m_max values with a nonzero probability, smallest and largest.
export function mmaxRange({ k, a }) {
  const keys = [...interleaveCostTable(leavesOf({ k, a }), k).keys()];
  return [keys[0], keys[keys.length - 1]];
}

// log2 of the expected grinding work at m_max, read from the table as
// costs.sage does: the entry for m_max, or the nearest one below it.
export function log2Work({ k, a, mmax }) {
  const table = interleaveCostTable(leavesOf({ k, a }), k);
  if (table.has(mmax)) return table.get(mmax);
  let below = null;
  for (const m of table.keys()) if (m <= mmax) below = m;
  return table.get(below ?? mmaxRange({ k, a })[0]);
}

// costs.sage, compute_mmax: start at (k-1)a - ceil(350/16) and step up until
// signing is within 1.11 times SPHINCS+ with WOTS+C and FORS+C at the same
// (k, a, h', d), giving up after 20 steps. It uses that script's own cost
// constants, which are for n = 128 (the cached-midstate convention of the
// vendored commit), and its expected WOTS+C trials, 1 / p_nu per layer.
// `wotsP` is p_nu and `l` the number of WOTS+C chains.
export function referenceMmax({ k, a, hp, d, w, l, wotsP }) {
  const th = (x) => Math.ceil((22 * 8 + 128 * x + 65) / 512);
  const C_TH2 = 1;
  const C_MSG = 2 + 2; // C_Hmsg + C_PRFmsg
  const merkle = 2 ** hp * (l + l * (w - 1) + th(l)) + (2 ** hp - 1) * C_TH2;
  const hyper = d * merkle + d * Math.ceil(1 / wotsP);
  const forsC = (k - 1) * 2 ** a * 2 + (k - 1) * (2 ** a - 1) * C_TH2 + th(k - 1) + 2 ** a * C_MSG;
  const t = leavesOf({ k, a });
  const porsFixed = 2 * t + (t - 1) * C_TH2;

  const [lo, hi] = mmaxRange({ k, a });
  let mmax = Math.max(lo, (k - 1) * a - Math.ceil(350 / 16));
  for (let i = 0; i < 20 && mmax < hi; i++) {
    const trials = Math.ceil(2 ** log2Work({ k, a, mmax }));
    if ((hyper + porsFixed + trials * C_MSG) / (hyper + forsC) < 1.11 || i === 19) break;
    mmax += 1;
  }
  return Math.min(mmax, hi);
}

// Signing uses the WC search: the number of trials that suffices except with
// probability 2^-30. Each trial draws a fresh digest, so `trialCall` is the
// compression cost of one PRF_msg and H_msg.
export function model({ n, k, a, mmax }, trialCall = 0) {
  const t = leavesOf({ k, a });
  const call = tweakedCompressions(n / 8);
  const nodeCall = tweakedCompressions((2 * n) / 8);

  // The authentication set has at most m_max nodes with probability p.
  const work = log2Work({ k, a, mmax });
  const p = 2 ** -work;
  const wcSearch = p >= 1 ? 1 : Math.ceil((-30 * Math.LN2) / Math.log1p(-p));
  const expected = Math.ceil(2 ** work);

  // Every leaf is PRF then Th, and a left-filled tree of t leaves has t - 1
  // inner nodes. The root is the public key, with no further compression.
  const keygen = {
    prf: t,
    th: t + (t - 1),
    compressions: 2 * t * call + (t - 1) * nodeCall,
  };

  return {
    t, p, wcSearch, expected,
    sizes: { sig: (k + mmax) * n, root: n },
    keygen,
    // Without a cache: rebuild the tree, then PRF for the k revealed leaves.
    sign: {
      prf: keygen.prf + k,
      th: keygen.th,
      compressions: keygen.compressions + k * call + (wcSearch - 1) * trialCall,
    },
    // Th on each revealed leaf, then at most m_max nodes of the authentication
    // set, as costs.sage counts it.
    verify: {
      th: k + mmax,
      compressions: k * call + mmax * nodeCall,
    },
  };
}

// log of Gamma(x) for x > 0: Stirling's series, shifted up past 10.
function lnGamma(x) {
  let shift = 0;
  while (x < 10) {
    shift -= Math.log(x);
    x += 1;
  }
  const inv = 1 / x;
  const inv2 = inv * inv;
  return shift + (x - 0.5) * Math.log(x) - x + 0.5 * Math.log(2 * Math.PI)
    + inv * (1 / 12 - inv2 * (1 / 360 - inv2 * (1 / 1260 - inv2 / 1680)));
}

const lnChoose = (n, r) => lnGamma(n + 1) - lnGamma(r + 1) - lnGamma(n - r + 1);

// security.sage, compute_security for PORS+FP: after q signatures spread over
// 2^h instances, the probability that one instance was hit r times and a fresh
// digest selects only its revealed leaves,
//   sigma = sum_r C(q, r) 2^(-hr) (1 - 2^-h)^(q - r) * C(min(rk, t), k) / C(t, k),
// and the security is -log2(max(2^-n, sigma)). The sum runs over r until the
// terms fall below 2^-1250 past r = q / 2^h. When that point is far out, the
// terms more than 40 standard deviations below it are left out; each is below
// 2^-1000.
export function securityBits({ n, k, a, h }, q) {
  const t = leavesOf({ k, a });
  const p = 2 ** -h;
  const mean = q * p;
  const lnP = Math.log(p);
  const ln1mP = Math.log1p(-p);
  const lnForge = (r) => {
    const m = Math.min(r * k, t);
    if (m < k) return -Infinity;
    if (m === t) return 0;
    let s = 0;
    for (let i = 0; i < k; i++) s += Math.log((m - i) / (t - i));
    return s;
  };

  const start = mean > 1e4 ? Math.max(1, Math.floor(mean - 40 * Math.sqrt(mean))) : 1;
  let lnHit = (start === 1 ? Math.log(q) : lnChoose(q, start)) + start * lnP + (q - start) * ln1mP;
  const floor = -1250 * Math.LN2;
  let sigma = 0;
  for (let r = start; r <= q; r++) {
    if (r > start) lnHit += Math.log((q - r + 1) / r) + lnP - ln1mP;
    const lnTerm = lnHit + lnForge(r);
    sigma += Math.exp(lnTerm);
    if (r > mean && lnTerm < floor) break;
  }
  return -Math.log2(Math.max(2 ** -n, sigma));
}
