import { approx, bytes, num } from './scheme.js';

// Result groups and tooltips shared by several schemes. Every scheme's
// derived values carry `sizes.sig` and `sizes.pk` in bits.

// Each operation also computes the cached PK.seed midstate once. `m` has
// `compressions` under keygen, sign, verify, and optionally signCached.
export function withMidstate(m) {
  const out = {
    keygenCompressions: m.keygen.compressions + 1,
    signCompressions: m.sign.compressions + 1,
    verifyCompressions: m.verify.compressions + 1,
  };
  if (m.signCached) out.signCachedCompressions = m.signCached.compressions + 1;
  return out;
}

export const compressionsTooltip = 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. Calls follow FIPS 205: a cached \\(\\mathrm{PK.seed}\\) block, then a 22-byte \\(\\mathrm{ADRS}^c\\) and the input. The cached block adds one compression per operation.';

// For schemes that also hash the message with PRF_msg and H_msg. `digest`
// describes a non-default digest length.
export const messageCompressionsTooltip = (digest = '') => `An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. \\(\\mathrm{Th}\\) and \\(\\mathbf{PRF}\\) follow FIPS 205 with a cached \\(\\mathrm{PK.seed}\\) block, adding one compression per operation. \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\) follow FIPS 205 for a 32-byte message${digest}.`;

export const messageHashNote = 'Signing also computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\); verification computes \\(\\mathbf{H}_{\\mathbf{msg}}\\).';

export const blockSpace = {
  heading: 'Block space',
  rows: [
    {
      label: 'Signature + public key per 4,000,000 WU block',
      tooltip: 'The BIP 141 block weight limit divided by signature plus public key bytes, counted as witness data at 1 WU per byte. Transaction overhead is not included.',
      value: (d) => num(Math.floor(4000000 / ((d.sizes.sig + d.sizes.pk) / 8))),
    },
  ],
};

export function signatureBudget(...rows) {
  return { heading: 'Signature budget', rows };
}

// One signature per key pair, for one-time signatures.
export const oneTime = (tooltip) => ({ label: 'Signatures per key pair', tooltip, value: () => '1' });

// Counter search formatting, shared by the schemes that grind a counter.
export const probability = (p) => (p >= 1e-4 ? p.toFixed(4) : `\\(2^{${Math.log2(p).toFixed(1)}}\\)`);
export const exhaustProbability = (log2) => (log2 > -10
  ? (2 ** log2).toFixed(4)
  : `\\(2^{${Math.round(log2).toLocaleString()}}\\)`);

// WOTS+C counter search rows. Derived values carry `p` and `wcSearch`.
export const successProbability = {
  label: 'Success probability per trial (\\(p_\\nu\\))',
  value: (d) => probability(d.p),
};
export const wcSearch = { label: 'WC search', value: (d) => approx(d.wcSearch) };

// Derived values carry `exhaustLog2`.
export const counterExhaustion = (tooltip) => ({
  label: 'Counter exhaustion probability',
  tooltip,
  value: (d) => exhaustProbability(d.exhaustLog2),
});

// Schemes with a Merkle tree of WOTS+C leaves: the parameter and result groups,
// and the results they share. Derived values carry `calls` (hash calls for
// keygen, sign, signCached, and verify), the compression counts, and `leaves`.

export const TREE = 'Tree';
export const OTS = 'OTS (WOTS+C)';
export const treeGroups = { [TREE]: 'var(--c-0a9396)', [OTS]: 'var(--c-ca6702)' };

export const treeKeys = (cacheTooltip) => ({
  rows: [
    { label: 'Secret key', value: (d) => bytes(d.sizes.sk) },
    { label: 'Public key', group: TREE, value: (d) => bytes(d.sizes.pk) },
    { label: 'Tree cache', group: TREE, tooltip: cacheTooltip, value: (d) => bytes(d.sizes.cache) },
  ],
});

export const otsSearch = (tooltip) => ({
  heading: 'Search',
  group: OTS,
  tooltip,
  rows: [successProbability, wcSearch],
});

// A hash call is one PRF or one Th. Both take a tweaked input of the same
// shape and cost the same, so they are counted together.
export const hashCalls = (c, fmt = approx) => fmt((c.prf ?? 0) + (c.th ?? 0));
export const hashCallsNote = 'Counts \\(\\mathbf{PRF}\\) and \\(\\mathrm{Th}\\) calls together.';

// Hash calls and compressions for key generation, signing without and with
// a cache (`cached` names what is cached), and verification.
export function treeCosts(hashTooltip, cached) {
  const signing = 'Signing (no cache, WC search)';
  const signingCached = `Signing (cached ${cached}, WC search)`;
  return [
    {
      heading: 'Hash calls',
      tooltip: `${hashTooltip} ${messageHashNote} ${hashCallsNote}`,
      rows: [
        { label: 'Key generation', value: (d) => hashCalls(d.calls.keygen) },
        { label: signing, value: (d) => hashCalls(d.calls.sign) },
        { label: signingCached, value: (d) => hashCalls(d.calls.signCached, num) },
        { label: 'Verification', value: (d) => hashCalls(d.calls.verify, num) },
      ],
    },
    // The SHA-256 compressions group, hidden for now.
    /*
    {
      heading: 'SHA-256 compressions',
      tooltip: messageCompressionsTooltip(),
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: signing, value: (d) => approx(d.signCompressions) },
        { label: signingCached, value: (d) => approx(d.signCachedCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    */
  ];
}

export const treeBudget = (perKeyPairTooltip, stateCounterTooltip) => ({
  ...signatureBudget(
    { label: 'Signatures per key pair', tooltip: perKeyPairTooltip, value: (d) => approx(d.leaves) },
    {
      label: 'State counter',
      tooltip: stateCounterTooltip,
      value: (d) => `${num(Math.ceil(Math.log2(d.leaves)) || 1)} bits`,
    },
  ),
  group: TREE,
});
