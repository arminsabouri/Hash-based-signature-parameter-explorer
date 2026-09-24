import * as fors from '../primitives/fors.js';
import { forgeryLog2 } from '../primitives/fors.js';
import * as messageHash from '../primitives/message-hash.js';
import { approx, bytes, num } from '../scheme.js';
import {
  blockSpace, counterExhaustion, hashCalls, hashCallsNote, messageCompressionsTooltip, messageHashNote,
  probability, signatureBudget, withMidstate,
} from '../common-results.js';
import { drawForest, svg } from '../draw.js';

// FORS and FORS+C as a standalone few-time signature, with FIPS 205 message
// hashing. Default k and a are those of SLH-DSA-SHA2-128s.

const pow2 = (x) => `\\(2^{${x.toFixed(1)}}\\)`;

export default {
  id: 'fors',
  title: 'FORS',

  parameters: [
    ...fors.parameters(),
    {
      key: 'logq', type: 'range', min: 0, max: 20, step: 1, default: 0,
      display: (x) => (2 ** x).toLocaleString(),
      label: '\\(q\\) (signatures on this key pair)',
      tooltip: 'Each signature reveals \\(k\\) more secret leaves. The forgery probability below is for a key pair that has signed \\(q\\) messages.',
    },
  ],

  derive(state) {
    const msg = messageHash.model(state, { digestBits: state.k * state.a, counterBits: state.plusC ? state.r : 0 });
    const m = fors.model(state, msg.mgf1);
    const sizes = {
      sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * state.n, // PK.seed and root
      R: msg.sizes.R,
      fors: m.sizes.sig,
    };
    sizes.sig = sizes.R + sizes.fors;
    const q = 2 ** state.logq;

    return {
      ...m,
      plusC: state.plusC, k: state.k, q,
      sizes,
      forgeryLog2: forgeryLog2(state, q),
      ...withMidstate({
        keygen: m.keygen,
        sign: { compressions: msg.sign.compressions + m.sign.compressions },
        signCached: { compressions: msg.sign.compressions + m.signCached.compressions },
        verify: { compressions: msg.verify.compressions + m.verify.compressions },
      }),
    };
  },

  results: [
    {
      heading: 'Trees',
      rows: [
        { label: 'Leaves per tree (\\(2^a\\))', value: (d) => approx(d.t) },
        {
          label: 'Trees with an authentication path',
          tooltip: 'All \\(k\\) trees for FORS. FORS+C leaves out the last tree, which always opens its first leaf.',
          value: (d) => num(d.built),
        },
      ],
    },
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.sizes.sk) },
        { label: 'Public key', value: (d) => bytes(d.sizes.pk) },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'The randomness \\(R\\) and, for each tree with an authentication path, the revealed secret leaf and its \\(a\\) sibling nodes. FORS+C adds the last tree\'s first leaf and the counter.',
      rows: [
        { label: 'Randomness \\(R\\)', value: (d) => bytes(d.sizes.R) },
        { label: 'FORS signature (\\(\\sigma_{\\mathrm{FORS}}\\))', value: (d) => bytes(d.sizes.fors) },
        { label: 'Total', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Search',
      show: (d) => d.plusC,
      tooltip: 'Each trial recomputes the MGF1 part of \\(\\mathbf{H}_{\\mathbf{msg}}\\) with the counter and succeeds when the last \\(a\\) digest bits are zero, with probability \\(2^{-a}\\). WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        { label: 'Success probability per trial', value: (d) => probability(d.p) },
        { label: 'WC search', value: (d) => approx(d.wcSearch) },
        counterExhaustion('Probability that none of the \\(2^r\\) counter values meets the condition, \\((1 - 2^{-a})^{2^r}\\).'),
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: `Key generation builds every tree and hashes the \\(k\\) roots into the public key. Without a cache, signing rebuilds the trees to get the authentication paths. With the trees cached, signing derives the \\(k\\) revealed leaves. ${messageHashNote} ${hashCallsNote}`,
      rows: [
        { label: 'Key generation', value: (d) => hashCalls(d.keygen) },
        { label: 'Signing (no cache)', value: (d) => hashCalls(d.sign) },
        { label: 'Signing (cached trees)', value: (d) => hashCalls(d.signCached, num) },
        { label: 'Verification', value: (d) => hashCalls(d.verify, num) },
      ],
    },
    // The SHA-256 compressions group, hidden for now.
    /*
    {
      heading: 'SHA-256 compressions',
      tooltip: `${messageCompressionsTooltip(' and a \\(ka\\)-bit digest')} FORS+C signing includes the WC search.`,
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: 'Signing (no cache)', value: (d) => approx(d.signCompressions) },
        { label: 'Signing (cached trees)', value: (d) => approx(d.signCachedCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    */
    signatureBudget(
      {
        label: 'Secret leaves revealed per signature',
        value: (d) => num(d.k),
      },
      {
        label: 'Forgery probability after \\(q\\) signatures',
        tooltip: 'Probability that a new digest opens only leaves already revealed: \\((1 - (1 - 2^{-a})^q)^k\\). For FORS+C the last tree is fixed and the digest must also end in \\(a\\) zero bits: \\(2^{-a}(1 - (1 - 2^{-a})^q)^{k-1}\\). Each digest an attacker tries succeeds with this probability.',
        value: (d) => pow2(d.forgeryLog2),
      },
    ),
    blockSpace,
  ],
};

// Structure diagram: the k trees with their roots compressed into the
// public key.
function forestSvg(k, a, plusC) {
  const W = 560;
  const g = svg();
  const forest = drawForest(g, {
    k, a, plusC, left: 40, right: W - 120, top: 30, bx: W - 100,
    pkLabel: 'FORS public key = Th(root\u2081, \u2026, root\u2096)',
  });
  return { svg: g.toString(), width: W, height: forest.bottom };
}

// Visualization state, nested inside the scheme component.
export function forsForest() {
  return {
    get drawing() {
      return forestSvg(this.state.k, this.state.a, this.state.plusC);
    },
  };
}
