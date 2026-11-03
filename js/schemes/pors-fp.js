import * as fors from '../primitives/fors.js';
import * as messageHash from '../primitives/message-hash.js';
import * as porsFp from '../primitives/pors-fp.js';
import * as wotsC from '../primitives/wots-c.js';
import { approx, bytes, num } from '../scheme.js';
import {
  blockSpace, hashCalls, hashCallsNote, messageHashNote, probability, sigPart, signatureBudget, withMidstate,
} from '../common-results.js';
import { drawPors, svg } from '../draw.js';

// PORS+FP as a standalone few-time signature, costed as in
// BlockstreamResearch/SPHINCS-Parameters. Defaults are the SHRIMPS compact
// instance's (k, a) = (8, 17).

const PORS = 'PORS+FP';
const pow2 = (x) => `\\(2^{${x.toFixed(1)}}\\)`;

// Neither SHRIMPS nor SPHINCS-Parameters gives a digest layout for PORS+FP.
// This charges k indices of ceil(log2 t) bits each, as the SHRIMPS tab does.
const digestBits = ({ k, a }) => 8 * Math.ceil((k * Math.ceil(Math.log2(k * 2 ** a))) / 8);

// compute_mmax weighs PORS+FP against a SPHINCS+ hypertree, which a standalone
// key pair lacks. The default takes the SHRIMPS compact instance's: h' = 12,
// d = 1, WOTS+C with w = 16 and S = 240.
const defaultMmax = ({ k, a }) => {
  const ots = wotsC.model({ n: 128, b: 4, z: 0, S: 240, r: 0, compressed: true });
  return porsFp.referenceMmax({ k, a, hp: 12, d: 1, w: ots.w, l: ots.l, wotsP: ots.p });
};

const [kParam, aParam, mmaxParam] = porsFp.parameters(PORS);

export default {
  id: 'pors-fp',
  title: 'PORS+FP',
  groups: { [PORS]: 'var(--c-0a9396)' },

  parameters: [
    { ...fors.parameters(PORS)[0], tooltip: 'Hash output length in bits. Every secret leaf and tree node is \\(n\\) bits.' },
    kParam,
    aParam,
    {
      ...mmaxParam,
      default: defaultMmax,
      resetOn: ['k', 'a'],
      tooltip: 'The signer grinds the digest until the Octopus authentication set of the \\(k\\) selected leaves has at most \\(m_{\\max}\\) nodes. A smaller \\(m_{\\max}\\) gives a smaller signature and more grinding trials. The default is the value SPHINCS-Parameters chooses (costs.sage, compute_mmax), which compares signing against a SPHINCS+ instance; this tab takes the SHRIMPS compact instance\'s hypertree, \\(h\' = 12\\), \\(d = 1\\), WOTS+C with \\(w = 16\\) and \\(S_{w,n} = 240\\).',
    },
    {
      key: 'logq', type: 'range', min: 0, max: 20, step: 1, default: 0,
      display: (x) => (2 ** x).toLocaleString(),
      label: '\\(q\\) (signatures on this key pair)',
      tooltip: 'Each signature reveals \\(k\\) more secret leaves. The forgery probability below is for a key pair that has signed \\(q\\) messages.',
    },
  ],

  derive(state) {
    const msg = messageHash.model(state, { digestBits: digestBits(state) });
    const m = porsFp.model(state, msg.sign.compressions);
    const sizes = {
      sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * state.n, // PK.seed and root
      R: msg.sizes.R,
      pors: m.sizes.sig,
    };
    sizes.sig = sizes.R + sizes.pors;
    const q = 2 ** state.logq;

    return {
      ...m,
      k: state.k, q,
      sizes,
      forgeryLog2: porsFp.forgeryLog2(state, q),
      ...withMidstate({
        keygen: m.keygen,
        sign: { compressions: msg.sign.compressions + m.sign.compressions },
        verify: { compressions: msg.verify.compressions + m.verify.compressions },
      }),
    };
  },

  results: [
    {
      heading: 'Tree',
      rows: [
        { label: 'Leaves (\\(t = k \\cdot 2^a\\))', value: (d) => approx(d.t) },
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
      tooltip: 'The randomness \\(R\\), the \\(k\\) revealed secret leaves, and at most \\(m_{\\max}\\) nodes of their Octopus authentication set. The size is charged at \\(k + m_{\\max}\\) values.',
      bar: true,
      rows: [
        sigPart('Randomness \\(R\\)', 'R'),
        sigPart('PORS+FP signature', 'pors', PORS),
        { label: 'Total', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Search',
      tooltip: 'Each trial computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\) for a fresh digest and succeeds when the authentication set has at most \\(m_{\\max}\\) nodes. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        { label: 'Success probability per trial', value: (d) => probability(d.p) },
        { label: 'WC search', value: (d) => approx(d.wcSearch) },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: `Key generation builds the tree, and its root is the public key. Signing rebuilds the tree to get the authentication set and includes the WC search. ${messageHashNote} ${hashCallsNote}`,
      rows: [
        { label: 'Key generation', value: (d) => hashCalls(d.keygen) },
        { label: 'Signing (no cache, WC search)', value: (d) => hashCalls(d.sign) },
        { label: 'Verification', value: (d) => hashCalls(d.verify, num) },
      ],
    },
    signatureBudget(
      {
        label: 'Secret leaves revealed per signature',
        value: (d) => num(d.k),
      },
      {
        label: 'Forgery probability after \\(q\\) signatures',
        tooltip: 'Probability that a fresh digest selects only leaves revealed by \\(q\\) signatures, as security.sage in SPHINCS-Parameters bounds it: \\(\\binom{\\min(qk,\\, t)}{k} / \\binom{t}{k}\\).',
        value: (d) => pow2(d.forgeryLog2),
      },
    ),
    blockSpace,
  ],
};

// Structure diagram: the one tree, whose root is the public key.
function porsSvg(k, a) {
  const W = 560;
  const g = svg();
  g.text((40 + W - 120) / 2, 18, 'Public key (root)');
  const tree = drawPors(g, { k, t: k * 2 ** a, left: 40, right: W - 120, top: 36, bx: W - 100 });
  return { svg: g.toString(), width: W, height: tree.bottom };
}

// Visualization state, nested inside the scheme component.
export function porsTree() {
  return {
    get drawing() {
      return porsSvg(this.state.k, this.state.a);
    },
  };
}
