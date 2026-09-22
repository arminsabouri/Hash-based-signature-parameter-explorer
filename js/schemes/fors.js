import * as fors from '../primitives/fors.js';
import { forgeryLog2 } from '../primitives/fors.js';
import * as messageHash from '../primitives/message-hash.js';
import { approx, bytes, num } from '../scheme.js';
import { blockSpace, signatureBudget } from '../common-results.js';
import { svg } from '../draw.js';

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
    const msg0 = messageHash.model(state, { digestBits: state.k * state.a, counterBits: state.plusC ? state.r : 0 });
    const m = fors.model(state, msg0.mgf1);
    const sizes = {
      sk: 4 * state.n, // SK.seed, SK.prf, PK.seed, and root
      pk: 2 * state.n, // PK.seed and root
      R: msg0.sizes.R,
      fors: m.sizes.sig,
    };
    sizes.sig = sizes.R + sizes.fors;
    const q = 2 ** state.logq;

    // Each operation also computes the cached PK.seed midstate once.
    return {
      ...m,
      plusC: state.plusC, k: state.k, q,
      sizes,
      forgeryLog2: forgeryLog2(state, q),
      keygenCompressions: m.keygen.compressions + 1,
      signCompressions: msg0.sign.compressions + m.sign.compressions + 1,
      signCachedCompressions: msg0.sign.compressions + m.signCached.compressions + 1,
      verifyCompressions: msg0.verify.compressions + m.verify.compressions + 1,
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
        { label: 'Success probability per trial', value: (d) => (d.p >= 1e-4 ? d.p.toFixed(4) : `\\(2^{${Math.log2(d.p).toFixed(1)}}\\)`) },
        { label: 'WC search', value: (d) => approx(d.wcSearch) },
        {
          label: 'Counter exhaustion probability',
          tooltip: 'Probability that none of the \\(2^r\\) counter values meets the condition, \\((1 - 2^{-a})^{2^r}\\).',
          value: (d) => (d.exhaustLog2 > -10
            ? (2 ** d.exhaustLog2).toFixed(4)
            : `\\(2^{${Math.round(d.exhaustLog2).toLocaleString()}}\\)`),
        },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation builds every tree and hashes the \\(k\\) roots into the public key. Without a cache, signing rebuilds the trees to get the authentication paths. With the trees cached, signing derives the \\(k\\) revealed leaves. Signing also computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\); verification computes \\(\\mathbf{H}_{\\mathbf{msg}}\\).',
      rows: [
        { label: 'Key generation', value: (d) => `${approx(d.keygen.prf)} \\(\\mathbf{PRF}\\) + ${approx(d.keygen.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (no cache)', value: (d) => `${approx(d.sign.prf)} \\(\\mathbf{PRF}\\) + ${approx(d.sign.th)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (cached trees)', value: (d) => `${num(d.signCached.prf)} \\(\\mathbf{PRF}\\)` },
        { label: 'Verification', value: (d) => `${num(d.verify.th)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. \\(\\mathrm{Th}\\) and \\(\\mathbf{PRF}\\) follow FIPS 205 with a cached \\(\\mathrm{PK.seed}\\) block, adding one compression per operation. \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\) follow FIPS 205 for a 32-byte message and a \\(ka\\)-bit digest. FORS+C signing includes the WC search.',
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: 'Signing (no cache)', value: (d) => approx(d.signCompressions) },
        { label: 'Signing (cached trees)', value: (d) => approx(d.signCachedCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
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

// Structure diagram: k trees of height a, each drawn as an outline with its
// root on top and its leaf row below, with one revealed leaf. The roots feed
// one Th into the public key. Trees are elided when k > 5. For FORS+C the
// last tree is dashed and opens its first leaf.
function forestSvg(k, a, plusC) {
  const W = 560;
  const g = svg();
  const slots = k <= 5 ? [...Array(k).keys()] : [0, 1, 2, null, k - 1];
  const left = 40, right = W - 120;
  const slotW = (right - left) / slots.length;
  const pkY = 30, rootY = 90, baseY = 170, size = 10;
  const pkX = (left + right) / 2;

  g.text(pkX, pkY - 12, `FORS public key = Th(root₁, …, rootₖ)`);
  g.circle(pkX, pkY, 7, 'tree-node');

  slots.forEach((j, s) => {
    const cx = left + (s + 0.5) * slotW;
    const hw = slotW / 2 - 8;
    if (j === null) {
      g.text(cx, (rootY + baseY) / 2, '…');
      return;
    }
    const last = j === k - 1;
    const dashed = plusC && last;
    const cls = dashed ? 'edge dashed' : 'edge';
    g.line(pkX, pkY + 7, cx, rootY - 7, 'edge faint');
    g.line(cx, rootY, cx - hw, baseY, cls);
    g.line(cx, rootY, cx + hw, baseY, cls);
    g.line(cx - hw, baseY, cx + hw, baseY, cls);
    g.circle(cx, rootY, 7, 'tree-node');
    // One revealed leaf per tree: the first leaf for the FORS+C last tree,
    // otherwise an arbitrary position.
    const leafX = dashed ? cx - hw + size / 2 : cx - hw + (hw * 2) * ((j * 0.37 + 0.3) % 1);
    g.rect(leafX - size / 2, baseY + 6, size, size, 'ots-node');
    g.text(cx, baseY + 34, `tree ${j + 1}`);
    if (dashed) g.text(cx, baseY + 48, 'leaf 0', 'middle', 'label ots-label');
  });

  // Height and leaf count annotations.
  const bx = W - 100;
  g.line(bx, rootY, bx, baseY, 'bracket');
  g.line(bx - 4, rootY, bx, rootY, 'bracket');
  g.line(bx - 4, baseY, bx, baseY, 'bracket');
  g.text(bx + 8, (rootY + baseY) / 2 + 4, `a = ${a}`, 'start');
  g.text(bx + 8, baseY + 16, `${(2 ** a).toLocaleString()} leaves`, 'start', 'label ots-label');
  g.text(bx + 8, baseY + 30, 'per tree', 'start', 'label ots-label');
  g.text(pkX, baseY + 70, `k = ${k} trees`, 'middle');

  return { svg: g.toString(), width: W, height: baseY + 80 };
}

// Visualization state, nested inside the scheme component.
export function forsForest() {
  return {
    get drawing() {
      return forestSvg(this.state.k, this.state.a, this.state.plusC);
    },
  };
}
