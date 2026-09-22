import * as lamport from '../primitives/lamport.js';
import { bytes, num } from '../scheme.js';
import { blockSpace, compressionsTooltip, oneTime, signatureBudget, withMidstate } from '../common-results.js';

export default {
  id: 'lamport',
  title: 'Lamport OTS',

  parameters: lamport.parameters(),

  derive(state) {
    const m = lamport.model(state);
    // Signing hashes nothing, and so skips the midstate, when secret values
    // are stored rather than derived.
    const c = withMidstate(m);
    return { ...m, ...c, signCompressions: m.sign.prf ? c.signCompressions : 0 };
  },

  results: [
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.sizes.sk) },
        { label: 'Public key', value: (d) => bytes(d.sizes.pk) },
        { label: 'Signature', value: (d) => bytes(d.sizes.sig) },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation hashes all \\(2n\\) secret values. Signing only reveals values, plus \\(n\\) \\(\\mathbf{PRF}\\) calls to rederive them when seed-based. Verification hashes the \\(n\\) revealed values.',
      rows: [
        {
          label: 'Key generation',
          value: (d) => `${num(d.keygen.th)} \\(\\mathrm{Th}\\)`
            + (d.keygen.prf ? ` + ${num(d.keygen.prf)} \\(\\mathbf{PRF}\\)` : ''),
        },
        { label: 'Signing', value: (d) => (d.sign.prf ? `${num(d.sign.prf)} \\(\\mathbf{PRF}\\)` : '0') },
        { label: 'Verification', value: (d) => `${num(d.verify.th)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: compressionsTooltip,
      rows: [
        { label: 'Key generation', value: (d) => num(d.keygenCompressions) },
        { label: 'Signing', value: (d) => num(d.signCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    signatureBudget(oneTime('Signing two different messages reveals both secret values at every bit where they differ.')),
    blockSpace,
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
