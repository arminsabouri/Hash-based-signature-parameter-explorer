import { approx, num } from './scheme.js';

// Result groups and tooltips shared by several schemes. Every scheme's
// derived values carry `sizes.sig` and `sizes.pk` in bits.

export const compressionsTooltip = 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. Calls follow FIPS 205: a cached \\(\\mathrm{PK.seed}\\) block, then a 22-byte \\(\\mathrm{ADRS}^c\\) and the input. The cached block adds one compression per operation.';

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

// WOTS+C counter search rows. Derived values carry `p` and `wcSearch`.
export const successProbability = {
  label: 'Success probability per trial (\\(p_\\nu\\))',
  value: (d) => (d.p >= 1e-4 ? d.p.toFixed(4) : `\\(2^{${Math.log2(d.p).toFixed(1)}}\\)`),
};
export const wcSearch = { label: 'WC search', value: (d) => approx(d.wcSearch) };
