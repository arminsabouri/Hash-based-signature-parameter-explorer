import { compressions } from '../../js/sha256.js';

// Every deliberate difference between this site's cost model and the vendored
// one, written out so a test can compare a figure against its reference plus a
// stated offset. All counts are SHA-256 compressions.
//
//   1. Cached midstate. The site adds one compression per operation for the
//      cached PK.seed block (js/common-results.js, withMidstate). The
//      reference leaves it out, so every operation reads one higher here.
//
//   2. Message hashing. The site costs H_msg from the digest length
//      (js/primitives/message-hash.js, model): an inner SHA-256 over
//      R || PK.seed || PK.root || M, then one MGF1 block per 256 digest bits.
//      The reference uses a flat C_Hmsg = 2 and C_PRFmsg = 2
//      (test/reference/formulas.js, costs.sage).
//
//   3. Signing. The reference builds each hypertree layer and reads the OTS
//      signature out of that work. The site adds the OTS chain walk on top of
//      the layer, and recomputes the FORS leaf secrets it reveals. See
//      slhSignParts below.
//
// Two further differences are not offsets but disagreements on what the
// signature holds; they are asserted where they arise, in
// test/reference-costs.test.js:
//
//   - the default WOTS+C target sum S_{w,n}, ceil(l(w-1)/2) here against
//     floor(l(w-1)/2) in the reference, which differ only when l(w-1) is odd;
//   - the FORS+C signature, (k-1)(a+1) hashes plus a revealed leaf and a
//     counter here, against (k-1)(a+1) hashes alone in the reference.

export const MIDSTATE = 1;

// C_Hmsg and C_PRFmsg in test/reference/formulas.js.
export const THEIR_HMSG = 2;
export const THEIR_PRFMSG = 2;

// H_msg and PRF_msg as js/primitives/message-hash.js costs them, restated here
// rather than imported so that a change to either model fails a test.
export const hmsg = (n, digestBits = 256, counterBits = 0) =>
  compressions(3 * (n / 8) + 32)
  + Math.ceil(digestBits / 256) * compressions(2 * (n / 8) + 32 + counterBits / 8 + 4);

export const prfMsg = (n) => compressions(64 + n / 8 + 32) + compressions(64 + 32);

// FIPS 205 message digest, as js/schemes/sphincs.js derives it.
export const digestBits = ({ k, a, hp, d }) =>
  8 * (Math.ceil((k * a) / 8) + Math.ceil(((d - 1) * hp) / 8) + Math.ceil(hp / 8));

// Key generation differs by the midstate alone.
export const keygenOffset = () => MIDSTATE;

// Verification differs by the midstate and by how H_msg is costed.
export const verifyOffset = (n, bits = 256, counterBits = 0) =>
  MIDSTATE + hmsg(n, bits, counterBits) - THEIR_HMSG;
