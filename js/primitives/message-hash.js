import { compressions } from '../sha256.js';

// Message hashing as in FIPS 205 for a 32-byte message:
// PRF_msg = HMAC-SHA-256(SK.prf, opt_rand || M) and
// H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M)).
const MESSAGE_BYTES = 32;

export function model({ n }) {
  const nb = n / 8;
  const prfMsg = compressions(64 + nb + MESSAGE_BYTES) + compressions(64 + 32);
  const hMsg = compressions(3 * nb + MESSAGE_BYTES) + compressions(2 * nb + 32 + 4);
  return {
    sizes: { R: n },
    sign: { compressions: prfMsg + hMsg },
    verify: { compressions: hMsg },
  };
}
