import { compressions } from '../sha256.js';

// Message hashing as in FIPS 205 for a 32-byte message:
// PRF_msg = HMAC-SHA-256(SK.prf, opt_rand || M) and
// H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M)).
// MGF1 produces 256 bits per block, so a longer digest costs more blocks. A
// grinding counter, when present, is appended to the MGF1 seed, so the inner
// SHA-256 is computed once and each trial recomputes only MGF1.
const MESSAGE_BYTES = 32;

export function model({ n }, { digestBits = 256, counterBits = 0 } = {}) {
  const nb = n / 8;
  const prfMsg = compressions(64 + nb + MESSAGE_BYTES) + compressions(64 + 32);
  const inner = compressions(3 * nb + MESSAGE_BYTES);
  const mgf1 = Math.ceil(digestBits / 256) * compressions(2 * nb + 32 + counterBits / 8 + 4);
  return {
    sizes: { R: n },
    // One MGF1 evaluation, the cost of each additional grinding trial.
    mgf1,
    sign: { compressions: prfMsg + inner + mgf1 },
    verify: { compressions: inner + mgf1 },
  };
}
