// SHA-256 compression function calls for a message of `bytes` bytes.
// Padding appends 0x80 and an 8-byte length, and blocks are 64 bytes.
export function compressions(bytes) {
  return Math.ceil((bytes + 9) / 64);
}

// FIPS 205 SHA2 instantiation: SHA-256(PK.seed || toByte(0, 64 - n) || ADRSc || M).
// The first block depends only on PK.seed, so its midstate is computed once and cached.
export const ADRSC_BYTES = 22;

export function tweakedCompressions(messageBytes) {
  return compressions(ADRSC_BYTES + messageBytes);
}
