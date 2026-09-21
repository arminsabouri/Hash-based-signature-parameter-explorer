import { compressions, tweakedCompressions, ADRSC_BYTES } from './sha256.js';

// Lamport OTS, Section 3 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".
export function lamport() {
  return {
    n: 128,          // message length in bits
    N: 256,          // hash output length in bits
    tweakable: true,
    seedBased: true,
    message: [],

    init() {
      this.randomize();
      this.$watch('n', () => this.randomize());
    },

    randomize() {
      this.message = Array.from({ length: this.n }, () => (Math.random() < 0.5 ? 1 : 0));
    },

    flip(i) {
      this.message[i] ^= 1;
    },

    // Column indexes to draw; null marks the ellipsis.
    get columns() {
      const n = this.n;
      if (n <= 8) return [...Array(n).keys()];
      return [0, 1, 2, 3, null, n - 2, n - 1];
    },

    // Sizes in bits. The public parameter P is taken to be N bits.
    get pBits() { return this.tweakable ? this.N : 0; },
    get skBits() { return (this.seedBased ? this.N : 2 * this.n * this.N) + this.pBits; },
    get pkBits() { return 2 * this.n * this.N + this.pBits; },
    get sigBits() { return this.n * this.N; },

    // Hash calls.
    get keygenHashCalls() { return 2 * this.n; },
    get keygenPrfCalls() { return this.seedBased ? 2 * this.n : 0; },
    get signPrfCalls() { return this.seedBased ? this.n : 0; },
    get verifyHashCalls() { return this.n; },

    // SHA-256 compressions per call.
    get hashCompressions() {
      const bytes = this.N / 8;
      return this.tweakable ? tweakedCompressions(bytes) : compressions(bytes);
    },
    get prfCompressions() {
      const bytes = this.N / 8;
      return this.tweakable ? tweakedCompressions(bytes) : compressions(bytes + ADRSC_BYTES);
    },
    get midstate() { return this.tweakable ? 1 : 0; },

    get keygenCompressions() {
      return this.keygenHashCalls * this.hashCompressions
        + this.keygenPrfCalls * this.prfCompressions + this.midstate;
    },
    get signCompressions() {
      return this.signPrfCalls ? this.signPrfCalls * this.prfCompressions + this.midstate : 0;
    },
    get verifyCompressions() {
      return this.verifyHashCalls * this.hashCompressions + this.midstate;
    },

    // BIP 141 block weight limit; witness bytes weigh 1 WU each.
    get perBlock() {
      return Math.floor(4000000 / ((this.sigBits + this.pkBits) / 8));
    },

    bytes(bits) {
      return (bits / 8).toLocaleString() + ' B';
    },
    num(x) {
      return x.toLocaleString();
    },
  };
}
