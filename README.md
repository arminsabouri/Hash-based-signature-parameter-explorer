# Hash Based Digital Signature Parameter Explorer

Bitcoin authorizes spending with ECDSA and Schnorr signatures over the secp256k1
curve. Shor's algorithm would allow a sufficiently large quantum computer to
solve the elliptic curve discrete logarithm problem and forge these signatures.
Hash-based signature schemes rely only on properties of hash functions, which
Bitcoin already depends on through SHA-256.
[Hash-based Signature Schemes for Bitcoin](https://eprint.iacr.org/2025/2203)
by Kudinov and Nick surveys these schemes and their parameter selection for
Bitcoin, and
[SHRINCS](https://github.com/SHRINCS/shrincs-bip/blob/main/SHRINCS.md)
specifies a scheme that combines a stateful component with a stateless
[SLH-DSA (FIPS 205)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf)
component.

These schemes are assembled from a small set of building blocks: one-time
signatures such as WOTS, few-time signatures such as FORS, and Merkle trees that
combine them. Each exposes parameters. This site lets you adjust those
parameters and see how they change signature size, public key size, signing and
verification cost, statefulness, and signature budget, in terms of block space
and transaction throughput. Figures can be cross-checked against the
[SPHINCS-Parameters](https://github.com/BlockstreamResearch/SPHINCS-Parameters)
scripts. Please note that all results are worst-case estimations. e.g
un-balanced (BXMSS) tree assumes we are opening the last leaf.

**Note:** This tool is a work in progress. Please use the results conservatively.

## Run locally

```sh
just run
```
## Tests

The schemes are checked against three published sources, against each other
where two tabs describe the same structure, and for result rows that fail to
render across their parameter ranges.

- **FIPS 205** Table 2, the six SLH-DSA-SHA2 parameter sets.
- The [SHRINCS BIP](https://github.com/SHRINCS/shrincs-bip/blob/main/SHRINCS.md),
  its constants, its key generation table and its verification bounds.
- [SPHINCS-Parameters](https://github.com/BlockstreamResearch/SPHINCS-Parameters),
  the scripts behind Kudinov and Nick,
  [Hash-based Signature Schemes for Bitcoin](https://eprint.iacr.org/2025/2203).
  Its fixtures and its cost model are vendored under `test/reference/`, which
  pins about 130 published figures and sweeps roughly 4,700 more across the
  parameter grid.

Node 18 or later, no dependencies:

```sh
just test
```

or:

```sh
node --test 'test/*.test.js'
```
