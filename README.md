# Hash Based Digital Signature Parameter Explorer

Static site built with plain HTML, CSS, and [Alpine.js](https://alpinejs.dev) (loaded from jsDelivr). No build step.

## Run locally

ES modules do not load over `file://`, so serve the directory:

```sh
just run
```

or without [just](https://github.com/casey/just):

```sh
python3 -m http.server 8000
```

Then open http://localhost:8000.

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

The three cost models differ in places by choice rather than by error.
`test/reference/conventions.js` states every such difference and the tests
apply it as an offset, so either side moving fails a test.

Node 18 or later, no dependencies:

```sh
just test
```

or:

```sh
node --test 'test/*.test.js'
```

## Deploy

GitHub Pages, deployed from the branch root.
