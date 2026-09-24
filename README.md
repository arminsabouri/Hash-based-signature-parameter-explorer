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

The schemes are checked against the sizes and hash counts published in FIPS 205
and the [SHRINCS BIP](https://github.com/SHRINCS/shrincs-bip/blob/main/SHRINCS.md),
against each other where two tabs describe the same structure, and for result
rows that fail to render across their parameter ranges. Node 18 or later, no
dependencies:

```sh
just test
```

or:

```sh
node --test 'test/*.test.js'
```

## Deploy

GitHub Pages, deployed from the branch root.
