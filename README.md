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

## Deploy

GitHub Pages, deployed from the branch root.
