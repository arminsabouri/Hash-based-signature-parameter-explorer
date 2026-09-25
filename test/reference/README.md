# Vendored reference model

`fixtures.json` and `formulas.js` are copied byte for byte from

    https://github.com/BlockstreamResearch/SPHINCS-Parameters
    commit ceee8ed67e8b69ae2d8efd10065b5a550c330018

the scripts behind Kudinov and Nick, *Hash-based Signature Schemes for
Bitcoin* (https://eprint.iacr.org/2025/2203). `fixtures.json` is that
project's regression fixture set; `formulas.js` is the cost model its site
pages share.

That repository publishes no licence file, and neither copied file carries a
copyright header. Both are kept unmodified so they can be re-fetched from the
pinned commit and diffed.

`load.js` and `conventions.js` are ours. `load.js` evaluates `formulas.js`,
which is a plain script rather than a module, and hands back the functions the
tests call. `conventions.js` states every deliberate difference between the two
cost models.
