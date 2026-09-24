import test from 'node:test';
import assert from 'node:assert/strict';

import sphincs, { spans } from '../js/schemes/sphincs.js';
import { initialState } from '../js/scheme.js';

// The tradeoff diagram's axes are scaled against the extremes the parameter
// ranges can reach. Walking every corner is too slow to do on first paint, so
// the spans are pinned in the source; this checks the pinned values still
// match, and so catches a parameter range changing underneath them.

const group = sphincs.results.find((g) => g.tradeoff);

// Kept here as well as in the source, so a change to either side has to be
// made deliberately in both.
const PINNED_SPANS = [
  [8, 343136],
  [3.3858550252753835e-12, 0.013513513513513514],
  [0.0000036825223805297676, 0.1111111111111111],
  [1.0954219119121497e-10, 0.02857142857142857],
  [2, 4.562440617622195e+192],
];

test('the pinned axis spans match a fresh walk of the parameter corners', () => {
  assert.deepEqual(spans(), PINNED_SPANS);
});

test('the pinned spans are the ones the diagram actually draws against', () => {
  // A configuration placed by hand against the pinned spans must land where
  // the diagram puts it, which ties the two together.
  const state = initialState(sphincs.parameters);
  const derived = sphincs.derive(state);
  const figures = [
    (derived.sizes.sig + derived.sizes.pk) / 8,
    1 / (derived.calls.sign.prf + derived.calls.sign.th),
    1 / derived.calls.verify.th,
    1 / (derived.calls.keygen.prf + derived.calls.keygen.th),
    derived.leaves,
  ];
  const { svg } = group.tradeoff(derived);
  const polygon = (cls) => svg.match(new RegExp(`<polygon points="([^"]*)" class="${cls}"`))[1]
    .split(' ').map((p) => p.split(',').map(Number));
  // The centre and radius come from the outermost grid ring, so that moving
  // the diagram's geometry does not require touching this test.
  const rings = [...svg.matchAll(/<polygon points="([^"]*)" class="radar-grid"/g)];
  const outer = rings[rings.length - 1][1].split(' ').map((p) => p.split(',').map(Number));
  const cx = outer.reduce((a, [x]) => a + x, 0) / outer.length;
  const cy = outer.reduce((a, [, y]) => a + y, 0) / outer.length;
  const radius = Math.hypot(outer[0][0] - cx, outer[0][1] - cy);

  const points = polygon('radar-shape');
  points.forEach(([x, y], i) => {
    const [min, max] = PINNED_SPANS[i];
    const want = (Math.log(figures[i]) - Math.log(min)) / (Math.log(max) - Math.log(min));
    const got = Math.hypot(x - cx, y - cy) / radius;
    assert.ok(Math.abs(got - want) < 1e-6, `axis ${i}: drew ${got}, expected ${want}`);
  });
});

test('the grinding knobs are kept out of the axis endpoints', () => {
  // The target sum can be dragged to 0, a 2^261 search at w = 256. If that
  // corner reached the endpoints, the signing axis would run past 1e79 and
  // stop separating realistic parameter sets.
  const [, [, fastest]] = [null, PINNED_SPANS[1]];
  const slowest = 1 / PINNED_SPANS[1][0];
  assert.ok(slowest < 1e12, `signing axis reaches ${slowest.toExponential(1)} hash calls`);
  assert.ok(fastest > 0);
});

test('every axis position stays within the diagram', () => {
  const base = initialState(sphincs.parameters);
  const resolve = (v, s) => (typeof v === 'function' ? v(s) : v);
  const cases = [base];
  for (const p of sphincs.parameters) {
    if (p.type === 'checkbox') cases.push({ ...base, [p.key]: !base[p.key] });
    else if (p.type === 'range') {
      cases.push({ ...base, [p.key]: resolve(p.min, base) });
      cases.push({ ...base, [p.key]: resolve(p.max, base) });
    }
  }
  for (const state of cases) {
    const { svg } = group.tradeoff(sphincs.derive(state));
    const points = svg.match(/<polygon points="([^"]*)" class="radar-shape"/)[1];
    for (const n of points.split(/[ ,]/).map(Number)) {
      assert.ok(Number.isFinite(n), `coordinate ${n} for ${JSON.stringify(state)}`);
    }
  }
});
