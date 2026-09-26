import test from 'node:test';
import assert from 'node:assert/strict';

import sphincs, { spans as sphincsSpans } from '../js/schemes/sphincs.js';
import shrincs, { spans as shrincsSpans } from '../js/schemes/shrincs.js';
import { initialState } from '../js/scheme.js';
import { clampState, placeOn, solveDrag } from '../js/tradeoff.js';

// The tradeoff diagram's axes are scaled against the extremes the parameter
// ranges can reach. Walking every corner is too slow to do on first paint, so
// the spans are pinned in the source; this checks the pinned values still
// match, and so catches a parameter range changing underneath them.

const group = sphincs.results.find((g) => g.tradeoff);
const shrincsGroup = shrincs.results.find((g) => g.tradeoff);

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
  assert.deepEqual(sphincsSpans(), PINNED_SPANS);
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

// SHRINCS draws one series per signing path on shared axes.

const SHRINCS_SPANS = [
  [10, 343169],
  [6.6158297076245084e-24, 0.012987012987012988],
  [0.0000036825223805297676, 0.14285714285714285],
  [6.615829707624109e-24, 0.011627906976744186],
  [2, 4.562440617622195e+192],
];

test('the pinned SHRINCS axis spans match a fresh walk of the parameter corners', () => {
  assert.deepEqual(shrincsSpans(), SHRINCS_SPANS);
});

test('SHRINCS draws both paths on the same axes', () => {
  const { svg } = shrincsGroup.tradeoff(shrincs.derive(initialState(shrincs.parameters)));
  const shapes = [...svg.matchAll(/<polygon points="([^"]*)" class="radar-shape"([^/]*)\/>/g)];
  assert.equal(shapes.length, 2, 'one shape per signing path');
  const colours = shapes.map((m) => m[2]);
  assert.notEqual(colours[0], colours[1], 'the two paths are told apart by colour');
  assert.ok(svg.includes('Stateful') && svg.includes('Stateless'), 'both are named in the legend');
  // Key generation builds both components, so that axis is shared.
  const radius = (points, i) => {
    const rings = [...svg.matchAll(/<polygon points="([^"]*)" class="radar-grid"/g)];
    const outer = rings[rings.length - 1][1].split(' ').map((p) => p.split(',').map(Number));
    const cx = outer.reduce((a, [x]) => a + x, 0) / outer.length;
    const cy = outer.reduce((a, [, y]) => a + y, 0) / outer.length;
    const [x, y] = points.split(' ')[i].split(',').map(Number);
    return Math.hypot(x - cx, y - cy);
  };
  assert.ok(Math.abs(radius(shapes[0][1], 3) - radius(shapes[1][1], 3)) < 1e-9,
    'key generation is the same on both paths');
});

// Dragging a vertex. No spoke can be set on its own, so the check is that the
// dragged one moves toward the cursor, that the others move only under that
// pressure, and that the state the search lands on is one the sliders allow.

const dragSetup = (scheme, results, axis, radius, seriesIndex = 0) => {
  const state = initialState(scheme.parameters);
  const place = placeOn(results.spans);
  const anchor = results.series.map((s) => place(s.metrics(scheme.derive(state))));
  const free = scheme.parameters
    .filter((p) => p.type === 'range' && !results.hold.includes(p.key))
    .map((p) => p.key);
  const solved = solveDrag({
    config: scheme,
    spans: results.spans,
    series: results.series,
    free,
    anchor,
    state,
    target: { series: seriesIndex, axis, radius },
  });
  const after = results.series.map((s) => place(s.metrics(scheme.derive(solved))));
  return { state, solved, anchor, after, free };
};

test('dragging a vertex moves that spoke toward the cursor', () => {
  for (const axis of [0, 1, 2, 3, 4]) {
    for (const radius of [0, 1]) {
      const { anchor, after } = dragSetup(sphincs, group, axis, radius);
      const before = Math.abs(anchor[0][axis] - radius);
      const now = Math.abs(after[0][axis] - radius);
      assert.ok(now <= before, `axis ${axis} toward ${radius}: ${before} -> ${now}`);
    }
  }
});

test('dragging a vertex steps only the parameters the diagram leaves free', () => {
  const { state, solved, free } = dragSetup(sphincs, group, 2, 1);
  for (const [key, value] of Object.entries(solved)) {
    if (value === state[key]) continue;
    if (free.includes(key)) continue;
    // A held parameter can still move, but only by following one that is free:
    // its bound or its default is a function of the others, so a slider moved
    // by hand would carry it along the same way.
    const p = sphincs.parameters.find((one) => one.key === key);
    const follows = ['min', 'max', 'default'].some((which) => typeof p[which] === 'function')
      || (p.resetOn ?? []).some((dep) => free.includes(dep));
    assert.ok(follows, `${key} moved but is held and depends on nothing free`);
  }
  assert.notDeepEqual(solved, state, 'the search moved something');
});

test('a dragged state stays inside the parameter bounds', () => {
  const { solved } = dragSetup(sphincs, group, 2, 1);
  assert.deepEqual(clampState(sphincs.parameters, solved), solved);
});

test('dragging one series in SHRINCS leaves the other shape anchored', () => {
  // Both shapes read the same parameters, so the other one moves; the check is
  // that it moves less than the one being dragged.
  const { anchor, after } = dragSetup(shrincs, shrincsGroup, 2, 1, 0);
  const pulled = Math.abs(after[0][2] - anchor[0][2]);
  const other = Math.abs(after[1][2] - anchor[1][2]);
  assert.ok(pulled > 0, 'the dragged vertex moved');
  assert.ok(other <= pulled, `other series moved ${other} against ${pulled}`);
});
