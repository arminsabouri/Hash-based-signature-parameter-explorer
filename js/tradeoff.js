import { tradeoffSvg } from './draw.js';

// The tradeoff diagram, shared by the schemes that show one. A scheme supplies
// one series per thing being compared, each reporting the same five figures,
// and they are drawn on one set of axes so the shapes can be read against each
// other.

// A series reports these five figures for the current parameters. Costs are
// hash calls; `budget` is the number of signatures a key pair can make.
export const metricKeys = ['blockSpace', 'signCalls', 'verifyCalls', 'keygenCalls', 'budget'];

// One spoke each, starting at the top and going clockwise. Block space grows
// outward with size; the three speeds grow outward as the call count falls.
export const AXES = [
  { label: ['Block space', 'consumption'], of: (m) => m.blockSpace },
  { label: ['Signature', 'generation speed'], of: (m) => 1 / m.signCalls },
  { label: ['Verification', 'speed'], of: (m) => 1 / m.verifyCalls },
  { label: ['Key generation', 'speed'], of: (m) => 1 / m.keygenCalls },
  { label: ['Signing budget'], of: (m) => m.budget },
];

// Hash calls for one operation, counting PRF and Th together.
export const hashCallCount = (c) => (c.prf ?? 0) + (c.th ?? 0);

const resolve = (value, state) => (typeof value === 'function' ? value(state) : value);

// Every corner of the parameter ranges: each slider at its minimum or its
// maximum, each toggle both ways, and each select at every option. Parameters
// named in `hold` stay at their defaults, which is where the knobs that only
// tune a counter search go: their extremes make a search astronomically long
// and would stretch an axis past every realistic setting. A bound that depends
// on other parameters is resolved against the corner being built, so the order
// of the parameter list matters here.
export function cornerStates(parameters, hold = []) {
  const held = new Set(hold);
  const ranges = parameters.filter((p) => p.type === 'range' && !held.has(p.key));
  const fixed = parameters.filter((p) => p.type === 'range' && held.has(p.key));
  const flags = parameters.filter((p) => p.type === 'checkbox');
  const selects = parameters.filter((p) => p.type === 'select');

  // The choices each select and toggle can take, as a list of partial states.
  let choices = [{}];
  for (const p of [...flags, ...selects]) {
    const options = p.type === 'checkbox' ? [false, true] : p.options;
    choices = choices.flatMap((c) => options.map((o) => ({ ...c, [p.key]: o })));
  }

  const states = [];
  for (const choice of choices) {
    for (let m = 0; m < 2 ** ranges.length; m++) {
      const state = { ...choice };
      ranges.forEach((p, i) => {
        const lo = resolve(p.min, state);
        const hi = resolve(p.max, state);
        state[p.key] = (m & (1 << i)) ? hi : lo;
      });
      fixed.forEach((p) => { state[p.key] = resolve(p.default, state); });
      states.push(state);
    }
  }
  return states;
}

// The span of each axis over those corners, taken across every series so that
// the series share one scale. Walking the corners is too slow to do on first
// paint, so a scheme pins the result and a test checks it still matches.
export function axisSpans(config, series, hold) {
  const spans = AXES.map(() => ({ min: Infinity, max: -Infinity }));
  for (const state of cornerStates(config.parameters, hold)) {
    const derived = config.derive(state);
    for (const s of series) {
      const metrics = s.metrics(derived);
      AXES.forEach((axis, i) => {
        const v = axis.of(metrics);
        if (!Number.isFinite(v) || v <= 0) return;
        spans[i].min = Math.min(spans[i].min, v);
        spans[i].max = Math.max(spans[i].max, v);
      });
    }
  }
  return spans.map((s) => [s.min, s.max]);
}

// A results group that draws the diagram. `spans` are the pinned endpoints.
export function tradeoffGroup({ heading = 'Tradeoff diagram', spans, series }) {
  // The figures span many orders of magnitude, so each sits on a log scale
  // between its two endpoints.
  const place = (metrics) => AXES.map((axis, i) => {
    const [min, max] = spans[i];
    const v = axis.of(metrics);
    const t = max > min ? (Math.log(v) - Math.log(min)) / (Math.log(max) - Math.log(min)) : 0.5;
    return Math.min(1, Math.max(0, t));
  });

  return {
    heading,
    tradeoff: (derived) => tradeoffSvg(
      AXES,
      series.map((s) => ({ name: s.name, color: s.color, values: place(s.metrics(derived)) })),
    ),
    rows: [],
  };
}
