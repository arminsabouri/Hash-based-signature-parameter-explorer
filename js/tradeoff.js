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

// Where a figure sits on its spoke, in [0, 1]. The figures span many orders of
// magnitude, so each sits on a log scale between its two pinned endpoints.
export const placeOn = (spans) => (metrics) => AXES.map((axis, i) => {
  const [min, max] = spans[i];
  const v = axis.of(metrics);
  const t = max > min ? (Math.log(v) - Math.log(min)) / (Math.log(max) - Math.log(min)) : 0.5;
  return Math.min(1, Math.max(0, t));
});

// The vertex nearest a point, as a series and axis pair, or null when the point
// is further than `within` from every vertex. `drawn` is what `tradeoffSvg`
// returned, so the search runs over the radii actually on screen.
export function vertexAt(drawn, x, y, within = 14) {
  let found = null;
  drawn.shapes.forEach((shape, s) => {
    shape.values.forEach((v, i) => {
      const r = drawn.radius * v;
      const dx = x - (drawn.cx + r * Math.cos(drawn.angle(i)));
      const dy = y - (drawn.cy + r * Math.sin(drawn.angle(i)));
      const distance = Math.hypot(dx, dy);
      if (distance <= within && (!found || distance < found.distance)) {
        found = { series: s, axis: i, distance };
      }
    });
  });
  return found;
}

// Where along a spoke a point falls, in [0, 1]: its distance from the centre
// projected onto that spoke's direction.
export function radiusAt(drawn, axis, x, y) {
  const t = ((x - drawn.cx) * Math.cos(drawn.angle(axis))
    + (y - drawn.cy) * Math.sin(drawn.angle(axis))) / drawn.radius;
  return Math.min(1, Math.max(0, t));
}

// A dragged vertex weighs this much more than a vertex holding its place, so
// the drag reaches the cursor when it can and the rest give way only as far as
// the structure forces.
const TARGET_WEIGHT = 8;

// A spoke's radius is a one-way function of the parameters, so a dragged vertex
// is placed by search rather than by inversion. `anchor` is the shape as it
// stood when the drag began; every vertex but the dragged one is charged for
// leaving it, which is what makes the rest of the shape respond to the drag
// instead of being rearranged freely. The search is coordinate descent over the
// free parameters, one step at a time, so it returns a state reachable from the
// current one and not merely one that fits.
export function solveDrag({
  config, spans, series, free, target, anchor, state, steps = 40,
}) {
  const place = placeOn(spans);
  const params = config.parameters.filter((p) => p.type === 'range' && free.includes(p.key));
  const shape = (s) => series.map((one) => place(one.metrics(config.derive({ ...s }))));

  const cost = (values) => {
    let total = TARGET_WEIGHT * (values[target.series][target.axis] - target.radius) ** 2;
    values.forEach((row, s) => row.forEach((v, i) => {
      if (s !== target.series || i !== target.axis) total += (v - anchor[s][i]) ** 2;
    }));
    return total;
  };

  let best = state;
  let bestCost = cost(shape(state));
  for (let step = 0; step < steps; step++) {
    let moved = false;
    for (const p of params) {
      for (const delta of [p.step, -p.step]) {
        const next = clampState(config.parameters, { ...best, [p.key]: best[p.key] + delta });
        if (next[p.key] === best[p.key]) continue;
        const c = cost(shape(next));
        if (c < bestCost - 1e-12) {
          best = next;
          bestCost = c;
          moved = true;
        }
      }
    }
    if (!moved) break;
  }
  return best;
}

// Every range parameter pulled inside its bounds, which may depend on the
// others. Shared with the component's own clamp so a searched state and a
// dragged slider land on the same rules.
export function clampState(parameters, state) {
  const next = { ...state };
  for (const p of parameters) {
    if (p.type !== 'range') continue;
    next[p.key] = Math.min(resolve(p.max, next), Math.max(resolve(p.min, next), next[p.key]));
  }
  return next;
}

// A results group that draws the diagram. `spans` are the pinned endpoints, and
// `hold` names the parameters a drag leaves alone.
export function tradeoffGroup({ heading = 'Tradeoff diagram', spans, series, hold = [] }) {
  const place = placeOn(spans);

  return {
    heading,
    spans,
    series,
    hold,
    tradeoff: (derived) => tradeoffSvg(
      AXES,
      series.map((s) => ({ name: s.name, color: s.color, values: place(s.metrics(derived)) })),
    ),
    rows: [],
  };
}
