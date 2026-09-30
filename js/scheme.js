import { clampState, radiusAt, solveDrag, vertexAt } from './tradeoff.js';

// Generic scheme component. A scheme config supplies `parameters`, `derive`,
// and `results`; the parameters and results panels render from it.
export function scheme(config) {
  let cacheKey, cache;
  const defaults = initialState(config.parameters);
  return {
    config,
    state: { ...defaults },

    // Whether anything has been moved away from the defaults, which is when
    // the reset control appears.
    get changed() {
      return config.parameters.some((p) => this.state[p.key] !== defaults[p.key]);
    },

    reset() {
      this.state = { ...defaults };
    },

    // Parameters can give `default`, `min`, and `max` as functions of the
    // other parameters, and list keys in `resetOn` that restore the default.
    init() {
      // A shared link opens this scheme with the parameters it carries. They
      // are applied before the watchers exist, so a dependent parameter keeps
      // the value in the link rather than being reset to its default.
      if (location.hash.slice(1) === config.id) {
        this.state = clampState(config.parameters, { ...defaults, ...stateFromQuery(config.parameters, location.search) });
      }

      // The parameters that differ from the defaults go in the query string
      // while this scheme is the one shown, so the address can be shared.
      // Writes are spaced out, since a drag changes the state on every move
      // and browsers throttle rapid history updates.
      let pending;
      const writeUrl = () => {
        clearTimeout(pending);
        pending = setTimeout(() => {
          if (this.selected !== config.id) return;
          const search = stateToQuery(config.parameters, this.state, defaults, location.search);
          history.replaceState(null, '', `${location.pathname}${search}#${config.id}`);
        }, 150);
      };
      this.$watch('state', writeUrl);
      this.$watch('selected', writeUrl);

      for (const p of config.parameters) {
        for (const key of p.resetOn ?? []) {
          this.$watch(`state.${key}`, () => {
            this.state[p.key] = resolve(p.default, this.state);
          });
        }
      }
      this.$watch('state', () => this.clamp());
    },

    clamp() {
      const next = clampState(config.parameters, this.state);
      for (const p of config.parameters) {
        if (next[p.key] !== this.state[p.key]) this.state[p.key] = next[p.key];
      }
    },

    bound(p, which) {
      return resolve(p[which], this.state);
    },

    // Recomputed only when a parameter changes.
    get derived() {
      const key = JSON.stringify(this.state);
      if (key !== cacheKey) {
        cacheKey = key;
        cache = config.derive({ ...this.state });
      }
      return cache;
    },

    // Segments of a results group's bar: the rows that carry a bit length,
    // with their share of the total and their index in the group.
    barParts(group) {
      const d = this.derived;
      const parts = group.rows
        .map((row, index) => ({ row, index }))
        .filter(({ row }) => row.bits && (!row.show || row.show(d)));
      const total = parts.reduce((a, { row }) => a + row.bits(d), 0);
      return parts.map((p) => ({ ...p, width: (100 * p.row.bits(d)) / total }));
    },

    // The line under the bar: the hovered segment, or a hint when none is.
    barReadout(group, active) {
      if (active === null) return 'Hover a segment to see what it contributes.';
      const d = this.derived;
      const row = group.rows[active];
      const total = this.barParts(group).reduce((a, p) => a + p.row.bits(d), 0);
      const share = (100 * row.bits(d)) / total;
      return `${row.label}: ${bytes(row.bits(d))}, ${share.toFixed(1)}% of the signature`;
    },

    // Plain-text form of a row label, for a bar segment's accessible name.
    barLabel(row) {
      return row.label
        .replace(/\\[()]/g, '')
        .replace(/\\[a-zA-Z]+|[{}_^]/g, '')
        .replace(/\s+/g, ' ')
        .trim();
    },

    // Where the column headings go: above the first group that has rows, so
    // they are not stranded over a group that only draws a diagram.
    get headsIndex() {
      return config.results.findIndex((group) => group.rows && group.rows.length);
    },

    // A tradeoff vertex under the pointer, dragged. The dragged spoke follows
    // the cursor and the rest of the shape moves with it as far as the
    // structure forces, since no spoke can be set on its own.
    drag: null,

    // Which shape a drag grabs. Two shapes can put a vertex in the same place,
    // so the choice is made with a control rather than by the pointer.
    dragSeries: 0,

    // The pointer in the diagram's own coordinates, which the viewBox scales.
    tradeoffPoint(event) {
      const ctm = event.currentTarget.getScreenCTM();
      if (!ctm) return null;
      return new DOMPoint(event.clientX, event.clientY).matrixTransform(ctm.inverse());
    },

    tradeoffGrab(group, event) {
      const at = this.tradeoffPoint(event);
      if (!at) return;
      const drawn = group.tradeoff(this.derived, this.dragSeries);
      const vertex = vertexAt(drawn, at.x, at.y, this.dragSeries);
      if (!vertex) return;
      // Where every vertex sat when the drag began. The solver charges the ones
      // that are not being dragged for leaving it.
      this.drag = { ...vertex, anchor: drawn.shapes.map((s) => s.values) };
      event.currentTarget.setPointerCapture(event.pointerId);
      event.preventDefault();
    },

    tradeoffDrag(group, event) {
      if (!this.drag) return;
      const at = this.tradeoffPoint(event);
      if (!at) return;
      const drawn = group.tradeoff(this.derived, this.dragSeries);
      const free = config.parameters
        .filter((p) => p.type === 'range' && !group.hold.includes(p.key))
        .map((p) => p.key);
      this.state = solveDrag({
        config,
        spans: group.spans,
        series: group.series,
        free,
        anchor: this.drag.anchor,
        state: this.state,
        target: {
          series: this.drag.series,
          axis: this.drag.axis,
          radius: radiusAt(drawn, this.drag.axis, at.x, at.y),
        },
      });
    },

    tradeoffRelease() {
      this.drag = null;
    },

    tooltipId(...parts) {
      return [config.id, 'tip', ...parts].join('-');
    },
    ticksId(key) {
      return `${config.id}-ticks-${key}`;
    },
  };
}

function resolve(value, state) {
  return typeof value === 'function' ? value(state) : value;
}

// Query entries that are not parameters, kept when the parameters are written.
const KEPT_QUERY = ['presentation'];

// The query string for a shared link: every parameter that differs from its
// default, by key. Of what `search` already holds, only the entries in
// KEPT_QUERY stay, so another scheme's parameters are dropped with it.
export function stateToQuery(parameters, state, defaults, search = '') {
  const params = new URLSearchParams(search);
  for (const key of [...params.keys()]) if (!KEPT_QUERY.includes(key)) params.delete(key);
  for (const p of parameters) {
    if (state[p.key] !== defaults[p.key]) params.set(p.key, String(state[p.key]));
  }
  // A flag with no value, such as ?presentation, is written back without "=".
  const query = params.toString().replace(/=(?=&|$)/g, '');
  return query ? `?${query}` : '';
}

// The parameters a query string sets, each read as its type allows. A value
// that is not a number, a checkbox value other than true or false, or a select
// value that is not one of its options is left out, so the default stands.
export function stateFromQuery(parameters, search) {
  const params = new URLSearchParams(search);
  const state = {};
  for (const p of parameters) {
    if (!params.has(p.key)) continue;
    const raw = params.get(p.key);
    if (p.type === 'range') {
      const value = Number(raw);
      if (raw !== '' && Number.isFinite(value)) state[p.key] = value;
    } else if (p.type === 'checkbox') {
      if (raw === 'true' || raw === 'false') state[p.key] = raw === 'true';
    } else if (p.type === 'select') {
      if (p.options.includes(raw)) state[p.key] = raw;
    }
  }
  return state;
}

export function initialState(parameters) {
  const state = {};
  for (const p of parameters) if (typeof p.default !== 'function') state[p.key] = p.default;
  for (const p of parameters) if (typeof p.default === 'function') state[p.key] = p.default(state);
  return state;
}

// Counts up to 2^40 as integers, larger ones as a power of two.
export const approx = (x) => (x < 2 ** 40
  ? Math.round(x).toLocaleString()
  : `\\(2^{${Math.log2(x).toFixed(1)}}\\)`);

export const bytes = (bits) => {
  const b = bits / 8;
  if (b >= 2 ** 30) return (b / 2 ** 30).toFixed(1) + ' GiB';
  if (b >= 2 ** 20) return (b / 2 ** 20).toFixed(1) + ' MiB';
  return Math.ceil(b).toLocaleString() + ' B';
};
export const num = (x) => x.toLocaleString();
