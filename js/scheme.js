// Generic scheme component. A scheme config supplies `parameters`, `derive`,
// and `results`; the parameters and results panels render from it.
export function scheme(config) {
  let cacheKey, cache;
  return {
    config,
    state: initialState(config.parameters),

    // Parameters can give `default`, `min`, and `max` as functions of the
    // other parameters, and list keys in `resetOn` that restore the default.
    init() {
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
      for (const p of config.parameters) {
        if (p.type !== 'range') continue;
        const v = Math.min(this.bound(p, 'max'), Math.max(this.bound(p, 'min'), this.state[p.key]));
        if (v !== this.state[p.key]) this.state[p.key] = v;
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
