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

function initialState(parameters) {
  const state = {};
  for (const p of parameters) if (typeof p.default !== 'function') state[p.key] = p.default;
  for (const p of parameters) if (typeof p.default === 'function') state[p.key] = p.default(state);
  return state;
}

// Counts up to 2^40 as integers, larger ones as a power of two.
export const approx = (x) => (x < 2 ** 40
  ? Math.round(x).toLocaleString()
  : `\\(2^{${Math.log2(x).toFixed(1)}}\\)`);

export const bytes = (bits) => (bits / 8).toLocaleString() + ' B';
export const num = (x) => x.toLocaleString();
