// Generic scheme component. A scheme config supplies `parameters`, `derive`,
// and `results`; the parameters and results panels render from it.
export function scheme(config) {
  let cacheKey, cache;
  return {
    config,
    state: Object.fromEntries(config.parameters.map((p) => [p.key, p.default])),

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

export const bytes = (bits) => (bits / 8).toLocaleString() + ' B';
export const num = (x) => x.toLocaleString();
