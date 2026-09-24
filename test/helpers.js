import { initialState } from '../js/scheme.js';

// The state a scheme starts with, as the parameters panel builds it, with
// overrides applied. `derive` is the same entry point the results panel uses.
export function derive(scheme, overrides = {}) {
  return scheme.derive({ ...initialState(scheme.parameters), ...overrides });
}

export const bytes = (bits) => bits / 8;
