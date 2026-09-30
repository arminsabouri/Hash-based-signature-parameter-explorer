import test from 'node:test';
import assert from 'node:assert/strict';

import { initialState, stateFromQuery, stateToQuery } from '../js/scheme.js';
import lamport from '../js/schemes/lamport.js';
import wots from '../js/schemes/wots.js';
import xmss from '../js/schemes/xmss.js';
import xmssMt from '../js/schemes/xmss-mt.js';
import fxmss from '../js/schemes/fxmss.js';
import fors from '../js/schemes/fors.js';
import sphincs from '../js/schemes/sphincs.js';
import shrincs from '../js/schemes/shrincs.js';

const schemes = { lamport, wots, xmss, 'xmss-mt': xmssMt, fxmss, fors, sphincs, shrincs };

// A shared link carries the parameters that differ from the defaults, and
// opening it restores them.

const resolve = (value, state) => (typeof value === 'function' ? value(state) : value);

// Every parameter moved off its default at once: a range to its other end, a
// checkbox flipped, a select to another option.
function moved(scheme) {
  const defaults = initialState(scheme.parameters);
  const state = { ...defaults };
  for (const p of scheme.parameters) {
    if (p.type === 'checkbox') state[p.key] = !defaults[p.key];
    else if (p.type === 'select') state[p.key] = p.options.find((o) => o !== defaults[p.key]);
    else {
      const min = resolve(p.min, state);
      const max = resolve(p.max, state);
      state[p.key] = defaults[p.key] === min ? max : min;
    }
  }
  return { defaults, state };
}

for (const [id, scheme] of Object.entries(schemes)) {
  test(`${id}: a link restores every parameter that was changed`, () => {
    const { defaults, state } = moved(scheme);
    const query = stateToQuery(scheme.parameters, state, defaults);
    assert.deepEqual({ ...defaults, ...stateFromQuery(scheme.parameters, query) }, state);
  });
}

test('a scheme on its defaults has no query string', () => {
  for (const scheme of Object.values(schemes)) {
    const defaults = initialState(scheme.parameters);
    assert.equal(stateToQuery(scheme.parameters, defaults, defaults), '');
  }
});

test('only the parameters that differ from the defaults are written', () => {
  const defaults = initialState(sphincs.parameters);
  const query = stateToQuery(sphincs.parameters, { ...defaults, d: 3, wotsPlusC: true }, defaults);
  assert.equal(query, '?d=3&wotsPlusC=true');
});

test('the presentation flag is kept and stale parameters are dropped', () => {
  const defaults = initialState(sphincs.parameters);
  // d is a SPHINCS+ parameter; depth belongs to SHRINCS, the tab left behind.
  const query = stateToQuery(sphincs.parameters, { ...defaults, k: 20 }, defaults, '?presentation&d=3&depth=12');
  assert.equal(query, '?presentation&k=20');
});

test('values a parameter cannot take are ignored', () => {
  const read = stateFromQuery(shrincs.parameters, '?depth=abc&shape=nope&n=&sfB=3');
  assert.deepEqual(read, { sfB: 3 });
  assert.deepEqual(stateFromQuery(sphincs.parameters, '?wotsPlusC=yes&forsPlusC=true'), { forsPlusC: true });
});
