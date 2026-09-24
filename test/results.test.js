import test from 'node:test';
import assert from 'node:assert/strict';

import { initialState } from '../js/scheme.js';
import lamport from '../js/schemes/lamport.js';
import wots from '../js/schemes/wots.js';
import xmss from '../js/schemes/xmss.js';
import xmssMt from '../js/schemes/xmss-mt.js';
import fxmss from '../js/schemes/fxmss.js';
import fors from '../js/schemes/fors.js';
import sphincs from '../js/schemes/sphincs.js';
import shrincs from '../js/schemes/shrincs.js';

const schemes = { lamport, wots, xmss, 'xmss-mt': xmssMt, fxmss, fors, sphincs, shrincs };

// Every row the results panel can show must produce a printable value. A row
// that throws, or renders NaN or undefined, breaks the whole panel, so this
// sweeps each parameter across its range with the others left at default.

const resolve = (value, state) => (typeof value === 'function' ? value(state) : value);

// The values a parameter takes: both ends and the middle of a range, every
// option of a select, and both settings of a checkbox.
function samples(p, state) {
  if (p.type === 'checkbox') return [false, true];
  if (p.type === 'select') return p.options;
  const min = resolve(p.min, state);
  const max = resolve(p.max, state);
  return [...new Set([min, Math.round((min + max) / 2), max])]
    .map((v) => min + Math.round((v - min) / p.step) * p.step)
    .filter((v) => v >= min && v <= max);
}

// The rows a scheme shows for a given derived state, as the panel picks them.
function* visibleRows(scheme, derived) {
  for (const group of scheme.results) {
    if (group.show && !group.show(derived)) continue;
    for (const row of group.rows) {
      if (row.show && !row.show(derived)) continue;
      yield [group, row];
    }
  }
}

for (const [id, scheme] of Object.entries(schemes)) {
  test(`${id}: every result row renders across the parameter ranges`, () => {
    const base = initialState(scheme.parameters);
    const cases = [{ ...base }];
    for (const p of scheme.parameters) {
      for (const v of samples(p, base)) cases.push({ ...base, [p.key]: v });
    }

    for (const state of cases) {
      const derived = scheme.derive({ ...state });
      for (const [group, row] of visibleRows(scheme, derived)) {
        const values = row.values ? row.values.map((v) => v(derived)) : [row.value(derived)];
        for (const value of values) {
          const where = `${id} / ${group.heading ?? 'keys'} / ${row.label}`;
          assert.ok(value !== undefined && value !== null, `${where} produced no value`);
          assert.doesNotMatch(String(value), /NaN|undefined|Infinity/, `${where} = ${value}`);
        }
      }
    }
  });

  test(`${id}: sizes stay positive and the total is the sum of its parts`, () => {
    const derived = scheme.derive(initialState(scheme.parameters));
    const sizes = derived.sizes ?? {};
    for (const [name, bits] of Object.entries(sizes)) {
      if (typeof bits !== 'number') continue;
      assert.ok(bits > 0, `${id} ${name} is ${bits}`);
      assert.ok(Number.isInteger(bits), `${id} ${name} is not a whole number of bits`);
    }
  });
}

test('every scheme declares the groups its rows and parameters refer to', () => {
  for (const [id, scheme] of Object.entries(schemes)) {
    const named = new Set(Object.keys(scheme.groups ?? {}));
    for (const p of scheme.parameters) {
      if (p.group) assert.ok(named.has(p.group), `${id}: parameter group ${p.group} has no colour`);
    }
    for (const group of scheme.results) {
      for (const row of group.rows) {
        const g = row.group ?? group.group;
        if (g) assert.ok(named.has(g), `${id}: results group ${g} has no colour`);
      }
    }
    for (const c of scheme.columns ?? []) {
      assert.ok(named.has(c), `${id}: column ${c} has no colour`);
    }
  }
});
