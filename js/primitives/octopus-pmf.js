// A port of octopus_pmf.py from https://github.com/MehdiAbri/PORS-FP (MIT),
// as vendored in BlockstreamResearch/SPHINCS-Parameters. It gives the
// distribution of the Octopus authentication set size when k distinct leaves
// are opened in a left-filled tree of t leaves, and from it the expected
// grinding work for PORS+FP at each m_max.
//
// The binomials are exact, as Python's math.comb is, and each ratio is rounded
// once, as Python's int / int is, so the floats follow the original closely.
// The loops and the order the sums are taken in are kept as they are there.
//
// The original's licence:
//
//   MIT License
//
//   Copyright (c) 2025 Anonymous
//
//   Permission is hereby granted, free of charge, to any person obtaining a copy
//   of this software and associated documentation files (the "Software"), to deal
//   in the Software without restriction, including without limitation the rights
//   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//   copies of the Software, and to permit persons to whom the Software is
//   furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in all
//   copies or substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//   SOFTWARE.

const combCache = new Map();

function comb(n, k) {
  if (n < 0 || k < 0 || k > n) return 0n;
  const r = Math.min(k, n - k);
  const key = `${n},${r}`;
  let c = combCache.get(key);
  if (c === undefined) {
    c = 1n;
    for (let i = 0; i < r; i++) c = (c * BigInt(n - i)) / BigInt(i + 1);
    combCache.set(key, c);
  }
  return c;
}

const bitLength = (x) => x.toString(2).length;

// num / den for non-negative BigInts, rounded to a double.
function ratio(num, den) {
  if (num === 0n || den === 0n) return 0;
  const shift = bitLength(den) - bitLength(num) + 64;
  const q = shift >= 0 ? (num << BigInt(shift)) / den : num / (den << BigInt(-shift));
  return Number(q) * 2 ** -shift;
}

function P(x, j, s) {
  if (x % 2 !== 0 || j < 0 || s < 0 || j > x || 2 * s > j) return 0;
  const num = comb(x / 2, j - s) * comb(j - s, s) * (1n << BigInt(j - 2 * s));
  const den = comb(x, j);
  if (den === 0n) return 0;
  return ratio(num, den);
}

const floorHalf = (x) => Math.floor(x / 2);

// Adds `w * p` for each (m, p) of `dist`, shifted by `singles`, into `out`.
function accumulate(out, dist, singles, w) {
  for (const [m, p] of dist) out.set(singles + m, (out.get(singles + m) ?? 0) + w * p);
}

// Upper-level recursion M_h(L, R, k_L, k_R, c) with c in {-1, 0, +1}.
const memo = new Map();

function M(ell, L, R, kL, kR, c = 0) {
  const key = `${ell},${L},${R},${kL},${kR},${c}`;
  const hit = memo.get(key);
  if (hit) return hit;
  const out = recurse(ell, L, R, kL, kR, c);
  memo.set(key, out);
  return out;
}

function recurse(ell, L, R, kL, kR, c) {
  if (ell === 0) return new Map([[0, 1]]);
  if (!(kL >= 0 && kL <= L && kR >= 0 && kR <= R)) return new Map();

  const out = new Map();

  if (L % 2 === 0) {
    // Even L: the boundary does not cut a sibling pair.
    if (c === 0) {
      for (let rL = 0; rL <= floorHalf(kL); rL++) {
        const wL = P(L, kL, rL);
        if (wL === 0) continue;
        for (let rR = 0; rR <= floorHalf(kR); rR++) {
          const wR = P(R, kR, rR);
          if (wR === 0) continue;
          const singles = (kL + kR) - 2 * (rL + rR);
          const nxt = M(ell - 1, floorHalf(L), floorHalf(R), kL - rL, kR - rR, 0);
          accumulate(out, nxt, singles, wL * wR);
        }
      }
    } else if (c === 1) {
      // The boundary index is forced selected.
      if (R < 1 || kR < 1) return new Map();
      if (R === 1) {
        for (let rL = 0; rL <= floorHalf(kL); rL++) {
          const wL = P(L, kL, rL);
          if (wL === 0) continue;
          const rR = 0;
          const singles = (kL + kR) - 2 * (rL + rR);
          const nxt = M(ell - 1, floorHalf(L), 0, kL - rL, kR - rR, 1);
          accumulate(out, nxt, singles, wL);
        }
      } else {
        const denom = comb(R - 1, kR - 1);
        if (denom === 0n) return new Map();
        // Y: whether the sibling of the forced index is selected.
        const wY1 = ratio(comb(R - 2, kR - 2), denom);
        const wY0 = ratio(comb(R - 2, kR - 1), denom);
        for (let rL = 0; rL <= floorHalf(kL); rL++) {
          const wL = P(L, kL, rL);
          if (wL === 0) continue;
          for (const [y, wy] of [[1, wY1], [0, wY0]]) {
            if (wy === 0) continue;
            for (let rRp = 0; rRp <= floorHalf(kR - 1 - y); rRp++) {
              const wRp = P(R - 2, kR - 1 - y, rRp);
              if (wRp === 0) continue;
              const rR = y + rRp;
              const singles = (kL + kR) - 2 * (rL + rR);
              const nxt = M(ell - 1, floorHalf(L), floorHalf(R), kL - rL, kR - rR, 1);
              accumulate(out, nxt, singles, wL * wy * wRp);
            }
          }
        }
      }
    } else {
      // The boundary index is forbidden.
      if (R === 0 || R === 1) {
        if (kR !== 0) return new Map();
        for (let rL = 0; rL <= floorHalf(kL); rL++) {
          const wL = P(L, kL, rL);
          if (wL === 0) continue;
          const singles = (kL + kR) - 2 * rL;
          const nxt = M(ell - 1, floorHalf(L), 0, kL - rL, kR, -1);
          accumulate(out, nxt, singles, wL);
        }
      } else {
        const denom = comb(R - 1, kR);
        if (denom === 0n) return new Map();
        // Z: whether position 1, the sibling of the forbidden 0, is selected.
        const wZ0 = ratio(comb(R - 2, kR), denom);
        const wZ1 = ratio(comb(R - 2, kR - 1), denom);
        for (let rL = 0; rL <= floorHalf(kL); rL++) {
          const wL = P(L, kL, rL);
          if (wL === 0) continue;
          for (const [z, wz] of [[0, wZ0], [1, wZ1]]) {
            if (wz === 0) continue;
            for (let rRp = 0; rRp <= floorHalf(kR - z); rRp++) {
              const wRp = P(R - 2, kR - z, rRp);
              if (wRp === 0) continue;
              const singles = (kL + kR) - 2 * (rL + rRp);
              const nxt = M(ell - 1, floorHalf(L), floorHalf(R), kL - rL, kR - rRp, z === 1 ? 1 : -1);
              accumulate(out, nxt, singles, wL * wz * wRp);
            }
          }
        }
      }
    }
  } else {
    // Odd L: the boundary cuts a sibling pair, between positions L - 1 and L.
    const denomL = comb(L, kL);
    if (denomL === 0n) return new Map();
    const side = (n, total, kk, x) => (kk - x >= 0 && kk - x <= n - 1 ? ratio(comb(n - 1, kk - x), total) : 0);
    const Lnext = floorHalf(L - 1);
    const Rnext = floorHalf(R - 1) + 1;

    if (c === 0) {
      const denomR = comb(R, kR);
      if (denomR === 0n) return new Map();
      for (const xL of [0, 1]) {
        const wxL = side(L, denomL, kL, xL);
        if (wxL === 0) continue;
        for (const xR of [0, 1]) {
          const wxR = side(R, denomR, kR, xR);
          if (wxR === 0) continue;
          const kLin = kL - xL;
          const kRin = kR - xR;
          for (let rL = 0; rL <= floorHalf(kLin); rL++) {
            const wL = P(L - 1, kLin, rL);
            if (wL === 0) continue;
            for (let rR = 0; rR <= floorHalf(kRin); rR++) {
              const wR = P(R - 1, kRin, rR);
              if (wR === 0) continue;
              const merge = xL * xR;
              const singles = (kL + kR) - 2 * (rL + rR + merge);
              const kLnext = kL - xL - rL;
              const kRnext = kR - xR - rR + (xL + xR - merge);
              const nxt = M(ell - 1, Lnext, Rnext, kLnext, kRnext, xL + xR >= 1 ? 1 : -1);
              accumulate(out, nxt, singles, wxL * wxR * wL * wR);
            }
          }
        }
      }
    } else if (c === 1) {
      if (R < 1 || kR < 1) return new Map();
      for (const xL of [0, 1]) {
        const wxL = side(L, denomL, kL, xL);
        if (wxL === 0) continue;
        const kLin = kL - xL;
        const kRin = kR - 1; // xR = 1
        for (let rL = 0; rL <= floorHalf(kLin); rL++) {
          const wL = P(L - 1, kLin, rL);
          if (wL === 0) continue;
          for (let rR = 0; rR <= floorHalf(kRin); rR++) {
            const wR = P(R - 1, kRin, rR);
            if (wR === 0) continue;
            const singles = (kL + kR) - 2 * (rL + rR + xL);
            const nxt = M(ell - 1, Lnext, Rnext, kL - xL - rL, kR - rR, 1);
            accumulate(out, nxt, singles, wxL * wL * wR);
          }
        }
      }
    } else {
      if (R < 1) return new Map();
      for (const xL of [0, 1]) {
        const wxL = side(L, denomL, kL, xL);
        if (wxL === 0) continue;
        const kLin = kL - xL;
        const kRin = kR; // xR = 0
        for (let rL = 0; rL <= floorHalf(kLin); rL++) {
          const wL = P(L - 1, kLin, rL);
          if (wL === 0) continue;
          for (let rR = 0; rR <= floorHalf(kRin); rR++) {
            const wR = P(R - 1, kRin, rR);
            if (wR === 0) continue;
            const singles = (kL + kR) - 2 * (rL + rR);
            const nxt = M(ell - 1, Lnext, Rnext, kL - xL - rL, kR - rR + xL, xL === 1 ? 1 : -1);
            accumulate(out, nxt, singles, wxL * wL * wR);
          }
        }
      }
    }
  }
  return out;
}

// The full distribution, Theorem 3.
export function pmfLeftfilled(t, k) {
  if (!(k >= 1 && k <= t)) return new Map();

  // h = ceil(log2 t); p = 2^(h-1); L = t - p; x = 2L, the bottom-layer population.
  const h = bitLength(BigInt(t - 1)) - (t - 1 === 0 ? 1 : 0);
  const p = h > 0 ? 2 ** (h - 1) : 1;
  const L = t - p;
  const x = 2 * L;

  const pmf = new Map();
  const denom = comb(t, k);
  if (denom === 0n) return new Map();

  // Hypergeometric j, the number selected among the bottom x leaves.
  for (let j = 0; j <= Math.min(k, x); j++) {
    const wj = ratio(comb(x, j) * comb(t - x, k - j), denom);
    if (wj === 0) continue;
    // s, the number of full sibling pairs among those j.
    for (let s = 0; s <= floorHalf(j); s++) {
      const ws = P(x, j, s);
      if (ws === 0) continue;
      const upper = M(Math.max(h - 1, 0), h > 0 ? L : 0, h > 0 ? p - L : 0, j - s, k - j, 0);
      accumulate(pmf, upper, j - 2 * s, wj * ws);
    }
  }
  return pmf;
}

const tables = new Map();

// (m_max, log2 E[work]) for every m_max whose probability is nonzero, as a
// Map from m_max. Cached per (t, k).
export function interleaveCostTable(t, k) {
  const key = `${t},${k}`;
  let table = tables.get(key);
  if (table) return table;
  table = new Map();
  const pmf = pmfLeftfilled(t, k);
  if (pmf.size) {
    const top = Math.max(...pmf.keys());
    let run = 0;
    for (let m = 0; m <= top; m++) {
      run += pmf.get(m) ?? 0;
      if (run > 0) table.set(m, -Math.log2(run));
    }
  }
  tables.set(key, table);
  return table;
}
