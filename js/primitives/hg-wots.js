// HG-WOTS keys and HagGrid, which nests them, on their own or at the leaves of
// an HGT tree.
//
// A key is a stack of levels. Each level has `units` units, and every
// unit has its own hash chain of `length` values running up to its parent. A
// signature opens `open` units of a level and reveals one node on the chain of
// each other unit. An opened unit holds the units of the next level, or below
// the last level a bottom group of `chains` chains, each revealing one node.
// HG-WOTS is one level that opens k - j groups. HagGrid is several levels that
// each open one unit.
//
// Positions are distances to the chain end, the steps the verifier walks. The
// distances of the hidden units of a level sum to that level's `sum`, and
// those of each opened bottom group to the bottom `sum`.
//
// The forgery model is forward hashing only. A node is derivable from an
// earlier node of its chain, and a unit's chain start from the ends of every
// chain under it, which a past signature exposes when it opened that unit.

export const TARGET_BITS = 128;

// Signatures per key, and per tree instance, the forgery probability is
// computed for.
export const Q_MAX = 32;
export const R_MAX = 32;

// The cover computation for `count` distances on chains of `length` values
// fills tables of length^(count - 1) cells, so `count` is kept to this.
export const maxCount = (length) => 1 + Math.floor(20 / Math.log2(length));

// Hash calls to build one leaf key: every chain to its end, plus one call per
// unit and per bottom group on the chain ends under it, and one for the key.
export function keygen({ levels, bottom }) {
  let unit = bottom.chains * (bottom.length - 1) + 1;
  for (let i = levels.length - 1; i >= 0; i--) {
    unit += levels[i].length - 1;
    unit = levels[i].units * unit + 1;
  }
  return unit;
}

// Hash calls to verify one leaf signature. The verifier walks each revealed
// node to its chain end and each opened unit's chain from its start.
export function verify({ levels, bottom }) {
  let opened = bottom.sum + 1;
  for (let i = levels.length - 1; i >= 0; i--) {
    opened += levels[i].length - 1;
    opened = levels[i].open * opened + levels[i].sum + 1;
  }
  return opened;
}

// Hash calls to sign: every chain from its start up to the node the signature
// sends. A hidden unit's chain starts from the ends of everything under it,
// which the signer builds in full. The fixed sums make this the same for
// every message.
export function sign({ levels, bottom }) {
  // Hash calls for the start of a unit's chain, from the deepest level up.
  const starts = new Array(levels.length);
  let start = bottom.chains * (bottom.length - 1) + 1;
  for (let i = levels.length - 1; i >= 0; i--) {
    starts[i] = start;
    start = levels[i].units * (start + levels[i].length - 1) + 1;
  }
  let opened = bottom.chains * (bottom.length - 1) - bottom.sum;
  for (let i = levels.length - 1; i >= 0; i--) {
    const { units, open, length, sum } = levels[i];
    const hidden = units - open;
    opened = open * opened + hidden * starts[i] + hidden * (length - 1) - sum;
  }
  return opened;
}

// n-bit nodes in one leaf signature.
export function nodes({ levels, bottom }) {
  let opened = 1, total = 0;
  for (const level of levels) {
    total += opened * (level.units - level.open);
    opened *= level.open;
  }
  return total + opened * bottom.chains;
}

const choose = (n, k) => {
  if (k < 0 || k > n) return 0;
  let r = 1;
  for (let i = 0; i < k; i++) r = (r * (n - i)) / (i + 1);
  return r;
};

// ways[i][s]: the ways to write s as i distances in [0, max].
function waysTable(count, sum, max) {
  const ways = [[1, ...new Array(sum).fill(0)]];
  for (let i = 1; i <= count; i++) {
    const row = new Array(sum + 1).fill(0);
    for (let s = 0; s <= sum; s++) {
      for (let d = 0; d <= Math.min(max, s); d++) row[s] += ways[i - 1][s - d];
    }
    ways.push(row);
  }
  return ways;
}

// cover[u][m]: for a uniform target of `count` distances in [0, max] summing
// to `sum`, and m uniform past ones, the probability that each of u given
// target distances is at most the same distance of some past one, so that a
// past node is at or before the target node on every one of those chains.
//
// By inclusion-exclusion over the chains no past one reaches, this is the sum
// over a of (-1)^a C(u, a) E[F_a(t)^m], with F_a the probability that one
// past vector is below the target on a given chains. The distances are
// exchangeable, so any a chains will do, and F_count is 0 since the sums are
// equal. The grids below have (max + 1)^a cells.
function coverTable(count, sum, max, mMax) {
  const ways = waysTable(count, sum, max);
  const total = ways[count][sum];
  const side = max + 1;
  const moments = [new Float64Array(mMax + 1).fill(1)];

  for (let a = 1; a < count; a++) {
    const size = side ** a;
    const pmf = new Float64Array(size);
    for (let idx = 0; idx < size; idx++) {
      let x = idx, s = 0;
      for (let c = 0; c < a; c++) {
        s += x % side;
        x = Math.floor(x / side);
      }
      if (s <= sum) pmf[idx] = ways[count - a][sum - s] / total;
    }
    // Cumulative along every axis, then read one step below on each axis for
    // the strict inequality.
    const cdf = Float64Array.from(pmf);
    let offset = 0;
    for (let c = 0, stride = 1; c < a; c++, stride *= side) {
      offset += stride;
      for (let idx = 0; idx < size; idx++) {
        if (Math.floor(idx / stride) % side > 0) cdf[idx] += cdf[idx - stride];
      }
    }
    const row = new Float64Array(mMax + 1);
    for (let idx = 0; idx < size; idx++) {
      if (pmf[idx] === 0) continue;
      let x = idx, inside = true;
      for (let c = 0; c < a; c++) {
        if (x % side === 0) inside = false;
        x = Math.floor(x / side);
      }
      const F = inside ? cdf[idx - offset] : 0;
      let term = pmf[idx];
      for (let m = 0; m <= mMax; m++) {
        row[m] += term;
        term *= F;
      }
    }
    moments.push(row);
  }
  const none = new Float64Array(mMax + 1);
  none[0] = 1;
  moments.push(none);

  const cover = [];
  for (let u = 0; u <= count; u++) {
    const row = new Float64Array(mMax + 1);
    for (let a = 0; a <= u; a++) {
      const c = (a % 2 ? -1 : 1) * choose(u, a);
      for (let m = 0; m <= mMax; m++) row[m] += c * moments[a][m];
    }
    cover.push(row);
  }
  return cover;
}

// States of m draws, each a uniform `open`-subset of `units` items, as seen
// from one fixed `open`-subset: how many draws included each of its items,
// sorted, and unless `others` is null, how many of the other `others` items
// some draw included. Kept per shape, since the transitions do not depend on
// `units`.
const shapes = new Map();

function drawShape(open, others, mMax) {
  const key = `${open}|${others}|${mMax}`;
  const hit = shapes.get(key);
  if (hit) return hit;

  const counts = [];
  const touched = [];
  const index = new Map();
  const code = (c, v) => c.reduce((x, y) => x * (mMax + 1) + y, v);
  (function enumerate(prefix, cap) {
    if (prefix.length === open) {
      for (let v = 0; v <= (others ?? 0); v++) {
        index.set(code(prefix, v), counts.length);
        counts.push(prefix);
        touched.push(v);
      }
      return;
    }
    for (let x = 0; x <= cap; x++) enumerate([...prefix, x], x);
  })([], mMax);

  // Each transition is a target state and the numbers of opened items, of
  // already touched others, and of new others that the draw includes.
  const from = [0];
  const to = [], opened = [], old = [], fresh = [];
  counts.forEach((c, s) => {
    const v = touched[s];
    for (let P = 0; P < 1 << open; P++) {
      const next = c.map((x, i) => x + ((P >> i) & 1)).sort((x, y) => y - x);
      if (next[0] > mMax) continue;
      let a = 0;
      for (let i = 0; i < open; i++) a += (P >> i) & 1;
      const push = (o, f) => {
        to.push(index.get(code(next, v + f)));
        opened.push(a);
        old.push(o);
        fresh.push(f);
      };
      if (others === null) {
        push(0, 0);
        continue;
      }
      for (let o = 0; o <= Math.min(v, open - a); o++) {
        const f = open - a - o;
        if (f <= others - v) push(o, f);
      }
    }
    from.push(to.length);
  });
  const shape = {
    counts, touched,
    from: Int32Array.from(from),
    to: Int32Array.from(to),
    opened: Int8Array.from(opened),
    old: Int8Array.from(old),
    fresh: Int8Array.from(fresh),
    start: index.get(code(new Array(open).fill(0), 0)),
  };
  shapes.set(key, shape);
  return shape;
}

// Runs the draws m = 0..mMax and calls visit(m, dist, shape) with the
// probability of every state after m draws. With `track`, the other items are
// tracked; otherwise a transition stands for every way the draw can fill its
// remaining picks from them.
function draws(units, open, mMax, track, visit) {
  const others = units - open;
  const shape = drawShape(open, track ? others : null, mMax);
  const all = choose(units, open);
  const w = new Float64Array(shape.to.length);
  for (let s = 0; s < shape.counts.length; s++) {
    const v = shape.touched[s];
    for (let t = shape.from[s]; t < shape.from[s + 1]; t++) {
      w[t] = track
        ? (choose(v, shape.old[t]) * choose(others - v, shape.fresh[t])) / all
        : choose(others, open - shape.opened[t]) / all;
    }
  }

  let dist = new Float64Array(shape.counts.length);
  dist[shape.start] = 1;
  for (let m = 0; m <= mMax; m++) {
    visit(m, dist, shape);
    if (m === mMax) break;
    const next = new Float64Array(dist.length);
    for (let s = 0; s < dist.length; s++) {
      const p = dist[s];
      if (p === 0) continue;
      for (let t = shape.from[s]; t < shape.from[s + 1]; t++) next[shape.to[t]] += p * w[t];
    }
    dist = next;
  }
}

// cover(x) for x = 0..xMax: the probability that a uniform target signature
// on one leaf is derivable from x uniform past signatures on that leaf.
//
// Within an opened unit, a hidden unit's node is derivable when a past
// signature opened that unit, or hid it at the same or a larger distance. The
// units no past signature opened are hidden in all of them. The bottom group
// needs, on every chain, a past signature that opened it at the same or a
// larger distance.
export function cover({ levels, bottom }, xMax) {
  let below = coverTable(bottom.chains, bottom.sum, bottom.length - 1, xMax)[bottom.chains];
  for (let i = levels.length - 1; i >= 0; i--) {
    const { units, open, length, sum } = levels[i];
    const hidden = units - open;
    const hid = coverTable(hidden, sum, length - 1, xMax);
    const level = new Float64Array(xMax + 1);
    const inner = below;
    draws(units, open, xMax, true, (m, dist, shape) => {
      let total = 0;
      for (let s = 0; s < dist.length; s++) {
        if (dist[s] === 0) continue;
        let p = dist[s] * hid[hidden - shape.touched[s]][m];
        for (const x of shape.counts[s]) p *= inner[x];
        total += p;
      }
      level[m] = total;
    });
    below = level;
  }
  return below;
}

// Forgery probability for r = 0..rMax: a fresh signature picks K of the N
// leaves, and every one of them must be derivable from the past signatures
// that picked it, out of r signatures that each picked K distinct leaves.
export function forgery(leafCover, N, K, rMax) {
  const out = new Float64Array(rMax + 1);
  draws(N, K, rMax, false, (r, dist, shape) => {
    let total = 0;
    for (let s = 0; s < dist.length; s++) {
      if (dist[s] === 0) continue;
      let p = dist[s];
      for (const x of shape.counts[s]) p *= leafCover[x];
      total += p;
    }
    out[r] = total;
  });
  return out;
}

// Bits of security against forgery on one key after q = 0..Q_MAX signatures,
// -log2 of `cover`. Kept per key shape.
const keySecurity = new Map();

export function keyForgeryBits(leaf) {
  const key = JSON.stringify(leaf);
  let bits = keySecurity.get(key);
  if (!bits) {
    bits = Array.from(cover(leaf, Q_MAX), (p) => -Math.log2(p));
    if (keySecurity.size > 64) keySecurity.clear();
    keySecurity.set(key, bits);
  }
  return bits;
}

// Bits of security against forgery for r = 0..R_MAX, -log2 of `forgery`.
// Kept per leaf shape and tree, since the other parameters do not change it.
const security = new Map();

export function forgeryBits(leaf, N, K) {
  const key = JSON.stringify([leaf, N, K]);
  let bits = security.get(key);
  if (!bits) {
    bits = Array.from(forgery(cover(leaf, R_MAX), N, K, R_MAX), (p) => -Math.log2(p));
    if (security.size > 64) security.clear();
    security.set(key, bits);
  }
  return bits;
}

// The largest r up to R_MAX whose bits plus `grinding` reach TARGET_BITS, or
// R_MAX + 1 when R_MAX does.
export function signaturesPerInstance(bits, grinding) {
  let r = 0;
  while (r < R_MAX && bits[r + 1] + grinding >= TARGET_BITS) r++;
  return r === R_MAX ? R_MAX + 1 : r;
}

// `count` distances in [0, max] summing to `sum`, uniform among all such.
export function sampleDistances(count, sum, max, random = Math.random) {
  const ways = waysTable(count, sum, max);
  const out = [];
  let left = sum;
  for (let i = count - 1; i >= 0; i--) {
    let u = random() * ways[i + 1][left];
    let d = 0;
    while (d < Math.min(max, left) && (u -= ways[i][left - d]) >= 0) d++;
    out.push(d);
    left -= d;
  }
  return out;
}
