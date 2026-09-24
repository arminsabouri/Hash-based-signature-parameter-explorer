// Drawing helpers shared by the visualizations.

// Collects SVG elements as strings.
export function svg() {
  const parts = [];
  return {
    line(x1, y1, x2, y2, cls = 'edge') {
      parts.push(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="${cls}"/>`);
    },
    text(x, y, s, anchor = 'middle', cls = 'label') {
      parts.push(`<text x="${x}" y="${y}" text-anchor="${anchor}" class="${cls}">${s}</text>`);
    },
    circle(x, y, r, cls) {
      parts.push(`<circle cx="${x}" cy="${y}" r="${r}" class="${cls}"/>`);
    },
    polygon(points, cls) {
      parts.push(`<polygon points="${points}" class="${cls}"/>`);
    },
    raw(markup) {
      parts.push(markup);
    },
    rect(x, y, width, height, cls) {
      parts.push(`<rect x="${x}" y="${y}" width="${width}" height="${height}" rx="2" class="${cls}"/>`);
    },
    toString() {
      return parts.join('');
    },
  };
}

// Balanced tree of height h between x = left and x = right, root at y = top.
// Draws the top three levels, elides the rest when h > 3, and draws up to
// eight leaf slots as squares. Returns the leaf row position.
export function drawTree(g, { h, left, right, top, level = 40, radius = 7, leafSize = 14 }) {
  const leafCount = 2 ** h;
  const inner = Math.min(h, 3);
  const elided = h > 3;
  const slots = leafCount <= 8 ? [...Array(leafCount).keys()] : [0, 1, 2, 3, null, leafCount - 2, leafCount - 1];
  const slotX = (i) => left + ((i + 0.5) * (right - left)) / slots.length;
  const levelX = (depth, k) => left + ((k + 0.5) * (right - left)) / 2 ** depth;
  const Y = (row) => top + row * level;

  for (let depth = 0; depth + 1 < inner; depth++) {
    for (let k = 0; k < 2 ** depth; k++) {
      g.line(levelX(depth, k), Y(depth), levelX(depth + 1, 2 * k), Y(depth + 1));
      g.line(levelX(depth, k), Y(depth), levelX(depth + 1, 2 * k + 1), Y(depth + 1));
    }
  }
  const leafRow = elided ? inner + 1 : inner;
  if (!elided) {
    for (let k = 0; k < 2 ** (inner - 1); k++) {
      g.line(levelX(inner - 1, k), Y(inner - 1), slotX(2 * k), Y(leafRow));
      g.line(levelX(inner - 1, k), Y(inner - 1), slotX(2 * k + 1), Y(leafRow));
    }
  } else {
    g.text((left + right) / 2, Y(inner) + 4, `⋮  ${h - 3} more levels`);
  }
  for (let depth = 0; depth < inner; depth++) {
    for (let k = 0; k < 2 ** depth; k++) g.circle(levelX(depth, k), Y(depth), radius, 'tree-node');
  }

  const leafY = Y(leafRow);
  slots.forEach((k, i) => {
    if (k === null) g.text(slotX(i), leafY + 4, '…');
    else g.rect(slotX(i) - leafSize / 2, leafY - leafSize / 2, leafSize, leafSize, 'ots-node');
  });

  return { rootX: levelX(0, 0), rootY: Y(0), leafY, leafCount, slotX };
}

// l hash chains of w values each, as rows starting at (left, top). Rows are
// elided when l > 5, and chains become a bar with the end cell when w > 16.
// With `compact`, only the first and last rows are drawn. Labels sk_i, the
// value count, and pk_i under the first, middle, and last positions. Returns the geometry for connecting lines.
export function drawChains(g, { l, w, left, top, compact = false, rowHeight = 16, cellWidth = 14, gap = 3 }) {
  const rows = compact
    ? (l <= 2 ? [...Array(l).keys()] : [0, null, l - 1])
    : (l <= 5 ? [...Array(l).keys()] : [0, 1, 2, null, l - 1]);
  const cells = Math.min(w, 16);
  const right = left + cells * (cellWidth + gap) - gap;
  const ends = [];

  rows.forEach((c, r) => {
    const y = top + r * (rowHeight + 4);
    if (c === null) {
      g.text((left + right) / 2, y + 12, '⋮');
      return;
    }
    g.text(left - 8, y + 12, `chain ${c + 1}`, 'end');
    if (w <= 16) {
      for (let j = 0; j < cells; j++) {
        g.rect(left + j * (cellWidth + gap), y, cellWidth, rowHeight, j === w - 1 ? 'chain-end' : 'chain-value');
      }
    } else {
      g.rect(left, y, right - left - cellWidth - gap, rowHeight, 'chain-value');
      g.rect(right - cellWidth, y, cellWidth, rowHeight, 'chain-end');
    }
    ends.push({ x: right + 2, y: y + rowHeight / 2 });
  });

  const bottom = top + rows.length * (rowHeight + 4);
  g.text(left + cellWidth / 2, bottom + 14, 'skᵢ');
  g.text((left + right) / 2, bottom + 14, `${w} values`);
  g.text(right - cellWidth / 2, bottom + 14, 'pkᵢ');
  return { right, bottom, ends };
}

// DOM for one chain with the value at position `digit` revealed. Positions
// are cells when w <= 16 and a proportional bar otherwise.
export function chainCells(w, digit) {
  const el = (cls, style) => {
    const d = document.createElement('div');
    d.className = cls;
    if (style) d.style.cssText = style;
    return d;
  };
  if (w <= 16) {
    return Array.from({ length: w }, (_, j) =>
      el('chain-cell ' + (j < digit ? 'signer' : j === digit ? 'revealed' : 'verifier')));
  }
  const pct = (x) => (100 * x) / (w - 1);
  return [
    el('chain-bar signer', `width: ${pct(digit)}%`),
    el('chain-bar-marker', `left: ${pct(digit)}%`),
    el('chain-bar verifier', `left: ${pct(digit)}%; width: ${100 - pct(digit)}%`),
  ];
}

// A leaf at (leafX, leafY) opened up into its l chains of w values, whose
// ends Th compresses into the leaf. `notes` are extra label lines under the
// leaf label, and `compact` draws only the first and last chains. Returns the bottom of the drawing, labels included.
export function drawLeafChains(g, { leafX, leafY, l, w, notes = [], compact = false }) {
  const top = leafY + 46 + 20 * notes.length;
  const busY = top - 16;
  g.line(leafX, leafY + 7, leafX, busY, 'ots-edge');
  g.text(leafX + 8, leafY + 26, 'WOTS+C public key = Th(pk\u2081, \u2026, pk\u2097)', 'start', 'label ots-label');
  notes.forEach((note, k) => g.text(leafX + 8, leafY + 40 + 14 * k, note, 'start', 'label ots-label'));
  const chains = drawChains(g, { l, w, left: 120, top, compact });
  const endsX = chains.right + 24;
  for (const end of chains.ends) g.line(end.x, end.y, endsX, busY, 'ots-edge faint');
  g.line(endsX, busY, leafX, busY, 'ots-edge');
  g.text(chains.right, chains.bottom + 30, `l = ${l} chains`, 'end', 'label ots-label');
  return { bottom: chains.bottom + 44 };
}

// Bracket from y1 to y2 at x, with label lines centered to its right.
export function bracket(g, x, y1, y2, lines) {
  g.line(x, y1, x, y2, 'bracket');
  g.line(x - 4, y1, x, y1, 'bracket');
  g.line(x - 4, y2, x, y2, 'bracket');
  lines.forEach((s, k) => g.text(x + 8, (y1 + y2) / 2 + 4 + 16 * (k - (lines.length - 1) / 2), s, 'start'));
}

// Height bracket at x beside a tree drawn by drawTree, and its leaf count.
export function annotateTree(g, tree, x, lines) {
  bracket(g, x, tree.rootY, tree.leafY, lines);
  g.text(x + 8, tree.leafY + 4, `${tree.leafCount.toLocaleString()} leaves`, 'start', 'label ots-label');
}

// A balanced tree of height h with WOTS+C leaves, the root labeled as the
// public key, and the first leaf opened up into its l chains of w values.
export function balancedTreeSvg({ h, lines, l, w, compact = false }) {
  const W = 560;
  const g = svg();
  const tree = drawTree(g, { h, left: 40, right: W - 110, top: 30 });
  g.text(tree.rootX, tree.rootY - 14, 'Public key (root)');
  annotateTree(g, tree, W - 92, lines);
  const leaf = drawLeafChains(g, { leafX: tree.slotX(0), leafY: tree.leafY, l, w, compact });
  return { svg: g.toString(), width: W, height: leaf.bottom };
}

// The d layers of a hypertree, top layer first, with the layers between the
// top and bottom elided when d > 3. An OTS key of each tree signs the root of
// the tree below it. Returns the position of the bottom-layer leaf.
export function drawHypertree(g, { hp, d, left, right, bx, top, otsLabel, rootLabel = 'Public key (root)' }) {
  const layers = d <= 3 ? [...Array(d).keys()].reverse() : [d - 1, null, 0];
  const gap = 56;
  let y = top;
  let from = null; // leaf position of the layer above

  const connect = (x, ty) => {
    g.line(from.x, from.y + 7, x, ty, 'ots-edge');
  };

  g.text((left + right) / 2, y - 14, rootLabel);
  for (const layer of layers) {
    if (layer === null) {
      const ly = y + 8;
      connect((left + right) / 2, ly - 12);
      g.text((left + right) / 2, ly + 4, `⋮  layers ${d - 2} to 1`);
      from = { x: (left + right) / 2, y: ly + 6 };
      y += gap;
      continue;
    }
    if (from) {
      connect((left + right) / 2, y - 8);
      g.text((left + right) / 2 + 14, y - gap / 2 + 4, `${otsLabel} key signs this root`, 'start', 'label ots-label');
    }
    const tree = drawTree(g, { h: hp, left, right, top: y, level: 30 });
    g.text(left - 16, (tree.rootY + tree.leafY) / 2 + 4, `layer ${layer}`, 'end');

    annotateTree(g, tree, bx, [`h' = ${hp}`]);

    from = { x: tree.slotX(0), y: tree.leafY };
    y = tree.leafY + gap;
  }
  return from;
}

// k FORS trees of height a as outlines, each with its root on top, its leaf
// row below, and one revealed leaf. The roots feed one Th into the FORS
// public key. Trees are elided when k > 5. With `plusC` the last tree is
// dashed and opens its first leaf. An empty `pkLabel` leaves the public key
// node unlabeled. Returns the public key node and the bottom.
export function drawForest(g, { k, a, plusC, left, right, top, bx, pkLabel }) {
  const slots = k <= 5 ? [...Array(k).keys()] : [0, 1, 2, null, k - 1];
  const slotW = (right - left) / slots.length;
  const pkY = top, rootY = top + 60, baseY = top + 140, size = 10;
  const pkX = (left + right) / 2;

  if (pkLabel) g.text(pkX, pkY - 12, pkLabel);
  g.circle(pkX, pkY, 7, 'tree-node');

  slots.forEach((j, s) => {
    const cx = left + (s + 0.5) * slotW;
    const hw = slotW / 2 - 8;
    if (j === null) {
      g.text(cx, (rootY + baseY) / 2, '…');
      return;
    }
    const last = j === k - 1;
    const dashed = plusC && last;
    const cls = dashed ? 'edge dashed' : 'edge';
    g.line(pkX, pkY + 7, cx, rootY - 7, 'edge faint');
    g.line(cx, rootY, cx - hw, baseY, cls);
    g.line(cx, rootY, cx + hw, baseY, cls);
    g.line(cx - hw, baseY, cx + hw, baseY, cls);
    g.circle(cx, rootY, 7, 'tree-node');
    // One revealed leaf per tree: the first leaf for the FORS+C last tree,
    // otherwise an arbitrary position.
    const leafX = dashed ? cx - hw + size / 2 : cx - hw + (hw * 2) * ((j * 0.37 + 0.3) % 1);
    g.rect(leafX - size / 2, baseY + 6, size, size, 'ots-node');
    g.text(cx, baseY + 34, `tree ${j + 1}`);
    if (dashed) g.text(cx, baseY + 48, 'leaf 0', 'middle', 'label ots-label');
  });

  // Height and leaf count annotations.
  bracket(g, bx, rootY, baseY, [`a = ${a}`]);
  g.text(bx + 8, baseY + 16, `${(2 ** a).toLocaleString()} leaves`, 'start', 'label ots-label');
  g.text(bx + 8, baseY + 30, 'per tree', 'start', 'label ots-label');
  g.text(pkX, baseY + 70, `k = ${k} trees`, 'middle');

  return { pkX, pkY, baseY, bottom: baseY + 80 };
}

// A tradeoff diagram: one spoke per axis, with one shape per series drawn on
// the same axes. Each shape carries `values` in [0, 1], one per axis, and an
// optional name and colour; several named shapes get a legend underneath.
// `label` on an axis is an array of lines placed outside the vertex. The first
// axis points up and the rest follow clockwise.
export function tradeoffSvg(axes, shapes, { radius = 68, rings = 4 } = {}) {
  const named = shapes.filter((s) => s.name).length;
  const W = 340, H = 226 + (named ? 18 : 0);
  const cx = W / 2, cy = 116;
  const g = svg();
  const angle = (i) => (-Math.PI / 2) + (i * 2 * Math.PI) / axes.length;
  const at = (i, r) => [cx + r * Math.cos(angle(i)), cy + r * Math.sin(angle(i))];
  const ring = (r) => axes.map((_, i) => at(i, r).join(',')).join(' ');

  for (let k = 1; k <= rings; k++) {
    g.polygon(ring((radius * k) / rings), 'radar-grid');
  }
  axes.forEach((_, i) => {
    const [x, y] = at(i, radius);
    g.line(cx, cy, x, y, 'radar-spoke');
  });

  for (const shape of shapes) {
    const style = shape.color ? ` style="--shape-color: ${shape.color}"` : '';
    g.raw(`<polygon points="${shape.values.map((v, i) => at(i, radius * v).join(',')).join(' ')}"`
      + ` class="radar-shape"${style}/>`);
    shape.values.forEach((v, i) => {
      const [x, y] = at(i, radius * v);
      g.raw(`<circle cx="${x}" cy="${y}" r="3" class="radar-point"${style}/>`);
    });
  }

  // Labels outside each vertex, anchored away from the centre.
  axes.forEach((a, i) => {
    const [x, y] = at(i, radius + 10);
    const dx = Math.cos(angle(i));
    const anchor = dx > 0.15 ? 'start' : dx < -0.15 ? 'end' : 'middle';
    const lines = a.label;
    // Above the centre the block grows upwards, below it downwards.
    const top = y + (Math.sin(angle(i)) < -0.15 ? -(lines.length - 1) * 12 : 4);
    lines.forEach((line, k) => g.text(x, top + k * 12, line, anchor, 'label radar-label'));
  });

  // A legend, when more than the one shape is drawn.
  if (named) {
    const width = 108;
    const left = cx - (named * width) / 2;
    shapes.filter((s) => s.name).forEach((s, i) => {
      const x = left + i * width;
      const style = s.color ? ` style="--shape-color: ${s.color}"` : '';
      g.raw(`<rect x="${x}" y="${H - 14}" width="10" height="10" rx="2" class="radar-swatch"${style}/>`);
      g.text(x + 16, H - 5, s.name, 'start', 'label radar-label');
    });
  }
  return { svg: g.toString(), width: W, height: H };
}
