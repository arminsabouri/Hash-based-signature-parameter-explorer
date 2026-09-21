import { compressions, tweakedCompressions } from '../sha256.js';
import { approx, bytes, num } from '../scheme.js';
import { wotsC, wotsCParameters } from './wots-c.js';

// XMSS with WOTS+C leaves, Section 7 of Kudinov and Nick, "Hash-based Signature
// Schemes for Bitcoin". Balanced tree of height h.

// Message hashing as in FIPS 205 for a 32-byte message:
// PRF_msg = HMAC-SHA-256(SK.prf, opt_rand || M) and
// H_msg = MGF1-SHA-256(R || PK.seed || SHA-256(R || PK.seed || PK.root || M)).
const MESSAGE_BYTES = 32;
const prfMsgCompressions = (nb) => compressions(64 + nb + MESSAGE_BYTES) + compressions(64 + 32);
const hMsgCompressions = (nb) => compressions(3 * nb + MESSAGE_BYTES) + compressions(2 * nb + 32 + 4);

export default {
  id: 'xmss',
  title: 'XMSS + WOTS+C',

  // Colors for the parameter groups.
  groups: {
    'Tree': 'var(--c-0a9396)',
    'OTS (WOTS+C)': 'var(--c-ca6702)',
  },

  parameters: [
    {
      key: 'h', type: 'range', min: 1, max: 30, step: 1, default: 10, group: 'Tree',
      ticks: [8, 16, 20],
      label: '\\(h\\) (tree height)',
      tooltip: 'The tree has \\(2^h\\) WOTS+C leaves, one per signature. Each extra level doubles the signature budget and the key generation work, and adds one \\(n\\)-bit node to the authentication path.',
    },
    ...wotsCParameters.map((p) => ({ ...p, group: 'OTS (WOTS+C)' })),
  ],

  derive(state) {
    const { h, n } = state;
    const nb = n / 8;
    const ots = wotsC(state);
    const { l, w, call } = ots;

    const leaves = 2 ** h;

    // Signature (i, R, sigma_OTS, AuthPath_i).
    const indexBits = 8 * Math.ceil(h / 8);
    const rBits = n;
    const otsBits = l * n + ots.r;
    const authBits = h * n;
    const sigBits = indexBits + rBits + otsBits + authBits;

    const pkBits = 2 * n; // PK.seed and root
    const skBits = 4 * n; // SK.seed, SK.prf, PK.seed, and root
    const cacheBits = (2 * leaves - 1) * n;

    // Hash calls. A leaf is a WOTS+C key: l PRF, l(w-1) chain steps, and one
    // Th to compress the chain ends. Inner nodes take one Th each.
    const leafPrf = l;
    const leafTh = l * (w - 1) + 1;
    const nodes = leaves - 1;
    const treePrf = leaves * leafPrf;
    const treeTh = leaves * leafTh + nodes;

    const signPrf = l;
    const signTh = ots.signSteps + ots.wcSearch;
    const verifyTh = 1 + ots.verifySteps + 1 + h; // search trial, chains, leaf, path

    // SHA-256 compressions.
    const pkCall = tweakedCompressions(l * nb);
    const nodeCall = tweakedCompressions(2 * nb);
    const leafCompressions = (leafPrf + l * (w - 1)) * call + pkCall;
    const treeCompressions = leaves * leafCompressions + nodes * nodeCall;
    const msgSign = prfMsgCompressions(nb) + hMsgCompressions(nb);
    const otsSign = (signPrf + ots.signSteps) * call + ots.wcSearch * ots.grindCall;

    return {
      ...ots, leaves,
      indexBits, rBits, otsBits, authBits, sigBits, pkBits, skBits, cacheBits,
      treePrf, treeTh, signPrf, signTh, verifyTh,
      keygenCompressions: treeCompressions + 1,
      signCompressions: treeCompressions + msgSign + otsSign + 1,
      signCachedCompressions: msgSign + otsSign + 1,
      verifyCompressions: hMsgCompressions(nb) + ots.grindCall + ots.verifySteps * call
        + pkCall + h * nodeCall + 1,
      perBlock: Math.floor(4000000 / ((sigBits + pkBits) / 8)),
    };
  },

  results: [
    {
      rows: [
        { label: 'Secret key', value: (d) => bytes(d.skBits) },
        { label: 'Public key', group: 'Tree', value: (d) => bytes(d.pkBits) },
        {
          label: 'Tree cache',
          group: 'Tree',
          tooltip: 'All \\(2^{h+1} - 1\\) tree nodes, kept by a signer that avoids rebuilding the tree on each signature.',
          value: (d) => bytes(d.cacheBits),
        },
      ],
    },
    {
      heading: 'Signature',
      tooltip: 'The tuple \\((i, R, \\sigma_{\\mathrm{OTS}}, \\mathrm{AuthPath}_i)\\): the leaf index, the message randomness, the WOTS+C signature with its counter, and the \\(h\\) sibling nodes from leaf to root.',
      rows: [
        { label: 'Leaf index \\(i\\)', group: 'Tree', value: (d) => bytes(d.indexBits) },
        { label: 'Randomness \\(R\\)', value: (d) => bytes(d.rBits) },
        { label: 'WOTS+C signature (\\(\\sigma_{\\mathrm{OTS}}\\))', group: 'OTS (WOTS+C)', value: (d) => bytes(d.otsBits) },
        { label: '\\(\\mathrm{AuthPath}_i\\)', group: 'Tree', value: (d) => bytes(d.authBits) },
        { label: 'Total', value: (d) => bytes(d.sigBits) },
      ],
    },
    {
      heading: 'Search',
      group: 'OTS (WOTS+C)',
      tooltip: 'The WOTS+C counter search on the message digest. WC search is the number of trials that suffices except with probability \\(2^{-30}\\).',
      rows: [
        { label: 'Success probability per trial (\\(p_\\nu\\))', value: (d) => (d.p >= 1e-4 ? d.p.toFixed(4) : `\\(2^{${Math.log2(d.p).toFixed(1)}}\\)`) },
        { label: 'WC search', value: (d) => approx(d.wcSearch) },
      ],
    },
    {
      heading: 'Hash calls',
      tooltip: 'Key generation builds every WOTS+C leaf and hashes the tree up to the root. Without a cache, signing rebuilds the tree to get the authentication path. With the tree cached, signing is the WOTS+C signature alone. Signing also computes \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\); verification computes \\(\\mathbf{H}_{\\mathbf{msg}}\\).',
      rows: [
        { label: 'Key generation', value: (d) => `${approx(d.treePrf)} \\(\\mathbf{PRF}\\) + ${approx(d.treeTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (no cache, WC search)', value: (d) => `${approx(d.treePrf + d.signPrf)} \\(\\mathbf{PRF}\\) + ${approx(d.treeTh + d.signTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Signing (cached tree, WC search)', value: (d) => `${num(d.signPrf)} \\(\\mathbf{PRF}\\) + ${approx(d.signTh)} \\(\\mathrm{Th}\\)` },
        { label: 'Verification', value: (d) => `${num(d.verifyTh)} \\(\\mathrm{Th}\\)` },
      ],
    },
    {
      heading: 'SHA-256 compressions',
      tooltip: 'An \\(L\\)-byte input costs \\(\\lceil (L+9)/64 \\rceil\\) compressions. \\(\\mathrm{Th}\\) and \\(\\mathbf{PRF}\\) follow FIPS 205 with a cached \\(\\mathrm{PK.seed}\\) block, adding one compression per operation. \\(\\mathbf{PRF}_{\\mathbf{msg}}\\) and \\(\\mathbf{H}_{\\mathbf{msg}}\\) follow FIPS 205 for a 32-byte message.',
      rows: [
        { label: 'Key generation', value: (d) => approx(d.keygenCompressions) },
        { label: 'Signing (no cache, WC search)', value: (d) => approx(d.signCompressions) },
        { label: 'Signing (cached tree, WC search)', value: (d) => approx(d.signCachedCompressions) },
        { label: 'Verification', value: (d) => num(d.verifyCompressions) },
      ],
    },
    {
      heading: 'Signature budget',
      group: 'Tree',
      rows: [
        {
          label: 'Signatures per key pair',
          tooltip: 'One per leaf, \\(2^h\\). Reusing a leaf for a second message breaks the security of its WOTS+C key.',
          value: (d) => num(d.leaves),
        },
        {
          label: 'State counter',
          tooltip: 'The signer stores the index of the next unused leaf and increments it before releasing each signature. SHRINCS requires that it never decrements and is never restored from a backup.',
          value: (d) => `${num(Math.ceil(Math.log2(d.leaves)) || 1)} bits`,
        },
      ],
    },
    {
      heading: 'Block space',
      rows: [
        {
          label: 'Signature + public key per 4,000,000 WU block',
          tooltip: 'The BIP 141 block weight limit divided by signature plus public key bytes, counted as witness data at 1 WU per byte. Transaction overhead is not included.',
          value: (d) => num(d.perBlock),
        },
      ],
    },
  ],
};

// Structure diagram: the tree (root = public key, inner nodes = Th of two
// children) with WOTS+C public keys as leaves, and one leaf opened up to show
// its l chains of w values compressed into the leaf.
function treeSvg(h, l, w) {
  const W = 560, R = 7, LEVEL = 40, TOP = 30;
  const parts = [];
  const add = (s) => parts.push(s);
  const line = (x1, y1, x2, y2, cls = 'edge') =>
    add(`<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" class="${cls}"/>`);
  const text = (x, y, s, anchor = 'middle', cls = 'label') =>
    add(`<text x="${x}" y="${y}" text-anchor="${anchor}" class="${cls}">${s}</text>`);
  const circle = (x, y) => add(`<circle cx="${x}" cy="${y}" r="${R}" class="tree-node"/>`);
  const square = (x, y, s = 14) => add(`<rect x="${x - s / 2}" y="${y - s / 2}" width="${s}" height="${s}" rx="2" class="ots-node"/>`);

  const leafCount = 2 ** h;
  const inner = Math.min(h, 3);            // inner levels drawn from the root down
  const elided = h > 3;
  const slots = leafCount <= 8 ? [...Array(leafCount).keys()] : [0, 1, 2, 3, null, leafCount - 2, leafCount - 1];
  const treeLeft = 40, treeRight = W - 110;
  const slotX = (k) => treeLeft + ((k + 0.5) * (treeRight - treeLeft)) / slots.length;
  const levelX = (depth, k) => treeLeft + ((k + 0.5) * (treeRight - treeLeft)) / 2 ** depth;
  const Y = (row) => TOP + row * LEVEL;

  // Inner nodes, depth 0 = root.
  for (let depth = 0; depth < inner; depth++) {
    for (let k = 0; k < 2 ** depth; k++) {
      if (depth + 1 < inner) {
        line(levelX(depth, k), Y(depth), levelX(depth + 1, 2 * k), Y(depth + 1));
        line(levelX(depth, k), Y(depth), levelX(depth + 1, 2 * k + 1), Y(depth + 1));
      }
    }
  }
  const leafRow = elided ? inner + 1 : inner;
  if (!elided) {
    for (let k = 0; k < 2 ** (inner - 1); k++) {
      line(levelX(inner - 1, k), Y(inner - 1), slotX(2 * k), Y(leafRow));
      line(levelX(inner - 1, k), Y(inner - 1), slotX(2 * k + 1), Y(leafRow));
    }
  } else {
    text((treeLeft + treeRight) / 2, Y(inner) + 4, `\u22EE  ${h - 3} more levels`);
  }
  for (let depth = 0; depth < inner; depth++) {
    for (let k = 0; k < 2 ** depth; k++) circle(levelX(depth, k), Y(depth));
  }
  text(levelX(0, 0), Y(0) - 14, 'Public key (root)');

  // Leaves.
  const leafY = Y(leafRow);
  slots.forEach((k, i) => {
    if (k === null) text(slotX(i), leafY + 4, '\u2026');
    else square(slotX(i), leafY);
  });

  // Height and leaf count annotations.
  const bx = treeRight + 18;
  line(bx, Y(0), bx, leafY, 'bracket');
  line(bx - 4, Y(0), bx, Y(0), 'bracket');
  line(bx - 4, leafY, bx, leafY, 'bracket');
  text(bx + 8, (Y(0) + leafY) / 2 - 4, `h = ${h}`, 'start');
  text(bx + 8, (Y(0) + leafY) / 2 + 12, 'levels', 'start');
  text(bx + 8, leafY + 4, `${leafCount.toLocaleString()} leaves`, 'start', 'label ots-label');

  // One leaf opened up: l chains of w values, chain ends compressed by Th.
  const rows = l <= 5 ? [...Array(l).keys()] : [0, 1, 2, null, l - 1];
  const boxTop = leafY + 46, rowH = 16;
  const cells = Math.min(w, 16);
  const cellW = 14, gap = 3;
  const chainLeft = 120, chainRight = chainLeft + cells * (cellW + gap) - gap;
  const leafX = slotX(0);
  const endsX = chainRight + 26;

  line(leafX, leafY + 7, leafX, boxTop - 16, 'ots-edge');
  text(leafX + 8, leafY + 26, 'WOTS+C public key = Th(pk\u2081, \u2026, pk\u2097)', 'start', 'label ots-label');

  rows.forEach((c, r) => {
    const y = boxTop + r * (rowH + 4);
    if (c === null) { text(chainLeft + (chainRight - chainLeft) / 2, y + 12, '\u22EE'); return; }
    text(chainLeft - 8, y + 12, `chain ${c + 1}`, 'end');
    if (w <= 16) {
      for (let j = 0; j < cells; j++) {
        add(`<rect x="${chainLeft + j * (cellW + gap)}" y="${y}" width="${cellW}" height="${rowH}" rx="2" class="${j === w - 1 ? 'chain-end' : 'chain-value'}"/>`);
      }
    } else {
      add(`<rect x="${chainLeft}" y="${y}" width="${chainRight - chainLeft - cellW - gap}" height="${rowH}" rx="2" class="chain-value"/>`);
      add(`<rect x="${chainRight - cellW}" y="${y}" width="${cellW}" height="${rowH}" rx="2" class="chain-end"/>`);
    }
    line(chainRight + 2, y + rowH / 2, endsX, boxTop - 16 + 0, 'ots-edge faint');
  });
  line(endsX, boxTop - 16, leafX, boxTop - 16, 'ots-edge');

  const boxBottom = boxTop + rows.length * (rowH + 4);
  text(chainLeft + cellW / 2, boxBottom + 14, 'sk\u1D62');
  text((chainLeft + chainRight) / 2, boxBottom + 14, `${w} values`);
  text(chainRight - cellW / 2, boxBottom + 14, 'pk\u1D62');
  text(chainRight, boxBottom + 30, `l = ${l} chains`, 'end', 'label ots-label');

  return { svg: parts.join(''), width: W, height: boxBottom + 44 };
}

// Visualization state, nested inside the scheme component.
export function xmssTree() {
  return {
    get drawing() {
      const { l, w } = wotsC(this.state);
      return treeSvg(this.state.h, l, w);
    },
  };
}
