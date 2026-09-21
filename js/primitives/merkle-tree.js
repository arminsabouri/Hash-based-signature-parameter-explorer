import { tweakedCompressions } from '../sha256.js';

// Balanced Merkle tree of height h whose leaves are compressed OTS public keys,
// Section 7 of Kudinov and Nick, "Hash-based Signature Schemes for Bitcoin".

export function parameters(group) {
  return [
    {
      key: 'h', type: 'range', min: 1, max: 30, step: 1, default: 10, group,
      ticks: [8, 16, 20],
      label: '\\(h\\) (tree height)',
      tooltip: 'The tree has \\(2^h\\) leaves, one per signature. Each extra level doubles the signature budget and the key generation work, and adds one \\(n\\)-bit node to the authentication path.',
    },
  ];
}

// `leaf` is an OTS model with a compressed public key. Key generation builds
// every leaf and hashes the tree up to the root; verification hashes the
// authentication path.
export function model({ h, n }, leaf) {
  const leaves = 2 ** h;
  const nodes = leaves - 1;
  const nodeCall = tweakedCompressions((2 * n) / 8);
  return {
    leaves,
    sizes: {
      root: n,
      authPath: h * n,
      cache: (2 * leaves - 1) * n,
    },
    keygen: {
      prf: leaves * leaf.keygen.prf,
      th: leaves * leaf.keygen.th + nodes,
      compressions: leaves * leaf.keygen.compressions + nodes * nodeCall,
    },
    verify: { th: h, compressions: h * nodeCall },
  };
}
