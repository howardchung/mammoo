const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const SHA256_IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

let minerView = null;

self.onmessage = async (evt) => {
  const msg = evt.data || {};
  if (msg.type === 'updateTarget' && minerView && msg.bestH64) {
    const nextTarget = BigInt(msg.bestH64);
    const curTarget = minerView.getBigUint64(32, true);
    if (nextTarget < curTarget) {
      minerView.setBigUint64(32, nextTarget, true);
    }
    return;
  }

  if (msg.type !== 'start') return;

  const { pubkey, startNonce, stride, bestH64 } = msg;
  const res = await fetch('/pow.wasm');
  const bytes = await res.arrayBuffer();
  const { instance } = await WebAssembly.instantiate(bytes);
  const { memory, compress, mine10k } = instance.exports;
  const u8 = new Uint8Array(memory.buffer);
  const u32 = new Uint32Array(memory.buffer);
  const view = new DataView(memory.buffer);
  minerView = view;

  u32.set(SHA256_K, 512 >> 2);

  const encoder = new TextEncoder();
  const prefixBytes = encoder.encode(`${pubkey}:`);
  const fullBlocks = Math.floor(prefixBytes.length / 64);
  const midstateOffset = fullBlocks * 64;
  const tailBase = prefixBytes.subarray(midstateOffset);

  u32.set(SHA256_IV, 0);
  for (let b = 0; b < fullBlocks; b++) {
    u8.set(prefixBytes.subarray(b * 64, (b + 1) * 64), 64);
    compress(0, 64);
  }

  view.setBigUint64(32, BigInt(bestH64), true);

  let nonce = Number(startNonce);
  let batches = 0;

  const step = () => {
    for (let i = 0; i < 5; i++) {
      const noncePrefixBytes = encoder.encode(String(nonce).slice(0, -4));
      const digitPos = tailBase.length + noncePrefixBytes.length;
      const totalLen = midstateOffset + digitPos + 4;

      u8.fill(0, 64, 128);
      u8.set(tailBase, 64);
      u8.set(noncePrefixBytes, 64 + tailBase.length);
      u8[64 + digitPos + 4] = 0x80;
      view.setBigUint64(64 + 56, BigInt(totalLen * 8), false);

      const bestK = mine10k(digitPos);
      if (bestK >= 0) {
        const foundH64 = view.getBigUint64(32, true);
        self.postMessage({
          type: 'found',
          nonce: nonce + bestK,
          bestH64: String(foundH64),
        });
      }
      nonce += stride;
      batches++;
    }
    self.postMessage({ type: 'progress', deltaHashes: 50000 });
    setTimeout(step, 0);
  };

  step();
};
