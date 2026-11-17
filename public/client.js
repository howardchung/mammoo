const STORAGE_KEY = 'pachytalk_keypair';

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function spkiToPem(spkiBuffer) {
  const b64 = arrayBufferToBase64(spkiBuffer);
  const lines = b64.match(/.{1,64}/g) || [];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

async function generateAndStoreKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['sign', 'verify']
  );

  const spki = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  const publicKeyPem = spkiToPem(spki);
  const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);

  localStorage.setItem(STORAGE_KEY, JSON.stringify({ publicKeyPem, privateKeyJwk, bestPow: null }));
  return { publicKeyPem, privateKey: keyPair.privateKey, bestPow: null };
}

function saveBestPowToIdentity(publicKeyPem, bestPow) {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (parsed.publicKeyPem !== publicKeyPem) return;
    parsed.bestPow = bestPow;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(parsed));
  } catch {
    // Ignore storage errors
  }
}

async function importIdentityFromJson(rawText) {
  const parsed = JSON.parse(rawText);
  if (!parsed || typeof parsed.publicKeyPem !== 'string' || !parsed.privateKeyJwk) {
    throw new Error('Invalid identity file');
  }
  const privateKey = await window.crypto.subtle.importKey(
    'jwk',
    parsed.privateKeyJwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const bestPow = parsed.bestPow && Number.isInteger(parsed.bestPow.nonce) && parsed.bestPow.nonce >= 0
    ? { nonce: parsed.bestPow.nonce }
    : null;
  localStorage.setItem(STORAGE_KEY, JSON.stringify({
    publicKeyPem: parsed.publicKeyPem,
    privateKeyJwk: parsed.privateKeyJwk,
    bestPow,
  }));
  return { publicKeyPem: parsed.publicKeyPem, privateKey, bestPow };
}

async function getOrCreateKeyPair() {
  const raw = localStorage.getItem(STORAGE_KEY);
  if (raw) {
    try {
      const parsed = JSON.parse(raw);
      if (parsed.publicKeyPem && parsed.privateKeyJwk) {
        const privateKey = await window.crypto.subtle.importKey(
          'jwk',
          parsed.privateKeyJwk,
          { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false,
          ['sign']
        );
        const bestPow = parsed.bestPow && Number.isInteger(parsed.bestPow.nonce) && parsed.bestPow.nonce >= 0
          ? { nonce: parsed.bestPow.nonce }
          : null;
        return {
          publicKeyPem: parsed.publicKeyPem,
          privateKey,
          bestPow,
        };
      }
    } catch {
      // Regenerate if stored keypair is corrupt
    }
  }
  return generateAndStoreKeyPair();
}

async function signText(text, privateKey) {
  const encoded = new TextEncoder().encode(text);
  const sigBuffer = await window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, encoded);
  return arrayBufferToHex(sigBuffer);
}

async function signActivityPubHeaders(follower, privateKey) {
  const inbox = follower.replace(/\/+$/, '') + '/inbox';
  const targetUrl = new URL(inbox);
  const date = new Date().toUTCString();
  const stringToSign = `(request-target): post ${targetUrl.pathname}\nhost: ${targetUrl.hostname}\ndate: ${date}`;
  const encoded = new TextEncoder().encode(stringToSign);
  const sigBuffer = await window.crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, encoded);
  return {
    date,
    signature: arrayBufferToBase64(sigBuffer),
  };
}

async function sendActivityPub(acct, message, follower) {
  const identity = await getOrCreateKeyPair();
  const { date, signature } = await signActivityPubHeaders(follower, identity.privateKey);
  const res = await fetch('/api/sendActivityPub', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      acct,
      message,
      follower,
      date,
      signature,
      pubkey: identity.publicKeyPem,
    }),
  });
  const json = await res.json();
  if (!res.ok) {
    throw new Error(json.error || 'Failed to send ActivityPub message');
  }
  return json;
}

window.pachytalkSendActivityPub = sendActivityPub;

const rawHashesPerSecond = Number(document.querySelector('.app')?.getAttribute('data-pow-hashes-per-second'));
const POW_HASHES_PER_SECOND = Number.isInteger(rawHashesPerSecond) && rawHashesPerSecond >= 1
  ? rawHashesPerSecond
  : 100000;
const POW_BASE_TARGET = (1n << 64n) / BigInt(POW_HASHES_PER_SECOND);
const POW_CRED_SCALE = 1n;

function formatCredMiningTime(cred) {
  const seconds = cred;
  if (seconds < 60) {
    return `${seconds < 10 ? seconds.toFixed(1).replace(/\.0$/, '') : Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    return `${(seconds / 60).toFixed(1).replace(/\.0$/, '')}m`;
  }
  if (seconds < 86400) {
    return `${(seconds / 3600).toFixed(1).replace(/\.0$/, '')}h`;
  }
  return `${(seconds / 86400).toFixed(1).replace(/\.0$/, '')}d`;
}

async function sha256Bytes(input) {
  const encoded = new TextEncoder().encode(input);
  const digest = await window.crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(digest);
}

function scoreH64Cred(h64) {
  if (h64 >= POW_BASE_TARGET) {
    return 0;
  }
  const scaled = (POW_BASE_TARGET * POW_CRED_SCALE) / (h64 + 1n);
  return scaled > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(scaled);
}

function scoreDigestCred(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, 8);
  return scoreH64Cred(view.getBigUint64(0, false));
}

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

let wasmMinerPromise = null;

function getWasmMiner() {
  if (!wasmMinerPromise) {
    wasmMinerPromise = (async () => {
      const res = await fetch('/pow.wasm');
      const bytes = await res.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(bytes);
      const { memory, compress, mine10k } = instance.exports;
      const u8 = new Uint8Array(memory.buffer);
      const u32 = new Uint32Array(memory.buffer);
      const view = new DataView(memory.buffer);
      u32.set(SHA256_K, 512 >> 2);
      return { compress, mine10k, u8, u32, view };
    })().catch((err) => {
      wasmMinerPromise = null;
      throw err;
    });
  }
  return wasmMinerPromise;
}

const ADJECTIVES = [
  'amber', 'brisk', 'calm', 'clear', 'cobalt', 'coral', 'crisp', 'dawn',
  'ember', 'fern', 'frost', 'gold', 'jade', 'keen', 'lively', 'lunar',
  'maple', 'misty', 'noble', 'olive', 'opal', 'pine', 'quiet', 'rapid',
  'river', 'sage', 'silver', 'solar', 'swift', 'teal', 'warm', 'wild',
];

const NOUNS = [
  'badger', 'beaver', 'bison', 'bobcat', 'condor', 'crane', 'deer', 'dolphin',
  'eagle', 'falcon', 'finch', 'fox', 'gecko', 'hawk', 'heron', 'ibis',
  'jay', 'koala', 'lemur', 'lynx', 'marmot', 'newt', 'osprey', 'otter',
  'owl', 'panda', 'puma', 'raven', 'robin', 'seal', 'swan', 'wolf',
];

async function deriveIdentityProfile(pubkey) {
  const digest = await sha256Bytes(pubkey || 'anonymous');
  const adj = ADJECTIVES[digest[0] % ADJECTIVES.length];
  const noun = NOUNS[digest[1] % NOUNS.length];
  const tag = Array.from(digest.slice(2, 4), (b) => b.toString(16).padStart(2, '0')).join('');
  const username = pubkey ? `${adj}-${noun}-${tag}` : 'anonymous';

  const hue = ((digest[0] << 8) | digest[1]) % 360;
  const fg = `hsl(${hue}, 65%, 48%)`;
  const cells = [];
  for (let row = 0; row < 5; row++) {
    for (let col = 0; col < 3; col++) {
      const bitIndex = row * 3 + col;
      const byte = digest[2 + Math.floor(bitIndex / 8)];
      const on = (byte >> (bitIndex % 8)) & 1;
      if (on) {
        cells.push(`<rect x="${col + 1}" y="${row + 1}" width="1" height="1" fill="${fg}"/>`);
        if (col < 2) {
          cells.push(`<rect x="${5 - col}" y="${row + 1}" width="1" height="1" fill="${fg}"/>`);
        }
      }
    }
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 7 7" shape-rendering="crispEdges"><rect width="7" height="7" fill="#f1f5f9"/>${cells.join('')}</svg>`;
  const avatarUri = `data:image/svg+xml;base64,${btoa(svg)}`;
  return { username, avatarUri };
}

async function init() {
  const pubkeyEl = document.getElementById('client-pubkey');
  const usernameEl = document.getElementById('client-username');
  const avatarEl = document.getElementById('client-avatar');
  const newIdBtn = document.getElementById('new-id-btn');

  const updateIdentityDisplay = async (pubkey) => {
    if (pubkeyEl) {
      pubkeyEl.textContent = pubkey;
    }
    const { username, avatarUri } = await deriveIdentityProfile(pubkey);
    if (usernameEl) {
      usernameEl.textContent = username;
    }
    if (avatarEl) {
      avatarEl.setAttribute('src', avatarUri);
      avatarEl.setAttribute('alt', `${username} avatar`);
    }
  };

  let currentIdentity = await getOrCreateKeyPair();
  await updateIdentityDisplay(currentIdentity.publicKeyPem);

  const appEl = document.querySelector('.app');
  const board = appEl?.getAttribute('data-board') || 'default';
  const exportIdBtn = document.getElementById('export-id-btn');
  const importIdBtn = document.getElementById('import-id-btn');
  const importIdFile = document.getElementById('import-id-file');
  const mineCredBtn = document.getElementById('mine-cred-btn');
  const mineCredMultiBtn = document.getElementById('mine-cred-multi-btn');
  const mineStatusEl = document.getElementById('cred-mine-status');

  let miningCred = false;
  let activeWorkers = [];
  const stopWorkers = () => {
    for (const w of activeWorkers) {
      w.terminate();
    }
    activeWorkers = [];
    if (mineCredMultiBtn) {
      mineCredMultiBtn.textContent = 'Mine Cred (Multi-Core)';
    }
  };
  let sessionCred = currentIdentity.bestPow
    ? scoreDigestCred(await sha256Bytes(`${currentIdentity.publicKeyPem}:${currentIdentity.bestPow.nonce}`))
    : 0;

  if (exportIdBtn) {
    exportIdBtn.addEventListener('click', () => {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const blob = new Blob([raw], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'pachytalk-identity.json';
      a.click();
      URL.revokeObjectURL(url);
    });
  }

  if (importIdBtn && importIdFile) {
    importIdBtn.addEventListener('click', () => importIdFile.click());
    importIdFile.addEventListener('change', async () => {
      const file = importIdFile.files?.[0];
      importIdFile.value = '';
      if (!file) return;
      try {
        miningCred = false;
        stopWorkers();
        if (mineCredBtn) mineCredBtn.textContent = 'Mine Cred';
        const imported = await importIdentityFromJson(await file.text());
        currentIdentity = imported;
        await updateIdentityDisplay(currentIdentity.publicKeyPem);
        sessionCred = 0;
        if (imported.bestPow) {
          const sig = await signText(imported.publicKeyPem, imported.privateKey);
          const json = await submitCredProof(imported.publicKeyPem, sig, imported.bestPow.nonce);
          sessionCred = Number(json.cred ?? 0);
          updateDomCredForPubkey(imported.publicKeyPem, sessionCred);
        }
        if (mineStatusEl) {
          mineStatusEl.textContent = sessionCred > 0 ? `Imported ID (cred: ${sessionCred})` : 'Imported ID';
        }
      } catch (err) {
        alert(err instanceof Error ? err.message : 'Failed to import identity');
      }
    });
  }

  if (newIdBtn) {
    newIdBtn.addEventListener('click', async () => {
      newIdBtn.disabled = true;
      try {
        miningCred = false;
        stopWorkers();
        sessionCred = 0;
        if (mineCredBtn) mineCredBtn.textContent = 'Mine Cred';
        if (mineStatusEl) mineStatusEl.textContent = '';
        currentIdentity = await generateAndStoreKeyPair();
        await updateIdentityDisplay(currentIdentity.publicKeyPem);
      } finally {
        newIdBtn.disabled = false;
      }
    });
  }

  const updateDomCredForPubkey = (pubkey, newCred) => {
    if (newCred <= 0) return;
    const estTime = formatCredMiningTime(newCred);
    for (const card of document.querySelectorAll('.message-card')) {
      if (card.getAttribute('data-pubkey') !== pubkey) continue;
      const header = card.querySelector('.message-header');
      if (!header) continue;
      let credBadge = header.querySelector('.message-cred');
      if (!credBadge) {
        credBadge = document.createElement('span');
        credBadge.className = 'message-cred';
        header.appendChild(credBadge);
      }
      credBadge.title = `Cred is verifiable proof-of-work mined for this public key (~${estTime} at 100k H/s).`;
      credBadge.innerHTML = `Cred: <strong>${newCred}</strong>`;
    }
  };

  const submitCredProof = async (pubkey, sig, proofNonce) => {
    const res = await fetch('/api/cred', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pubkey, sig, pow: { nonce: proofNonce } }),
    });
    const json = await res.json();
    if (!res.ok) {
      throw new Error(json.error || 'Failed to submit cred');
    }
    return json;
  };

  if (mineCredBtn) {
    mineCredBtn.addEventListener('click', async () => {
      stopWorkers();
      if (miningCred) {
        miningCred = false;
        return;
      }
      miningCred = true;
      mineCredBtn.textContent = 'Stop Mining';
      if (mineStatusEl) {
        mineStatusEl.textContent = sessionCred > 0 ? `Cred: ${sessionCred} (mining...)` : 'Mining...';
      }
      const pubkey = currentIdentity.publicKeyPem;
      const rand = new Uint32Array(1);
      window.crypto.getRandomValues(rand);
      let nonce = Math.max(10000, rand[0] * 1000000);
      let hashes = 0;
      try {
        const sig = await signText(pubkey, currentIdentity.privateKey);
        if (currentIdentity.bestPow && Number.isInteger(currentIdentity.bestPow.nonce)) {
          const json = await submitCredProof(pubkey, sig, currentIdentity.bestPow.nonce);
          sessionCred = Number(json.cred ?? sessionCred);
          updateDomCredForPubkey(pubkey, sessionCred);
          if (mineStatusEl && sessionCred > 0) {
            mineStatusEl.textContent = `Cred: ${sessionCred} (mining...)`;
          }
        }

        const miner = await getWasmMiner();
        const encoder = new TextEncoder();
        const prefixBytes = encoder.encode(`${pubkey}:`);
        const fullBlocks = Math.floor(prefixBytes.length / 64);
        const midstateOffset = fullBlocks * 64;
        const tailBase = prefixBytes.subarray(midstateOffset);

        miner.u32.set(SHA256_IV, 0);
        for (let b = 0; b < fullBlocks; b++) {
          miner.u8.set(prefixBytes.subarray(b * 64, (b + 1) * 64), 64);
          miner.compress(0, 64);
        }

        let bestH64 = sessionCred > 0
          ? (POW_BASE_TARGET * POW_CRED_SCALE) / BigInt(sessionCred)
          : POW_BASE_TARGET;
        miner.view.setBigUint64(32, bestH64, true);

        while (miningCred && pubkey === currentIdentity.publicKeyPem) {
          const noncePrefixBytes = encoder.encode(String(nonce).slice(0, -4));
          const digitPos = tailBase.length + noncePrefixBytes.length;
          const totalLen = midstateOffset + digitPos + 4;

          miner.u8.fill(0, 64, 128);
          miner.u8.set(tailBase, 64);
          miner.u8.set(noncePrefixBytes, 64 + tailBase.length);
          miner.u8[64 + digitPos + 4] = 0x80;
          miner.view.setBigUint64(64 + 56, BigInt(totalLen * 8), false);

          const bestK = miner.mine10k(digitPos);
          hashes += 10000;

          if (bestK >= 0) {
            bestH64 = miner.view.getBigUint64(32, true);
            const cred = scoreH64Cred(bestH64);
            if (cred > sessionCred) {
              const winningNonce = nonce + bestK;
              const json = await submitCredProof(pubkey, sig, winningNonce);
              sessionCred = Number(json.cred ?? cred);
              currentIdentity.bestPow = { nonce: winningNonce };
              saveBestPowToIdentity(pubkey, currentIdentity.bestPow);
              updateDomCredForPubkey(pubkey, sessionCred);
            }
          }

          nonce += 10000;
          if (mineStatusEl) {
            mineStatusEl.textContent = sessionCred > 0
              ? `Cred: ${sessionCred} (${hashes} hashes)`
              : `Mining (${hashes} hashes)...`;
          }
          await new Promise((r) => setTimeout(r, 0));
        }
        mineCredBtn.textContent = 'Mine Cred';
        if (mineStatusEl) {
          mineStatusEl.textContent = sessionCred > 0 ? `Cred: ${sessionCred}` : '';
        }
      } catch (err) {
        miningCred = false;
        mineCredBtn.textContent = 'Mine Cred';
        alert(err instanceof Error ? err.message : 'Mining failed');
        if (mineStatusEl) mineStatusEl.textContent = '';
      }
    });
  }

  if (mineCredMultiBtn) {
    mineCredMultiBtn.addEventListener('click', async () => {
      if (activeWorkers.length > 0) {
        stopWorkers();
        if (mineStatusEl) {
          mineStatusEl.textContent = sessionCred > 0 ? `Cred: ${sessionCred}` : '';
        }
        return;
      }
      if (miningCred) {
        miningCred = false;
        if (mineCredBtn) mineCredBtn.textContent = 'Mine Cred';
      }

      const workerCount = Math.max(1, navigator.hardwareConcurrency || 4);
      mineCredMultiBtn.textContent = `Stop Multi-Core (${workerCount}x)`;
      if (mineStatusEl) {
        mineStatusEl.textContent = sessionCred > 0
          ? `Cred: ${sessionCred} (mining on ${workerCount} cores...)`
          : `Mining on ${workerCount} cores...`;
      }

      const pubkey = currentIdentity.publicKeyPem;
      const rand = new Uint32Array(1);
      window.crypto.getRandomValues(rand);
      const baseNonce = Math.max(10000, rand[0] * 1000000);
      const stride = workerCount * 10000;
      let totalHashes = 0;

      try {
        const sig = await signText(pubkey, currentIdentity.privateKey);
        if (currentIdentity.bestPow && Number.isInteger(currentIdentity.bestPow.nonce)) {
          const json = await submitCredProof(pubkey, sig, currentIdentity.bestPow.nonce);
          sessionCred = Number(json.cred ?? sessionCred);
          updateDomCredForPubkey(pubkey, sessionCred);
        }

        let globalBestH64 = sessionCred > 0
          ? (POW_BASE_TARGET * POW_CRED_SCALE) / BigInt(sessionCred)
          : POW_BASE_TARGET;
        let submitChain = Promise.resolve();

        for (let i = 0; i < workerCount; i++) {
          const worker = new Worker('/pow-worker.js');
          activeWorkers.push(worker);

          worker.onmessage = (evt) => {
            if (pubkey !== currentIdentity.publicKeyPem || activeWorkers.length === 0) return;
            const msg = evt.data || {};
            if (msg.type === 'progress') {
              totalHashes += Number(msg.deltaHashes || 0);
              if (mineStatusEl) {
                mineStatusEl.textContent = sessionCred > 0
                  ? `Cred: ${sessionCred} (${totalHashes} hashes, ${workerCount} cores)`
                  : `Mining (${totalHashes} hashes, ${workerCount} cores)...`;
              }
              return;
            }
            if (msg.type === 'found') {
              const foundH64 = BigInt(msg.bestH64);
              const winningNonce = Number(msg.nonce);
              if (foundH64 < globalBestH64) {
                globalBestH64 = foundH64;
                for (const w of activeWorkers) {
                  w.postMessage({ type: 'updateTarget', bestH64: String(globalBestH64) });
                }
              }
              const cred = scoreH64Cred(foundH64);
              if (cred > sessionCred) {
                sessionCred = cred;
                currentIdentity.bestPow = { nonce: winningNonce };
                saveBestPowToIdentity(pubkey, currentIdentity.bestPow);
                updateDomCredForPubkey(pubkey, sessionCred);
                submitChain = submitChain.then(async () => {
                  try {
                    const json = await submitCredProof(pubkey, sig, winningNonce);
                    if (Number(json.cred) > sessionCred) {
                      sessionCred = Number(json.cred);
                      updateDomCredForPubkey(pubkey, sessionCred);
                    }
                  } catch {}
                });
              }
            }
          };

          worker.postMessage({
            type: 'start',
            pubkey,
            startNonce: baseNonce + i * 10000,
            stride,
            bestH64: String(globalBestH64),
          });
        }
      } catch (err) {
        stopWorkers();
        alert(err instanceof Error ? err.message : 'Multi-core mining failed');
        if (mineStatusEl) mineStatusEl.textContent = '';
      }
    });
  }

  for (const form of document.querySelectorAll('.message-form')) {
    const submitBtn = form.querySelector('button[type="submit"]');
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const formData = new FormData(form);
      const data = String(formData.get('data') || '').trim();
      const path = String(formData.get('path') || '/default');
      const board = String(formData.get('board') || 'default');
      const file = formData.get('image');
      const hasFile = file instanceof File && file.size > 0;

      if (!data && !hasFile) {
        return;
      }

      if (submitBtn) submitBtn.disabled = true;
      try {
        let imageCid = null;
        let mediaType = null;
        if (hasFile) {
          const uploadBody = new FormData();
          uploadBody.append('image', file);
          const uploadRes = await fetch('/api/upload', {
            method: 'POST',
            body: uploadBody,
          });
          const uploadJson = await uploadRes.json();
          if (!uploadRes.ok || !uploadJson.cid) {
            throw new Error(uploadJson.error || 'Media upload failed');
          }
          imageCid = uploadJson.cid;
          mediaType = uploadJson.media_type || (
            file.type.startsWith('video/')
              ? 'video'
              : file.type.startsWith('audio/')
                ? 'audio'
                : file.type.startsWith('image/')
                  ? 'image'
                  : 'file'
          );
        }

        const payloadToSign = JSON.stringify({
          data: data || '',
          content_cid: imageCid || null,
        });
        const sig = await signText(payloadToSign, currentIdentity.privateKey);

        const sendRes = await fetch('/api/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            path,
            data,
            pubkey: currentIdentity.publicKeyPem,
            sig,
            content_cid: imageCid,
            media_type: mediaType,
          }),
        });
        const sendJson = await sendRes.json();
        if (!sendRes.ok) {
          throw new Error(sendJson.error || 'Failed to send message');
        }

        window.location.href = '/?board=' + encodeURIComponent(board);
      } catch (err) {
        alert(err instanceof Error ? err.message : 'Failed to send message');
        if (submitBtn) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'Send';
        }
      }
    });
  }

  const boardSelect = document.getElementById('board-select');
  if (boardSelect) {
    boardSelect.addEventListener('change', () => {
      if (boardSelect.form) {
        boardSelect.form.submit();
      }
    });
  }
}

init();
