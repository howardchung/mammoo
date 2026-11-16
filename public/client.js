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

const rawDifficultyBits = Number(document.querySelector('.app')?.getAttribute('data-pow-difficulty-bits'));
const POW_DIFFICULTY_BITS = Number.isInteger(rawDifficultyBits) && rawDifficultyBits >= 1 && rawDifficultyBits <= 63
  ? rawDifficultyBits
  : 16;
const POW_BASE_TARGET = 1n << BigInt(64 - POW_DIFFICULTY_BITS);
const POW_CRED_SCALE = 1n;

async function sha256Bytes(input) {
  const encoded = new TextEncoder().encode(input);
  const digest = await window.crypto.subtle.digest('SHA-256', encoded);
  return new Uint8Array(digest);
}

function scoreDigestCred(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, 8);
  const h64 = view.getBigUint64(0, false);
  if (h64 >= POW_BASE_TARGET) {
    return 0;
  }
  const scaled = (POW_BASE_TARGET * POW_CRED_SCALE) / (h64 + 1n);
  return scaled > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(scaled);
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
  const mineStatusEl = document.getElementById('cred-mine-status');

  let miningCred = false;
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
    for (const card of document.querySelectorAll('.message-card')) {
      if (card.getAttribute('data-pubkey') !== pubkey) continue;
      const header = card.querySelector('.message-header');
      if (!header) continue;
      let credBadge = header.querySelector('.message-cred');
      if (!credBadge) {
        credBadge = document.createElement('span');
        credBadge.className = 'message-cred';
        credBadge.title = 'Cred is verifiable proof-of-work mined for this public key.';
        header.appendChild(credBadge);
      }
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
      let nonce = rand[0] * 1000000;
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
        while (miningCred && pubkey === currentIdentity.publicKeyPem) {
          const digest = await sha256Bytes(`${pubkey}:${nonce}`);
          const cred = scoreDigestCred(digest);
          if (cred > sessionCred) {
            const json = await submitCredProof(pubkey, sig, nonce);
            sessionCred = Number(json.cred ?? cred);
            currentIdentity.bestPow = { nonce };
            saveBestPowToIdentity(pubkey, currentIdentity.bestPow);
            updateDomCredForPubkey(pubkey, sessionCred);
            if (mineStatusEl) {
              mineStatusEl.textContent = `Cred: ${sessionCred} (${hashes} hashes)`;
            }
          }
          nonce++;
          hashes++;
          if (hashes % 250 === 0) {
            if (mineStatusEl) {
              mineStatusEl.textContent = sessionCred > 0
                ? `Cred: ${sessionCred} (${hashes} hashes)`
                : `Mining (${hashes} hashes)...`;
            }
            await new Promise((r) => setTimeout(r, 0));
          }
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
}

init();
