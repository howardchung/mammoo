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

  localStorage.setItem(STORAGE_KEY, JSON.stringify({ publicKeyPem, privateKeyJwk }));
  return { publicKeyPem, privateKey: keyPair.privateKey };
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
        return { publicKeyPem: parsed.publicKeyPem, privateKey };
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

async function init() {
  const pubkeyEl = document.getElementById('client-pubkey');
  const newIdBtn = document.getElementById('new-id-btn');

  let currentIdentity = await getOrCreateKeyPair();
  if (pubkeyEl) {
    pubkeyEl.textContent = currentIdentity.publicKeyPem;
  }

  if (newIdBtn) {
    newIdBtn.addEventListener('click', async () => {
      newIdBtn.disabled = true;
      try {
        currentIdentity = await generateAndStoreKeyPair();
        if (pubkeyEl) {
          pubkeyEl.textContent = currentIdentity.publicKeyPem;
        }
      } finally {
        newIdBtn.disabled = false;
      }
    });
  }

  for (const form of document.querySelectorAll('.message-form')) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const submitBtn = form.querySelector('button[type="submit"]');
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
        if (hasFile) {
          const uploadBody = new FormData();
          uploadBody.append('image', file);
          const uploadRes = await fetch('/api/upload', {
            method: 'POST',
            body: uploadBody,
          });
          const uploadJson = await uploadRes.json();
          if (!uploadRes.ok || !uploadJson.cid) {
            throw new Error(uploadJson.error || 'Image upload failed');
          }
          imageCid = uploadJson.cid;
        }

        const payloadToSign = data || imageCid || '';
        const sig = await signText(payloadToSign, currentIdentity.privateKey);

        const sendRes = await fetch('/api/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            path,
            data,
            pubkey: currentIdentity.publicKeyPem,
            sig,
            image_cid: imageCid,
          }),
        });
        const sendJson = await sendRes.json();
        if (!sendRes.ok) {
          throw new Error(sendJson.error || 'Failed to send message');
        }

        window.location.href = '/?board=' + encodeURIComponent(board);
      } catch (err) {
        alert(err instanceof Error ? err.message : 'Failed to send message');
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
}

init();
