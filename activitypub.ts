import crypto from 'node:crypto';
import express from 'express';
import type { Request, Response, Router } from 'express';

function verifyBase64Signature(data: string, pubkey: string, sigB64: string): boolean {
  try {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(data);
    verifier.end();
    return verifier.verify(pubkey, sigB64, 'base64');
  } catch {
    return false;
  }
}

export async function sendSignedActivityPub(
  message: Record<string, unknown>,
  name: string,
  domain: string,
  targetDomain: string,
  inbox: string,
  date: string,
  signatureB64: string
): Promise<number> {
  const header = `keyId="https://${domain}/u/${name}",headers="(request-target) host date",signature="${signatureB64}"`;
  const response = await fetch(inbox, {
    method: 'POST',
    headers: {
      'Host': targetDomain,
      'Date': date,
      'Signature': header,
      'Content-Type': 'application/activity+json',
    },
    body: JSON.stringify(message),
  });
  console.log(`Sent message to an inbox at ${targetDomain}!`);
  console.log('Response Status Code:', response.status);
  return response.status;
}

export function createActivityPubMessage(text: string, name: string, domain: string): Record<string, unknown> {
  const guidCreate = crypto.randomBytes(16).toString('hex');
  const guidNote = crypto.randomBytes(16).toString('hex');
  const d = new Date();

  // TODO replace IDs with path
  // TODO add support for inReplyTo
  const noteMessage = {
    'id': `https://${domain}/m/${guidNote}`,
    'type': 'Note',
    'published': d.toISOString(),
    'attributedTo': `https://${domain}/u/${name}`,
    'content': text,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
  };

  const activity = {
    '@context': 'https://www.w3.org/ns/activitystreams',

    'id': `https://${domain}/m/${guidCreate}`,
    'type': 'Create',
    'actor': `https://${domain}/u/${name}`,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],

    'object': noteMessage,
  };

  return activity;
}

export async function sendActivityPubMessage(
  text: string,
  name: string,
  domain: string,
  follower: string,
  date: string,
  signatureB64: string,
  pubkey: string,
  res: Response
): Promise<void> {
  const inbox = follower.replace(/\/+$/, '') + '/inbox';
  const myURL = new URL(inbox);
  const targetDomain = myURL.hostname;
  const stringToSign = `(request-target): post ${myURL.pathname}\nhost: ${targetDomain}\ndate: ${date}`;
  if (!verifyBase64Signature(stringToSign, pubkey, signatureB64)) {
    res.status(400).json({ error: 'Invalid ActivityPub HTTP signature' });
    return;
  }
  const message = createActivityPubMessage(text, name, domain);
  const status = await sendSignedActivityPub(message, name, domain, targetDomain, inbox, date, signatureB64);
  res.status(200).json({ ok: true, status });
}

export function createActivityPubRouter(getDomain: (req?: Request) => string): Router {
  const router = express.Router();

  router.post('/sendActivityPub', async (req, res) => {
    const body = req.body || {};
    const acct = String(body.acct || '');
    const message = String(body.message || '');
    const follower = String(body.follower || '');
    const date = String(body.date || '');
    const signature = String(body.signature || '');
    const pubkey = String(body.pubkey || '');
    if (!acct || !follower || !date || !signature || !pubkey) {
      return res.status(400).json({ error: 'Missing required fields (acct, follower, date, signature, pubkey)' });
    }
    try {
      await sendActivityPubMessage(message, acct, getDomain(req), follower, date, signature, pubkey, res);
    } catch (e) {
      console.error(e);
      return res.status(400).json({ error: (e as Error).message });
    }
  });

  return router;
}
