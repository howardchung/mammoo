import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import type { Request, Response, Router } from 'express';

export interface ActivityPubIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface IncomingActivityPubNote {
  id: string;
  uri?: string;
  url?: string;
  content: string;
  published?: string;
  tags: string[];
  author?: string;
  authorUrl?: string;
}

const remoteActorCache = new Map<string, { author: string; authorUrl?: string }>();

function formatHandleFromActorUrl(actorUrl: string): string {
  try {
    const u = new URL(actorUrl);
    const seg = u.pathname.split('/').filter(Boolean).pop();
    return seg ? `@${seg}@${u.hostname}` : u.hostname;
  } catch {
    return actorUrl;
  }
}

async function resolveRemoteAuthor(
  attributedTo: unknown
): Promise<{ author: string; authorUrl?: string } | null> {
  if (!attributedTo) return null;
  if (typeof attributedTo === 'object') {
    const obj = attributedTo as { id?: string; url?: string; preferredUsername?: string; name?: string };
    const actorId = typeof obj.id === 'string' ? obj.id : undefined;
    const authorUrl = typeof obj.url === 'string' ? obj.url : actorId;
    if (typeof obj.preferredUsername === 'string' && obj.preferredUsername && actorId) {
      try {
        const host = new URL(actorId).hostname;
        return { author: `@${obj.preferredUsername}@${host}`, authorUrl };
      } catch {}
    }
    if (typeof obj.name === 'string' && obj.name) {
      return { author: obj.name, authorUrl };
    }
    if (actorId) {
      return { author: formatHandleFromActorUrl(actorId), authorUrl };
    }
    return null;
  }
  if (typeof attributedTo !== 'string' || !attributedTo.startsWith('http')) {
    return null;
  }
  const cached = remoteActorCache.get(attributedTo);
  if (cached) return cached;

  let resolved: { author: string; authorUrl?: string } = {
    author: formatHandleFromActorUrl(attributedTo),
    authorUrl: attributedTo,
  };
  try {
    const res = await fetch(attributedTo, {
      headers: { Accept: 'application/activity+json, application/ld+json' },
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const actor = (await res.json()) as { preferredUsername?: string; name?: string; url?: string };
      const host = new URL(attributedTo).hostname;
      const authorUrl = typeof actor.url === 'string' ? actor.url : attributedTo;
      if (typeof actor.preferredUsername === 'string' && actor.preferredUsername) {
        resolved = { author: `@${actor.preferredUsername}@${host}`, authorUrl };
      } else if (typeof actor.name === 'string' && actor.name) {
        resolved = { author: actor.name, authorUrl };
      }
    }
  } catch {
    // Fall back to handle parsed from attributedTo URL
  }
  remoteActorCache.set(attributedTo, resolved);
  return resolved;
}

export interface ActivityPubDeps {
  getDomain: (req?: Request) => string;
  getServerIdentity: () => Promise<ActivityPubIdentity>;
  dataDir: string;
  onIncomingNote?: (note: IncomingActivityPubNote) => Promise<void> | void;
}

export const DEFAULT_ACTIVITYPUB_RELAYS = [
  'https://relay.c64.social/actor',
  'https://oceania.federate.cloud/actor',
  'https://relay.fedibird.com/actor',
  'https://relay.fedimins.net/actor',
  'https://en.relay.friendi.ca/actor',
  'https://fedi-relay.gyptazy.com/actor',
  'https://relay.intahnet.co.uk/actor',
  'https://relay.minecloud.ro/actor',
  'https://rel.re/actor',
  'https://relay.rollenspiel.monster/actor',
  'https://mastodon-relay.moew.science/actor',
  'https://mastodon-relay.thedoodleproject.net/actor',
  'https://relay.toot.yukimochi.jp/actor',
];

export function getConfiguredRelays(): string[] {
  if (process.env.ACTIVITYPUB_RELAYS !== undefined) {
    return process.env.ACTIVITYPUB_RELAYS
      .split(',')
      .map((u) => u.trim())
      .filter((u) => u.startsWith('http://') || u.startsWith('https://'));
  }
  return DEFAULT_ACTIVITYPUB_RELAYS;
}

export interface PublishablePost {
  id: string;
  board: string;
  data: string;
  content_cid?: string | null;
}

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

function getOrigin(getDomain: (req?: Request) => string, req?: Request): string {
  const domain = getDomain(req);
  if (process.env.PUBLIC_URL) {
    try {
      return new URL(process.env.PUBLIC_URL).origin;
    } catch {}
  }
  const scheme = process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH ? 'https' : 'http';
  return `${scheme}://${domain}`;
}

function getConfiguredInboxes(): string[] {
  return (process.env.ACTIVITYPUB_INBOXES || '')
    .split(',')
    .map((u) => u.trim())
    .filter((u) => u.startsWith('http://') || u.startsWith('https://'));
}

async function loadFollowers(dataDir: string): Promise<Set<string>> {
  const filePath = path.join(dataDir, 'activitypub-followers.json');
  try {
    const raw = await fs.promises.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    return new Set(Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return new Set<string>();
    }
    throw err;
  }
}

async function saveFollowers(dataDir: string, followers: Set<string>): Promise<void> {
  const filePath = path.join(dataDir, 'activitypub-followers.json');
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  await fs.promises.writeFile(filePath, JSON.stringify(Array.from(followers), null, 2), 'utf8');
}

interface RelayRecord {
  inbox: string;
  status: 'pending' | 'accepted';
  followedAt: string;
}

async function loadRelays(dataDir: string): Promise<Record<string, RelayRecord>> {
  const filePath = path.join(dataDir, 'activitypub-relays.json');
  try {
    const raw = await fs.promises.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, RelayRecord>)
      : {};
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
      return {};
    }
    throw err;
  }
}

async function saveRelays(dataDir: string, relays: Record<string, RelayRecord>): Promise<void> {
  const filePath = path.join(dataDir, 'activitypub-relays.json');
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
  await fs.promises.writeFile(filePath, JSON.stringify(relays, null, 2), 'utf8');
}

function isPublicHttpsDomain(origin: string): boolean {
  try {
    const u = new URL(origin);
    if (u.protocol !== 'https:') return false;
    const host = u.hostname;
    if (host === 'localhost' || host === '127.0.0.1' || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export async function followRelays(deps: ActivityPubDeps): Promise<void> {
  const relayUrls = getConfiguredRelays();
  if (relayUrls.length === 0) return;

  const origin = getOrigin(deps.getDomain);
  // Relays require a reachable public HTTPS domain unless ACTIVITYPUB_RELAYS is explicitly overridden
  if (process.env.ACTIVITYPUB_RELAYS === undefined && !isPublicHttpsDomain(origin)) {
    console.warn(`Skipping ActivityPub relays: ${origin} is not a public https:// domain (set PUBLIC_URL)`);
    return;
  }

  const actorUrl = `${origin}/u/default`;
  const keyId = `${actorUrl}#main-key`;
  const identity = await deps.getServerIdentity();
  const relays = await loadRelays(deps.dataDir);
  let changed = false;

  for (const rawRelayUrl of relayUrls) {
    const relayActorUrl = rawRelayUrl.replace(/\/+$/, '');
    if (relays[relayActorUrl]) continue;
    try {
      let inbox = relayActorUrl.endsWith('/inbox') ? relayActorUrl : '';
      if (!inbox) {
        const actorLookupUrl = relayActorUrl.endsWith('/actor')
          ? relayActorUrl
          : `${relayActorUrl}/actor`;
        const actorRes = await fetch(actorLookupUrl, {
          headers: { Accept: 'application/activity+json, application/ld+json' },
          signal: AbortSignal.timeout(5000),
        }).catch(() => null);
        if (actorRes && actorRes.ok) {
          const actorJson = (await actorRes.json().catch(() => ({}))) as {
            inbox?: string;
            endpoints?: { sharedInbox?: string };
          };
          inbox = actorJson.endpoints?.sharedInbox || actorJson.inbox || '';
        }
        if (!inbox) {
          inbox = `${relayActorUrl.replace(/\/actor$/, '')}/inbox`;
        }
      }

      const followActivity: Record<string, unknown> = {
        '@context': 'https://www.w3.org/ns/activitystreams',
        id: `${actorUrl}#follow-${crypto.randomBytes(8).toString('hex')}`,
        type: 'Follow',
        actor: actorUrl,
        object: 'https://www.w3.org/ns/activitystreams#Public',
      };
      const status = await deliverSignedActivity(followActivity, keyId, identity.privateKeyPem, inbox);
      if (status >= 200 && status < 300) {
        relays[relayActorUrl] = {
          inbox,
          status: 'pending',
          followedAt: new Date().toISOString(),
        };
        changed = true;
        console.log(`Sent ActivityPub Follow to relay ${relayActorUrl} (${status})`);
      }
    } catch (err) {
      console.warn(`Failed to follow ActivityPub relay ${relayActorUrl}:`, (err as Error).message);
    }
  }

  if (changed) {
    await saveRelays(deps.dataDir, relays);
  }
}

async function deliverSignedActivity(
  activity: Record<string, unknown>,
  keyId: string,
  privateKeyPem: string,
  inbox: string
): Promise<number> {
  const url = new URL(inbox);
  const body = JSON.stringify(activity);
  const date = new Date().toUTCString();
  const digest = `SHA-256=${crypto.createHash('sha256').update(body).digest('base64')}`;
  const signingString = `(request-target): post ${url.pathname}${url.search}\nhost: ${url.host}\ndate: ${date}\ndigest: ${digest}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingString);
  signer.end();
  const signatureB64 = signer.sign(privateKeyPem, 'base64');

  const header = `keyId="${keyId}",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="${signatureB64}"`;
  const response = await fetch(inbox, {
    method: 'POST',
    headers: {
      Host: url.host,
      Date: date,
      Digest: digest,
      Signature: header,
      'Content-Type': 'application/activity+json',
    },
    body,
    signal: AbortSignal.timeout(8000),
  });
  return response.status;
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

  const noteMessage = {
    'id': `https://${domain}/m/${guidNote}`,
    'type': 'Note',
    'published': d.toISOString(),
    'attributedTo': `https://${domain}/u/${name}`,
    'content': text,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
  };

  return {
    '@context': 'https://www.w3.org/ns/activitystreams',
    'id': `https://${domain}/m/${guidCreate}`,
    'type': 'Create',
    'actor': `https://${domain}/u/${name}`,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
    'object': noteMessage,
  };
}

export async function publishPostToFediverse(
  post: PublishablePost,
  deps: ActivityPubDeps
): Promise<void> {
  const followers = await loadFollowers(deps.dataDir);
  const targets = new Set<string>([...followers, ...getConfiguredInboxes()]);
  if (targets.size === 0) return;

  const origin = getOrigin(deps.getDomain);
  const actorUrl = `${origin}/u/${encodeURIComponent(post.board)}`;
  const keyId = `${actorUrl}#main-key`;
  const identity = await deps.getServerIdentity();
  const noteId = `${origin}/m/${encodeURIComponent(post.id)}`;
  const attachmentHtml = post.content_cid
    ? `<p><a href="${origin}/ipfs/${encodeURIComponent(post.content_cid)}">Attachment</a></p>`
    : '';

  const activity: Record<string, unknown> = {
    '@context': 'https://www.w3.org/ns/activitystreams',
    id: `${noteId}/activity`,
    type: 'Create',
    actor: actorUrl,
    to: ['https://www.w3.org/ns/activitystreams#Public'],
    cc: [`${actorUrl}/followers`],
    object: {
      id: noteId,
      type: 'Note',
      published: new Date().toISOString(),
      attributedTo: actorUrl,
      content: `${post.data || ''}${attachmentHtml}`,
      url: `${origin}/?board=${encodeURIComponent(post.board)}`,
      to: ['https://www.w3.org/ns/activitystreams#Public'],
      cc: [`${actorUrl}/followers`],
      tag: [
        {
          type: 'Hashtag',
          href: `${origin}/?board=${encodeURIComponent(post.board)}`,
          name: `#${post.board}`,
        },
      ],
    },
  };

  await Promise.allSettled(
    Array.from(targets).map(async (inbox) => {
      try {
        const status = await deliverSignedActivity(activity, keyId, identity.privateKeyPem, inbox);
        if (status >= 400) {
          console.warn(`ActivityPub delivery to ${inbox} returned ${status}`);
        }
      } catch (err) {
        console.warn(`ActivityPub delivery to ${inbox} failed:`, (err as Error).message);
      }
    })
  );
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

export function createActivityPubRootRouter(deps: ActivityPubDeps): Router {
  const router = express.Router();

  router.get('/.well-known/webfinger', (req, res) => {
    const resource = String(req.query.resource || '');
    const match = resource.match(/^acct:([^@]+)@(.+)$/);
    if (!match) {
      return res.status(400).json({ error: 'Invalid acct resource' });
    }
    const name = match[1];
    const origin = getOrigin(deps.getDomain, req);
    return res.type('application/jrd+json').json({
      subject: resource,
      links: [
        {
          rel: 'self',
          type: 'application/activity+json',
          href: `${origin}/u/${encodeURIComponent(name)}`,
        },
      ],
    });
  });

  router.get('/u/:name', async (req, res) => {
    try {
      const name = String(req.params.name || 'default');
      const origin = getOrigin(deps.getDomain, req);
      const actorUrl = `${origin}/u/${encodeURIComponent(name)}`;
      const identity = await deps.getServerIdentity();
      return res.type('application/activity+json').json({
        '@context': [
          'https://www.w3.org/ns/activitystreams',
          'https://w3id.org/security/v1',
        ],
        id: actorUrl,
        type: 'Service',
        preferredUsername: name,
        inbox: `${actorUrl}/inbox`,
        outbox: `${actorUrl}/outbox`,
        followers: `${actorUrl}/followers`,
        publicKey: {
          id: `${actorUrl}#main-key`,
          owner: actorUrl,
          publicKeyPem: identity.publicKeyPem,
        },
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: (e as Error).message });
    }
  });

  router.post(
    '/u/:name/inbox',
    express.json({ type: ['application/activity+json', 'application/ld+json', 'application/json'] }),
    async (req, res) => {
      try {
        const name = String(req.params.name || 'default');
        const body = req.body || {};
        const origin = getOrigin(deps.getDomain, req);
        const actorUrl = `${origin}/u/${encodeURIComponent(name)}`;

        const resolveActorInbox = async (actorRef: unknown): Promise<string | null> => {
          if (typeof actorRef !== 'string' || !actorRef.startsWith('http')) return null;
          try {
            const actorRes = await fetch(actorRef, {
              headers: { Accept: 'application/activity+json, application/ld+json' },
              signal: AbortSignal.timeout(5000),
            });
            if (!actorRes.ok) return null;
            const actor = (await actorRes.json()) as {
              inbox?: string;
              endpoints?: { sharedInbox?: string };
            };
            return actor.endpoints?.sharedInbox || actor.inbox || null;
          } catch {
            return null;
          }
        };

        if (body.type === 'Follow') {
          const inbox = await resolveActorInbox(body.actor);
          if (inbox) {
            const followers = await loadFollowers(deps.dataDir);
            followers.add(inbox);
            await saveFollowers(deps.dataDir, followers);
            const identity = await deps.getServerIdentity();
            void deliverSignedActivity(
              {
                '@context': 'https://www.w3.org/ns/activitystreams',
                id: `${actorUrl}#accept-${crypto.randomBytes(8).toString('hex')}`,
                type: 'Accept',
                actor: actorUrl,
                object: body,
              },
              `${actorUrl}#main-key`,
              identity.privateKeyPem,
              inbox
            ).catch(() => {});
          }
          return res.status(202).json({ ok: true });
        }

        if (body.type === 'Undo' && body.object?.type === 'Follow') {
          const inbox = await resolveActorInbox(body.actor);
          if (inbox) {
            const followers = await loadFollowers(deps.dataDir);
            if (followers.delete(inbox)) {
              await saveFollowers(deps.dataDir, followers);
            }
          }
          return res.status(202).json({ ok: true });
        }

        if (body.type === 'Accept') {
          const actorRef = typeof body.actor === 'string' ? body.actor : null;
          if (actorRef) {
            const relays = await loadRelays(deps.dataDir);
            if (relays[actorRef] && relays[actorRef].status !== 'accepted') {
              relays[actorRef].status = 'accepted';
              await saveRelays(deps.dataDir, relays);
              console.log(`ActivityPub relay accepted follow: ${actorRef}`);
            }
          }
          return res.status(202).json({ ok: true });
        }

        if ((body.type === 'Create' || body.type === 'Announce') && deps.onIncomingNote) {
          let noteObj: Record<string, unknown> | null = null;
          if (body.object && typeof body.object === 'object') {
            noteObj = body.object as Record<string, unknown>;
          } else if (body.type === 'Announce' && typeof body.object === 'string' && body.object.startsWith('http')) {
            try {
              const noteRes = await fetch(body.object, {
                headers: { Accept: 'application/activity+json, application/ld+json' },
                signal: AbortSignal.timeout(5000),
              });
              if (noteRes.ok) {
                noteObj = (await noteRes.json()) as Record<string, unknown>;
              }
            } catch {
              // Ignore unreachable announced objects
            }
          }

          if (noteObj && noteObj.type === 'Note' && typeof noteObj.content === 'string' && noteObj.content) {
            const rawTags = Array.isArray(noteObj.tag) ? noteObj.tag : [];
            const tags = rawTags
              .filter((t): t is { type?: string; name?: string } => Boolean(t && typeof t === 'object'))
              .filter((t) => !t.type || t.type === 'Hashtag')
              .map((t) => String(t.name || '').replace(/^#/, '').trim())
              .filter(Boolean);
            const attributed = await resolveRemoteAuthor(noteObj.attributedTo ?? body.actor);
            await deps.onIncomingNote({
              id: String(noteObj.id || body.id || crypto.randomUUID()),
              uri: typeof noteObj.id === 'string' ? noteObj.id : undefined,
              url: typeof noteObj.url === 'string' ? noteObj.url : undefined,
              content: noteObj.content,
              published: typeof noteObj.published === 'string' ? noteObj.published : undefined,
              tags,
              author: attributed?.author,
              authorUrl: attributed?.authorUrl,
            });
          }
          return res.status(202).json({ ok: true });
        }

        return res.status(202).json({ ok: true });
      } catch (e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
      }
    }
  );

  return router;
}
