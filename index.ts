import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import https from 'node:https';
import { on } from 'node:events';
import { DatabaseSync } from 'node:sqlite';
import express from 'express';
import type { Request, Response } from 'express';
import cors from 'cors';
import compression from 'compression';
import multer from 'multer';
import { createHelia } from 'helia';
import { unixfs } from '@helia/unixfs';
import type { UnixFS } from '@helia/unixfs';
import { mfs } from '@helia/mfs';
import type { MFS } from '@helia/mfs';
import { FsBlockstore } from 'blockstore-fs';
import { FsDatastore } from 'datastore-fs';
import { CID } from 'multiformats/cid';
import { multiaddr } from '@multiformats/multiaddr';
import { renderForumPage } from './views/forum.ts';
import type { ForumMessage } from './views/forum.ts';
import startFirehose from './firehose.ts';

interface MessageRow extends ForumMessage {
    id: string;
    depth: number;
    data: string;
    pubkey: string;
    sig: string;
    image_cid: string | null;
    cid?: string;
}

const __dirname = import.meta.dirname;
try {
    process.loadEnvFile(path.join(__dirname, '.env'));
} catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
}

const IPFS_GATEWAY_URL = (process.env.IPFS_GATEWAY_URL || '/ipfs').replace(/\/+$/, '');
const IPFS_DATA_DIR = path.resolve(process.env.IPFS_DATA_DIR || path.join(__dirname, 'ipfs-data'));
const app = express();
const db = new DatabaseSync(path.join(__dirname, 'database.sqlite'));
db.exec(`
    CREATE TABLE IF NOT EXISTS cred (
        pubkey TEXT PRIMARY KEY,
        balance INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
    );
`);

const POW_DIFFICULTY = Number(process.env.POW_DIFFICULTY) || 4;
const POW_TTL_MS = 5 * 60 * 1000;

interface PowChallenge {
    pubkey: string;
    difficulty: number;
    expiresAt: number;
}

const activePowChallenges = new Map<string, PowChallenge>();

function countLeadingHexZeros(hex: string): number {
    let count = 0;
    while (count < hex.length && hex[count] === '0') {
        count++;
    }
    return count;
}

function getCredBalance(pubkey: string): number {
    const row = db.prepare('SELECT balance FROM cred WHERE pubkey = ?').get(pubkey) as { balance: number } | undefined;
    return row ? row.balance : 0;
}

function awardCred(pubkey: string, amount: number): number {
    const now = new Date().toISOString();
    db.prepare(`
        INSERT INTO cred (pubkey, balance, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(pubkey) DO UPDATE SET
            balance = balance + excluded.balance,
            updated_at = excluded.updated_at
    `).run(pubkey, amount, now);
    return getCredBalance(pubkey);
}

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: (_req, file, cb) => {
        if (file.mimetype && file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image uploads are allowed'));
        }
    },
});

type HeliaNode = ReturnType<typeof createHelia>;

interface IpfsServices {
    helia: HeliaNode;
    ufs: UnixFS;
    mfsFs: MFS;
}

let ipfsPromise: Promise<IpfsServices> | null = null;

async function getIpfs(): Promise<IpfsServices> {
    if (!ipfsPromise) {
        ipfsPromise = (async () => {
            fs.mkdirSync(IPFS_DATA_DIR, { recursive: true });
            const blockstore = new FsBlockstore(path.join(IPFS_DATA_DIR, 'blocks'));
            const datastore = new FsDatastore(path.join(IPFS_DATA_DIR, 'data'));
            const helia = createHelia({ blockstore, datastore });
            await helia.start();
            console.log('Embedded IPFS node started:', helia.libp2p.peerId.toString());
            return { helia, ufs: unixfs(helia), mfsFs: mfs(helia) };
        })().catch((err) => {
            ipfsPromise = null;
            throw err;
        });
    }
    return ipfsPromise;
}

async function uploadToIpfs(buffer: Buffer): Promise<string> {
    const { ufs } = await getIpfs();
    const cid = await ufs.addBytes(new Uint8Array(buffer));
    return cid.toString();
}

async function readBytesFromIpfs(cidStr: string): Promise<Buffer> {
    const cid = CID.parse(cidStr);
    const { ufs } = await getIpfs();
    const chunks: Uint8Array[] = [];
    for await (const chunk of ufs.cat(cid)) {
        chunks.push(chunk);
    }
    return Buffer.concat(chunks);
}

async function readJsonFromIpfs<T>(cidStr: string): Promise<T> {
    const buf = await readBytesFromIpfs(cidStr);
    return JSON.parse(buf.toString('utf8')) as T;
}

async function ensureMfsDir(mfsFs: MFS, dirPath: string): Promise<void> {
    const parts = dirPath.split('/').filter(Boolean);
    let cur = '';
    for (const part of parts) {
        cur += '/' + part;
        try {
            await mfsFs.stat(cur);
        } catch {
            await mfsFs.mkdir(cur);
        }
    }
}

function toMfsPrefixPath(prefix?: string): string {
    const cleaned = String(prefix || '')
        .split('/')
        .map((s) => s.trim())
        .filter((s) => s && s !== '.' && s !== '..')
        .join('/');
    return cleaned ? `/messages/${cleaned}` : '/messages';
}

async function collectMfsMessages(mfsFs: MFS, dirPath: string, out: MessageRow[]): Promise<void> {
    for await (const entry of mfsFs.ls(dirPath)) {
        const entryPath = `${dirPath}/${entry.name}`;
        if (entry.name === 'message.json') {
            const cid = entry.cid.toString();
            const msg = await readJsonFromIpfs<MessageRow>(cid);
            out.push({ ...msg, cid });
        } else {
            await collectMfsMessages(mfsFs, entryPath, out);
        }
    }
}

async function listMessagesFromIpfs(prefix?: string): Promise<MessageRow[]> {
    const { mfsFs } = await getIpfs();
    const mfsDir = toMfsPrefixPath(prefix);
    try {
        await mfsFs.stat(mfsDir);
    } catch {
        return [];
    }
    const messages: MessageRow[] = [];
    await collectMfsMessages(mfsFs, mfsDir, messages);
    return messages.sort((a, b) => a.id.localeCompare(b.id));
}

async function saveMessageToIpfs(message: MessageRow): Promise<string> {
    const { mfsFs } = await getIpfs();
    const mfsDir = toMfsPrefixPath(message.id);
    await ensureMfsDir(mfsFs, mfsDir);
    const filePath = `${mfsDir}/message.json`;
    const bytes = new TextEncoder().encode(JSON.stringify(message));
    await mfsFs.writeBytes(bytes, filePath);
    const stat = await mfsFs.stat(filePath);
    return stat.cid.toString();
}

function verifySignature(data: unknown, pubkey: unknown, sig: unknown): boolean {
    if (!pubkey || !sig || typeof pubkey !== 'string' || typeof sig !== 'string') {
        return false;
    }
    try {
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(String(data));
        verifier.end();
        return verifier.verify(pubkey, sig, 'hex');
    } catch {
        return false;
    }
}

function sanitizeBoard(board: unknown): string {
    const cleaned = String(board || 'default').replace(/[^a-zA-Z0-9_-]/g, '');
    return cleaned || 'default';
}

app.use(cors());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', async (req, res) => {
    try {
        const board = sanitizeBoard(req.query.board);
        const replyTo = req.query.replyTo ? String(req.query.replyTo) : '';
        const rows = await listMessagesFromIpfs(`/${board}`);
        const html = renderForumPage({
            board,
            messages: rows,
            replyTo,
            ipfsGatewayUrl: IPFS_GATEWAY_URL,
        });
        res.type('html').send(html);
    } catch (e) {
        console.error(e);
        res.status(500).type('text').send('Internal server error');
    }
});

const apiRouter = express.Router();

apiRouter.get('/messages', async (req, res) => {
    try {
        // TODO API should support queries for top level messages (boards), all messages within a topic (threads)
        // TODO add endpoints to get all messages in a board, all messages in a thread
        // TODO depth param to indicate whether we want topics or full message threads?
        const prefix = req.query.prefix ? String(req.query.prefix) : '';
        const rows = await listMessagesFromIpfs(prefix);
        res.json(rows);
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: (e as Error).message });
    }
});

app.get('/ipfs/:cid', async (req, res) => {
    try {
        const data = await readBytesFromIpfs(String(req.params.cid));
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        return res.send(data);
    } catch (e) {
        console.error(e);
        return res.status(404).type('text').send('IPFS content not found');
    }
});

apiRouter.post('/upload', upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No image file provided' });
        }
        const cid = await uploadToIpfs(req.file.buffer);
        return res.json({
            ok: true,
            cid,
            url: `${IPFS_GATEWAY_URL}/${cid}`,
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
});

function createMessageId(basePath: string): string {
    return `${basePath}/${new Date().toISOString()}-${crypto.randomUUID()}`;
}

// Publishes a client-signed message to this instance
// TODO make this activitypub compatible?
apiRouter.post('/send', async (req, res) => {
    const json = req.body || {};
    try {
        const data = json.data == null ? '' : String(json.data).trim();
        const imageCid = typeof json.image_cid === 'string' && json.image_cid ? json.image_cid : null;
        if (!data && !imageCid) {
            return res.status(400).json({ error: 'Message data or image_cid is required' });
        }
        const signedPayload = data || imageCid || '';
        if (!verifySignature(signedPayload, json.pubkey, json.sig)) {
            return res.status(400).json({ error: 'Invalid signature' });
        }
        // TODO parameterize the input to ensure a well formed ID, what if the board name contains / or user spoofs path?
        const id = createMessageId(String(json.path || '/default'));
        const depth = id.split('/').length - 1;
        const cid = await saveMessageToIpfs({
            id,
            depth,
            data,
            pubkey: String(json.pubkey),
            sig: String(json.sig),
            image_cid: imageCid,
        });
        return res.json({ ok: true, id, cid, image_cid: imageCid });
    }
    catch(e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
    // TODO forward these messages to our peers
});

apiRouter.get('/bootstrap', async (_req, res) => {
    try {
        const { helia, mfsFs } = await getIpfs();
        let rootCid: string | null = null;
        try {
            const stat = await mfsFs.stat('/messages');
            rootCid = stat.cid.toString();
        } catch {
            // No messages yet
        }
        res.json({
            peerId: helia.libp2p.peerId.toString(),
            rootCid,
            multiaddrs: helia.libp2p.getMultiaddrs().map((ma) => ma.toString()),
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: (e as Error).message });
    }
});

apiRouter.get('/cred', (req, res) => {
    const pubkey = String(req.query.pubkey || '');
    if (!pubkey) {
        return res.status(400).json({ error: 'pubkey query parameter is required' });
    }
    return res.json({ cred: getCredBalance(pubkey) });
});

apiRouter.post('/pow/challenge', (req, res) => {
    const body = req.body || {};
    const pubkey = String(body.pubkey || '');
    if (!pubkey) {
        return res.status(400).json({ error: 'pubkey is required' });
    }
    const now = Date.now();
    for (const [id, entry] of activePowChallenges.entries()) {
        if (entry.expiresAt <= now) {
            activePowChallenges.delete(id);
        }
    }
    const challenge = crypto.randomBytes(16).toString('hex');
    activePowChallenges.set(challenge, {
        pubkey,
        difficulty: POW_DIFFICULTY,
        expiresAt: now + POW_TTL_MS,
    });
    return res.json({
        challenge,
        difficulty: POW_DIFFICULTY,
    });
});

apiRouter.post('/pow/submit', (req, res) => {
    const body = req.body || {};
    const challenge = String(body.challenge || '');
    const nonce = body.nonce == null ? '' : String(body.nonce);
    const pubkey = String(body.pubkey || '');
    if (!challenge || nonce === '' || !pubkey) {
        return res.status(400).json({ error: 'challenge, nonce, and pubkey are required' });
    }

    const entry = activePowChallenges.get(challenge);
    if (!entry) {
        return res.status(400).json({ error: 'Unknown or already used challenge' });
    }
    activePowChallenges.delete(challenge);

    if (entry.expiresAt <= Date.now()) {
        return res.status(400).json({ error: 'Challenge expired' });
    }
    if (entry.pubkey !== pubkey) {
        return res.status(400).json({ error: 'Challenge does not match pubkey' });
    }

    const hash = crypto.createHash('sha256').update(`${challenge}:${nonce}`).digest('hex');
    const leadingZeros = countLeadingHexZeros(hash);
    if (leadingZeros < entry.difficulty) {
        return res.status(400).json({ error: `Insufficient work: ${leadingZeros} leading zeros (need ${entry.difficulty})` });
    }

    const awarded = Math.pow(2, leadingZeros - entry.difficulty);
    const cred = awardCred(pubkey, awarded);
    return res.json({
        ok: true,
        hash,
        leadingZeros,
        awarded,
        cred,
    });
});

const PORT = Number(process.env.PORT) || 3141;
let domain = process.env.DOMAIN || '';

/**
 * Queries a STUN server (RFC 5389 Binding Request) to discover our public IPv4 address.
 */
async function getPublicIpViaStun(host: string = 'stun.l.google.com', port: number = 19302, timeoutMs: number = 3000): Promise<string> {
  const socket = dgram.createSocket('udp4');
  const tid = crypto.randomBytes(12);
  const req = Buffer.alloc(20);
  req.writeUInt16BE(0x0001, 0); // Binding Request
  req.writeUInt16BE(0x0000, 2); // Message Length
  req.writeUInt32BE(0x2112a442, 4); // Magic Cookie
  tid.copy(req, 8);

  try {
    socket.send(req, port, host);
    for await (const [msg] of on(socket, 'message', { signal: AbortSignal.timeout(timeoutMs) })) {
      if (msg.length < 20 || !msg.subarray(8, 20).equals(tid)) continue;
      let offset = 20;
      while (offset + 4 <= msg.length) {
        const type = msg.readUInt16BE(offset);
        const len = msg.readUInt16BE(offset + 2);
        if (offset + 4 + len > msg.length) break;
        const family = len >= 8 ? msg[offset + 5] : 0;
        if (type === 0x0020 && family === 0x01) { // XOR-MAPPED-ADDRESS (IPv4)
          return [
            msg[offset + 8] ^ 0x21,
            msg[offset + 9] ^ 0x12,
            msg[offset + 10] ^ 0xa4,
            msg[offset + 11] ^ 0x42,
          ].join('.');
        }
        if (type === 0x0001 && family === 0x01) { // MAPPED-ADDRESS (IPv4)
          return [
            msg[offset + 8],
            msg[offset + 9],
            msg[offset + 10],
            msg[offset + 11],
          ].join('.');
        }
        offset += 4 + ((len + 3) & ~3);
      }
      throw new Error('No IPv4 address in STUN response');
    }
    throw new Error('STUN socket closed before response');
  } finally {
    try {
      socket.close();
    } catch {}
  }
}

function getDomain(req?: Request): string {
  return domain || req?.get('host') || `127.0.0.1:${PORT}`;
}

async function resolvePublicDomain(): Promise<void> {
  if (domain) return;
  try {
    const ip = await getPublicIpViaStun();
    domain = `${ip}:${PORT}`;
    console.log('Public domain resolved via STUN:', domain);
  } catch (err) {
    console.warn('STUN lookup failed, falling back to request host:', (err as Error).message);
  }
}

resolvePublicDomain();

apiRouter.post('/sendActivityPub', async (req, res) => {
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

app.use('/api', apiRouter);

const sslKeyPath = process.env.SSL_KEY_PATH;
const sslCertPath = process.env.SSL_CERT_PATH;

if (sslKeyPath && sslCertPath) {
  https.createServer(
    {
      key: fs.readFileSync(sslKeyPath),
      cert: fs.readFileSync(sslCertPath),
    },
    app
  ).listen(PORT, () => {
    console.log(`HTTPS server listening on port ${PORT}`);
  });
} else {
  app.listen(PORT, () => {
    console.log(`HTTP server listening on port ${PORT}`);
  });
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

async function sendSignedActivityPub(
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

function createActivityPubMessage(text: string, name: string, domain: string): Record<string, unknown> {
  const guidCreate = crypto.randomBytes(16).toString('hex');
  const guidNote = crypto.randomBytes(16).toString('hex');
  let d = new Date();

  // TODO replace IDs with path
  // TODO add support for inReplyTo
  let noteMessage = {
    'id': `https://${domain}/m/${guidNote}`,
    'type': 'Note',
    'published': d.toISOString(),
    'attributedTo': `https://${domain}/u/${name}`,
    'content': text,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],
  };

  let activity = {
    '@context': 'https://www.w3.org/ns/activitystreams',

    'id': `https://${domain}/m/${guidCreate}`,
    'type': 'Create',
    'actor': `https://${domain}/u/${name}`,
    'to': ['https://www.w3.org/ns/activitystreams#Public'],

    'object': noteMessage
  };

  return activity;
}

async function sendActivityPubMessage(
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

async function syncUnixFsMessages(dirCid: CID, ufs: UnixFS, mfsFs: MFS): Promise<number> {
  let imported = 0;
  for await (const entry of ufs.ls(dirCid, { signal: AbortSignal.timeout(15000) })) {
    if (entry.name === 'message.json') {
      const chunks: Uint8Array[] = [];
      for await (const chunk of ufs.cat(entry.cid, { signal: AbortSignal.timeout(15000) })) {
        chunks.push(chunk);
      }
      const msg = JSON.parse(Buffer.concat(chunks).toString('utf8')) as MessageRow;
      const signedPayload = msg.data || msg.image_cid || '';
      if (!verifySignature(signedPayload, msg.pubkey, msg.sig)) {
        continue;
      }
      if (msg.image_cid) {
        const imgChunks: Uint8Array[] = [];
        for await (const chunk of ufs.cat(CID.parse(msg.image_cid), { signal: AbortSignal.timeout(15000) })) {
          imgChunks.push(chunk);
        }
        await ufs.addBytes(Buffer.concat(imgChunks));
      }
      const mfsDir = toMfsPrefixPath(msg.id);
      const filePath = `${mfsDir}/message.json`;
      let exists = false;
      try {
        await mfsFs.stat(filePath);
        exists = true;
      } catch {}
      if (!exists) {
        await saveMessageToIpfs(msg);
        imported++;
      }
    } else {
      imported += await syncUnixFsMessages(entry.cid, ufs, mfsFs);
    }
  }
  return imported;
}

async function bootstrapFromPeer(bootstrapUrl: string): Promise<void> {
  const baseUrl = bootstrapUrl.replace(/\/+$/, '');
  const res = await fetch(`${baseUrl}/api/bootstrap`);
  if (!res.ok) {
    throw new Error(`Bootstrap request failed (${res.status} ${res.statusText})`);
  }
  const info = (await res.json()) as { peerId?: string; rootCid?: string | null; multiaddrs?: string[] };
  if (!info.rootCid) {
    console.log('Bootstrap peer has no messages yet.');
    return;
  }

  const { helia, ufs, mfsFs } = await getIpfs();
  let dialed = false;
  for (const addr of info.multiaddrs || []) {
    try {
      await helia.libp2p.dial(multiaddr(addr), { signal: AbortSignal.timeout(5000) });
      dialed = true;
      break;
    } catch {}
  }
  if (!dialed) {
    throw new Error('Could not dial any libp2p multiaddr from bootstrap peer');
  }

  const imported = await syncUnixFsMessages(CID.parse(info.rootCid), ufs, mfsFs);
  console.log(`Bootstrapped ${imported} message(s) via IPFS from ${baseUrl}`);
}

if (process.env.BOOTSTRAP_URL) {
  bootstrapFromPeer(process.env.BOOTSTRAP_URL).catch((err) => {
    console.error('Bootstrap error:', err);
  });
}

// BitTorrent DHT removed; peer discovery handled by Helia/libp2p
try {
  await startFirehose();
} catch (err) {
  console.error('Firehose error:', err);
}

/*
// Create POST connection to peers, send them messages when our users post them
//public list of operators, or webrtc p2p communication with socketio signaling
// TODO organize servers in a ring, use hashing to determine token ranges that each server is responsible for?
// TODO overlap ranges to provide replication in case nodes drop out of the ring
const postReq = http.request({hostname: '127.0.0.1', port: 3141, path: '/', method: 'POST'}, res => {});
setInterval(() => {
    const msg = 'hi ' + Math.random();
    postReq.write(JSON.stringify({
    id: '/test',
    message: msg,
    signature: signature(msg),
    }));
}, 1000);
*/