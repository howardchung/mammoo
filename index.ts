import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import https from 'node:https';
import { on } from 'node:events';
import express from 'express';
import type { Request } from 'express';
import cors from 'cors';
import compression from 'compression';
import multer from 'multer';
import { createHelia } from 'helia';
import { unixfs } from '@helia/unixfs';
import type { UnixFS } from '@helia/unixfs';
import { FsBlockstore } from 'blockstore-fs';
import { FsDatastore } from 'datastore-fs';
import { CID } from 'multiformats/cid';
import { renderForumPage } from './views/forum.ts';
import type { ForumMessage, PowProof } from './views/forum.ts';
import startFirehose from './firehose.ts';
import { createActivityPubRouter } from './activitypub.ts';
import { bootstrapFromPeer, createBootstrapRouter } from './bootstrap.ts';

interface MessageRow extends ForumMessage {
    id: string;
    depth: number;
    data: string;
    pubkey: string;
    sig: string;
    image_cid: string | null;
    pow?: PowProof[];
    cred?: number;
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
const LOGS_DIR = path.resolve(process.env.LOGS_DIR || path.join(IPFS_DATA_DIR, 'logs'));
const app = express();
const POW_DIFFICULTY = Number(process.env.POW_DIFFICULTY) || 4;
const POW_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const POW_FUTURE_SKEW_MS = 60 * 1000;

function countLeadingHexZeros(hex: string): number {
    let count = 0;
    while (count < hex.length && hex[count] === '0') {
        count++;
    }
    return count;
}

function verifyPowProofs(pubkey: string, proofs: unknown): { totalCred: number; validProofs: PowProof[] } {
    if (!pubkey || !Array.isArray(proofs)) {
        return { totalCred: 0, validProofs: [] };
    }
    const now = Date.now();
    const seenHashes = new Set<string>();
    const validProofs: PowProof[] = [];
    let totalCred = 0;

    for (const raw of proofs) {
        if (!raw || typeof raw !== 'object') continue;
        const { timestamp, nonce } = raw as { timestamp?: unknown; nonce?: unknown };
        if (typeof timestamp !== 'number' || !Number.isFinite(timestamp)) continue;
        if (typeof nonce !== 'number' || !Number.isInteger(nonce) || nonce < 0) continue;
        if (timestamp > now + POW_FUTURE_SKEW_MS || timestamp < now - POW_MAX_AGE_MS) continue;

        const hash = crypto.createHash('sha256').update(`${pubkey}:${timestamp}:${nonce}`).digest('hex');
        if (seenHashes.has(hash)) continue;
        const leadingZeros = countLeadingHexZeros(hash);
        if (leadingZeros < POW_DIFFICULTY) continue;

        seenHashes.add(hash);
        const cred = Math.pow(2, leadingZeros - POW_DIFFICULTY);
        totalCred += cred;
        validProofs.push({ timestamp, nonce, hash, leadingZeros, cred });
    }

    return { totalCred, validProofs };
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
            return { helia, ufs: unixfs(helia) };
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

const credByPubkey = new Map<string, number>();

function attachCredToMessages(messages: MessageRow[]): MessageRow[] {
    return messages.map((msg) => ({
        ...msg,
        cred: credByPubkey.get(msg.pubkey) ?? 0,
    }));
}

async function listMessagesFromIpfs(prefix?: string): Promise<MessageRow[]> {
    const normalized = String(prefix || '')
        .split('/')
        .map((s) => s.trim())
        .filter((s) => s && s !== '.' && s !== '..');
    if (normalized.length === 0) {
        return attachCredToMessages(await readMessageLog());
    }
    const board = sanitizeBoard(normalized[0]);
    const messages = await readMessageLog(board);
    const targetPrefix = `/${[board, ...normalized.slice(1)].join('/')}`;
    const filtered = messages
        .filter((m) => m.id === targetPrefix || m.id.startsWith(`${targetPrefix}/`))
        .sort((a, b) => a.id.localeCompare(b.id));
    return attachCredToMessages(filtered);
}

function getBoardFromId(id: string): string {
    const first = String(id || '').split('/').filter(Boolean)[0];
    return sanitizeBoard(first);
}

function getBoardLogPath(board: string): string {
    return path.join(LOGS_DIR, `${sanitizeBoard(board)}.log`);
}

const boardCidSets = new Map<string, Promise<Set<string>>>();
const postCache = new Map<string, MessageRow>();

function getBoardCidSet(board: string): Promise<Set<string>> {
    const cleanBoard = sanitizeBoard(board);
    let setPromise = boardCidSets.get(cleanBoard);
    if (!setPromise) {
        setPromise = (async () => {
            try {
                const raw = await fs.promises.readFile(getBoardLogPath(cleanBoard), 'utf8');
                return new Set(
                    raw
                        .split('\n')
                        .map((line) => line.trim())
                        .filter(Boolean)
                );
            } catch (err) {
                if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
                    return new Set<string>();
                }
                boardCidSets.delete(cleanBoard);
                throw err;
            }
        })();
        boardCidSets.set(cleanBoard, setPromise);
    }
    return setPromise;
}

async function readBoardCids(board: string, offset: number = 0): Promise<string[]> {
    const cids = Array.from(await getBoardCidSet(board));
    return offset > 0 ? cids.slice(offset) : cids;
}

async function appendCidToBoardLog(board: string, postCid: string): Promise<boolean> {
    const cleanBoard = sanitizeBoard(board);
    const cidSet = await getBoardCidSet(cleanBoard);
    if (cidSet.has(postCid)) {
        return false;
    }
    cidSet.add(postCid);
    const logPath = getBoardLogPath(cleanBoard);
    try {
        await fs.promises.mkdir(path.dirname(logPath), { recursive: true });
        await fs.promises.appendFile(logPath, `${postCid}\n`, 'utf8');
        return true;
    } catch (err) {
        cidSet.delete(postCid);
        throw err;
    }
}

async function readPostByCid(postCid: string): Promise<MessageRow> {
    const cached = postCache.get(postCid);
    if (cached) {
        return cached;
    }
    const buf = await readBytesFromIpfs(postCid);
    const msg = JSON.parse(buf.toString('utf8')) as MessageRow;
    const row: MessageRow = { ...msg, cid: postCid };
    postCache.set(postCid, row);
    return row;
}

async function appendMessageLog(message: MessageRow): Promise<string> {
    const cleanMessage: MessageRow = {
        id: message.id,
        depth: message.depth,
        data: message.data,
        pubkey: message.pubkey,
        sig: message.sig,
        image_cid: message.image_cid,
    };
    const postCid = await uploadToIpfs(Buffer.from(JSON.stringify(cleanMessage)));
    postCache.set(postCid, { ...cleanMessage, cid: postCid });
    await appendCidToBoardLog(getBoardFromId(cleanMessage.id), postCid);
    return postCid;
}

async function listBoardsFromDisk(): Promise<string[]> {
    try {
        const entries = await fs.promises.readdir(LOGS_DIR, { withFileTypes: true });
        return entries
            .filter((e) => e.isFile() && e.name.endsWith('.log'))
            .map((e) => e.name.slice(0, -4));
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
            return [];
        }
        throw err;
    }
}

function filterBySince(entries: MessageRow[], since?: string): MessageRow[] {
    if (!since) {
        return entries;
    }
    return entries.filter((msg) => {
        const leaf = msg.id.split('/').pop() || '';
        return leaf > since;
    });
}

async function readMessageLog(board?: string, offset: number = 0, since?: string): Promise<MessageRow[]> {
    if (board) {
        const cids = await readBoardCids(board, offset);
        const entries = await Promise.all(cids.map((cid) => readPostByCid(cid)));
        entries.sort((a, b) => a.id.localeCompare(b.id));
        return filterBySince(entries, since);
    }
    const boards = await listBoardsFromDisk();
    const allEntries: MessageRow[] = [];
    for (const b of boards) {
        const cids = await readBoardCids(b);
        const entries = await Promise.all(cids.map((cid) => readPostByCid(cid)));
        allEntries.push(...filterBySince(entries, since));
    }
    allEntries.sort((a, b) => a.id.localeCompare(b.id));
    return offset > 0 ? allEntries.slice(offset) : allEntries;
}

async function saveMessageToIpfs(message: MessageRow): Promise<string> {
    return appendMessageLog(message);
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

function resolveValidatedSendPath(rawPath: unknown): string {
    const str = rawPath == null || rawPath === '' ? '/default' : String(rawPath).trim();
    if (!str.startsWith('/') || str.includes('\\')) {
        throw new Error('Invalid path');
    }
    const segments = str.slice(1).split('/');
    if (segments.length === 0 || segments.some((s) => !s || s === '.' || s === '..')) {
        throw new Error('Invalid path segments');
    }
    const board = sanitizeBoard(segments[0]);
    if (board !== segments[0]) {
        throw new Error('Invalid board name in path');
    }
    return `/${segments.join('/')}`;
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
        let basePath: string;
        try {
            basePath = resolveValidatedSendPath(json.path);
        } catch (pathErr) {
            return res.status(400).json({ error: (pathErr as Error).message });
        }
        const id = createMessageId(basePath);
        const depth = id.split('/').length - 1;
        const pubkey = String(json.pubkey);
        const cred = credByPubkey.get(pubkey) ?? 0;
        const cid = await saveMessageToIpfs({
            id,
            depth,
            data,
            pubkey,
            sig: String(json.sig),
            image_cid: imageCid,
        });
        return res.json({ ok: true, id, cid, image_cid: imageCid, cred });
    }
    catch(e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
    // TODO forward these messages to our peers
});

const bootstrapDeps = {
    sanitizeBoard,
    getBoardFromId,
    readMessageLog,
    readBoardCids,
    listBoardsFromDisk,
    uploadToIpfs,
    verifySignature,
    appendCidToBoardLog,
    saveMessageToIpfs,
    postCache,
    getIpfs,
};

apiRouter.use(createBootstrapRouter(bootstrapDeps));

apiRouter.post('/pow/verify', (req, res) => {
    const body = req.body || {};
    const pubkey = String(body.pubkey || '');
    if (!pubkey || !Array.isArray(body.proofs)) {
        return res.status(400).json({ error: 'pubkey and proofs array are required' });
    }
    const { totalCred, validProofs } = verifyPowProofs(pubkey, body.proofs);
    credByPubkey.set(pubkey, totalCred);
    return res.json({
        ok: true,
        cred: totalCred,
        validCount: validProofs.length,
        validProofs,
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

apiRouter.use(createActivityPubRouter(getDomain));

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

if (process.env.BOOTSTRAP_URL) {
  bootstrapFromPeer(process.env.BOOTSTRAP_URL, bootstrapDeps).catch((err) => {
    console.error('Bootstrap error:', err);
  });
}

// BitTorrent DHT removed; peer discovery handled by Helia/libp2p
try {
  await startFirehose();
} catch (err) {
  console.error('Firehose error:', err);
}
