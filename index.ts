import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
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
import { buildMessageSignaturePayload, renderForumPage } from './views/forum.ts';
import type { ForumMessage, PowProof } from './views/forum.ts';
import startFirehose from './firehose.ts';
import type { FediverseStatus } from './firehose.ts';
import { createActivityPubRouter } from './activitypub.ts';
import {
    bootstrapFromPeer,
    createBootstrapRouter,
    getConfiguredPeers,
    getKnownPeers,
    pushMessageToPeers,
    startPeerDiscovery,
    startPeerSync,
} from './bootstrap.ts';

interface MessageRow extends ForumMessage {
    id: string;
    depth: number;
    data: string;
    pubkey: string;
    sig: string;
    content_cid: string | null;
    media_type?: 'image' | 'video' | 'audio' | 'file' | null;
    pow?: PowProof | null;
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
const POW_DIFFICULTY_BITS = Math.min(63, Math.max(1, Number(process.env.POW_DIFFICULTY_BITS) || 16));
const POW_BASE_TARGET = 1n << BigInt(64 - POW_DIFFICULTY_BITS);
const POW_CRED_SCALE = BigInt(Number(process.env.POW_CRED_SCALE) || 1);

function scoreDigestCred(bytes: Uint8Array): number {
    const view = new DataView(bytes.buffer, bytes.byteOffset, 8);
    const h64 = view.getBigUint64(0, false);
    if (h64 >= POW_BASE_TARGET) {
        return 0;
    }
    const scaled = (POW_BASE_TARGET * POW_CRED_SCALE) / (h64 + 1n);
    return scaled > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(scaled);
}

function verifyPubkeyPow(
    pubkey: string,
    rawProof: unknown
): { cred: number; validProof: PowProof | null } {
    if (!pubkey || rawProof == null) {
        return { cred: 0, validProof: null };
    }
    const nonce = typeof rawProof === 'number'
        ? rawProof
        : (typeof rawProof === 'object' ? (rawProof as { nonce?: unknown }).nonce : undefined);
    if (typeof nonce !== 'number' || !Number.isInteger(nonce) || nonce < 0) {
        return { cred: 0, validProof: null };
    }

    const digest = crypto.createHash('sha256').update(`${pubkey}:${nonce}`).digest();
    const cred = scoreDigestCred(digest);
    if (cred <= 0) {
        return { cred: 0, validProof: null };
    }

    return { cred, validProof: { nonce } };
}

const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: Number(process.env.MAX_UPLOAD_BYTES) || 50 * 1024 * 1024 },
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

const CREDS_INDEX_PATH = path.join(LOGS_DIR, 'creds.json');
let credIndexPromise: Promise<Record<string, number>> | null = null;

function getPubkeyHash(pubkey: string): string {
    return crypto.createHash('sha256').update(pubkey).digest('hex');
}

function getCredIndex(): Promise<Record<string, number>> {
    if (!credIndexPromise) {
        credIndexPromise = (async () => {
            try {
                const raw = await fs.promises.readFile(CREDS_INDEX_PATH, 'utf8');
                const parsed = JSON.parse(raw);
                if (!parsed || typeof parsed !== 'object') {
                    return {};
                }
                const out: Record<string, number> = {};
                for (const [k, v] of Object.entries(parsed as Record<string, unknown>)) {
                    if (typeof v === 'number' && Number.isInteger(v) && v >= 0) {
                        out[k] = v;
                    }
                }
                return out;
            } catch (err) {
                if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
                    return {};
                }
                credIndexPromise = null;
                throw err;
            }
        })();
    }
    return credIndexPromise;
}

async function getPubkeyCred(pubkey: string): Promise<{ cred: number; nonce: number | null }> {
    if (!pubkey) {
        return { cred: 0, nonce: null };
    }
    const index = await getCredIndex();
    const nonce = index[getPubkeyHash(pubkey)];
    if (typeof nonce !== 'number') {
        return { cred: 0, nonce: null };
    }
    const { cred } = verifyPubkeyPow(pubkey, nonce);
    return { cred, nonce };
}

async function upsertPubkeyCred(
    pubkey: string,
    rawPow: unknown
): Promise<{ ok: boolean; cred: number; updated: boolean; error?: string }> {
    if (!pubkey) {
        return { ok: false, cred: 0, updated: false, error: 'pubkey is required' };
    }
    const { cred, validProof } = verifyPubkeyPow(pubkey, rawPow);
    if (!validProof || cred <= 0) {
        return { ok: false, cred: 0, updated: false, error: 'Valid PoW proof is required' };
    }
    const existing = await getPubkeyCred(pubkey);
    if (cred <= existing.cred) {
        return { ok: true, cred: existing.cred, updated: false };
    }
    const index = await getCredIndex();
    index[getPubkeyHash(pubkey)] = validProof.nonce;
    await fs.promises.mkdir(LOGS_DIR, { recursive: true });
    await fs.promises.writeFile(CREDS_INDEX_PATH, JSON.stringify(index, null, 2), 'utf8');
    return { ok: true, cred, updated: true };
}

async function attachCredToMessages(messages: MessageRow[]): Promise<MessageRow[]> {
    if (messages.length === 0) {
        return messages;
    }
    const uniquePubkeys = new Set<string>();
    for (const msg of messages) {
        if (msg.pubkey) {
            uniquePubkeys.add(msg.pubkey);
        }
    }
    const credByPubkey = new Map<string, number>();
    await Promise.all(
        Array.from(uniquePubkeys).map(async (pk) => {
            const { cred } = await getPubkeyCred(pk);
            credByPubkey.set(pk, cred);
        })
    );
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
        return readMessageLog();
    }
    const board = sanitizeBoard(normalized[0]);
    const messages = await readMessageLog(board);
    const targetPrefix = `/${[board, ...normalized.slice(1)].join('/')}`;
    return messages
        .filter((m) => m.id === targetPrefix || m.id.startsWith(`${targetPrefix}/`))
        .sort((a, b) => a.id.localeCompare(b.id));
}

function getBoardFromId(id: string): string {
    const first = String(id || '').split('/').filter(Boolean)[0];
    return sanitizeBoard(first);
}

function getBoardLogPath(board: string): string {
    return path.join(LOGS_DIR, `${sanitizeBoard(board)}.log`);
}

interface BoardLogState {
    ids: Set<string>;
    messages: MessageRow[];
}

const boardLogs = new Map<string, Promise<BoardLogState>>();

function getBoardLogState(board: string): Promise<BoardLogState> {
    const cleanBoard = sanitizeBoard(board);
    let statePromise = boardLogs.get(cleanBoard);
    if (!statePromise) {
        statePromise = (async () => {
            const ids = new Set<string>();
            const messages: MessageRow[] = [];
            try {
                const raw = await fs.promises.readFile(getBoardLogPath(cleanBoard), 'utf8');
                for (const rawLine of raw.split('\n')) {
                    const line = rawLine.trim();
                    if (!line) continue;
                    const msg = JSON.parse(line) as MessageRow;
                    if (msg && msg.id && !ids.has(msg.id)) {
                        ids.add(msg.id);
                        messages.push(msg);
                    }
                }
                return { ids, messages };
            } catch (err) {
                if ((err as NodeJS.ErrnoException).code === 'ENOENT') {
                    return { ids, messages };
                }
                boardLogs.delete(cleanBoard);
                throw err;
            }
        })();
        boardLogs.set(cleanBoard, statePromise);
    }
    return statePromise;
}

async function appendMessageLog(message: MessageRow): Promise<boolean> {
    const cleanMessage: MessageRow = {
        id: message.id,
        depth: message.depth,
        data: message.data,
        pubkey: message.pubkey,
        sig: message.sig,
        content_cid: message.content_cid,
        ...(message.media_type ? { media_type: message.media_type } : {}),
    };
    const board = getBoardFromId(cleanMessage.id);
    const state = await getBoardLogState(board);
    if (state.ids.has(cleanMessage.id)) {
        return false;
    }
    state.ids.add(cleanMessage.id);
    state.messages.push(cleanMessage);
    const logPath = getBoardLogPath(board);
    try {
        await fs.promises.mkdir(path.dirname(logPath), { recursive: true });
        await fs.promises.appendFile(logPath, `${JSON.stringify(cleanMessage)}\n`, 'utf8');
        return true;
    } catch (err) {
        state.ids.delete(cleanMessage.id);
        state.messages.pop();
        throw err;
    }
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
    const boards = board ? [sanitizeBoard(board)] : await listBoardsFromDisk();
    const messages: MessageRow[] = [];
    for (const b of boards) {
        const state = await getBoardLogState(b);
        messages.push(...state.messages);
    }
    const withCred = await attachCredToMessages(messages);
    withCred.sort((a, b) => a.id.localeCompare(b.id));
    const filtered = filterBySince(withCred, since);
    return offset > 0 ? filtered.slice(offset) : filtered;
}

async function hasMessageId(id: string): Promise<boolean> {
    const state = await getBoardLogState(getBoardFromId(id));
    return state.ids.has(id);
}

async function saveMessage(message: MessageRow): Promise<boolean> {
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
            powDifficultyBits: POW_DIFFICULTY_BITS,
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

function detectContentType(buf: Buffer): string {
    if (buf.length >= 4 && buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return 'image/png';
    if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return 'image/jpeg';
    if (buf.length >= 4 && buf.subarray(0, 4).toString('ascii') === 'GIF8') return 'image/gif';
    if (buf.length >= 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WEBP') return 'image/webp';
    if (buf.length >= 12 && buf.subarray(0, 4).toString('ascii') === 'RIFF' && buf.subarray(8, 12).toString('ascii') === 'WAVE') return 'audio/wav';
    if (buf.length >= 8 && buf.subarray(4, 8).toString('ascii') === 'ftyp') return 'video/mp4';
    if (buf.length >= 4 && buf[0] === 0x1a && buf[1] === 0x45 && buf[2] === 0xdf && buf[3] === 0xa3) return 'video/webm';
    if (buf.length >= 4 && buf.subarray(0, 4).toString('ascii') === 'OggS') return 'video/ogg';
    if (buf.length >= 3 && buf.subarray(0, 3).toString('ascii') === 'ID3') return 'audio/mpeg';
    if (buf.length >= 2 && buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0) return 'audio/mpeg';
    if (buf.length >= 4 && buf.subarray(0, 4).toString('ascii') === '%PDF') return 'application/pdf';
    return 'application/octet-stream';
}

function classifyMediaType(mimetype?: string | null): 'image' | 'video' | 'audio' | 'file' {
    if (!mimetype) return 'file';
    if (mimetype.startsWith('video/')) return 'video';
    if (mimetype.startsWith('audio/')) return 'audio';
    if (mimetype.startsWith('image/')) return 'image';
    return 'file';
}

app.get('/ipfs/:cid', async (req, res) => {
    try {
        const data = await readBytesFromIpfs(String(req.params.cid));
        res.type(detectContentType(data));
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
            return res.status(400).json({ error: 'No file provided' });
        }
        const cid = await uploadToIpfs(req.file.buffer);
        const mediaType = classifyMediaType(req.file.mimetype);
        return res.json({
            ok: true,
            cid,
            media_type: mediaType,
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
        const contentCid = typeof json.content_cid === 'string' && json.content_cid ? json.content_cid : null;
        if (!data && !contentCid) {
            return res.status(400).json({ error: 'Message data or content_cid is required' });
        }
        const signedPayload = buildMessageSignaturePayload(data, contentCid);
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
        const sig = String(json.sig);
        const validMediaTypes = new Set(['image', 'video', 'audio', 'file']);
        const mediaType = validMediaTypes.has(json.media_type)
            ? json.media_type
            : (contentCid ? 'image' : null);
        const newMessage: MessageRow = {
            id,
            depth,
            data,
            pubkey,
            sig,
            content_cid: contentCid,
            media_type: mediaType,
        };
        await saveMessage(newMessage);
        void pushMessageToPeers(newMessage, getKnownPeers(getSelfUrl()), getSelfUrl());
        return res.json({ ok: true, id, content_cid: contentCid, media_type: mediaType });
    }
    catch(e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
});

apiRouter.post('/cred', async (req, res) => {
    const json = req.body || {};
    try {
        const pubkey = String(json.pubkey || '');
        const sig = String(json.sig || '');
        if (!verifySignature(pubkey, pubkey, sig)) {
            return res.status(400).json({ error: 'Invalid signature' });
        }
        const result = await upsertPubkeyCred(pubkey, json.pow);
        if (!result.ok) {
            return res.status(400).json({ error: result.error });
        }
        return res.json({ ok: true, pubkey, cred: result.cred, updated: result.updated });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
});

const PORT = Number(process.env.PORT) || 3141;
let discoveredHost = '';

function isPrivateIpv4(ip: string): boolean {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return true;
    const [a, b] = parts;
    return (
        a === 10 ||
        a === 127 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254) ||
        (a === 100 && b >= 64 && b <= 127)
    );
}

function getLocalInterfaceIp(): string {
    let privateFallback = '';
    const interfaces = os.networkInterfaces();
    for (const addrs of Object.values(interfaces)) {
        for (const addr of addrs || []) {
            if (addr.internal || addr.family !== 'IPv4') continue;
            if (!isPrivateIpv4(addr.address)) {
                return addr.address;
            }
            if (!privateFallback) {
                privateFallback = addr.address;
            }
        }
    }
    return privateFallback;
}

async function resolvePublicHost(): Promise<void> {
    if (process.env.PUBLIC_URL) return;
    const nicIp = getLocalInterfaceIp();
    if (nicIp && !isPrivateIpv4(nicIp)) {
        discoveredHost = nicIp;
        console.log('Public IP detected from network interface:', discoveredHost);
        return;
    }
    try {
        const res = await fetch('https://api.ipify.org', { signal: AbortSignal.timeout(3000) });
        if (res.ok) {
            const ip = (await res.text()).trim();
            if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) {
                discoveredHost = ip;
                console.log('Public IP discovered:', discoveredHost);
                return;
            }
        }
    } catch {
        // Fall back to private NIC IP or localhost
    }
    if (nicIp) {
        discoveredHost = nicIp;
    }
}

void resolvePublicHost();

function getSelfUrl(): string {
    if (process.env.PUBLIC_URL) {
        return process.env.PUBLIC_URL.replace(/\/+$/, '');
    }
    const scheme = process.env.SSL_KEY_PATH && process.env.SSL_CERT_PATH ? 'https' : 'http';
    const host = discoveredHost || getLocalInterfaceIp() || 'localhost';
    return `${scheme}://${host}:${PORT}`;
}

const bootstrapDeps = {
    sanitizeBoard,
    listBoardsFromDisk,
    getPubkeyHash,
    readMessageLog,
    getCredIndex,
    upsertPubkeyCred,
    uploadToIpfs,
    verifySignature,
    hasMessageId,
    saveMessage,
    getIpfs,
};

apiRouter.use(createBootstrapRouter(bootstrapDeps, { getSelfUrl }));

function getDomain(req?: Request): string {
  if (process.env.PUBLIC_URL) {
    try {
      return new URL(process.env.PUBLIC_URL).host;
    } catch {}
  }
  return req?.get('host') || `127.0.0.1:${PORT}`;
}

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

for (const peer of getConfiguredPeers()) {
  bootstrapFromPeer(peer, bootstrapDeps).catch((err) => {
    console.error(`Bootstrap error from ${peer}:`, err);
  });
}
const syncIntervalMs = process.env.SYNC_INTERVAL_MS !== undefined ? Number(process.env.SYNC_INTERVAL_MS) : 30000;
startPeerSync(() => getKnownPeers(getSelfUrl()), bootstrapDeps, syncIntervalMs);

const discoveryIntervalMs = process.env.DISCOVERY_INTERVAL_MS !== undefined ? Number(process.env.DISCOVERY_INTERVAL_MS) : 60000;
startPeerDiscovery(bootstrapDeps, { getSelfUrl, intervalMs: discoveryIntervalMs }).catch((err) => {
  console.error('Peer discovery error:', err);
});

interface ServerIdentity {
  publicKeyPem: string;
  privateKeyPem: string;
}

let serverIdentityPromise: Promise<ServerIdentity> | null = null;

function getOrCreateServerIdentity(): Promise<ServerIdentity> {
  if (!serverIdentityPromise) {
    serverIdentityPromise = (async () => {
      const keyPath = path.join(IPFS_DATA_DIR, 'server-key.json');
      try {
        const raw = await fs.promises.readFile(keyPath, 'utf8');
        const parsed = JSON.parse(raw) as ServerIdentity;
        if (parsed.publicKeyPem && parsed.privateKeyPem) {
          return parsed;
        }
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      }

      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const identity: ServerIdentity = {
        publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
      };
      await fs.promises.mkdir(path.dirname(keyPath), { recursive: true });
      await fs.promises.writeFile(keyPath, JSON.stringify(identity, null, 2), { mode: 0o600 });
      return identity;
    })();
  }
  return serverIdentityPromise;
}

function signServerPayload(payload: string, privateKeyPem: string): string {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(payload);
  signer.end();
  return signer.sign(privateKeyPem, 'hex');
}

async function routeFirehoseStatus(status: FediverseStatus, host: string): Promise<void> {
  const rawTags = Array.isArray(status.tags) ? status.tags : [];
  const boards = new Set<string>();
  for (const tag of rawTags) {
    const rawName = typeof tag?.name === 'string' ? tag.name.trim().toLowerCase() : '';
    if (!rawName) continue;
    const cleaned = rawName.replace(/[^a-zA-Z0-9_-]/g, '');
    if (cleaned) {
      boards.add(sanitizeBoard(cleaned));
    }
  }
  if (boards.size === 0) return;

  const data = status.content || status.url || status.id;
  if (!data) return;

  const parsedDate = status.created_at ? new Date(status.created_at) : new Date();
  const timestamp = Number.isNaN(parsedDate.getTime()) ? new Date().toISOString() : parsedDate.toISOString();
  const statusHash = crypto
    .createHash('sha256')
    .update(String(status.uri || `${host}:${status.id}`))
    .digest('hex')
    .slice(0, 16);

  const identity = await getOrCreateServerIdentity();
  const sig = signServerPayload(buildMessageSignaturePayload(data, null), identity.privateKeyPem);

  for (const board of boards) {
    const id = `/${board}/${timestamp}-fedi-${statusHash}`;
    if (await hasMessageId(id)) continue;
    const msg: MessageRow = {
      id,
      depth: 2,
      data,
      pubkey: identity.publicKeyPem,
      sig,
      content_cid: null,
    };
    const saved = await saveMessage(msg);
    if (saved) {
      void pushMessageToPeers(msg, getKnownPeers(getSelfUrl()), getSelfUrl());
    }
  }
}

try {
  await startFirehose({ onStatus: routeFirehoseStatus });
} catch (err) {
  console.error('Firehose error:', err);
}
