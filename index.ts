import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import https from 'node:https';
import { DatabaseSync } from 'node:sqlite';
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
import {
    createActivityPubRootRouter,
    createActivityPubRouter,
    followRelays,
    publishPostToFediverse,
} from './activitypub.ts';
import type { IncomingActivityPubNote } from './activitypub.ts';
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
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(__dirname, 'pachytalk.db'));
const app = express();
const POW_HASHES_PER_SECOND = Math.max(1, Number(process.env.POW_HASHES_PER_SECOND) || 100000);
const POW_BASE_TARGET = (1n << 64n) / BigInt(POW_HASHES_PER_SECOND);
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
            const helia = createHelia({
                blockstore,
                datastore,
                http: { delegatedRouters: [] },
            });
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

let dbInstance: DatabaseSync | null = null;

function getDb(): DatabaseSync {
    if (!dbInstance) {
        fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
        const db = new DatabaseSync(DB_PATH);
        db.exec(`
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                board TEXT NOT NULL,
                leaf TEXT NOT NULL,
                depth INTEGER NOT NULL,
                data TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                sig TEXT NOT NULL,
                content_cid TEXT,
                media_type TEXT,
                author TEXT,
                author_url TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_messages_board_id ON messages(board, id);
            CREATE INDEX IF NOT EXISTS idx_messages_leaf ON messages(leaf);
            CREATE TABLE IF NOT EXISTS creds (
                pubkey_hash TEXT PRIMARY KEY,
                nonce INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activitypub_followers (
                inbox TEXT PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS activitypub_relays (
                actor_url TEXT PRIMARY KEY,
                inbox TEXT NOT NULL,
                status TEXT NOT NULL,
                followed_at TEXT NOT NULL
            );
        `);
        dbInstance = db;
    }
    return dbInstance;
}

function getPubkeyHash(pubkey: string): string {
    return crypto.createHash('sha256').update(pubkey).digest('hex');
}

async function getCredIndex(): Promise<Record<string, number>> {
    const rows = getDb()
        .prepare('SELECT pubkey_hash, nonce FROM creds')
        .all() as Array<{ pubkey_hash: string; nonce: number }>;
    const out: Record<string, number> = {};
    for (const row of rows) {
        if (typeof row.nonce === 'number' && Number.isInteger(row.nonce) && row.nonce >= 0) {
            out[row.pubkey_hash] = row.nonce;
        }
    }
    return out;
}

async function getPubkeyCred(pubkey: string): Promise<{ cred: number; nonce: number | null }> {
    if (!pubkey) {
        return { cred: 0, nonce: null };
    }
    const row = getDb()
        .prepare('SELECT nonce FROM creds WHERE pubkey_hash = ?')
        .get(getPubkeyHash(pubkey)) as { nonce?: number } | undefined;
    const nonce = row?.nonce;
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
    getDb()
        .prepare(
            'INSERT INTO creds (pubkey_hash, nonce) VALUES (?, ?) ON CONFLICT(pubkey_hash) DO UPDATE SET nonce = excluded.nonce'
        )
        .run(getPubkeyHash(pubkey), validProof.nonce);
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

function rowToMessage(row: Record<string, unknown>): MessageRow {
    return {
        id: String(row.id),
        depth: Number(row.depth),
        data: String(row.data),
        pubkey: String(row.pubkey),
        sig: String(row.sig),
        content_cid: typeof row.content_cid === 'string' ? row.content_cid : null,
        ...(typeof row.media_type === 'string'
            ? { media_type: row.media_type as MessageRow['media_type'] }
            : {}),
        ...(typeof row.author === 'string' && row.author ? { author: row.author } : {}),
        ...(typeof row.author_url === 'string' && row.author_url ? { author_url: row.author_url } : {}),
    };
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
    if (normalized.length === 1) {
        return readMessageLog(board);
    }
    const targetPrefix = `/${[board, ...normalized.slice(1)].join('/')}`;
    const rows = getDb()
        .prepare('SELECT * FROM messages WHERE board = ? AND (id = ? OR id LIKE ?) ORDER BY id ASC')
        .all(board, targetPrefix, `${targetPrefix}/%`) as Array<Record<string, unknown>>;
    return attachCredToMessages(rows.map(rowToMessage));
}

function getBoardFromId(id: string): string {
    const first = String(id || '').split('/').filter(Boolean)[0];
    return sanitizeBoard(first);
}

async function appendMessageLog(message: MessageRow): Promise<boolean> {
    const board = getBoardFromId(message.id);
    const leaf = message.id.split('/').pop() || '';
    const res = getDb()
        .prepare(
            `INSERT OR IGNORE INTO messages
             (id, board, leaf, depth, data, pubkey, sig, content_cid, media_type, author, author_url)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .run(
            message.id,
            board,
            leaf,
            message.depth,
            message.data,
            message.pubkey,
            message.sig,
            message.content_cid ?? null,
            message.media_type ?? null,
            message.author ?? null,
            message.author_url ?? null
        );
    return Number(res.changes) > 0;
}

async function listBoardsFromDisk(): Promise<string[]> {
    const rows = getDb()
        .prepare('SELECT DISTINCT board FROM messages ORDER BY board ASC')
        .all() as Array<{ board: string }>;
    return rows.map((r) => r.board);
}

async function readMessageLog(board?: string, offset: number = 0, since?: string): Promise<MessageRow[]> {
    const clauses: string[] = [];
    const params: Array<string | number> = [];
    if (board) {
        clauses.push('board = ?');
        params.push(sanitizeBoard(board));
    }
    if (since) {
        clauses.push('leaf > ?');
        params.push(since);
    }
    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const offsetSql = offset > 0 ? ' LIMIT -1 OFFSET ?' : '';
    if (offset > 0) {
        params.push(offset);
    }
    const rows = getDb()
        .prepare(`SELECT * FROM messages ${whereSql} ORDER BY id ASC${offsetSql}`)
        .all(...params) as Array<Record<string, unknown>>;
    return attachCredToMessages(rows.map(rowToMessage));
}

async function hasMessageId(id: string): Promise<boolean> {
    const row = getDb().prepare('SELECT 1 FROM messages WHERE id = ?').get(id);
    return Boolean(row);
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
        const [rows, diskBoards] = await Promise.all([
            listMessagesFromIpfs(`/${board}`),
            listBoardsFromDisk(),
        ]);
        const envBoards = (process.env.BOARDS || '')
            .split(',')
            .map((b) => b.trim())
            .filter(Boolean)
            .map((b) => sanitizeBoard(b));
        const boards = Array.from(new Set(['default', board, ...diskBoards, ...envBoards])).sort();
        const html = renderForumPage({
            board,
            boards,
            messages: rows,
            replyTo,
            ipfsGatewayUrl: IPFS_GATEWAY_URL,
            powHashesPerSecond: POW_HASHES_PER_SECOND,
        });
        res.setHeader(
            'Content-Security-Policy',
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https: http:; media-src 'self' https: http:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        );
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
        void publishPostToFediverse(
            { id, board: getBoardFromId(id), data, content_cid: contentCid },
            activityPubDeps
        );
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

function getCertDomain(): string {
    const certPath = process.env.SSL_CERT_PATH;
    if (!certPath) return '';
    try {
        const cert = new crypto.X509Certificate(fs.readFileSync(certPath));
        if (cert.subjectAltName) {
            for (const entry of cert.subjectAltName.split(',')) {
                const trimmed = entry.trim();
                if (trimmed.startsWith('DNS:')) {
                    const dns = trimmed.slice(4).trim();
                    if (dns && !dns.startsWith('*')) {
                        return dns;
                    }
                }
            }
        }
        const cnMatch = cert.subject.match(/CN=([^\n,]+)/);
        if (cnMatch && cnMatch[1] && !cnMatch[1].startsWith('*')) {
            return cnMatch[1].trim();
        }
    } catch {
        // Ignore unreadable cert
    }
    return '';
}

const certDomain = getCertDomain();

async function resolvePublicHost(): Promise<void> {
    if (process.env.PUBLIC_URL || certDomain) return;
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
    const host = certDomain || discoveredHost || getLocalInterfaceIp() || 'localhost';
    const defaultPort = (scheme === 'https' && PORT === 443) || (scheme === 'http' && PORT === 80);
    return defaultPort ? `${scheme}://${host}` : `${scheme}://${host}:${PORT}`;
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
  const reqHost = req?.get('host');
  if (reqHost) return reqHost;
  if (certDomain) {
    return PORT === 443 ? certDomain : `${certDomain}:${PORT}`;
  }
  return `127.0.0.1:${PORT}`;
}

const activityPubDeps = {
  getDomain,
  getServerIdentity: getOrCreateServerIdentity,
  getDb,
  onIncomingNote: routeIncomingNote,
};

apiRouter.use(createActivityPubRouter(getDomain));

app.use('/api', apiRouter);
app.use(createActivityPubRootRouter(activityPubDeps));

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
      const baseDir = process.env.STATE_DIR ? path.resolve(process.env.STATE_DIR) : __dirname;
      const keyPath = path.join(baseDir, 'server-key.json');
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

async function routeIncomingNote(note: IncomingActivityPubNote): Promise<void> {
  const boards = new Set<string>();
  for (const tag of note.tags) {
    const cleaned = tag.trim().toLowerCase().replace(/[^a-zA-Z0-9_-]/g, '');
    if (cleaned) {
      boards.add(sanitizeBoard(cleaned));
    }
  }
  if (boards.size === 0) return;

  const data = note.content || note.url || note.id;
  if (!data) return;

  const parsedDate = note.published ? new Date(note.published) : null;
  const timestamp =
    parsedDate && !Number.isNaN(parsedDate.getTime())
      ? parsedDate.toISOString()
      : '1970-01-01T00:00:00.000Z';
  const statusHash = crypto
    .createHash('sha256')
    .update(String(note.uri || note.id))
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
      ...(note.author ? { author: note.author } : {}),
      ...(note.authorUrl ? { author_url: note.authorUrl } : {}),
    };
    const saved = await saveMessage(msg);
    if (saved) {
      console.log(`Ingested Fediverse post into ${board}: ${id}`);
      void pushMessageToPeers(msg, getKnownPeers(getSelfUrl()), getSelfUrl());
    }
  }
}

if (process.env.ACTIVITYPUB_RELAYS_ENABLED === '1' || process.env.ACTIVITYPUB_RELAYS_ENABLED === 'true') {
  followRelays(activityPubDeps).catch((err) => {
    console.error('ActivityPub relay follow error:', err);
  });
}

async function handleFirehoseStatus(status: FediverseStatus, host: string): Promise<void> {
  const tags = (status.tags || [])
    .map((t) => String(t?.name || '').trim())
    .filter(Boolean);
  if (tags.length === 0) return;

  const rawAcct = status.account?.acct || status.account?.username || '';
  const author = rawAcct
    ? `@${rawAcct.includes('@') ? rawAcct : `${rawAcct}@${host}`}`
    : undefined;
  const authorUrl = status.account?.url || status.url;

  await routeIncomingNote({
    id: status.id,
    uri: status.uri || `${host}:${status.id}`,
    url: status.url,
    content: status.content || status.url || status.id,
    published: status.created_at,
    tags,
    author,
    authorUrl,
  });
}

if (process.env.FIREHOSE_ENABLED === '1' || process.env.FIREHOSE_ENABLED === 'true') {
  startFirehose({ onStatus: handleFirehoseStatus }).catch((err) => {
    console.error('Firehose error:', err);
  });
}
