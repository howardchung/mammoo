import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import dgram from 'node:dgram';
import https from 'node:https';
import { on } from 'node:events';
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
import * as Block from 'multiformats/block';
import * as jsonCodec from 'multiformats/codecs/json';
import { sha256 } from 'multiformats/hashes/sha2';
import { multiaddr } from '@multiformats/multiaddr';
import { renderForumPage } from './views/forum.ts';
import type { ForumMessage, PowProof } from './views/forum.ts';
import startFirehose from './firehose.ts';
import { createActivityPubRouter } from './activitypub.ts';

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

interface LogClock {
    id: string;
    time: number;
}

interface LogEntry {
    id: string;
    payload: MessageRow;
    next: string[];
    clock: LogClock;
}

interface DagNode {
    cid: string;
    entry: LogEntry;
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

async function listMessagesFromIpfs(prefix?: string): Promise<MessageRow[]> {
    const normalized = String(prefix || '')
        .split('/')
        .map((s) => s.trim())
        .filter((s) => s && s !== '.' && s !== '..');
    if (normalized.length === 0) {
        const all = await readMessageLog();
        return attachCredToMessages(all);
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
    return `/messages/${sanitizeBoard(board)}/messages.log`;
}

function getBoardHeadsPath(board: string): string {
    return `/messages/${sanitizeBoard(board)}/heads.json`;
}

const boardLocks = new Map<string, Promise<void>>();

async function withBoardLock<T>(board: string, fn: () => Promise<T>): Promise<T> {
    const key = sanitizeBoard(board);
    const prev = boardLocks.get(key) || Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
        release = resolve;
    });
    boardLocks.set(key, next);
    await prev;
    try {
        return await fn();
    } finally {
        release();
        if (boardLocks.get(key) === next) {
            boardLocks.delete(key);
        }
    }
}

async function readMfsLogText(mfsFs: MFS, filePath: string): Promise<string> {
    try {
        await mfsFs.stat(filePath);
    } catch {
        return '';
    }
    const chunks: Uint8Array[] = [];
    for await (const chunk of mfsFs.cat(filePath)) {
        chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString('utf8');
}

async function writeMfsText(mfsFs: MFS, filePath: string, text: string): Promise<string> {
    try {
        await mfsFs.rm(filePath);
    } catch {
        // File may not exist yet
    }
    await mfsFs.writeBytes(new TextEncoder().encode(text), filePath);
    const stat = await mfsFs.stat(filePath);
    return stat.cid.toString();
}

async function readBoardHeads(mfsFs: MFS, board: string): Promise<string[]> {
    const raw = await readMfsLogText(mfsFs, getBoardHeadsPath(board));
    if (!raw) {
        return [];
    }
    try {
        const parsed = JSON.parse(raw) as { heads?: string[] };
        return Array.isArray(parsed.heads) ? [...parsed.heads].sort() : [];
    } catch {
        return [];
    }
}

async function putLogBlock(helia: HeliaNode, entry: LogEntry): Promise<string> {
    const block = await Block.encode({ value: entry, codec: jsonCodec, hasher: sha256 });
    await helia.blockstore.put(block.cid, block.bytes);
    return block.cid.toString();
}

async function getLogBlock(helia: HeliaNode, cidStr: string): Promise<LogEntry> {
    const cid = CID.parse(cidStr);
    const raw = await helia.blockstore.get(cid);
    const bytes = raw instanceof Uint8Array ? raw : await (async () => {
        const chunks: Uint8Array[] = [];
        for await (const chunk of raw as AsyncIterable<Uint8Array>) {
            chunks.push(chunk);
        }
        return Buffer.concat(chunks);
    })();
    const block = await Block.decode<LogEntry, typeof jsonCodec.code, typeof sha256.code>({
        bytes,
        codec: jsonCodec,
        hasher: sha256,
    });
    if (block.cid.toString() !== cid.toString()) {
        throw new Error(`CID mismatch for log entry ${cidStr}`);
    }
    return block.value;
}

function compareDagNodes(a: DagNode, b: DagNode): number {
    if (a.entry.clock.time !== b.entry.clock.time) {
        return a.entry.clock.time - b.entry.clock.time;
    }
    const idCmp = a.entry.clock.id.localeCompare(b.entry.clock.id);
    if (idCmp !== 0) {
        return idCmp;
    }
    return a.cid.localeCompare(b.cid);
}

function computeHeads(nodes: Map<string, LogEntry>): string[] {
    const referenced = new Set<string>();
    for (const entry of nodes.values()) {
        for (const prev of entry.next) {
            referenced.add(prev);
        }
    }
    return Array.from(nodes.keys())
        .filter((cid) => !referenced.has(cid))
        .sort();
}

async function traverseBoardDag(
    helia: HeliaNode,
    heads: string[],
    stopAtCids?: Set<string>
): Promise<Map<string, LogEntry>> {
    const nodes = new Map<string, LogEntry>();
    const queue = [...heads];
    while (queue.length > 0) {
        const cidStr = queue.shift()!;
        if (nodes.has(cidStr) || stopAtCids?.has(cidStr)) {
            continue;
        }
        try {
            const entry = await getLogBlock(helia, cidStr);
            nodes.set(cidStr, entry);
            for (const prev of entry.next || []) {
                if (!nodes.has(prev) && !stopAtCids?.has(prev)) {
                    queue.push(prev);
                }
            }
        } catch {
            // Stop at missing ancestor
        }
    }
    return nodes;
}

async function writeBoardState(
    mfsFs: MFS,
    board: string,
    nodes: Map<string, LogEntry>
): Promise<{ heads: string[]; logCid: string }> {
    const cleanBoard = sanitizeBoard(board);
    await ensureMfsDir(mfsFs, `/messages/${cleanBoard}`);
    const heads = computeHeads(nodes);
    const sortedNodes: DagNode[] = Array.from(nodes.entries())
        .map(([cid, entry]) => ({ cid, entry }))
        .sort(compareDagNodes);
    const seenMsgIds = new Set<string>();
    const logLines: string[] = [];
    for (const node of sortedNodes) {
        if (!seenMsgIds.has(node.entry.payload.id)) {
            seenMsgIds.add(node.entry.payload.id);
            logLines.push(JSON.stringify(node.entry.payload));
        }
    }
    await writeMfsText(mfsFs, getBoardHeadsPath(cleanBoard), JSON.stringify({ heads }));
    const logText = logLines.length > 0 ? logLines.join('\n') + '\n' : '';
    const logCid = await writeMfsText(mfsFs, getBoardLogPath(cleanBoard), logText);
    return { heads, logCid };
}

async function appendMessageLog(message: MessageRow): Promise<string> {
    const board = getBoardFromId(message.id);
    return withBoardLock(board, async () => {
        const { helia, mfsFs } = await getIpfs();
        const heads = await readBoardHeads(mfsFs, board);
        const nodes = await traverseBoardDag(helia, heads);
        let maxTime = 0;
        for (const entry of nodes.values()) {
            if (entry.clock.time > maxTime) {
                maxTime = entry.clock.time;
            }
        }
        const entry: LogEntry = {
            id: `/messages/${board}`,
            payload: message,
            next: [...heads].sort(),
            clock: {
                id: helia.libp2p.peerId.toString(),
                time: heads.length === 0 ? 1 : maxTime + 1,
            },
        };
        const newCid = await putLogBlock(helia, entry);
        nodes.set(newCid, entry);
        const { logCid } = await writeBoardState(mfsFs, board, nodes);
        return logCid;
    });
}

const credLocks = new Map<string, Promise<void>>();

async function withCredLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = credLocks.get(key) || Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
        release = resolve;
    });
    credLocks.set(key, next);
    await prev;
    try {
        return await fn();
    } finally {
        release();
        if (credLocks.get(key) === next) {
            credLocks.delete(key);
        }
    }
}

function getPubkeyHash(pubkey: string): string {
    return crypto.createHash('sha256').update(pubkey).digest('hex');
}

function getCredFilePath(pubkey: string): string {
    return `/cred/${getPubkeyHash(pubkey)}.json`;
}

interface CredRecord {
    pubkey: string;
    proofs: PowProof[];
}

async function readPubkeyCredProofs(mfsFs: MFS, pubkey: string): Promise<PowProof[]> {
    const raw = await readMfsLogText(mfsFs, getCredFilePath(pubkey));
    if (!raw) {
        return [];
    }
    try {
        const parsed = JSON.parse(raw) as CredRecord | PowProof[];
        if (Array.isArray(parsed)) {
            return parsed;
        }
        return Array.isArray(parsed?.proofs) ? parsed.proofs : [];
    } catch {
        return [];
    }
}

async function savePubkeyCred(
    pubkey: string,
    incomingProofs: unknown
): Promise<{ powCid: string | null; cred: number; validCount: number }> {
    if (!pubkey) {
        return { powCid: null, cred: 0, validCount: 0 };
    }
    const keyHash = getPubkeyHash(pubkey);
    return withCredLock(keyHash, async () => {
        const { mfsFs } = await getIpfs();
        const existing = await readPubkeyCredProofs(mfsFs, pubkey);
        const incoming = Array.isArray(incomingProofs) ? incomingProofs : [];
        const { totalCred, validProofs } = verifyPowProofs(pubkey, [...existing, ...incoming]);
        if (validProofs.length === 0) {
            return { powCid: null, cred: 0, validCount: 0 };
        }
        await ensureMfsDir(mfsFs, '/cred');
        const record: CredRecord = { pubkey, proofs: validProofs };
        const powCid = await writeMfsText(mfsFs, getCredFilePath(pubkey), JSON.stringify(record));
        return { powCid, cred: totalCred, validCount: validProofs.length };
    });
}

async function computeCredForPubkey(pubkey: string): Promise<number> {
    if (!pubkey) {
        return 0;
    }
    const { mfsFs } = await getIpfs();
    const proofs = await readPubkeyCredProofs(mfsFs, pubkey);
    if (proofs.length === 0) {
        return 0;
    }
    return verifyPowProofs(pubkey, proofs).totalCred;
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
            credByPubkey.set(pk, await computeCredForPubkey(pk));
        })
    );
    return messages.map((msg) => ({
        ...msg,
        cred: credByPubkey.get(msg.pubkey) ?? 0,
    }));
}

async function readAllCredRecords(): Promise<CredRecord[]> {
    const { mfsFs } = await getIpfs();
    try {
        await mfsFs.stat('/cred');
    } catch {
        return [];
    }
    const records: CredRecord[] = [];
    for await (const entry of mfsFs.ls('/cred')) {
        if (!entry.name.endsWith('.json')) continue;
        const raw = await readMfsLogText(mfsFs, `/cred/${entry.name}`);
        if (!raw) continue;
        try {
            const parsed = JSON.parse(raw) as CredRecord;
            if (parsed?.pubkey && Array.isArray(parsed.proofs)) {
                records.push(parsed);
            }
        } catch {
            // Skip malformed record
        }
    }
    return records;
}

async function mergeBoardDagNodes(
    board: string,
    remoteNodes: DagNode[],
    pinAsset?: (cidStr: string) => Promise<void>
): Promise<number> {
    const cleanBoard = sanitizeBoard(board);
    return withBoardLock(cleanBoard, async () => {
        const { helia, mfsFs } = await getIpfs();
        const localHeads = await readBoardHeads(mfsFs, cleanBoard);
        const nodes = await traverseBoardDag(helia, localHeads);
        const existingMsgIds = new Set(Array.from(nodes.values()).map((e) => e.payload.id));
        let imported = 0;

        for (const { cid, entry } of remoteNodes) {
            if (!entry || !entry.payload || !entry.payload.id) {
                continue;
            }
            const block = await Block.encode({ value: entry, codec: jsonCodec, hasher: sha256 });
            const encodedCid = block.cid.toString();
            if (cid && encodedCid !== cid) {
                continue;
            }
            if (nodes.has(encodedCid)) {
                continue;
            }
            const msg = entry.payload;
            const signedPayload = msg.data || msg.image_cid || '';
            if (!verifySignature(signedPayload, msg.pubkey, msg.sig)) {
                continue;
            }
            if (msg.image_cid && pinAsset) {
                await pinAsset(msg.image_cid);
            }
            if (Array.isArray(msg.pow) && msg.pow.length > 0) {
                await savePubkeyCred(msg.pubkey, msg.pow);
            }
            const cleanPayload: MessageRow = {
                id: msg.id,
                depth: msg.depth,
                data: msg.data,
                pubkey: msg.pubkey,
                sig: msg.sig,
                image_cid: msg.image_cid,
            };
            const verifiedEntry: LogEntry = {
                ...entry,
                payload: cleanPayload,
            };
            if (JSON.stringify(cleanPayload) === JSON.stringify(msg)) {
                await helia.blockstore.put(block.cid, block.bytes);
                nodes.set(encodedCid, entry);
            } else {
                const reCid = await putLogBlock(helia, verifiedEntry);
                nodes.set(reCid, verifiedEntry);
            }
            if (!existingMsgIds.has(msg.id)) {
                existingMsgIds.add(msg.id);
                imported++;
            }
        }

        if (remoteNodes.length > 0) {
            await writeBoardState(mfsFs, cleanBoard, nodes);
        }
        return imported;
    });
}

function parseLogLines(raw: string, offset: number = 0, since?: string): MessageRow[] {
    if (!raw) {
        return [];
    }
    const lines = raw
        .split('\n')
        .filter((line) => line.trim().length > 0);
    const sliced = offset > 0 ? lines.slice(offset) : lines;
    const entries = sliced.map((line) => JSON.parse(line) as MessageRow);
    if (!since) {
        return entries;
    }
    return entries.filter((msg) => {
        const leaf = msg.id.split('/').pop() || '';
        return leaf > since;
    });
}

async function listBoardsFromMfs(mfsFs: MFS): Promise<string[]> {
    try {
        await mfsFs.stat('/messages');
    } catch {
        return [];
    }
    const boards: string[] = [];
    for await (const entry of mfsFs.ls('/messages')) {
        boards.push(entry.name);
    }
    return boards;
}

async function readMessageLog(board?: string, offset: number = 0, since?: string): Promise<MessageRow[]> {
    const { mfsFs } = await getIpfs();
    if (board) {
        const raw = await readMfsLogText(mfsFs, getBoardLogPath(board));
        return parseLogLines(raw, offset, since);
    }
    const boards = await listBoardsFromMfs(mfsFs);
    const allEntries: MessageRow[] = [];
    for (const b of boards) {
        const raw = await readMfsLogText(mfsFs, getBoardLogPath(b));
        allEntries.push(...parseLogLines(raw, 0, since));
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

async function resolveValidatedSendPath(rawPath: unknown): Promise<string> {
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
    if (segments.length === 1) {
        return `/${board}`;
    }
    const normalized = `/${segments.join('/')}`;
    const boardMessages = await readMessageLog(board);
    if (!boardMessages.some((m) => m.id === normalized)) {
        throw new Error('Parent message not found');
    }
    return normalized;
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
            basePath = await resolveValidatedSendPath(json.path);
        } catch (pathErr) {
            return res.status(400).json({ error: (pathErr as Error).message });
        }
        const id = createMessageId(basePath);
        const depth = id.split('/').length - 1;
        const pubkey = String(json.pubkey);
        if (Array.isArray(json.pow) && json.pow.length > 0) {
            await savePubkeyCred(pubkey, json.pow);
        }
        const cid = await saveMessageToIpfs({
            id,
            depth,
            data,
            pubkey,
            sig: String(json.sig),
            image_cid: imageCid,
        });
        const cred = await computeCredForPubkey(pubkey);
        return res.json({ ok: true, id, cid, image_cid: imageCid, cred });
    }
    catch(e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
    // TODO forward these messages to our peers
});

apiRouter.get('/bootstrap', async (req, res) => {
    try {
        const board = req.query.board ? sanitizeBoard(req.query.board) : undefined;
        const offset = Math.max(0, Number(req.query.offset) || 0);
        const since = req.query.since ? String(req.query.since) : undefined;
        const haveHeadsRaw = req.query.haveHeads ? String(req.query.haveHeads) : '';
        const stopAtCids = new Set(
            haveHeadsRaw
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean)
        );
        const messages = await readMessageLog(board, offset, since);

        if (req.query.format === 'ndjson') {
            res.type('application/x-ndjson');
            return res.send(messages.map((m) => JSON.stringify(m)).join('\n') + (messages.length ? '\n' : ''));
        }

        const { helia, mfsFs } = await getIpfs();
        let rootCid: string | null = null;
        const boardLogs: Record<string, string> = {};
        const boardHeads: Record<string, string[]> = {};
        const entries: DagNode[] = [];
        try {
            const stat = await mfsFs.stat('/messages');
            rootCid = stat.cid.toString();
        } catch {
            // No messages yet
        }
        const boardsToInspect = board ? [board] : await listBoardsFromMfs(mfsFs);
        for (const b of boardsToInspect) {
            try {
                const logStat = await mfsFs.stat(getBoardLogPath(b));
                boardLogs[b] = logStat.cid.toString();
            } catch {
                // No log for this board yet
            }
            const heads = await readBoardHeads(mfsFs, b);
            boardHeads[b] = heads;
            if (heads.length > 0) {
                const nodes = await traverseBoardDag(helia, heads, stopAtCids);
                for (const [cid, entry] of nodes.entries()) {
                    entries.push({ cid, entry });
                }
            }
        }
        entries.sort(compareDagNodes);
        const credRecords = await readAllCredRecords();
        res.json({
            peerId: helia.libp2p.peerId.toString(),
            board: board || null,
            rootCid,
            boardLogs,
            boardHeads,
            multiaddrs: helia.libp2p.getMultiaddrs().map((ma) => ma.toString()),
            offset,
            count: messages.length,
            messages,
            entries,
            credRecords,
        });
    } catch (e) {
        console.error(e);
        res.status(500).json({ error: (e as Error).message });
    }
});

apiRouter.get('/log/entry/:cid', async (req, res) => {
    try {
        const { helia } = await getIpfs();
        const cid = String(req.params.cid);
        const entry = await getLogBlock(helia, cid);
        res.json({ cid, entry });
    } catch (e) {
        res.status(404).json({ error: (e as Error).message });
    }
});

apiRouter.post('/pow/upload', async (req, res) => {
    try {
        const body = req.body || {};
        const pubkey = String(body.pubkey || '');
        if (!pubkey || !Array.isArray(body.proofs)) {
            return res.status(400).json({ error: 'pubkey and proofs array are required' });
        }
        const { powCid, cred, validCount } = await savePubkeyCred(pubkey, body.proofs);
        return res.json({
            ok: true,
            pow_cid: powCid,
            cred,
            validCount,
        });
    } catch (e) {
        console.error(e);
        return res.status(500).json({ error: (e as Error).message });
    }
});

apiRouter.post('/pow/verify', (req, res) => {
    const body = req.body || {};
    const pubkey = String(body.pubkey || '');
    if (!pubkey || !Array.isArray(body.proofs)) {
        return res.status(400).json({ error: 'pubkey and proofs array are required' });
    }
    const { totalCred, validProofs } = verifyPowProofs(pubkey, body.proofs);
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

async function importPeerMessage(
  msg: MessageRow,
  existingIds: Set<string>,
  pinAsset: (cidStr: string) => Promise<void>
): Promise<boolean> {
  if (!msg || !msg.id || existingIds.has(msg.id)) {
    return false;
  }
  const signedPayload = msg.data || msg.image_cid || '';
  if (!verifySignature(signedPayload, msg.pubkey, msg.sig)) {
    return false;
  }
  if (msg.image_cid) {
    await pinAsset(msg.image_cid);
  }
  if (Array.isArray(msg.pow) && msg.pow.length > 0) {
    await savePubkeyCred(msg.pubkey, msg.pow);
  }
  await saveMessageToIpfs({
    id: msg.id,
    depth: msg.depth,
    data: msg.data,
    pubkey: msg.pubkey,
    sig: msg.sig,
    image_cid: msg.image_cid,
  });
  existingIds.add(msg.id);
  return true;
}

async function syncUnixFsMessages(dirCid: CID, ufs: UnixFS, existingIds: Set<string>): Promise<number> {
  let imported = 0;
  const { helia, mfsFs } = await getIpfs();
  const pinViaUfs = async (cidStr: string) => {
    const imgChunks: Uint8Array[] = [];
    for await (const chunk of ufs.cat(CID.parse(cidStr), { signal: AbortSignal.timeout(15000) })) {
      imgChunks.push(chunk);
    }
    await ufs.addBytes(Buffer.concat(imgChunks));
  };

  for await (const entry of ufs.ls(dirCid, { signal: AbortSignal.timeout(15000) })) {
    if (entry.name === 'heads.json') {
      const chunks: Uint8Array[] = [];
      for await (const chunk of ufs.cat(entry.cid, { signal: AbortSignal.timeout(15000) })) {
        chunks.push(chunk);
      }
      const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { heads?: string[] };
      const remoteHeads = Array.isArray(parsed.heads) ? parsed.heads : [];
      if (remoteHeads.length > 0) {
        const nodes = await traverseBoardDag(helia, remoteHeads);
        const byBoard = new Map<string, DagNode[]>();
        for (const [cid, logEntry] of nodes.entries()) {
          const b = getBoardFromId(logEntry.payload.id);
          const list = byBoard.get(b) || [];
          list.push({ cid, entry: logEntry });
          byBoard.set(b, list);
        }
        for (const [b, list] of byBoard.entries()) {
          const localHeads = await readBoardHeads(mfsFs, b);
          const merged = await mergeBoardDagNodes(b, list, pinViaUfs);
          imported += merged;
          void localHeads;
        }
      }
    } else if (entry.name === 'messages.log') {
      const chunks: Uint8Array[] = [];
      for await (const chunk of ufs.cat(entry.cid, { signal: AbortSignal.timeout(15000) })) {
        chunks.push(chunk);
      }
      const entries = parseLogLines(Buffer.concat(chunks).toString('utf8'));
      for (const msg of entries) {
        if (await importPeerMessage(msg, existingIds, pinViaUfs)) {
          imported++;
        }
      }
    } else if (entry.name !== 'message.json') {
      try {
        imported += await syncUnixFsMessages(entry.cid, ufs, existingIds);
      } catch {
        // Ignore non-directory entries
      }
    }
  }
  return imported;
}

async function bootstrapFromPeer(bootstrapUrl: string): Promise<void> {
  const baseUrl = bootstrapUrl.replace(/\/+$/, '');
  const targetBoard = process.env.BOOTSTRAP_BOARD ? sanitizeBoard(process.env.BOOTSTRAP_BOARD) : undefined;
  const { mfsFs } = await getIpfs();
  const existingMessages = await readMessageLog(targetBoard);
  const existingIds = new Set(existingMessages.map((m) => m.id));
  const localCount = existingMessages.length;

  const boardsForHeads = targetBoard ? [targetBoard] : await listBoardsFromMfs(mfsFs);
  const localHeads: string[] = [];
  for (const b of boardsForHeads) {
    localHeads.push(...(await readBoardHeads(mfsFs, b)));
  }

  const params = new URLSearchParams({ offset: String(localCount) });
  if (targetBoard) {
    params.set('board', targetBoard);
  }
  if (localHeads.length > 0) {
    params.set('haveHeads', localHeads.join(','));
  }
  const res = await fetch(`${baseUrl}/api/bootstrap?${params.toString()}`);
  if (!res.ok) {
    throw new Error(`Bootstrap request failed (${res.status} ${res.statusText})`);
  }
  const info = (await res.json()) as {
    peerId?: string;
    rootCid?: string | null;
    multiaddrs?: string[];
    messages?: MessageRow[];
    entries?: DagNode[];
    credRecords?: CredRecord[];
  };

  if (Array.isArray(info.credRecords)) {
    for (const rec of info.credRecords) {
      if (rec?.pubkey && Array.isArray(rec.proofs)) {
        await savePubkeyCred(rec.pubkey, rec.proofs);
      }
    }
  }

  const pinViaHttp = async (cidStr: string) => {
    const imgRes = await fetch(`${baseUrl}/ipfs/${encodeURIComponent(cidStr)}`);
    if (imgRes.ok) {
      const buf = Buffer.from(await imgRes.arrayBuffer());
      await uploadToIpfs(buf);
    }
  };

  if (Array.isArray(info.entries) && info.entries.length > 0) {
    const byBoard = new Map<string, DagNode[]>();
    for (const node of info.entries) {
      if (!node?.entry?.payload?.id) continue;
      const b = getBoardFromId(node.entry.payload.id);
      const list = byBoard.get(b) || [];
      list.push(node);
      byBoard.set(b, list);
    }
    let imported = 0;
    for (const [b, list] of byBoard.entries()) {
      imported += await mergeBoardDagNodes(b, list, pinViaHttp);
    }
    console.log(`Bootstrapped ${imported} message(s) via Merkle-CRDT DAG from ${baseUrl}`);
    return;
  }

  if (Array.isArray(info.messages) && info.messages.length > 0) {
    let imported = 0;
    for (const msg of info.messages) {
      if (await importPeerMessage(msg, existingIds, pinViaHttp)) {
        imported++;
      }
    }
    console.log(`Bootstrapped ${imported} message(s) from append-only log at ${baseUrl}`);
    return;
  }

  if (!info.rootCid) {
    console.log('Bootstrap peer has no new messages.');
    return;
  }

  const { helia, ufs } = await getIpfs();
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

  const imported = await syncUnixFsMessages(CID.parse(info.rootCid), ufs, existingIds);
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
