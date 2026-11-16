import crypto from 'node:crypto';
import express from 'express';
import type { Router } from 'express';
import { CID } from 'multiformats/cid';
import * as digest from 'multiformats/hashes/digest';
import { buildMessageSignaturePayload } from './views/forum.ts';
import type { ForumMessage, PowProof } from './views/forum.ts';

export interface BootstrapMessageRow extends ForumMessage {
  id: string;
  depth: number;
  data: string;
  pubkey: string;
  sig: string;
  content_cid: string | null;
  pow?: PowProof | null;
  cred?: number;
  cid?: string;
}

export interface BootstrapDeps {
  sanitizeBoard: (board: unknown) => string;
  listBoardsFromDisk: () => Promise<string[]>;
  getPubkeyHash: (pubkey: string) => string;
  readMessageLog: (board?: string, offset?: number, since?: string) => Promise<BootstrapMessageRow[]>;
  getCredIndex: () => Promise<Record<string, number>>;
  upsertPubkeyCred: (
    pubkey: string,
    rawPow: unknown
  ) => Promise<{ ok: boolean; cred: number; updated: boolean }>;
  uploadToIpfs: (buffer: Buffer) => Promise<string>;
  verifySignature: (data: unknown, pubkey: unknown, sig: unknown) => boolean;
  hasMessageId: (id: string) => Promise<boolean>;
  saveMessage: (message: BootstrapMessageRow) => Promise<boolean>;
  getIpfs: () => Promise<{
    helia: {
      routing: {
        provide: (cid: CID, options?: { signal?: AbortSignal }) => Promise<void>;
        findProviders: (cid: CID, options?: { signal?: AbortSignal }) => AsyncIterable<{ id: unknown }>;
      };
      libp2p: {
        peerId: { toString: () => string };
        getMultiaddrs: () => Array<{ toString: () => string }>;
        handle: (protocol: string, handler: (stream: any, connection: any) => void | Promise<void>) => Promise<void>;
        dialProtocol: (peer: any, protocols: string | string[], options?: { signal?: AbortSignal }) => Promise<any>;
        addEventListener: (type: 'peer:connect', listener: (evt: { detail: any }) => void) => void;
      };
    };
  }>;
}

const PEER_DISCOVERY_PROTOCOL = '/pachytalk/peer/1.0.0';
const discoveredPeers = new Set<string>();
const peerBoards = new Map<string, string[]>();

async function getHostedBoards(deps: BootstrapDeps): Promise<string[]> {
  const fromDisk = await deps.listBoardsFromDisk();
  const fromEnv = (process.env.BOARDS || process.env.BOOTSTRAP_BOARD || '')
    .split(',')
    .map((b) => b.trim())
    .filter(Boolean)
    .map((b) => deps.sanitizeBoard(b));
  return Array.from(new Set([...fromDisk, ...fromEnv])).sort();
}

function recordPeerBoards(peerUrl: string | null, boards: unknown, sanitizeBoard: (b: unknown) => string) {
  if (!peerUrl || !Array.isArray(boards)) return;
  const cleaned = Array.from(
    new Set(
      boards
        .filter((b): b is string => typeof b === 'string' && b.trim().length > 0)
        .map((b) => sanitizeBoard(b))
    )
  ).sort();
  if (cleaned.length > 0) {
    peerBoards.set(peerUrl, cleaned);
  }
}

function normalizePeerUrl(rawUrl: unknown): string | null {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim().replace(/\/+$/, '');
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return parsed.origin + parsed.pathname.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

export function getConfiguredPeers(): string[] {
  const raw = process.env.PEERS || '';
  const seen = new Set<string>();
  for (const entry of raw.split(',')) {
    const normalized = normalizePeerUrl(entry);
    if (normalized) {
      seen.add(normalized);
    }
  }
  return Array.from(seen);
}

export function getKnownPeers(selfUrl?: string): string[] {
  const normalizedSelf = normalizePeerUrl(selfUrl);
  const all = new Set<string>([...getConfiguredPeers(), ...discoveredPeers]);
  if (normalizedSelf) {
    all.delete(normalizedSelf);
  }
  return Array.from(all);
}

function addDiscoveredPeer(rawUrl: unknown, selfUrl?: string): string | null {
  const normalized = normalizePeerUrl(rawUrl);
  const normalizedSelf = normalizePeerUrl(selfUrl);
  if (!normalized || normalized === normalizedSelf) {
    return null;
  }
  if (!discoveredPeers.has(normalized) && !getConfiguredPeers().includes(normalized)) {
    discoveredPeers.add(normalized);
    return normalized;
  }
  return null;
}

async function pinAssetFromPeer(
  baseUrl: string,
  cidStr: string,
  uploadToIpfs: (buffer: Buffer) => Promise<string>
): Promise<void> {
  const assetRes = await fetch(`${baseUrl}/ipfs/${encodeURIComponent(cidStr)}`, {
    signal: AbortSignal.timeout(15000),
  });
  if (!assetRes.ok) return;
  const buf = Buffer.from(await assetRes.arrayBuffer());
  await uploadToIpfs(buf);
}

export async function pushMessageToPeers(
  message: BootstrapMessageRow,
  peers: string[],
  sourceUrl?: string
): Promise<void> {
  const normalizedSource = sourceUrl ? sourceUrl.replace(/\/+$/, '') : undefined;
  const targets = peers.filter((peer) => peer !== normalizedSource);
  if (targets.length === 0) return;

  await Promise.allSettled(
    targets.map(async (peer) => {
      try {
        const res = await fetch(`${peer}/api/receive`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message, sourceUrl: normalizedSource }),
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) {
          console.warn(`Peer push to ${peer} failed (${res.status})`);
        }
      } catch (err) {
        console.warn(`Peer push to ${peer} error:`, (err as Error).message);
      }
    })
  );
}

export function createBootstrapRouter(
  deps: BootstrapDeps,
  options?: { getSelfUrl?: () => string }
): Router {
  const router = express.Router();

  router.post('/receive', async (req, res) => {
    try {
      const body = req.body || {};
      const msg = (body.message || body) as BootstrapMessageRow;
      const sourceUrl = typeof body.sourceUrl === 'string' ? body.sourceUrl.replace(/\/+$/, '') : undefined;

      if (!msg || typeof msg.id !== 'string' || !msg.id) {
        return res.status(400).json({ error: 'Invalid message payload' });
      }
      if (!msg.data && !msg.content_cid) {
        return res.status(400).json({ error: 'Message data or content_cid is required' });
      }

      const signedPayload = buildMessageSignaturePayload(msg.data, msg.content_cid);
      if (!deps.verifySignature(signedPayload, msg.pubkey, msg.sig)) {
        return res.status(400).json({ error: 'Invalid signature' });
      }

      if (await deps.hasMessageId(msg.id)) {
        return res.json({ ok: true, imported: false });
      }

      if (msg.content_cid && sourceUrl) {
        await pinAssetFromPeer(sourceUrl, msg.content_cid, deps.uploadToIpfs);
      }

      const cleanMessage: BootstrapMessageRow = {
        id: msg.id,
        depth: msg.depth,
        data: msg.data,
        pubkey: msg.pubkey,
        sig: msg.sig,
        content_cid: msg.content_cid ?? null,
        ...(msg.media_type ? { media_type: msg.media_type } : {}),
      };
      const saved = await deps.saveMessage(cleanMessage);
      if (saved) {
        const selfUrl = options?.getSelfUrl?.();
        void pushMessageToPeers(cleanMessage, getKnownPeers(selfUrl), sourceUrl || selfUrl);
      }
      return res.json({ ok: true, imported: saved });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: (e as Error).message });
    }
  });

  router.get('/peers', async (_req, res) => {
    try {
      const selfUrl = options?.getSelfUrl?.() || null;
      const boards = await getHostedBoards(deps);
      const peers = getKnownPeers(selfUrl || undefined).map((url) => ({
        url,
        boards: peerBoards.get(url) || [],
      }));
      res.json({ self: selfUrl, boards, peers });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: (e as Error).message });
    }
  });

  router.get('/bootstrap', async (req, res) => {
    try {
      const board = req.query.board ? deps.sanitizeBoard(req.query.board) : undefined;
      const offset = Math.max(0, Number(req.query.offset) || 0);
      const since = req.query.since ? String(req.query.since) : undefined;
      const messages = await deps.readMessageLog(board, offset, since);

      if (req.query.format === 'ndjson') {
        res.type('application/x-ndjson');
        return res.send(messages.map((m) => JSON.stringify(m)).join('\n') + (messages.length ? '\n' : ''));
      }

      const { helia } = await deps.getIpfs();
      const creds = await deps.getCredIndex();
      const hostedBoards = await getHostedBoards(deps);
      res.json({
        peerId: helia.libp2p.peerId.toString(),
        board: board || null,
        boards: hostedBoards,
        peers: getKnownPeers(options?.getSelfUrl?.()),
        creds,
        multiaddrs: helia.libp2p.getMultiaddrs().map((ma) => ma.toString()),
        offset,
        count: messages.length,
        messages,
      });
    } catch (e) {
      console.error(e);
      res.status(500).json({ error: (e as Error).message });
    }
  });

  return router;
}

async function importPeerMessage(
  msg: BootstrapMessageRow,
  existingIds: Set<string>,
  pinAsset: (cidStr: string) => Promise<void>,
  deps: BootstrapDeps
): Promise<boolean> {
  if (!msg || !msg.id || existingIds.has(msg.id)) {
    return false;
  }
  const signedPayload = buildMessageSignaturePayload(msg.data, msg.content_cid);
  if (!deps.verifySignature(signedPayload, msg.pubkey, msg.sig)) {
    return false;
  }
  if (msg.content_cid) {
    await pinAsset(msg.content_cid);
  }
  const saved = await deps.saveMessage({
    id: msg.id,
    depth: msg.depth,
    data: msg.data,
    pubkey: msg.pubkey,
    sig: msg.sig,
    content_cid: msg.content_cid,
    ...(msg.media_type ? { media_type: msg.media_type } : {}),
  });
  existingIds.add(msg.id);
  return saved;
}

export async function bootstrapFromPeer(
  bootstrapUrl: string,
  deps: BootstrapDeps,
  options?: { quiet?: boolean; useSince?: boolean }
): Promise<number> {
  const baseUrl = bootstrapUrl.replace(/\/+$/, '');
  const targetBoard = process.env.BOOTSTRAP_BOARD ? deps.sanitizeBoard(process.env.BOOTSTRAP_BOARD) : undefined;
  const existingMessages = await deps.readMessageLog(targetBoard);
  const existingIds = new Set(existingMessages.map((m) => m.id));

  const params = new URLSearchParams();
  if (targetBoard) {
    params.set('board', targetBoard);
  }
  if (options?.useSince && existingMessages.length > 0) {
    let latestLeaf = '';
    for (const msg of existingMessages) {
      const leaf = msg.id.split('/').pop() || '';
      if (leaf > latestLeaf) {
        latestLeaf = leaf;
      }
    }
    if (latestLeaf) {
      params.set('since', latestLeaf);
    }
  }
  const qs = params.toString();
  const res = await fetch(`${baseUrl}/api/bootstrap${qs ? `?${qs}` : ''}`, {
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) {
    throw new Error(`Bootstrap request failed (${res.status} ${res.statusText})`);
  }
  const info = (await res.json()) as {
    boards?: string[];
    creds?: Record<string, number>;
    messages?: BootstrapMessageRow[];
  };
  recordPeerBoards(baseUrl, info.boards, deps.sanitizeBoard);

  const applyBootstrappedCreds = async () => {
    if (!info.creds || typeof info.creds !== 'object') return;
    const allMessages = await deps.readMessageLog(targetBoard);
    const pubkeyByHash = new Map<string, string>();
    for (const msg of allMessages) {
      if (msg.pubkey) {
        pubkeyByHash.set(deps.getPubkeyHash(msg.pubkey), msg.pubkey);
      }
    }
    for (const [pkHash, nonce] of Object.entries(info.creds)) {
      const pk = pubkeyByHash.get(pkHash);
      if (pk && typeof nonce === 'number') {
        await deps.upsertPubkeyCred(pk, nonce);
      }
    }
  };

  const pinViaHttp = (cidStr: string) => pinAssetFromPeer(baseUrl, cidStr, deps.uploadToIpfs);

  if (Array.isArray(info.messages) && info.messages.length > 0) {
    let imported = 0;
    for (const msg of info.messages) {
      if (await importPeerMessage(msg, existingIds, pinViaHttp, deps)) {
        imported++;
      }
    }
    await applyBootstrappedCreds();
    if (!options?.quiet || imported > 0) {
      console.log(`Synced ${imported} message(s) from ${baseUrl}`);
    }
    return imported;
  }

  await applyBootstrappedCreds();
  if (!options?.quiet) {
    console.log('Bootstrap peer has no new messages.');
  }
  return 0;
}

export function startPeerSync(
  getPeers: () => string[],
  deps: BootstrapDeps,
  intervalMs: number = 30000
): NodeJS.Timeout | null {
  if (intervalMs <= 0) {
    return null;
  }
  let syncing = false;
  const timer = setInterval(async () => {
    const peers = getPeers();
    if (syncing || peers.length === 0) return;
    syncing = true;
    try {
      for (const peer of peers) {
        try {
          await bootstrapFromPeer(peer, deps, { quiet: true, useSince: true });
        } catch (err) {
          console.warn(`Peer sync from ${peer} failed:`, (err as Error).message);
        }
      }
    } finally {
      syncing = false;
    }
  }, intervalMs);
  timer.unref?.();
  return timer;
}

export function getRendezvousCid(key: string = process.env.RENDEZVOUS_KEY || 'pachytalk-v1'): CID {
  const hash = crypto.createHash('sha256').update(key).digest();
  return CID.createV1(0x55, digest.create(0x12, hash));
}

async function readStreamJson(stream: AsyncIterable<Uint8Array>): Promise<Record<string, unknown> | null> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  for await (const chunk of stream) {
    total += chunk.byteLength;
    if (total > 64 * 1024) {
      throw new Error('Peer discovery payload too large');
    }
    chunks.push(chunk);
  }
  if (chunks.length === 0) return null;
  const text = Buffer.concat(chunks).toString('utf8').trim();
  return text ? (JSON.parse(text) as Record<string, unknown>) : null;
}

export async function startPeerDiscovery(
  deps: BootstrapDeps,
  options?: { getSelfUrl?: () => string; intervalMs?: number }
): Promise<() => void> {
  const { helia } = await deps.getIpfs();
  const rendezvousCid = getRendezvousCid();
  const intervalMs = options?.intervalMs ?? 60000;
  const queriedPeers = new Map<string, number>();

  const recordPeerAnnouncement = (payload: Record<string, unknown> | null) => {
    if (!payload) return;
    const selfUrl = options?.getSelfUrl?.();
    const senderUrl = normalizePeerUrl(payload.url);
    if (senderUrl && senderUrl !== normalizePeerUrl(selfUrl)) {
      recordPeerBoards(senderUrl, payload.boards, deps.sanitizeBoard);
    }

    const candidates: unknown[] = [];
    if (typeof payload.url === 'string') candidates.push(payload.url);
    if (Array.isArray(payload.peers)) candidates.push(...payload.peers);

    for (const candidate of candidates) {
      const added = addDiscoveredPeer(candidate, selfUrl);
      if (added) {
        console.log(`Discovered PachyTalk peer via libp2p: ${added}`);
        void bootstrapFromPeer(added, deps, { quiet: false }).catch((err) => {
          console.warn(`Bootstrap sync from discovered peer ${added} failed:`, (err as Error).message);
        });
      }
    }
  };

  const buildAnnouncement = async () => {
    const selfUrl = options?.getSelfUrl?.();
    const boards = await getHostedBoards(deps);
    return Buffer.from(
      JSON.stringify({ url: selfUrl || null, boards, peers: getKnownPeers(selfUrl) })
    );
  };

  await helia.libp2p.handle(PEER_DISCOVERY_PROTOCOL, async (stream) => {
    try {
      stream.send(await buildAnnouncement());
      await stream.close();
      const incoming = await readStreamJson(stream).catch(() => null);
      recordPeerAnnouncement(incoming);
    } catch {
      // Ignore malformed discovery streams
    }
  });

  const queryLibp2pPeer = async (peerIdOrAddr: unknown) => {
    const key = String(peerIdOrAddr);
    if (!key || key === helia.libp2p.peerId.toString()) return;
    const now = Date.now();
    const last = queriedPeers.get(key) || 0;
    if (now - last < 30000) return;
    queriedPeers.set(key, now);

    try {
      const stream = await helia.libp2p.dialProtocol(peerIdOrAddr, PEER_DISCOVERY_PROTOCOL, {
        signal: AbortSignal.timeout(5000),
      });
      stream.send(await buildAnnouncement());
      await stream.close();
      const reply = await readStreamJson(stream).catch(() => null);
      recordPeerAnnouncement(reply);
    } catch {
      // Peer does not speak PEER_DISCOVERY_PROTOCOL or is unreachable
    }
  };

  helia.libp2p.addEventListener('peer:connect', (evt) => {
    void queryLibp2pPeer(evt.detail);
  });

  const runDhtRendezvous = async () => {
    const baseKey = process.env.RENDEZVOUS_KEY || 'pachytalk-v1';
    const hostedBoards = await getHostedBoards(deps);
    const cidsToProvide = [
      rendezvousCid,
      ...hostedBoards.map((b) => getRendezvousCid(`${baseKey}:board:${b}`)),
    ];
    for (const cid of cidsToProvide) {
      try {
        await helia.routing.provide(cid, { signal: AbortSignal.timeout(15000) });
      } catch {
        // DHT provide can fail when isolated or before routing table warms up
      }
    }
    try {
      for await (const provider of helia.routing.findProviders(rendezvousCid, {
        signal: AbortSignal.timeout(15000),
      })) {
        void queryLibp2pPeer(provider.id);
      }
    } catch {
      // Ignore transient DHT lookup errors
    }
  };

  let timer: NodeJS.Timeout | null = null;
  if (intervalMs > 0) {
    void runDhtRendezvous();
    timer = setInterval(() => {
      void runDhtRendezvous();
    }, intervalMs);
    timer.unref?.();
  }

  return () => {
    if (timer) clearInterval(timer);
  };
}
