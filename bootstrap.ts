import express from 'express';
import type { Router } from 'express';
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
      libp2p: {
        peerId: { toString: () => string };
        getMultiaddrs: () => Array<{ toString: () => string }>;
      };
    };
  }>;
}

export function getConfiguredPeers(): string[] {
  const raw = [process.env.PEERS || '', process.env.BOOTSTRAP_URL || ''].join(',');
  const seen = new Set<string>();
  for (const entry of raw.split(',')) {
    const cleaned = entry.trim().replace(/\/+$/, '');
    if (cleaned) {
      seen.add(cleaned);
    }
  }
  return Array.from(seen);
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
        void pushMessageToPeers(cleanMessage, getConfiguredPeers(), sourceUrl || selfUrl);
      }
      return res.json({ ok: true, imported: saved });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: (e as Error).message });
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
      res.json({
        peerId: helia.libp2p.peerId.toString(),
        board: board || null,
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
    creds?: Record<string, number>;
    messages?: BootstrapMessageRow[];
  };

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
  peers: string[],
  deps: BootstrapDeps,
  intervalMs: number = 30000
): NodeJS.Timeout | null {
  if (peers.length === 0 || intervalMs <= 0) {
    return null;
  }
  let syncing = false;
  const timer = setInterval(async () => {
    if (syncing) return;
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
