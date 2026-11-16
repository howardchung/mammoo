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

export function createBootstrapRouter(deps: BootstrapDeps): Router {
  const router = express.Router();

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

export async function bootstrapFromPeer(bootstrapUrl: string, deps: BootstrapDeps): Promise<void> {
  const baseUrl = bootstrapUrl.replace(/\/+$/, '');
  const targetBoard = process.env.BOOTSTRAP_BOARD ? deps.sanitizeBoard(process.env.BOOTSTRAP_BOARD) : undefined;
  const existingMessages = await deps.readMessageLog(targetBoard);
  const existingIds = new Set(existingMessages.map((m) => m.id));

  const params = new URLSearchParams();
  if (targetBoard) {
    params.set('board', targetBoard);
  }
  const qs = params.toString();
  const res = await fetch(`${baseUrl}/api/bootstrap${qs ? `?${qs}` : ''}`);
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

  const pinViaHttp = async (cidStr: string) => {
    const assetRes = await fetch(`${baseUrl}/ipfs/${encodeURIComponent(cidStr)}`);
    if (!assetRes.ok) return;
    const buf = Buffer.from(await assetRes.arrayBuffer());
    await deps.uploadToIpfs(buf);
  };

  if (Array.isArray(info.messages) && info.messages.length > 0) {
    let imported = 0;
    for (const msg of info.messages) {
      if (await importPeerMessage(msg, existingIds, pinViaHttp, deps)) {
        imported++;
      }
    }
    await applyBootstrappedCreds();
    console.log(`Bootstrapped ${imported} message(s) from ${baseUrl}`);
    return;
  }

  await applyBootstrappedCreds();
  console.log('Bootstrap peer has no new messages.');
}
