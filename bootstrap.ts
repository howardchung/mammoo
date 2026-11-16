import express from 'express';
import type { Router } from 'express';
import type { UnixFS } from '@helia/unixfs';
import { CID } from 'multiformats/cid';
import { multiaddr } from '@multiformats/multiaddr';
import type { ForumMessage, PowProof } from './views/forum.ts';

export interface BootstrapMessageRow extends ForumMessage {
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

export interface BootstrapDeps {
  sanitizeBoard: (board: unknown) => string;
  getBoardFromId: (id: string) => string;
  readMessageLog: (board?: string, offset?: number, since?: string) => Promise<BootstrapMessageRow[]>;
  readBoardCids: (board: string, offset?: number) => Promise<string[]>;
  listBoardsFromDisk: () => Promise<string[]>;
  uploadToIpfs: (buffer: Buffer) => Promise<string>;
  verifySignature: (data: unknown, pubkey: unknown, sig: unknown) => boolean;
  appendCidToBoardLog: (board: string, postCid: string) => Promise<boolean>;
  saveMessageToIpfs: (message: BootstrapMessageRow) => Promise<string>;
  postCache: Map<string, BootstrapMessageRow>;
  getIpfs: () => Promise<{
    helia: {
      libp2p: {
        peerId: { toString: () => string };
        getMultiaddrs: () => Array<{ toString: () => string }>;
        dial: (addr: ReturnType<typeof multiaddr>, opts?: { signal?: AbortSignal }) => Promise<unknown>;
      };
    };
    ufs: UnixFS;
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
      const boardCids: Record<string, string[]> = {};
      const cids: string[] = [];
      const boardsToInspect = board ? [board] : await deps.listBoardsFromDisk();
      for (const b of boardsToInspect) {
        const list = await deps.readBoardCids(b, board ? offset : 0);
        boardCids[b] = list;
        cids.push(...list);
      }
      res.json({
        peerId: helia.libp2p.peerId.toString(),
        board: board || null,
        rootCid: null,
        boardLogs: {},
        boardCids,
        cids,
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
  const signedPayload = msg.data || msg.image_cid || '';
  if (!deps.verifySignature(signedPayload, msg.pubkey, msg.sig)) {
    return false;
  }
  if (msg.image_cid) {
    await pinAsset(msg.image_cid);
  }
  await deps.saveMessageToIpfs({
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

async function importPostByCid(
  postCid: string,
  existingCids: Set<string>,
  existingIds: Set<string>,
  fetchBytes: (cidStr: string) => Promise<Buffer | null>,
  deps: BootstrapDeps
): Promise<boolean> {
  if (existingCids.has(postCid)) {
    return false;
  }
  const buf = await fetchBytes(postCid);
  if (!buf) {
    return false;
  }
  const uploadedCid = await deps.uploadToIpfs(buf);
  if (uploadedCid !== postCid) {
    return false;
  }
  const msg = JSON.parse(buf.toString('utf8')) as BootstrapMessageRow;
  if (!msg || !msg.id) {
    return false;
  }
  const signedPayload = msg.data || msg.image_cid || '';
  if (!deps.verifySignature(signedPayload, msg.pubkey, msg.sig)) {
    return false;
  }
  if (msg.image_cid) {
    const imgBuf = await fetchBytes(msg.image_cid);
    if (imgBuf) {
      await deps.uploadToIpfs(imgBuf);
    }
  }
  deps.postCache.set(postCid, { ...msg, cid: postCid });
  const board = deps.getBoardFromId(msg.id);
  const appended = await deps.appendCidToBoardLog(board, postCid);
  existingCids.add(postCid);
  existingIds.add(msg.id);
  return appended;
}

async function syncUnixFsMessages(
  dirCid: CID,
  ufs: UnixFS,
  existingCids: Set<string>,
  existingIds: Set<string>,
  deps: BootstrapDeps
): Promise<number> {
  let imported = 0;
  const fetchViaUfs = async (cidStr: string): Promise<Buffer | null> => {
    try {
      const chunks: Uint8Array[] = [];
      for await (const chunk of ufs.cat(CID.parse(cidStr), { signal: AbortSignal.timeout(15000) })) {
        chunks.push(chunk);
      }
      return Buffer.concat(chunks);
    } catch {
      return null;
    }
  };

  for await (const entry of ufs.ls(dirCid, { signal: AbortSignal.timeout(15000) })) {
    if (entry.name === 'cids.log') {
      const chunks: Uint8Array[] = [];
      for await (const chunk of ufs.cat(entry.cid, { signal: AbortSignal.timeout(15000) })) {
        chunks.push(chunk);
      }
      const cids = Buffer.concat(chunks)
        .toString('utf8')
        .split('\n')
        .map((line) => line.trim())
        .filter(Boolean);
      for (const postCid of cids) {
        if (await importPostByCid(postCid, existingCids, existingIds, fetchViaUfs, deps)) {
          imported++;
        }
      }
    } else if (entry.name !== 'message.json') {
      try {
        imported += await syncUnixFsMessages(entry.cid, ufs, existingCids, existingIds, deps);
      } catch {
        // Ignore non-directory entries
      }
    }
  }
  return imported;
}

export async function bootstrapFromPeer(bootstrapUrl: string, deps: BootstrapDeps): Promise<void> {
  const baseUrl = bootstrapUrl.replace(/\/+$/, '');
  const targetBoard = process.env.BOOTSTRAP_BOARD ? deps.sanitizeBoard(process.env.BOOTSTRAP_BOARD) : undefined;
  const existingMessages = await deps.readMessageLog(targetBoard);
  const existingIds = new Set(existingMessages.map((m) => m.id));
  const boards = targetBoard ? [targetBoard] : await deps.listBoardsFromDisk();
  const existingCids = new Set<string>();
  for (const b of boards) {
    for (const cid of await deps.readBoardCids(b)) {
      existingCids.add(cid);
    }
  }

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
    peerId?: string;
    rootCid?: string | null;
    multiaddrs?: string[];
    cids?: string[];
    boardCids?: Record<string, string[]>;
    messages?: BootstrapMessageRow[];
  };

  const fetchViaHttp = async (cidStr: string): Promise<Buffer | null> => {
    const assetRes = await fetch(`${baseUrl}/ipfs/${encodeURIComponent(cidStr)}`);
    if (!assetRes.ok) return null;
    return Buffer.from(await assetRes.arrayBuffer());
  };

  const remoteCids: string[] = [];
  if (info.boardCids && typeof info.boardCids === 'object') {
    for (const list of Object.values(info.boardCids)) {
      if (Array.isArray(list)) {
        remoteCids.push(...list);
      }
    }
  } else if (Array.isArray(info.cids)) {
    remoteCids.push(...info.cids);
  }

  if (remoteCids.length > 0) {
    let imported = 0;
    for (const postCid of remoteCids) {
      if (await importPostByCid(postCid, existingCids, existingIds, fetchViaHttp, deps)) {
        imported++;
      }
    }
    console.log(`Merged ${imported} new message(s) from CID log at ${baseUrl}`);
    return;
  }

  const pinViaHttp = async (cidStr: string) => {
    const buf = await fetchViaHttp(cidStr);
    if (buf) {
      await deps.uploadToIpfs(buf);
    }
  };

  if (Array.isArray(info.messages) && info.messages.length > 0) {
    let imported = 0;
    for (const msg of info.messages) {
      if (await importPeerMessage(msg, existingIds, pinViaHttp, deps)) {
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

  const { helia, ufs } = await deps.getIpfs();
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

  const imported = await syncUnixFsMessages(CID.parse(info.rootCid), ufs, existingCids, existingIds, deps);
  console.log(`Bootstrapped ${imported} message(s) via IPFS from ${baseUrl}`);
}
