Quickstart
====
* `npm install`
* `npm start`
* Open `http://localhost:3141` (or `https://localhost:3141` if `SSL_KEY_PATH` / `SSL_CERT_PATH` are set in `.env`)

Typecheck & Dev
====
* `npm run dev` — run with `node --watch index.ts`
* `npm run typecheck` — run `tsc --noEmit`

Bootstrapping Another Instance
====
Each server stores post JSON in per-board JSONL log files (`${IPFS_DATA_DIR}/logs/<board>.log`), stores uploaded binary/media attachments (`content_cid`) in an embedded Helia IPFS node, and exposes `GET /api/bootstrap` returning `{ peerId, board, creds, multiaddrs, offset, count, messages }` (or NDJSON with `?format=ndjson`, with optional `?board=`, `?offset=`, and `?since=` filters).

To bootstrap a new instance from an existing seed server:
```bash
PORT=3141 IPFS_DATA_DIR=./ipfs-data BOOTSTRAP_URL=https://seed-host:3141 npm start
```
*(Optionally set `BOOTSTRAP_BOARD=<board>` to sync only a single board.)*

On startup, the new instance:
1. Fetches `/api/bootstrap` from `BOOTSTRAP_URL`.
2. For each unseen message, verifies the client signature over `{ data, content_cid }`.
3. If `content_cid` is present, downloads the attachment from `${BOOTSTRAP_URL}/ipfs/<content_cid>` and stores it in its local Helia IPFS node.
4. Appends the verified message to its local per-board `.log` file and imports any proof-of-work `creds` nonces for known public keys.

*(For self-signed or mismatched TLS certs in local testing, pass `NODE_TLS_REJECT_UNAUTHORIZED=0`.)*

TODO
====
* Allow each server to specify the names of boards it is interested in
* Implement some mechanism for keeping peers in sync (forward messages at send time, with periodic reconciles?)
* add voting feature
* Integrate with Mastodon/ActivityPub
