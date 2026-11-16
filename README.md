Quickstart
====
* `npm install`
* `npm start`
* Open `http://localhost:3141` (or `https://localhost:3141` if `SSL_KEY_PATH` / `SSL_CERT_PATH` are set in `.env`)

Typecheck & Dev
====
* `npm run dev` — run with `node --watch index.ts`
* `npm run typecheck` — run `tsc --noEmit`

Bootstrapping Another Instance (IPFS / Helia)
====
Each server embeds a Helia IPFS node storing messages under `/messages` in MFS and exposes `GET /api/bootstrap` returning `{ peerId, rootCid, multiaddrs }`.

To bootstrap a new instance from an existing seed server:
```bash
PORT=3141 IPFS_DATA_DIR=./ipfs-data BOOTSTRAP_URL=https://seed-host:3141 npm start
```
On startup, the new instance fetches `/api/bootstrap` from `BOOTSTRAP_URL`, dials the seed peer over libp2p, and pulls the `/messages` UnixFS DAG (including any referenced `image_cid`s), verifying each message's client signature before saving it locally.

*(For self-signed or mismatched TLS certs in local testing, pass `NODE_TLS_REJECT_UNAUTHORIZED=0`.)*

TODO
====
* Allow each server to specify the names of boards it is interested in
* add voting feature
* have users do JS hashes in the background (opt-in) to generate a currency/voting/posting power?
* Integrate with Mastodon/ActivityPub
