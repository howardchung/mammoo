Quickstart
====
* `npm install`
* `npm start`
* Open `http://localhost:3141` (or `https://localhost:3141` if `SSL_KEY_PATH` / `SSL_CERT_PATH` are set in `.env`)

Typecheck & Dev
====
* `npm run dev` — run with `node --watch index.ts`
* `npm run typecheck` — run `tsc --noEmit`

Bootstrapping & Automatic Peer Discovery
====
Each server stores post JSON in per-board JSONL log files (`${IPFS_DATA_DIR}/logs/<board>.log`), stores uploaded binary/media attachments (`content_cid`) in an embedded Helia IPFS node, and exposes `GET /api/bootstrap` returning `{ peerId, board, peers, creds, multiaddrs, offset, count, messages }` (or NDJSON with `?format=ndjson`, with optional `?board=`, `?offset=`, and `?since=` filters).

Peers discover each other automatically via libp2p / IPFS DHT rendezvous:
```bash
PORT=3141 IPFS_DATA_DIR=./ipfs-data PUBLIC_URL=https://your-host:3141 npm start
```
*(Optionally set `BOOTSTRAP_BOARD=<board>` to sync only a single board, `PEERS=https://peer1:3141,...` for static peers, or `RENDEZVOUS_KEY` to isolate a private cluster.)*

When a node starts:
1. It advertises a deterministic rendezvous CID (`pachytalk-v1`) on the IPFS DHT (`helia.routing.provide`) and queries `helia.routing.findProviders`, while also listening for `peer:connect` (e.g. mDNS on LAN).
2. Over `/pachytalk/peer/1.0.0`, nodes exchange their `PUBLIC_URL` and known peers.
3. For each newly discovered peer, the node fetches `/api/bootstrap`, verifies each message's client signature over `{ data, content_cid }`, downloads and pins any `content_cid` attachment from `/ipfs/<content_cid>` into its local IPFS node, appends the messages to its local per-board `.log` files, and imports `creds` nonces.
4. Ongoing updates propagate via push-on-send (`POST /api/receive`) and periodic delta polling (`?since=`).

*(For self-signed or mismatched TLS certs in local testing, pass `NODE_TLS_REJECT_UNAUTHORIZED=0`.)*

Ports
====
* **Inbound:**
  * **TCP `3141`** (or `PORT` env var) — HTTP/HTTPS server for the web UI, `/api/*` endpoints, and `/ipfs/:cid`.
  * **Ephemeral TCP/WebSocket** — Embedded Helia `libp2p` listeners for P2P connections and `/pachytalk/peer/1.0.0` handshakes (plus **UDP `5353`** on LAN for mDNS).
* **Outbound:**
  * **Peer HTTP/HTTPS ports** (e.g. `3141`, `443`) — Peer sync (`/api/bootstrap`, `/api/receive`, `/ipfs/:cid`).
  * **IPFS / libp2p peers** (typically TCP/UDP `4001` and advertised peer ports) — DHT rendezvous and Bitswap.
  * **TCP `443`** — Outbound HTTPS stream for the Mastodon firehose.

Environment Variables
====
All variables can be set in the environment or in `.env`:

* **Server & TLS:**
  * `PORT` — HTTP/HTTPS listen port (default: `3141`).
  * `PUBLIC_URL` — Canonical external URL advertised to peers and used for ActivityPub links/actors (if unset, auto-detects public IP via network interface or `api.ipify.org`, falling back to `localhost`).
  * `SSL_KEY_PATH` / `SSL_CERT_PATH` — Paths to TLS private key and certificate to serve HTTPS instead of HTTP.
* **Storage & Uploads:**
  * `IPFS_DATA_DIR` — Directory for embedded Helia IPFS blocks/data, `server-key.json`, and `activitypub-followers.json` (default: `./ipfs-data`).
  * `LOGS_DIR` — Directory for per-board `.log` files and `creds.json` (default: `${IPFS_DATA_DIR}/logs`).
  * `IPFS_GATEWAY_URL` — Base URL prefix for rendering attachment links (default: `/ipfs`).
  * `MAX_UPLOAD_BYTES` — Maximum upload file size in bytes (default: `52428800` / 50 MB).
* **Proof-of-Work (`cred`):**
  * `POW_DIFFICULTY_BITS` — Required leading zero bits (`1`–`63`, default: `16`).
  * `POW_CRED_SCALE` — Multiplier for `cred` scoring (default: `1`).
* **Peer Discovery & Sync:**
  * `PEERS` — Comma-separated list of static peer base URLs.
  * `BOARDS` — Comma-separated list of additional board names to advertise.
  * `BOOTSTRAP_BOARD` — Restrict peer sync to a single board name.
  * `RENDEZVOUS_KEY` — Cluster key for IPFS DHT rendezvous (default: `pachytalk-v1`).
  * `SYNC_INTERVAL_MS` — Periodic peer delta-polling interval in ms (`0` disables polling; default: `30000`).
  * `DISCOVERY_INTERVAL_MS` — Periodic IPFS DHT rendezvous interval in ms (`0` disables DHT loop; default: `60000`).
* **ActivityPub & Relays:**
  * `ACTIVITYPUB_RELAYS` — Comma-separated ActivityPub relay URLs to follow when `PUBLIC_URL` (or `SSL_CERT_PATH`) is a public `https://` domain (defaults to the non-pre-approval relays from `joinfediverse.wiki/Relays`; set empty to disable).
  * `ACTIVITYPUB_INBOXES` — Comma-separated ActivityPub inbox URLs to always publish new posts to in addition to stored followers.

TODO
====
* add upvote/downvote (weighted by cred)
* Mastodon/ActivityPub: read firehose and seed intitial content
* Mastodon/ActivityPub: publish posts to the Fediverse
* some kind of pagination
