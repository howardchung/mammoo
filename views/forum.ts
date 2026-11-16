import crypto from 'node:crypto';

export interface PowProof {
  timestamp: number;
  nonce: number;
  hash?: string;
  leadingZeros?: number;
  cred?: number;
}

export interface ForumMessage {
  id: string;
  depth?: number;
  data: string;
  pubkey?: string;
  sig?: string;
  image_cid?: string | null;
  pow_cid?: string | null;
  pow?: PowProof[];
  cred?: number;
}

export interface ForumPageProps {
  board: string;
  messages: ForumMessage[];
  replyTo: string;
  ipfsGatewayUrl: string;
}

const ADJECTIVES = [
  'amber', 'brisk', 'calm', 'clear', 'cobalt', 'coral', 'crisp', 'dawn',
  'ember', 'fern', 'frost', 'gold', 'jade', 'keen', 'lively', 'lunar',
  'maple', 'misty', 'noble', 'olive', 'opal', 'pine', 'quiet', 'rapid',
  'river', 'sage', 'silver', 'solar', 'swift', 'teal', 'warm', 'wild',
];

const NOUNS = [
  'badger', 'beaver', 'bison', 'bobcat', 'condor', 'crane', 'deer', 'dolphin',
  'eagle', 'falcon', 'finch', 'fox', 'gecko', 'hawk', 'heron', 'ibis',
  'jay', 'koala', 'lemur', 'lynx', 'marmot', 'newt', 'osprey', 'otter',
  'owl', 'panda', 'puma', 'raven', 'robin', 'seal', 'swan', 'wolf',
];

function deriveUsername(pubkey?: string): string {
  if (!pubkey) {
    return 'anonymous';
  }
  const digest = crypto.createHash('sha256').update(pubkey).digest();
  const adj = ADJECTIVES[digest[0] % ADJECTIVES.length];
  const noun = NOUNS[digest[1] % NOUNS.length];
  const tag = digest.subarray(2, 4).toString('hex');
  return `${adj}-${noun}-${tag}`;
}

function deriveAvatarDataUri(pubkey?: string): string {
  const digest = crypto.createHash('sha256').update(pubkey || 'anonymous').digest();
  const hue = ((digest[0] << 8) | digest[1]) % 360;
  const fg = `hsl(${hue}, 65%, 48%)`;
  const cells: string[] = [];
  for (let row = 0; row < 5; row++) {
    for (let col = 0; col < 3; col++) {
      const bitIndex = row * 3 + col;
      const byte = digest[2 + Math.floor(bitIndex / 8)];
      const on = (byte >> (bitIndex % 8)) & 1;
      if (on) {
        cells.push(`<rect x="${col + 1}" y="${row + 1}" width="1" height="1" fill="${fg}"/>`);
        if (col < 2) {
          cells.push(`<rect x="${5 - col}" y="${row + 1}" width="1" height="1" fill="${fg}"/>`);
        }
      }
    }
  }
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 7 7" shape-rendering="crispEdges"><rect width="7" height="7" fill="#f1f5f9"/>${cells.join('')}</svg>`;
  return `data:image/svg+xml;base64,${Buffer.from(svg).toString('base64')}`;
}

function escapeHtml(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

interface ThreadNode {
  message: ForumMessage;
  children: ThreadNode[];
}

function buildThreadTree(messages: ForumMessage[]): ThreadNode[] {
  const byId = new Map<string, ThreadNode>();
  const roots: ThreadNode[] = [];
  for (const message of messages) {
    byId.set(message.id, { message, children: [] });
  }
  for (const message of messages) {
    const node = byId.get(message.id)!;
    const lastSlash = message.id.lastIndexOf('/');
    const parentId = lastSlash > 0 ? message.id.slice(0, lastSlash) : '';
    const parent = parentId ? byId.get(parentId) : undefined;
    if (parent) {
      parent.children.push(node);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

function countDescendants(node: ThreadNode): number {
  let count = 0;
  for (const child of node.children) {
    count += 1 + countDescendants(child);
  }
  return count;
}

function renderMessage(node: ThreadNode, board: string, replyTo: string, ipfsGatewayUrl: string): string {
  const { message, children } = node;
  const id = message.id || '';
  const isOpen = replyTo === id ? ' open' : '';
  const imageUrl = message.image_cid
    ? `${ipfsGatewayUrl}/${encodeURIComponent(message.image_cid)}`
    : '';
  const renderedImage = imageUrl
    ? `
      <div class="message-image">
        <a href="${escapeHtml(imageUrl)}" target="_blank" rel="noopener noreferrer">
          <img src="${escapeHtml(imageUrl)}" alt="Uploaded image" loading="lazy">
        </a>
        <div class="message-cid">IPFS: ${escapeHtml(message.image_cid)}</div>
      </div>`
    : '';

  const author = deriveUsername(message.pubkey);
  const avatarUri = deriveAvatarDataUri(message.pubkey);
  const renderedCred = message.cred && message.cred > 0
    ? `<span class="message-cred">Verified Cred: <strong>${escapeHtml(message.cred)}</strong></span>`
    : '';

  const totalReplies = countDescendants(node);
  const renderedReplies = children.length > 0
    ? `
      <details class="thread-replies">
        <summary class="replies-toggle">${totalReplies} ${totalReplies === 1 ? 'reply' : 'replies'}</summary>
        <div class="thread-children">
          ${children.map((child) => renderMessage(child, board, replyTo, ipfsGatewayUrl)).join('\n')}
        </div>
      </details>`
    : '';

  return `
    <div class="thread-node">
      <div class="message-card">
        <div class="message-header">
          <img class="message-avatar" src="${avatarUri}" alt="${escapeHtml(author)} avatar" width="28" height="28">
          <span class="message-author">${escapeHtml(author)}</span>
          ${renderedCred}
        </div>
        <div class="message-data">${escapeHtml(message.data)}</div>${renderedImage}
        <details class="meta-details">
          <summary class="meta-toggle">Metadata</summary>
          <div class="meta-content">
            <pre class="message-json">${escapeHtml(JSON.stringify(message, null, 2))}</pre>
          </div>
        </details>
        <details class="reply-details"${isOpen}>
          <summary class="reply-btn">Reply</summary>
          <form method="POST" action="/api/send" enctype="multipart/form-data" class="message-form">
            <input type="hidden" name="path" value="${escapeHtml(id)}">
            <input type="hidden" name="board" value="${escapeHtml(board)}">
            <textarea name="data" placeholder="Reply"></textarea>
            <div class="form-actions">
              <input type="file" name="image" accept="image/*" class="image-input">
              <button type="submit">Send</button>
            </div>
          </form>
        </details>
      </div>${renderedReplies}
    </div>
  `;
}

function renderForumPage({ board, messages, replyTo, ipfsGatewayUrl }: ForumPageProps): string {
  const safeBoard = escapeHtml(board);
  const tree = buildThreadTree(messages);
  const renderedMessages = tree.length
    ? tree.map((node) => renderMessage(node, board, replyTo, ipfsGatewayUrl)).join('\n')
    : '<p class="empty-state">No messages yet. Start a new topic below!</p>';

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>pachytalk</title>
    <link rel="stylesheet" href="/style.css">
    <script src="/client.js" defer></script>
  </head>
  <body>
    <div class="app">
      <header class="app-header">
        <h2>You're on board ${safeBoard}</h2>
        <div class="header-actions">
          <button type="button" id="new-id-btn">Create New ID</button>
          <button type="button" id="pow-btn">Start Proof-of-Work</button>
          <span class="cred-badge">Cred: <strong id="cred-balance">0</strong></span>
          <span id="pow-status" class="pow-status">Idle</span>
        </div>
        <h3>You're posting as</h3>
        <pre class="pubkey" id="client-pubkey">Generating client keypair...</pre>
      </header>
      <main class="messages-container">
        ${renderedMessages}
      </main>
      <form method="POST" action="/api/send" enctype="multipart/form-data" class="message-form new-topic-form">
        <input type="hidden" name="path" value="/${safeBoard}">
        <input type="hidden" name="board" value="${safeBoard}">
        <textarea name="data" placeholder="Start a new topic"></textarea>
        <div class="form-actions">
          <input type="file" name="image" accept="image/*" class="image-input">
          <button type="submit">Send</button>
        </div>
      </form>
    </div>
  </body>
</html>
`;
}

export { renderForumPage };
