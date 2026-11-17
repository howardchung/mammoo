import crypto from 'node:crypto';

export interface PowProof {
  nonce: number;
}

export type MediaType = 'image' | 'video' | 'audio' | 'file';

export function buildMessageSignaturePayload(
  data?: string | null,
  contentCid?: string | null
): string {
  return JSON.stringify({
    data: data || '',
    content_cid: contentCid || null,
  });
}

export interface ForumMessage {
  id: string;
  cid?: string;
  depth?: number;
  data: string;
  pubkey?: string;
  sig?: string;
  content_cid?: string | null;
  media_type?: MediaType | null;
  author?: string | null;
  author_url?: string | null;
  cred?: number;
}

export interface ForumPageProps {
  board: string;
  boards?: string[];
  messages: ForumMessage[];
  replyTo: string;
  ipfsGatewayUrl: string;
  powHashesPerSecond?: number;
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

const ALLOWED_POST_TAGS = new Set([
  'p', 'br', 'a', 'span', 'strong', 'b', 'em', 'i', 'u', 's', 'del',
  'code', 'pre', 'blockquote', 'ul', 'ol', 'li', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr',
]);
const VOID_POST_TAGS = new Set(['br', 'hr']);

function isSafeHref(rawHref: string): boolean {
  const decoded = rawHref
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&#([0-9]+);?/g, (_, dec) => String.fromCharCode(parseInt(dec, 10)))
    .replace(/[\u0000-\u0020]+/g, '')
    .toLowerCase();
  return (
    decoded.startsWith('http://') ||
    decoded.startsWith('https://') ||
    decoded.startsWith('mailto:') ||
    decoded.startsWith('/') ||
    decoded.startsWith('#')
  );
}

function escapeTextNode(value: string): string {
  return value
    .replace(/&(?!(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z0-9]+);)/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildSafeTag(rawTagContent: string): string {
  const trimmed = rawTagContent.trim();
  const isClosing = trimmed.startsWith('/');
  const body = isClosing ? trimmed.slice(1).trim() : trimmed.replace(/\/$/, '').trim();
  const spaceIdx = body.search(/\s/);
  const tag = (spaceIdx === -1 ? body : body.slice(0, spaceIdx)).toLowerCase();
  if (!ALLOWED_POST_TAGS.has(tag)) {
    return '';
  }
  if (isClosing) {
    return VOID_POST_TAGS.has(tag) ? '' : `</${tag}>`;
  }

  const rawAttrs = spaceIdx === -1 ? '' : body.slice(spaceIdx);
  const safeAttrs: string[] = [];
  const attrRegex = /([a-zA-Z0-9:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+))/g;
  let match: RegExpExecArray | null;
  while ((match = attrRegex.exec(rawAttrs)) !== null) {
    const attrName = match[1].toLowerCase();
    const attrVal = (match[2] ?? match[3] ?? match[4] ?? '').trim();
    if (tag === 'a' && attrName === 'href' && isSafeHref(attrVal)) {
      safeAttrs.push(`href="${escapeHtml(attrVal)}"`);
    } else if (attrName === 'class' && /^[a-zA-Z0-9_\-\s]+$/.test(attrVal)) {
      safeAttrs.push(`class="${escapeHtml(attrVal)}"`);
    }
  }
  if (tag === 'a') {
    safeAttrs.push('target="_blank"', 'rel="noopener noreferrer"');
  }
  const attrStr = safeAttrs.length > 0 ? ` ${safeAttrs.join(' ')}` : '';
  return `<${tag}${attrStr}>`;
}

export function sanitizePostHtml(value: unknown): string {
  let cleaned = String(value == null ? '' : value).replace(/<!--[\s\S]*?-->/g, '');
  let prev = '';
  while (cleaned !== prev) {
    prev = cleaned;
    cleaned = cleaned.replace(
      /<(script|style|iframe|object|embed|applet|svg|math|form|textarea)\b[\s\S]*?<\/\1>/gi,
      ''
    );
  }

  // Tokenize character-by-character respecting quoted attributes; escape all text nodes
  const out: string[] = [];
  let i = 0;
  const len = cleaned.length;
  while (i < len) {
    const lt = cleaned.indexOf('<', i);
    if (lt === -1) {
      out.push(escapeTextNode(cleaned.slice(i)));
      break;
    }
    if (lt > i) {
      out.push(escapeTextNode(cleaned.slice(i, lt)));
    }
    // Scan for matching '>' outside quotes
    let j = lt + 1;
    let quote: string | null = null;
    while (j < len) {
      const ch = cleaned[j];
      if (quote) {
        if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === '>') {
        break;
      }
      j++;
    }
    if (j >= len) {
      // Unclosed '<' -> escape the rest as text
      out.push(escapeTextNode(cleaned.slice(lt)));
      break;
    }
    const rawInside = cleaned.slice(lt + 1, j);
    if (/^\/?[a-zA-Z][a-zA-Z0-9-]*(?:\s|\/|$)/.test(rawInside.trim())) {
      out.push(buildSafeTag(rawInside));
    } else {
      out.push(escapeTextNode(cleaned.slice(lt, j + 1)));
    }
    i = j + 1;
  }
  return out.join('');
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
  roots.sort((a, b) => b.message.id.localeCompare(a.message.id));
  return roots;
}

export function formatCredMiningTime(cred: number): string {
  const seconds = cred;
  if (seconds < 60) {
    return `${seconds < 10 ? seconds.toFixed(1).replace(/\.0$/, '') : Math.round(seconds)}s`;
  }
  if (seconds < 3600) {
    return `${(seconds / 60).toFixed(1).replace(/\.0$/, '')}m`;
  }
  if (seconds < 86400) {
    return `${(seconds / 3600).toFixed(1).replace(/\.0$/, '')}h`;
  }
  return `${(seconds / 86400).toFixed(1).replace(/\.0$/, '')}d`;
}

function countDescendants(node: ThreadNode): number {
  let count = 0;
  for (const child of node.children) {
    count += 1 + countDescendants(child);
  }
  return count;
}

function renderMessage(
  node: ThreadNode,
  board: string,
  replyTo: string,
  ipfsGatewayUrl: string,
  powDifficultyBits: number = 16
): string {
  const { message, children } = node;
  const id = message.id || '';
  const isOpen = replyTo === id ? ' open' : '';
  const mediaUrl = message.content_cid
    ? `${ipfsGatewayUrl}/${encodeURIComponent(message.content_cid)}`
    : '';
  const renderedMediaBody = message.media_type === 'video'
    ? `<video controls preload="metadata" src="${escapeHtml(mediaUrl)}"></video>`
    : message.media_type === 'audio'
      ? `<audio controls preload="metadata" src="${escapeHtml(mediaUrl)}"></audio>`
      : message.media_type === 'file'
        ? `<a class="message-file" href="${escapeHtml(mediaUrl)}" target="_blank" rel="noopener noreferrer">Download attachment</a>`
        : `<a href="${escapeHtml(mediaUrl)}" target="_blank" rel="noopener noreferrer">
            <img src="${escapeHtml(mediaUrl)}" alt="Uploaded image" loading="lazy">
          </a>`;
  const renderedImage = mediaUrl
    ? `
      <div class="message-image">
        ${renderedMediaBody}
        <div class="message-cid">IPFS: ${escapeHtml(message.content_cid)}</div>
      </div>`
    : '';

  const author = message.author ? message.author : deriveUsername(message.pubkey);
  const avatarUri = deriveAvatarDataUri(message.author_url || message.author || message.pubkey);
  const safeAuthorUrl =
    message.author_url && (message.author_url.startsWith('http://') || message.author_url.startsWith('https://'))
      ? message.author_url
      : '';
  const renderedAuthor = safeAuthorUrl
    ? `<a class="message-author" href="${escapeHtml(safeAuthorUrl)}" target="_blank" rel="noopener noreferrer">${escapeHtml(author)}</a>`
    : `<span class="message-author">${escapeHtml(author)}</span>`;
  const isFediversePost = Boolean(message.author || id.includes('-fedi-'));
  const signerName = deriveUsername(message.pubkey);
  const signerAvatarUri = deriveAvatarDataUri(message.pubkey);
  const renderedSigner =
    isFediversePost && message.pubkey
      ? `<span class="message-signer" title="Signed by server key (${escapeHtml(signerName)})">signed by <img class="signer-avatar" src="${signerAvatarUri}" alt="${escapeHtml(signerName)} avatar" width="16" height="16"> <strong>${escapeHtml(signerName)}</strong></span>`
      : '';
  const estTime = message.cred && message.cred > 0 ? formatCredMiningTime(message.cred) : '';
  const credTooltip = estTime
    ? `Cred is verifiable proof-of-work mined for this public key (~${estTime} at 100k H/s; 1 cred = 1 expected second).`
    : 'Cred is verifiable proof-of-work mined for this public key.';
  const renderedCred = message.cred && message.cred > 0
    ? `<span class="message-cred" title="${escapeHtml(credTooltip)}">Cred: <strong>${escapeHtml(message.cred)}</strong></span>`
    : '';

  const totalReplies = countDescendants(node);
  const renderedReplies = children.length > 0
    ? `
      <details class="thread-replies">
        <summary class="replies-toggle">${totalReplies} ${totalReplies === 1 ? 'reply' : 'replies'}</summary>
        <div class="thread-children">
          ${children.map((child) => renderMessage(child, board, replyTo, ipfsGatewayUrl, powDifficultyBits)).join('\n')}
        </div>
      </details>`
    : '';

  return `
    <div class="thread-node">
      <div class="message-card" data-pubkey="${escapeHtml(message.pubkey || '')}">
        <div class="message-header">
          <img class="message-avatar" src="${avatarUri}" alt="${escapeHtml(author)} avatar" width="28" height="28">
          ${renderedAuthor}
          ${renderedSigner}
          ${renderedCred}
        </div>
        <div class="message-data">${sanitizePostHtml(message.data)}</div>${renderedImage}
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
              <input type="file" name="image" class="image-input">
              <button type="submit">Send</button>
            </div>
          </form>
        </details>
      </div>${renderedReplies}
    </div>
  `;
}

function renderForumPage({ board, boards, messages, replyTo, ipfsGatewayUrl, powHashesPerSecond = 100000 }: ForumPageProps): string {
  const safeBoard = escapeHtml(board);
  const availableBoards = Array.from(new Set(boards && boards.length ? boards : [board])).sort();
  const renderedBoards = availableBoards
    .map((b) => {
      const selected = b === board ? ' selected' : '';
      return `<option value="${escapeHtml(b)}"${selected}>${escapeHtml(b)}</option>`;
    })
    .join('');
  const tree = buildThreadTree(messages);
  const renderedMessages = tree.length
    ? tree.map((node) => renderMessage(node, board, replyTo, ipfsGatewayUrl)).join('\n')
    : '<p class="empty-state">No messages yet. Start a new topic above!</p>';

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>pachytalk</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg">
    <link rel="stylesheet" href="/style.css">
    <script src="/client.js" defer></script>
  </head>
  <body>
    <div class="app" data-board="${safeBoard}" data-pow-hashes-per-second="${escapeHtml(powHashesPerSecond)}">
      <header class="app-header">
        <h2>You're on board ${safeBoard}</h2>
        <form method="GET" action="/" class="board-switcher">
          <label for="board-select">Board:</label>
          <select id="board-select" name="board">
            ${renderedBoards}
          </select>
        </form>
        <div class="header-actions">
          <button type="button" id="new-id-btn">Create New ID</button>
          <button type="button" id="export-id-btn">Export ID</button>
          <button type="button" id="import-id-btn">Import ID</button>
          <input type="file" id="import-id-file" accept=".json,application/json" hidden>
          <button type="button" id="mine-cred-btn">Mine Cred</button>
          <span id="cred-mine-status" class="pow-status"></span>
        </div>
        <h3>You're posting as</h3>
        <div class="header-identity">
          <img id="client-avatar" class="message-avatar" alt="Your avatar" width="28" height="28">
          <span id="client-username" class="message-author">Generating client keypair...</span>
        </div>
        <details class="pubkey-details">
          <summary class="meta-toggle">Public key</summary>
          <pre class="pubkey" id="client-pubkey">Generating client keypair...</pre>
        </details>
      </header>
      <form method="POST" action="/api/send" enctype="multipart/form-data" class="message-form new-topic-form">
        <input type="hidden" name="path" value="/${safeBoard}">
        <input type="hidden" name="board" value="${safeBoard}">
        <textarea name="data" placeholder="Start a new topic"></textarea>
        <div class="form-actions">
          <input type="file" name="image" class="image-input">
          <button type="submit">Send</button>
        </div>
      </form>
      <main class="messages-container">
        ${renderedMessages}
      </main>
    </div>
  </body>
</html>
`;
}

export { renderForumPage };
