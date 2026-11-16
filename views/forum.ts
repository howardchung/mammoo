export interface ForumMessage {
  id: string;
  depth?: number;
  data: string;
  pubkey?: string;
  sig?: string;
  image_cid?: string | null;
}

export interface ForumPageProps {
  board: string;
  messages: ForumMessage[];
  replyTo: string;
  ipfsGatewayUrl: string;
}

function escapeHtml(value: unknown): string {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderMessage(message: ForumMessage, board: string, replyTo: string, ipfsGatewayUrl: string): string {
  const id = message.id || '';
  const indentation = id.split('/').length * 20;
  const leafId = id.split('/').pop();
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

  return `
    <div class="message-card" style="margin-left: ${indentation}px;">
      <pre class="message-json">${escapeHtml(JSON.stringify(message, null, 2))}</pre>
      <div class="message-meta">${escapeHtml(id)}</div>
      <div class="message-meta">${escapeHtml(leafId)}</div>
      <div class="message-data">${escapeHtml(message.data)}</div>${renderedImage}
      <details class="reply-details"${isOpen}>
        <summary class="reply-btn">Reply</summary>
        <form method="POST" action="/api/send" enctype="multipart/form-data" class="message-form">
          <input type="hidden" name="path" value="${escapeHtml(id)}">
          <input type="hidden" name="board" value="${escapeHtml(board)}">
          <textarea name="data" placeholder="Reply"></textarea>
          <input type="file" name="image" accept="image/*" class="image-input">
          <button type="submit">Send</button>
        </form>
      </details>
    </div>
  `;
}

function renderForumPage({ board, messages, replyTo, ipfsGatewayUrl }: ForumPageProps): string {
  const safeBoard = escapeHtml(board);
  const renderedMessages = messages.length
    ? messages.map(msg => renderMessage(msg, board, replyTo, ipfsGatewayUrl)).join('\n')
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
        <div>
          <button type="button" id="new-id-btn">Create New ID</button>
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
        <input type="file" name="image" accept="image/*" class="image-input">
        <button type="submit">Send</button>
      </form>
    </div>
  </body>
</html>
`;
}

export { renderForumPage };
