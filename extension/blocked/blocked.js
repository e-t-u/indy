/**
 * Indy Blocked Connection Page Controller
 */

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('target') || '';
const host = params.get('host') || '';
const port = Number(params.get('port') || 443);
const tabIdParam = params.get('tabId');
const tabId = tabIdParam !== null ? Number(tabIdParam) : null;

let currentInspection = null;

async function initBlockedView() {
  document.getElementById('blocked-url').textContent = targetUrl || `https://${host}`;

  const res = await chrome.runtime.sendMessage({
    action: 'inspect_host',
    host,
    port,
    force: false
  });

  const listEl = document.getElementById('denied-chain-list');
  listEl.textContent = '';

  if (!res || !res.ok) {
    document.getElementById('blocked-reason').textContent =
      (res && res.error) || 'Blocked by Certificate Policy';
    return;
  }

  currentInspection = res;
  const { evaluation } = res;
  document.getElementById('blocked-reason').textContent = evaluation.reason;

  const chainCerts = [
    ...(evaluation.root ? [evaluation.root] : []),
    ...([...(evaluation.intermediates || [])].reverse()),
    ...(evaluation.leaf ? [evaluation.leaf] : [])
  ];

  for (const cert of chainCerts) {
    const item = document.createElement('div');
    const isDenied = cert.policy === 'deny';
    item.className = `cert-item${isDenied ? ' is-denied' : ''}`;

    const title = document.createElement('div');
    title.className = 'cert-item-title';
    const polStr = cert.role === 'leaf' ? 'LEAF' : `Policy: ${(cert.policy || 'ask').toUpperCase()}`;
    title.textContent = `[${cert.role.toUpperCase()}] ${cert.commonName} (${polStr})`;

    const sub = document.createElement('div');
    sub.className = 'cert-item-sub';
    sub.textContent = `Org: ${cert.organization || cert.commonName} | SHA-256: ${cert.fingerprint || cert.id}`;

    item.append(title, sub);
    listEl.appendChild(item);
  }
}

async function updateBlockedChainPolicy(newPolicy) {
  if (!currentInspection || !currentInspection.evaluation) return;
  const { evaluation } = currentInspection;
  const authorities = [
    ...(evaluation.root ? [evaluation.root] : []),
    ...(evaluation.intermediates || [])
  ];

  const updates = authorities.map((c) => ({
    id: c.id,
    commonName: c.commonName,
    policy: newPolicy
  }));

  await chrome.runtime.sendMessage({
    action: 'set_cert_policy',
    updates
  });

  if (newPolicy === 'ask') {
    const promptUrl = new URL(chrome.runtime.getURL('prompt/prompt.html'));
    promptUrl.searchParams.set('target', targetUrl || `https://${host}`);
    promptUrl.searchParams.set('host', host);
    promptUrl.searchParams.set('port', String(port));
    if (tabId !== null) promptUrl.searchParams.set('tabId', String(tabId));
    window.location.replace(promptUrl.toString());
  } else if (newPolicy === 'accept' && targetUrl) {
    window.location.replace(targetUrl);
  }
}

document.getElementById('btn-switch-ask').addEventListener('click', async () => {
  await updateBlockedChainPolicy('ask');
});

document.getElementById('btn-switch-accept').addEventListener('click', async () => {
  await updateBlockedChainPolicy('accept');
});

document.getElementById('btn-open-options').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

initBlockedView();
