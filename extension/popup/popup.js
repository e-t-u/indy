/**
 * Indy Toolbar Popup Controller
 */

async function refreshDbStats() {
  const res = await chrome.runtime.sendMessage({ action: 'get_database' });
  if (!res || !res.ok) return;
  const certs = Object.values(res.certDatabase || {});
  const roots = certs.filter((c) => c.role === 'root').length;
  const ints = certs.filter((c) => c.role === 'intermediate').length;
  const accepted = certs.filter((c) => c.policy === 'accept').length;
  document.getElementById('db-stats').textContent =
    `${roots} Roots | ${ints} Intermediates | ${accepted} Accepted`;
}

function renderChainView(host, evaluation) {
  document.getElementById('active-host').textContent = host;
  const pill = document.getElementById('active-decision');
  pill.textContent = evaluation.decision.toUpperCase();
  pill.className = `status-pill ${evaluation.decision}`;

  const container = document.getElementById('chain-container');
  container.textContent = '';

  const certs = [
    ...(evaluation.root ? [evaluation.root] : []),
    ...([...(evaluation.intermediates || [])].reverse()),
    ...(evaluation.leaf ? [evaluation.leaf] : [])
  ];

  for (const cert of certs) {
    const card = document.createElement('div');
    card.className = 'mini-card';

    const top = document.createElement('div');
    top.className = 'mini-top';

    const left = document.createElement('div');
    const roleSpan = document.createElement('div');
    roleSpan.className = 'mini-role';
    roleSpan.textContent =
      cert.role === 'root'
        ? 'Root Certificate'
        : cert.role === 'intermediate'
          ? 'Intermediate Certificate'
          : 'Leaf Server Certificate';

    const cnSpan = document.createElement('div');
    cnSpan.className = 'mini-cn';
    cnSpan.textContent = cert.commonName;
    left.append(roleSpan, cnSpan);
    top.appendChild(left);

    if (cert.role !== 'leaf') {
      const seg = document.createElement('div');
      seg.className = 'mini-seg';
      for (const pol of ['accept', 'ask', 'deny']) {
        const b = document.createElement('button');
        b.type = 'button';
        b.dataset.pol = pol;
        b.className = cert.policy === pol ? 'active' : '';
        b.textContent = pol.toUpperCase();
        b.addEventListener('click', async () => {
          await chrome.runtime.sendMessage({
            action: 'set_cert_policy',
            id: cert.id,
            commonName: cert.commonName,
            policy: pol
          });
          await inspectHostInPopup(host);
          await refreshDbStats();
        });
        seg.appendChild(b);
      }
      top.appendChild(seg);
    }

    const org = document.createElement('div');
    org.className = 'mini-org';
    org.textContent = `Issuer: ${cert.issuerCommonName || 'Self-Signed'} | Org: ${cert.organization || cert.commonName}`;

    card.append(top, org);
    container.appendChild(card);
  }
}

async function inspectHostInPopup(host) {
  const res = await chrome.runtime.sendMessage({
    action: 'inspect_host',
    host,
    port: 443,
    force: false
  });
  if (res && res.ok) {
    renderChainView(host, res.evaluation);
  } else {
    document.getElementById('active-host').textContent = host || 'No HTTPS tab';
    document.getElementById('active-decision').textContent = 'N/A';
    document.getElementById('chain-container').textContent =
      (res && res.error) || 'Navigate to an HTTPS site to inspect its Root and Intermediate CA chain.';
  }
}

async function initPopup() {
  await refreshDbStats();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab && tab.url) {
    try {
      const u = new URL(tab.url);
      if (u.protocol === 'https:') {
        await inspectHostInPopup(u.hostname);
        return;
      }
      const targetHost = u.searchParams.get('host');
      if (targetHost) {
        await inspectHostInPopup(targetHost);
        return;
      }
    } catch (_err) {
      // Ignore non-standard URLs
    }
  }
  await inspectHostInPopup('indy.test.local');
}

document.getElementById('btn-options').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

document.getElementById('btn-sync').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ action: 'sync_system_roots', force: true });
  await refreshDbStats();
});

document.getElementById('btn-test-indy').addEventListener('click', async () => {
  await inspectHostInPopup('indy.test.local');
  await refreshDbStats();
});

initPopup();
