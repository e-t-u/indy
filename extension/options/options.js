/**
 * Indy Certificate Database Manager (Options Page)
 */

let allCerts = [];
let auditEntries = [];
let currentSettings = {
  defaultRootPolicy: 'ask',
  defaultIntermediatePolicy: 'ask',
  enforceIntermediates: true
};

async function loadState() {
  const res = await chrome.runtime.sendMessage({ action: 'get_database' });
  if (!res || !res.ok) return;

  allCerts = Object.values(res.certDatabase || {}).sort((a, b) => {
    if (a.commonName === 'indy') return -1;
    if (b.commonName === 'indy') return 1;
    if (a.role !== b.role) return a.role === 'root' ? -1 : 1;
    return String(a.commonName || '').localeCompare(String(b.commonName || ''));
  });

  auditEntries = res.auditLog || [];
  currentSettings = res.settings || currentSettings;

  document.getElementById('chk-enforce-intermediates').checked =
    currentSettings.enforceIntermediates !== false;

  if (res.bundlePath) {
    document.getElementById('bundle-info').textContent =
      `Booted from OS trust store: ${res.bundlePath} (${allCerts.length} certificates tracked)`;
  }

  updateStats();
  renderTable();
  renderAuditLog();
}

function updateStats() {
  const roots = allCerts.filter((c) => c.role === 'root').length;
  const ints = allCerts.filter((c) => c.role === 'intermediate').length;
  const acceptCount = allCerts.filter((c) => c.policy === 'accept').length;
  const askCount = allCerts.filter((c) => c.policy === 'ask').length;
  const denyCount = allCerts.filter((c) => c.policy === 'deny').length;

  document.getElementById('stat-roots').textContent = String(roots);
  document.getElementById('stat-intermediates').textContent = String(ints);
  document.getElementById('stat-accept').textContent = String(acceptCount);
  document.getElementById('stat-ask').textContent = String(askCount);
  document.getElementById('stat-deny').textContent = String(denyCount);
}

function renderTable() {
  const query = document.getElementById('search-input').value.trim().toLowerCase();
  const roleFilter = document.getElementById('filter-role').value;
  const policyFilter = document.getElementById('filter-policy').value;

  const filtered = allCerts.filter((cert) => {
    if (roleFilter !== 'all' && cert.role !== roleFilter) return false;
    if (policyFilter !== 'all' && cert.policy !== policyFilter) return false;
    if (!query) return true;
    const hay = `${cert.commonName} ${cert.organization} ${cert.issuerCommonName} ${cert.fingerprint} ${cert.subject}`.toLowerCase();
    return hay.includes(query);
  });

  const tbody = document.getElementById('cert-tbody');
  tbody.textContent = '';

  for (const cert of filtered) {
    const tr = document.createElement('tr');
    tr.dataset.certId = cert.id;
    tr.dataset.commonName = cert.commonName;

    const tdRole = document.createElement('td');
    const roleSpan = document.createElement('span');
    roleSpan.className = `badge-role ${cert.role}`;
    roleSpan.textContent = cert.role;
    tdRole.appendChild(roleSpan);

    const tdCn = document.createElement('td');
    const cnDiv = document.createElement('div');
    cnDiv.className = 'cn-cell';
    cnDiv.textContent = cert.commonName;
    const subDiv = document.createElement('div');
    subDiv.className = 'sub-cell';
    subDiv.textContent = cert.subject || '';
    tdCn.append(cnDiv, subDiv);

    const tdOrg = document.createElement('td');
    const orgMain = document.createElement('div');
    orgMain.textContent = cert.organization || cert.commonName;
    const orgSub = document.createElement('div');
    orgSub.className = 'sub-cell';
    orgSub.textContent = `Issuer: ${cert.issuerCommonName || 'Self-Signed'}`;
    tdOrg.append(orgMain, orgSub);

    const tdValid = document.createElement('td');
    tdValid.className = 'sub-cell';
    tdValid.textContent = `${(cert.notBefore || '').slice(0, 10)} -> ${(cert.notAfter || '').slice(0, 10)}`;

    const tdFp = document.createElement('td');
    tdFp.className = 'fp-cell';
    const fpText = cert.fingerprint || cert.id.replace('sha256:', '');
    tdFp.textContent = `${fpText.slice(0, 16)}...${fpText.slice(-12)}`;
    tdFp.title = fpText;

    const tdPol = document.createElement('td');
    const seg = document.createElement('div');
    seg.className = 'seg-group';

    for (const pol of ['accept', 'ask', 'deny']) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.dataset.pol = pol;
      btn.className = `seg-btn${cert.policy === pol ? ' active' : ''}`;
      btn.textContent = pol.toUpperCase();
      btn.addEventListener('click', async () => {
        await chrome.runtime.sendMessage({
          action: 'set_cert_policy',
          id: cert.id,
          commonName: cert.commonName,
          policy: pol
        });
        cert.policy = pol;
        updateStats();
        renderTable();
      });
      seg.appendChild(btn);
    }
    tdPol.appendChild(seg);

    tr.append(tdRole, tdCn, tdOrg, tdValid, tdFp, tdPol);
    tbody.appendChild(tr);
  }
}

function renderAuditLog() {
  const tbody = document.getElementById('audit-tbody');
  tbody.textContent = '';

  for (const item of auditEntries.slice(0, 30)) {
    const tr = document.createElement('tr');

    const tdTime = document.createElement('td');
    tdTime.className = 'sub-cell';
    tdTime.textContent = (item.timestamp || '').replace('T', ' ').slice(0, 19);

    const tdHost = document.createElement('td');
    tdHost.className = 'cn-cell';
    tdHost.textContent = item.host || '';

    const tdRoot = document.createElement('td');
    tdRoot.textContent = item.rootCommonName || '';

    const tdInt = document.createElement('td');
    tdInt.className = 'sub-cell';
    tdInt.textContent = (item.intermediateCommonNames || []).join(' -> ') || 'None';

    const tdDec = document.createElement('td');
    tdDec.textContent = (item.decision || '').toUpperCase();

    const tdReason = document.createElement('td');
    tdReason.className = 'sub-cell';
    tdReason.textContent = item.reason || '';

    tr.append(tdTime, tdHost, tdRoot, tdInt, tdDec, tdReason);
    tbody.appendChild(tr);
  }
}

document.getElementById('search-input').addEventListener('input', renderTable);
document.getElementById('filter-role').addEventListener('change', renderTable);
document.getElementById('filter-policy').addEventListener('change', renderTable);

document.getElementById('chk-enforce-intermediates').addEventListener('change', async (e) => {
  await chrome.runtime.sendMessage({
    action: 'update_settings',
    settings: { enforceIntermediates: e.target.checked }
  });
});

document.getElementById('btn-sync-roots').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ action: 'sync_system_roots', force: true });
  await loadState();
});

document.getElementById('btn-bulk-ask').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ action: 'bulk_set_policy', policy: 'ask', role: 'all' });
  await loadState();
});

document.getElementById('btn-bulk-accept').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ action: 'bulk_set_policy', policy: 'accept', role: 'all' });
  await loadState();
});

document.getElementById('btn-clear-audit').addEventListener('click', async () => {
  await chrome.runtime.sendMessage({ action: 'clear_audit_log' });
  await loadState();
});

loadState();
