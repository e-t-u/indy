/**
 * Indy Certificate Database Manager (Options Page)
 * Supports browsing system roots, managing policies, and uploading new private root CAs.
 */

let allCerts = [];
let auditEntries = [];
let currentSettings = {
  defaultRootPolicy: 'ask',
  defaultIntermediatePolicy: 'ask',
  enforceIntermediates: true
};

let previewDebounceTimer = null;
let currentParsedCert = null;

async function loadState() {
  const res = await chrome.runtime.sendMessage({ action: 'get_database' });
  if (!res || !res.ok) return;

  allCerts = Object.values(res.certDatabase || {}).sort((a, b) => {
    if (a.source === 'custom' && b.source !== 'custom') return -1;
    if (b.source === 'custom' && a.source !== 'custom') return 1;
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
  const roots = allCerts.filter((c) => c.role === 'root' && c.source !== 'custom').length;
  const customRoots = allCerts.filter((c) => c.source === 'custom').length;
  const ints = allCerts.filter((c) => c.role === 'intermediate').length;
  const acceptCount = allCerts.filter((c) => c.policy === 'accept').length;
  const askCount = allCerts.filter((c) => c.policy === 'ask').length;
  const denyCount = allCerts.filter((c) => c.policy === 'deny').length;

  document.getElementById('stat-roots').textContent = String(roots);
  document.getElementById('stat-custom').textContent = String(customRoots);
  document.getElementById('stat-intermediates').textContent = String(ints);
  document.getElementById('stat-accept').textContent = String(acceptCount);
  document.getElementById('stat-ask').textContent = String(askCount);
  document.getElementById('stat-deny').textContent = String(denyCount);
}

function renderTable() {
  const query = document.getElementById('search-input').value.trim().toLowerCase();
  const roleFilter = document.getElementById('filter-role').value;
  const sourceFilter = document.getElementById('filter-source').value;
  const policyFilter = document.getElementById('filter-policy').value;

  const filtered = allCerts.filter((cert) => {
    if (roleFilter !== 'all' && cert.role !== roleFilter) return false;
    if (sourceFilter !== 'all') {
      if (sourceFilter === 'system' && cert.source !== 'system') return false;
      if (sourceFilter === 'custom' && cert.source !== 'custom') return false;
      if (sourceFilter === 'discovered' && cert.source !== 'discovered') return false;
    }
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

    // Role & Source cell
    const tdRole = document.createElement('td');
    const roleSpan = document.createElement('span');
    roleSpan.className = `badge-role ${cert.role}`;
    roleSpan.textContent = cert.role;
    tdRole.appendChild(roleSpan);

    const sourceDiv = document.createElement('div');
    const sourceSpan = document.createElement('span');
    sourceSpan.className = `badge-source ${cert.source || 'system'}`;
    sourceSpan.textContent = cert.source === 'custom' ? 'Private CA' : (cert.source || 'system');
    sourceDiv.appendChild(sourceSpan);
    tdRole.appendChild(sourceDiv);

    // Common Name & Subject
    const tdCn = document.createElement('td');
    const cnDiv = document.createElement('div');
    cnDiv.className = 'cn-cell';
    cnDiv.textContent = cert.commonName;
    const subDiv = document.createElement('div');
    subDiv.className = 'sub-cell';
    subDiv.textContent = cert.subject || '';
    tdCn.append(cnDiv, subDiv);

    // Organization & Issuer
    const tdOrg = document.createElement('td');
    const orgMain = document.createElement('div');
    orgMain.textContent = cert.organization || cert.commonName;
    const orgSub = document.createElement('div');
    orgSub.className = 'sub-cell';
    orgSub.textContent = `Issuer: ${cert.issuerCommonName || 'Self-Signed'}`;
    tdOrg.append(orgMain, orgSub);

    // Validity
    const tdValid = document.createElement('td');
    tdValid.className = 'sub-cell';
    tdValid.textContent = `${(cert.notBefore || '').slice(0, 10)} -> ${(cert.notAfter || '').slice(0, 10)}`;

    // Fingerprint
    const tdFp = document.createElement('td');
    tdFp.className = 'fp-cell';
    const fpText = cert.fingerprint || cert.id.replace('sha256:', '');
    tdFp.textContent = `${fpText.slice(0, 16)}...${fpText.slice(-12)}`;
    tdFp.title = fpText;

    // Actions & Policy
    const tdPol = document.createElement('td');
    const actionCell = document.createElement('div');
    actionCell.className = 'action-cell';

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
    actionCell.appendChild(seg);

    if (cert.source === 'custom') {
      const delBtn = document.createElement('button');
      delBtn.type = 'button';
      delBtn.className = 'btn-delete btn-delete-cert';
      delBtn.textContent = 'Remove';
      delBtn.title = 'Remove this custom root certificate from Indy';
      delBtn.addEventListener('click', async () => {
        if (confirm(`Remove private root certificate "${cert.commonName}" from Indy?`)) {
          await chrome.runtime.sendMessage({
            action: 'delete_certificate',
            id: cert.id
          });
          await loadState();
        }
      });
      actionCell.appendChild(delBtn);
    }

    tdPol.appendChild(actionCell);

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

/* Modal and Upload Handling */
const uploadModal = document.getElementById('upload-modal');
const pemTextarea = document.getElementById('pem-textarea');
const certFileInput = document.getElementById('cert-file-input');
const dropZone = document.getElementById('drop-zone');
const btnSubmitUpload = document.getElementById('btn-submit-upload');
const certPreviewCard = document.getElementById('cert-preview-card');
const previewGrid = document.getElementById('preview-grid');
const uploadAlert = document.getElementById('upload-alert');

function openModal() {
  uploadModal.classList.remove('hidden');
  resetUploadForm();
  pemTextarea.focus();
}

function closeModal() {
  uploadModal.classList.add('hidden');
  resetUploadForm();
}

function resetUploadForm() {
  pemTextarea.value = '';
  certFileInput.value = '';
  currentParsedCert = null;
  btnSubmitUpload.disabled = true;
  certPreviewCard.classList.add('hidden');
  previewGrid.textContent = '';
  uploadAlert.className = 'alert-box hidden';
  uploadAlert.textContent = '';
}

function showAlert(type, text) {
  uploadAlert.className = `alert-box ${type}`;
  uploadAlert.textContent = text;
}

function clearAlert() {
  uploadAlert.className = 'alert-box hidden';
  uploadAlert.textContent = '';
}

async function handlePemInput() {
  clearTimeout(previewDebounceTimer);
  const text = pemTextarea.value.trim();

  if (!text) {
    resetUploadForm();
    return;
  }

  previewDebounceTimer = setTimeout(async () => {
    try {
      const res = await chrome.runtime.sendMessage({
        action: 'parse_certificate',
        pemData: text
      });

      if (res && res.ok && res.cert) {
        currentParsedCert = res.cert;
        renderPreview(res.cert);
        btnSubmitUpload.disabled = false;
        clearAlert();
      } else {
        currentParsedCert = null;
        certPreviewCard.classList.add('hidden');
        btnSubmitUpload.disabled = true;
        showAlert('error', (res && res.error) || 'Invalid X.509 PEM certificate.');
      }
    } catch (err) {
      currentParsedCert = null;
      certPreviewCard.classList.add('hidden');
      btnSubmitUpload.disabled = true;
      showAlert('error', `Parse error: ${err.message || err}`);
    }
  }, 250);
}

function renderPreview(cert) {
  certPreviewCard.classList.remove('hidden');
  document.getElementById('preview-role-badge').textContent =
    cert.role === 'root' ? 'Root CA' : 'Intermediate CA';

  previewGrid.textContent = '';

  const addField = (label, val) => {
    const item = document.createElement('div');
    item.className = 'preview-grid-item';
    item.innerHTML = `<strong>${label}:</strong> `;
    item.append(document.createTextNode(val || 'N/A'));
    previewGrid.appendChild(item);
  };

  addField('Common Name', cert.commonName);
  addField('Organization', cert.organization || cert.commonName);
  addField('Subject', cert.subject);
  addField('Issuer', cert.issuerCommonName || 'Self-Signed');
  addField('Valid From', (cert.notBefore || '').slice(0, 10));
  addField('Valid Until', (cert.notAfter || '').slice(0, 10));
  addField('Basic Constraints', cert.isCA ? 'CA: TRUE (Certificate Authority)' : 'CA: FALSE (End-Entity)');
  addField('SHA-256', `${(cert.fingerprint || cert.id).slice(0, 24)}...`);
}

function loadFileContent(file) {
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    pemTextarea.value = e.target.result;
    handlePemInput();
  };
  reader.onerror = () => {
    showAlert('error', 'Failed to read selected file.');
  };
  reader.readAsText(file);
}

// Event Listeners for Filters and Table
document.getElementById('search-input').addEventListener('input', renderTable);
document.getElementById('filter-role').addEventListener('change', renderTable);
document.getElementById('filter-source').addEventListener('change', renderTable);
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

// Modal Dialog Triggers
document.getElementById('btn-open-upload').addEventListener('click', openModal);
document.getElementById('btn-close-modal').addEventListener('click', closeModal);
document.getElementById('btn-cancel-modal').addEventListener('click', closeModal);

uploadModal.addEventListener('click', (e) => {
  if (e.target === uploadModal) {
    closeModal();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !uploadModal.classList.contains('hidden')) {
    closeModal();
  }
});

// Textarea input
pemTextarea.addEventListener('input', handlePemInput);

// File input and drag & drop
certFileInput.addEventListener('change', (e) => {
  const file = e.target.files && e.target.files[0];
  loadFileContent(file);
});

dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  const file = e.dataTransfer.files && e.dataTransfer.files[0];
  loadFileContent(file);
});

// Submit / Import
btnSubmitUpload.addEventListener('click', async () => {
  const pem = pemTextarea.value.trim();
  const policy = document.getElementById('upload-policy').value;

  if (!pem) return;

  btnSubmitUpload.disabled = true;
  showAlert('success', 'Importing certificate...');

  try {
    const res = await chrome.runtime.sendMessage({
      action: 'upload_root_certificate',
      pemData: pem,
      policy
    });

    if (res && res.ok) {
      showAlert('success', `Certificate "${res.cert.commonName}" successfully imported!`);
      await loadState();
      setTimeout(() => {
        closeModal();
      }, 700);
    } else {
      btnSubmitUpload.disabled = false;
      showAlert('error', (res && res.error) || 'Failed to import certificate.');
    }
  } catch (err) {
    btnSubmitUpload.disabled = false;
    showAlert('error', `Import error: ${err.message || err}`);
  }
});

loadState();
