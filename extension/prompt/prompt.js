/**
 * Indy Interstitial Decision Prompt Controller
 */

const params = new URLSearchParams(window.location.search);
const targetUrl = params.get('target') || '';
const host = params.get('host') || '';
const port = Number(params.get('port') || 443);
const tabIdParam = params.get('tabId');
const tabId = tabIdParam !== null ? Number(tabIdParam) : null;

let currentInspection = null;
const selectedPolicies = new Map();

function createCertCard(cert, isAuthority) {
  const card = document.createElement('div');
  card.className = `cert-card role-${cert.role}`;
  card.dataset.certId = cert.id;
  card.dataset.commonName = cert.commonName;

  const header = document.createElement('div');
  header.className = 'cert-header';

  const titleGroup = document.createElement('div');
  titleGroup.className = 'cert-title-group';

  const badge = document.createElement('span');
  badge.className = `role-badge ${cert.role}`;
  badge.textContent =
    cert.role === 'root'
      ? 'Root CA'
      : cert.role === 'intermediate'
        ? 'Intermediate CA'
        : 'Server Leaf Cert';

  const cn = document.createElement('span');
  cn.className = 'cert-cn';
  cn.textContent = cert.commonName;

  const sourceTag = document.createElement('span');
  sourceTag.className = 'source-tag';
  sourceTag.textContent =
    cert.source === 'system'
      ? 'Booted from System Root Store'
      : cert.role === 'intermediate'
        ? 'Intermediate Authority'
        : 'End-Entity Server';

  titleGroup.append(badge, cn, sourceTag);
  header.appendChild(titleGroup);

  if (isAuthority) {
    const initialPolicy = cert.policy || 'ask';
    selectedPolicies.set(cert.id, initialPolicy);

    const selector = document.createElement('div');
    selector.className = 'policy-selector';
    selector.setAttribute('role', 'group');

    for (const pol of ['accept', 'ask', 'deny']) {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = `policy-option${pol === initialPolicy ? ' active' : ''}`;
      btn.dataset.policy = pol;
      btn.dataset.certId = cert.id;
      btn.textContent = pol.toUpperCase();
      btn.addEventListener('click', () => {
        selectedPolicies.set(cert.id, pol);
        for (const sibling of selector.querySelectorAll('.policy-option')) {
          sibling.classList.toggle('active', sibling.dataset.policy === pol);
        }
      });
      selector.appendChild(btn);
    }
    header.appendChild(selector);
  }

  const meta = document.createElement('div');
  meta.className = 'cert-meta';

  const orgDiv = document.createElement('div');
  orgDiv.innerHTML = `<strong>Organization:</strong> `;
  orgDiv.append(document.createTextNode(cert.organization || cert.commonName));

  const issuerDiv = document.createElement('div');
  issuerDiv.innerHTML = `<strong>Issued By:</strong> `;
  issuerDiv.append(document.createTextNode(cert.issuerCommonName || 'Self-Signed'));

  const validDiv = document.createElement('div');
  validDiv.innerHTML = `<strong>Valid Until:</strong> `;
  validDiv.append(document.createTextNode((cert.notAfter || '').slice(0, 10)));

  const sigDiv = document.createElement('div');
  sigDiv.innerHTML = `<strong>Algorithm:</strong> `;
  sigDiv.append(document.createTextNode(cert.signatureAlgorithm || 'Unknown'));

  meta.append(orgDiv, issuerDiv, validDiv, sigDiv);

  const fpDiv = document.createElement('div');
  fpDiv.className = 'fp-code';
  fpDiv.textContent = `SHA-256: ${cert.fingerprint || cert.id}`;

  card.append(header, meta, fpDiv);
  return card;
}

async function loadChainDetails() {
  document.getElementById('target-url').textContent = targetUrl || `https://${host}`;

  const response = await chrome.runtime.sendMessage({
    action: 'inspect_host',
    host,
    port,
    force: false
  });

  const chainList = document.getElementById('chain-list');
  chainList.textContent = '';

  if (!response || !response.ok) {
    document.getElementById('trigger-reason').textContent =
      (response && response.error) || 'Unable to inspect certificate chain';
    return;
  }

  currentInspection = response;
  const { evaluation } = response;
  document.getElementById('trigger-reason').textContent = evaluation.reason;

  // Render hierarchy from Root CA -> Intermediate CA(s) -> Leaf Certificate
  if (evaluation.root) {
    chainList.appendChild(createCertCard(evaluation.root, true));
  }

  const intermediatesTopDown = [...(evaluation.intermediates || [])].reverse();
  for (const intCert of intermediatesTopDown) {
    chainList.appendChild(createCertCard(intCert, true));
  }

  if (evaluation.leaf) {
    chainList.appendChild(createCertCard(evaluation.leaf, false));
  }
}

async function submitDecision(decisionMode, policyOverride = null) {
  if (!currentInspection || !currentInspection.evaluation) return;
  const { evaluation } = currentInspection;
  const authorities = [
    ...(evaluation.root ? [evaluation.root] : []),
    ...(evaluation.intermediates || [])
  ];

  const updates = authorities.map((cert) => ({
    id: cert.id,
    commonName: cert.commonName,
    policy: policyOverride ? policyOverride : selectedPolicies.get(cert.id) || cert.policy
  }));

  const currentTabId =
    tabId !== null && tabId >= 0
      ? tabId
      : (await chrome.tabs.getCurrent())?.id ?? -1;

  const res = await chrome.runtime.sendMessage({
    action: 'submit_prompt_decision',
    decisionMode,
    updates,
    host,
    port,
    targetUrl,
    tabId: currentTabId
  });

  if (res && res.ok) {
    if (res.nextAction === 'navigate' && res.targetUrl) {
      window.location.replace(res.targetUrl);
    } else if (res.nextAction === 'blocked' && res.blockedUrl) {
      window.location.replace(res.blockedUrl);
    }
  }
}

document.getElementById('btn-accept-all').addEventListener('click', async () => {
  await submitDecision('accept', 'accept');
});

document.getElementById('btn-ask-once').addEventListener('click', async () => {
  await submitDecision('ask_allow_once', 'ask');
});

document.getElementById('btn-deny-all').addEventListener('click', async () => {
  await submitDecision('deny', 'deny');
});

document.getElementById('btn-apply-custom').addEventListener('click', async () => {
  const values = Array.from(selectedPolicies.values());
  let mode = 'accept';
  if (values.includes('deny')) {
    mode = 'deny';
  } else if (values.includes('ask')) {
    mode = 'ask_allow_once';
  }
  await submitDecision(mode, null);
});

document.getElementById('btn-open-options').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});

loadChainDetails();
