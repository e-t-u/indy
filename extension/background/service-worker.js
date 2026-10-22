/**
 * Indy — Root & Intermediate Certificate Trust Guard
 * Manifest V3 Background Service Worker
 *
 * State is persisted exclusively in chrome.storage.local (certificate database,
 * user policies, settings, audit log) and chrome.storage.session (per-tab state,
 * temporary "allow once" approvals, short-lived host chain cache).
 */

const HOST_HTTP_URL = 'http://127.0.0.1:7879';
const NATIVE_HOST_NAME = 'com.etu.indy';
const HOST_CACHE_TTL_MS = 5 * 60 * 1000;
const ALLOW_ONCE_TTL_MS = 60 * 1000;

const DEFAULT_SETTINGS = {
  defaultRootPolicy: 'ask',
  defaultIntermediatePolicy: 'ask',
  enforceIntermediates: true
};

/**
 * Communicate with the Indy Certificate Host via HTTP bridge (preferred for
 * Flatpak / Chromium compatibility) with automatic fallback to Chrome Native Messaging.
 */
async function callIndyHost(payload) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(`${HOST_HTTP_URL}/rpc`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (response.ok) {
      return await response.json();
    }
  } catch (_httpErr) {
    // Fallback to Chrome Native Messaging stdio transport
  }

  try {
    return await chrome.runtime.sendNativeMessage(NATIVE_HOST_NAME, payload);
  } catch (nativeErr) {
    return {
      ok: false,
      error: `Indy host unreachable via HTTP (${HOST_HTTP_URL}) and Native Messaging (${NATIVE_HOST_NAME}): ${nativeErr.message || String(nativeErr)}`
    };
  }
}

/**
 * Retrieve persistent database and settings from chrome.storage.local.
 */
async function getStoredState() {
  const data = await chrome.storage.local.get({
    certDatabase: {},
    settings: DEFAULT_SETTINGS,
    auditLog: [],
    bootstrappedAt: null,
    bundlePath: null
  });
  return {
    certDatabase: data.certDatabase || {},
    settings: { ...DEFAULT_SETTINGS, ...(data.settings || {}) },
    auditLog: Array.isArray(data.auditLog) ? data.auditLog : [],
    bootstrappedAt: data.bootstrappedAt,
    bundlePath: data.bundlePath
  };
}

/**
 * Bootstrap or synchronize the certificate database from OS system root certificates.
 */
async function syncSystemRoots(forceReload = false) {
  const hostRes = await callIndyHost({
    action: 'get_system_roots',
    reload: Boolean(forceReload)
  });

  if (!hostRes || !hostRes.ok || !Array.isArray(hostRes.roots)) {
    return {
      ok: false,
      error: (hostRes && hostRes.error) || 'Failed to retrieve system root certificates'
    };
  }

  const { certDatabase, settings } = await getStoredState();
  const nowIso = new Date().toISOString();
  let addedCount = 0;
  let updatedCount = 0;

  for (const root of hostRes.roots) {
    const existing = certDatabase[root.id];
    if (!existing) {
      certDatabase[root.id] = {
        ...root,
        role: root.role || 'root',
        source: root.source || 'system',
        policy: settings.defaultRootPolicy || 'ask',
        firstSeenAt: nowIso,
        updatedAt: nowIso
      };
      addedCount += 1;
    } else {
      certDatabase[root.id] = {
        ...existing,
        ...root,
        policy: existing.policy || settings.defaultRootPolicy || 'ask',
        updatedAt: nowIso
      };
      updatedCount += 1;
    }
  }

  await chrome.storage.local.set({
    certDatabase,
    bootstrappedAt: nowIso,
    bundlePath: hostRes.bundlePath || null
  });

  return {
    ok: true,
    totalInDb: Object.keys(certDatabase).length,
    systemRootCount: hostRes.roots.length,
    addedCount,
    updatedCount,
    bundlePath: hostRes.bundlePath || null
  };
}

/**
 * Ensure all authority certificates (Root + Intermediates) from a resolved TLS chain
 * are registered in certDatabase and return their enriched database records.
 */
async function registerChainAuthorities(chainResult) {
  const { certDatabase, settings } = await getStoredState();
  const nowIso = new Date().toISOString();
  let dbModified = false;

  const authorities = [
    ...(Array.isArray(chainResult.intermediates) ? chainResult.intermediates : []),
    ...(chainResult.root ? [chainResult.root] : [])
  ];

  for (const cert of authorities) {
    if (!cert || !cert.id) continue;
    const existing = certDatabase[cert.id];
    const defaultPolicy =
      cert.role === 'intermediate'
        ? settings.defaultIntermediatePolicy || 'ask'
        : settings.defaultRootPolicy || 'ask';

    if (!existing) {
      certDatabase[cert.id] = {
        ...cert,
        policy: defaultPolicy,
        firstSeenAt: nowIso,
        updatedAt: nowIso
      };
      dbModified = true;
    } else if (cert.parentId && !existing.parentId) {
      existing.parentId = cert.parentId;
      existing.updatedAt = nowIso;
      dbModified = true;
    }
  }

  if (dbModified) {
    await chrome.storage.local.set({ certDatabase });
  }

  return { certDatabase, settings };
}

/**
 * Evaluate a resolved TLS certificate chain against the stored policies for both
 * the Root CA and all Intermediate CAs in the chain.
 *
 * Precedence:
 * 1. If ANY certificate (Root or Intermediate) has policy === 'deny' -> 'deny'
 * 2. If ANY enforced certificate (Root, or Intermediate when enforceIntermediates is true)
 *    has policy !== 'accept' (i.e. 'ask') -> 'ask'
 * 3. Otherwise -> 'accept'
 */
function evaluateChainPolicy(chainResult, certDatabase, settings) {
  const rootRaw = chainResult.root;
  const intermediatesRaw = Array.isArray(chainResult.intermediates)
    ? chainResult.intermediates
    : [];

  const enrich = (c, fallbackRole) => {
    if (!c) return null;
    const dbEntry = certDatabase[c.id];
    const defaultPol =
      (c.role || fallbackRole) === 'intermediate'
        ? settings.defaultIntermediatePolicy || 'ask'
        : settings.defaultRootPolicy || 'ask';
    return {
      ...c,
      ...(dbEntry || {}),
      role: c.role || fallbackRole,
      policy: dbEntry && dbEntry.policy ? dbEntry.policy : defaultPol
    };
  };

  const root = enrich(rootRaw, 'root');
  const intermediates = intermediatesRaw.map((c) => enrich(c, 'intermediate')).filter(Boolean);
  const allAuthorities = [...intermediates, ...(root ? [root] : [])];

  const deniedCerts = allAuthorities.filter((c) => c.policy === 'deny');
  if (deniedCerts.length > 0) {
    return {
      decision: 'deny',
      reason: `Blocked by ${deniedCerts.map((c) => `${c.role.toUpperCase()} "${c.commonName}"`).join(', ')}`,
      triggeringCerts: deniedCerts,
      root,
      intermediates,
      leaf: chainResult.leaf || null
    };
  }

  const enforcedAuthorities =
    settings.enforceIntermediates !== false
      ? allAuthorities
      : root
        ? [root]
        : [];

  const askCerts = enforcedAuthorities.filter((c) => c.policy !== 'accept');
  if (askCerts.length > 0) {
    return {
      decision: 'ask',
      reason: `Confirmation required for ${askCerts.map((c) => `${c.role.toUpperCase()} "${c.commonName}" (${c.policy})`).join(', ')}`,
      triggeringCerts: askCerts,
      root,
      intermediates,
      leaf: chainResult.leaf || null
    };
  }

  return {
    decision: 'accept',
    reason: `Trusted chain anchored by Root "${root ? root.commonName : 'Unknown'}"`,
    triggeringCerts: [],
    root,
    intermediates,
    leaf: chainResult.leaf || null
  };
}

/**
 * Resolve TLS chain for host:port with session caching.
 */
async function resolveHostChain(host, port = 443, forceRefresh = false) {
  const cleanHost = String(host || '').trim().toLowerCase();
  const cacheKey = `${cleanHost}:${port}`;

  if (!forceRefresh) {
    const { hostChainCache = {} } = await chrome.storage.session.get('hostChainCache');
    const cached = hostChainCache[cacheKey];
    if (cached && Date.now() - cached.cachedAt < HOST_CACHE_TTL_MS) {
      return cached.result;
    }
  }

  const result = await callIndyHost({
    action: 'resolve_chain',
    host: cleanHost,
    port: Number(port || 443),
    force: Boolean(forceRefresh)
  });

  if (result && result.ok) {
    const { hostChainCache = {} } = await chrome.storage.session.get('hostChainCache');
    hostChainCache[cacheKey] = {
      cachedAt: Date.now(),
      result
    };
    await chrome.storage.session.set({ hostChainCache });
  }

  return result;
}

/**
 * Record an entry in the persistent audit log (keeps most recent 100 entries).
 */
async function appendAuditLog(entry) {
  const { auditLog = [] } = await chrome.storage.local.get('auditLog');
  const updated = [
    {
      timestamp: new Date().toISOString(),
      ...entry
    },
    ...auditLog
  ].slice(0, 100);
  await chrome.storage.local.set({ auditLog: updated });
}

/**
 * Compute deterministic numeric rule ID from hostname for declarativeNetRequest session rules.
 */
function hostToRuleId(host) {
  let hash = 5381;
  const str = String(host).toLowerCase();
  for (let i = 0; i < str.length; i += 1) {
    hash = ((hash << 5) + hash + str.charCodeAt(i)) & 0x3fffffff;
  }
  return (hash % 900000) + 1000;
}

/**
 * Update declarativeNetRequest session blocking rule for a specific host.
 */
async function syncHostDnrBlockRule(host, shouldBlock) {
  const ruleId = hostToRuleId(host);
  const addRules = shouldBlock
    ? [
        {
          id: ruleId,
          priority: 1,
          action: { type: 'block' },
          condition: {
            urlFilter: `||${host}^`,
            resourceTypes: [
              'xmlhttprequest',
              'script',
              'image',
              'stylesheet',
              'sub_frame',
              'media',
              'font',
              'websocket'
            ]
          }
        }
      ]
    : [];

  try {
    await chrome.declarativeNetRequest.updateSessionRules({
      removeRuleIds: [ruleId],
      addRules
    });
  } catch (_err) {
    // Ignore DNR update race conditions
  }
}

/**
 * Update extension badge for a specific tab to reflect the active certificate status.
 */
async function updateTabBadge(tabId, decision) {
  if (typeof tabId !== 'number' || tabId < 0) return;
  const badgeMap = {
    accept: { text: 'OK', color: '#10B981' },
    ask: { text: 'ASK', color: '#F59E0B' },
    deny: { text: 'DENY', color: '#EF4444' },
    err: { text: 'ERR', color: '#64748B' }
  };
  const cfg = badgeMap[decision] || badgeMap.err;
  try {
    await chrome.action.setBadgeText({ tabId, text: cfg.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
  } catch (_err) {
    // Tab may have closed before badge update completed
  }
}

/**
 * Check if host has an active temporary "Allow Once" approval in session storage.
 * Matches exact host, root domain, or www. variant.
 */
async function hasAllowOncePass(host) {
  const cleanHost = String(host || '').toLowerCase();
  const rootDomain = cleanHost.replace(/^www\./, '');
  const { allowOnceHosts = {} } = await chrome.storage.session.get('allowOnceHosts');
  const expiry =
    allowOnceHosts[cleanHost] ||
    allowOnceHosts[rootDomain] ||
    allowOnceHosts[`www.${rootDomain}`];
  if (expiry && Date.now() < expiry) {
    return true;
  }
  return false;
}

/**
 * Grant a temporary "Allow Once" pass for a host so navigation proceeds when user
 * selects "Ask Every Time (Allow This Visit)" without flipping the CA policy to "accept".
 */
async function grantAllowOncePass(host, durationMs = ALLOW_ONCE_TTL_MS) {
  const cleanHost = String(host || '').toLowerCase();
  const rootDomain = cleanHost.replace(/^www\./, '');
  const { allowOnceHosts = {} } = await chrome.storage.session.get('allowOnceHosts');
  const expiresAt = Date.now() + durationMs;
  allowOnceHosts[cleanHost] = expiresAt;
  allowOnceHosts[rootDomain] = expiresAt;
  allowOnceHosts[`www.${rootDomain}`] = expiresAt;
  await chrome.storage.session.set({ allowOnceHosts });
}

/**
 * Inspect a host's TLS certificate chain and return full evaluation details.
 */
async function inspectHost(host, port = 443, forceRefresh = false) {
  const chainResult = await resolveHostChain(host, port, forceRefresh);
  if (!chainResult || !chainResult.ok) {
    return {
      ok: false,
      host,
      port,
      error: (chainResult && chainResult.error) || 'Failed to resolve TLS chain'
    };
  }

  const { certDatabase, settings } = await registerChainAuthorities(chainResult);
  const evaluation = evaluateChainPolicy(chainResult, certDatabase, settings);

  return {
    ok: true,
    host: chainResult.host,
    port: chainResult.port,
    verified: chainResult.verified,
    chainResult,
    evaluation
  };
}

/**
 * Store per-tab certificate inspection result in chrome.storage.session.
 */
async function saveTabState(tabId, stateObj) {
  if (typeof tabId !== 'number' || tabId < 0) return;
  const { tabStates = {} } = await chrome.storage.session.get('tabStates');
  tabStates[String(tabId)] = {
    ...stateObj,
    updatedAt: new Date().toISOString()
  };
  await chrome.storage.session.set({ tabStates });
}

/**
 * Core Navigation Enforcement Engine
 * Handles top-level navigations across all stages:
 * - onBeforeNavigate: Early interception & background TLS cache pre-warming
 * - onCommitted: Post-redirect commitment enforcement (catches http->https 301/302 redirects)
 * - onHistoryStateUpdated: Single-page application router transitions
 */
async function enforceNavigation(details, stage = 'before') {
  if (details.frameId !== 0) return;
  if (!details.url) return;
  if (
    details.url.startsWith('chrome-extension://') ||
    details.url.startsWith('chrome://') ||
    details.url.startsWith('about:')
  ) {
    return;
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(details.url);
  } catch (_err) {
    return;
  }

  // If user entered http:// (e.g. "aliexpress.com"), pre-warm TLS inspection for https in background
  if (parsedUrl.protocol === 'http:') {
    const rawHost = parsedUrl.hostname.toLowerCase();
    resolveHostChain(rawHost, 443, false).catch(() => {});
    return;
  }

  if (parsedUrl.protocol !== 'https:') return;

  const host = parsedUrl.hostname.toLowerCase();
  const port = Number(parsedUrl.port || 443);
  const tabId = details.tabId;

  const inspection = await inspectHost(host, port, false);
  if (!inspection.ok) {
    await updateTabBadge(tabId, 'err');
    await saveTabState(tabId, {
      ok: false,
      url: details.url,
      host,
      port,
      error: inspection.error
    });
    return;
  }

  const { evaluation, chainResult } = inspection;
  const rootName = evaluation.root ? evaluation.root.commonName : 'Unknown';
  const intNames = evaluation.intermediates.map((i) => i.commonName);

  await saveTabState(tabId, {
    ok: true,
    url: details.url,
    host,
    port,
    chainResult,
    evaluation
  });

  if (evaluation.decision === 'accept') {
    await syncHostDnrBlockRule(host, false);
    await updateTabBadge(tabId, 'accept');
    await appendAuditLog({
      host,
      url: details.url,
      rootCommonName: rootName,
      intermediateCommonNames: intNames,
      decision: 'accept',
      reason: evaluation.reason,
      stage
    });
    return;
  }

  if (evaluation.decision === 'deny') {
    await syncHostDnrBlockRule(host, true);
    await updateTabBadge(tabId, 'deny');
    await appendAuditLog({
      host,
      url: details.url,
      rootCommonName: rootName,
      intermediateCommonNames: intNames,
      decision: 'deny',
      reason: evaluation.reason,
      stage
    });

    const blockedUrl = new URL(chrome.runtime.getURL('blocked/blocked.html'));
    blockedUrl.searchParams.set('target', details.url);
    blockedUrl.searchParams.set('host', host);
    blockedUrl.searchParams.set('port', String(port));
    blockedUrl.searchParams.set('tabId', String(tabId));
    try {
      await chrome.tabs.update(tabId, { url: blockedUrl.toString() });
    } catch (_err) {
      // Ignore if tab closed
    }
    return;
  }

  // evaluation.decision === 'ask'
  const allowedOnce = await hasAllowOncePass(host);
  if (allowedOnce) {
    await syncHostDnrBlockRule(host, false);
    await updateTabBadge(tabId, 'ask');
    await appendAuditLog({
      host,
      url: details.url,
      rootCommonName: rootName,
      intermediateCommonNames: intNames,
      decision: 'ask_allowed_once',
      reason: 'User granted temporary one-time visit approval (policy remains ask)',
      stage
    });
    return;
  }

  await updateTabBadge(tabId, 'ask');
  await appendAuditLog({
    host,
    url: details.url,
    rootCommonName: rootName,
    intermediateCommonNames: intNames,
    decision: 'ask_prompted',
    reason: evaluation.reason,
    stage
  });

  const promptUrl = new URL(chrome.runtime.getURL('prompt/prompt.html'));
  promptUrl.searchParams.set('target', details.url);
  promptUrl.searchParams.set('host', host);
  promptUrl.searchParams.set('port', String(port));
  promptUrl.searchParams.set('tabId', String(tabId));
  try {
    await chrome.tabs.update(tabId, { url: promptUrl.toString() });
  } catch (_err) {
    // Ignore if tab closed
  }
}

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  enforceNavigation(details, 'before_navigate');
});

chrome.webNavigation.onCommitted.addListener((details) => {
  enforceNavigation(details, 'committed');
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  enforceNavigation(details, 'history_state');
});

/**
 * Update policies for one or more certificates by ID or Common Name.
 */
async function updateCertificatePolicies(updates) {
  const { certDatabase } = await getStoredState();
  const nowIso = new Date().toISOString();
  const modifiedRecords = [];

  for (const item of updates) {
    const targetPolicy = item.policy;
    if (!['accept', 'ask', 'deny'].includes(targetPolicy)) continue;

    if (item.id && certDatabase[item.id]) {
      certDatabase[item.id].policy = targetPolicy;
      certDatabase[item.id].updatedAt = nowIso;
      modifiedRecords.push(certDatabase[item.id]);
    } else if (item.commonName) {
      const needle = String(item.commonName).trim().toLowerCase();
      for (const cert of Object.values(certDatabase)) {
        if (String(cert.commonName || '').trim().toLowerCase() === needle) {
          cert.policy = targetPolicy;
          cert.updatedAt = nowIso;
          modifiedRecords.push(cert);
        }
      }
    }
  }

  await chrome.storage.local.set({ certDatabase });
  return modifiedRecords;
}

/**
 * Service Worker lifecycle hooks
 */
chrome.runtime.onInstalled.addListener(async () => {
  await syncSystemRoots(true);
});

chrome.runtime.onStartup.addListener(async () => {
  await syncSystemRoots(false);
});

/**
 * Message handler for Popup, Options, Prompt, Blocked pages, and E2E test harness.
 */
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  (async () => {
    try {
      const action = message && message.action;

      if (action === 'get_database') {
        let state = await getStoredState();
        if (Object.keys(state.certDatabase).length === 0) {
          await syncSystemRoots(false);
          state = await getStoredState();
        }
        sendResponse({ ok: true, ...state });
        return;
      }

      if (action === 'sync_system_roots') {
        const res = await syncSystemRoots(Boolean(message.force));
        sendResponse(res);
        return;
      }

      if (action === 'inspect_host') {
        const res = await inspectHost(
          message.host,
          Number(message.port || 443),
          Boolean(message.force)
        );
        sendResponse(res);
        return;
      }

      if (action === 'get_tab_state') {
        const tabId = Number(message.tabId);
        const { tabStates = {} } = await chrome.storage.session.get('tabStates');
        const existing = tabStates[String(tabId)];
        if (existing) {
          // Re-evaluate against latest certDatabase in case user toggled policies
          if (existing.chainResult) {
            const { certDatabase, settings } = await getStoredState();
            existing.evaluation = evaluateChainPolicy(
              existing.chainResult,
              certDatabase,
              settings
            );
          }
          sendResponse({ ok: true, state: existing });
          return;
        }
        sendResponse({ ok: false, error: 'No recorded TLS state for tab' });
        return;
      }

      if (action === 'set_cert_policy') {
        const updates = Array.isArray(message.updates)
          ? message.updates
          : [
              {
                id: message.id,
                commonName: message.commonName,
                policy: message.policy
              }
            ];
        const updated = await updateCertificatePolicies(updates);
        sendResponse({ ok: true, updated });
        return;
      }

      if (action === 'bulk_set_policy') {
        const targetPolicy = message.policy;
        const roleFilter = message.role || 'all';
        if (!['accept', 'ask', 'deny'].includes(targetPolicy)) {
          sendResponse({ ok: false, error: 'Invalid policy value' });
          return;
        }
        const { certDatabase } = await getStoredState();
        const nowIso = new Date().toISOString();
        let count = 0;
        for (const cert of Object.values(certDatabase)) {
          if (roleFilter === 'all' || cert.role === roleFilter) {
            cert.policy = targetPolicy;
            cert.updatedAt = nowIso;
            count += 1;
          }
        }
        await chrome.storage.local.set({ certDatabase });
        sendResponse({ ok: true, updatedCount: count });
        return;
      }

      if (action === 'update_settings') {
        const { settings } = await getStoredState();
        const nextSettings = {
          ...settings,
          ...(message.settings || {})
        };
        await chrome.storage.local.set({ settings: nextSettings });
        sendResponse({ ok: true, settings: nextSettings });
        return;
      }

      if (action === 'submit_prompt_decision') {
        const {
          decisionMode,
          updates,
          host,
          port = 443,
          targetUrl,
          tabId
        } = message;

        if (Array.isArray(updates) && updates.length > 0) {
          await updateCertificatePolicies(updates);
        }

        // Re-evaluate chain after applying user policy updates
        const inspection = await inspectHost(host, Number(port || 443), false);
        const finalDecision =
          decisionMode === 'deny'
            ? 'deny'
            : inspection.ok
              ? inspection.evaluation.decision
              : decisionMode;

        if (decisionMode === 'ask_allow_once' || finalDecision === 'accept') {
          await syncHostDnrBlockRule(host, false);
          await grantAllowOncePass(host, ALLOW_ONCE_TTL_MS);
          await appendAuditLog({
            host,
            url: targetUrl,
            rootCommonName:
              inspection.ok && inspection.evaluation.root
                ? inspection.evaluation.root.commonName
                : 'Unknown',
            intermediateCommonNames: inspection.ok
              ? inspection.evaluation.intermediates.map((c) => c.commonName)
              : [],
            decision: decisionMode === 'ask_allow_once' ? 'ask_allowed_once' : 'accept',
            reason: `User selected ${decisionMode} on interstitial prompt`
          });

          if (typeof tabId === 'number' && tabId >= 0 && targetUrl) {
            await chrome.tabs.update(tabId, { url: targetUrl });
          }
          sendResponse({ ok: true, nextAction: 'navigate', targetUrl });
          return;
        }

        // Otherwise decision is deny
        await syncHostDnrBlockRule(host, true);
        await appendAuditLog({
          host,
          url: targetUrl,
          rootCommonName:
            inspection.ok && inspection.evaluation.root
              ? inspection.evaluation.root.commonName
              : 'Unknown',
          intermediateCommonNames: inspection.ok
            ? inspection.evaluation.intermediates.map((c) => c.commonName)
            : [],
          decision: 'deny',
          reason: 'User denied certificate authority on interstitial prompt'
        });

        const blockedUrl = new URL(chrome.runtime.getURL('blocked/blocked.html'));
        blockedUrl.searchParams.set('target', targetUrl || `https://${host}`);
        blockedUrl.searchParams.set('host', host);
        blockedUrl.searchParams.set('port', String(port));
        blockedUrl.searchParams.set('tabId', String(tabId || -1));
        if (typeof tabId === 'number' && tabId >= 0) {
          await chrome.tabs.update(tabId, { url: blockedUrl.toString() });
        }
        sendResponse({ ok: true, nextAction: 'blocked', blockedUrl: blockedUrl.toString() });
        return;
      }

      if (action === 'parse_certificate') {
        const hostRes = await callIndyHost({
          action: 'parse_certificate',
          pemData: message.pemData
        });
        sendResponse(hostRes);
        return;
      }

      if (action === 'upload_root_certificate') {
        const hostRes = await callIndyHost({
          action: 'upload_root_certificate',
          pemData: message.pemData,
          policy: message.policy || 'ask'
        });

        if (!hostRes || !hostRes.ok) {
          sendResponse({
            ok: false,
            error: (hostRes && hostRes.error) || 'Failed to upload certificate to host'
          });
          return;
        }

        const { certDatabase } = await getStoredState();
        const nowIso = new Date().toISOString();
        const certsToSave = Array.isArray(hostRes.certs) ? hostRes.certs : [hostRes.cert];

        for (const c of certsToSave) {
          if (!c || !c.id) continue;
          certDatabase[c.id] = {
            ...c,
            policy: message.policy || 'ask',
            source: 'custom',
            firstSeenAt: nowIso,
            updatedAt: nowIso
          };
        }

        await chrome.storage.local.set({ certDatabase });
        sendResponse({
          ok: true,
          count: certsToSave.length,
          cert: certsToSave[0]
        });
        return;
      }

      if (action === 'delete_certificate') {
        const certId = message.id;
        const { certDatabase } = await getStoredState();
        delete certDatabase[certId];
        await chrome.storage.local.set({ certDatabase });

        // Also notify host to remove file from ~/.config/indy/custom_roots
        await callIndyHost({
          action: 'delete_custom_root',
          id: certId
        });

        sendResponse({ ok: true });
        return;
      }

      if (action === 'clear_audit_log') {
        await chrome.storage.local.set({ auditLog: [] });
        sendResponse({ ok: true });
        return;
      }

      sendResponse({ ok: false, error: `Unknown message action: ${action}` });
    } catch (err) {
      sendResponse({ ok: false, error: err.message || String(err) });
    }
  })();
  return true;
});
