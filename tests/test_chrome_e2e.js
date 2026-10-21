#!/usr/bin/env node
/**
 * Chrome E2E Test Suite for Indy Extension
 * Tests:
 * 1. Bootstrapping system roots & "indy" root/intermediate entries.
 * 2. "indy" Root CA lifecycle: "ask" -> "accept" -> "deny".
 * 3. Inspection & policy evaluation of Top 5 USA and Top 5 Indian websites.
 * 4. Verification of both Root and Intermediary certificates in DB.
 * 5. Options UI and Database Manager rendering.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const cp = require('child_process');

function requirePuppeteer() {
  try {
    return require('puppeteer');
  } catch (err) {
    const candidatePaths = [
      path.join(os.homedir(), 'node_modules', 'puppeteer'),
      path.join(__dirname, '..', 'node_modules', 'puppeteer'),
      path.join(__dirname, 'node_modules', 'puppeteer')
    ];
    for (const p of candidatePaths) {
      if (fs.existsSync(p)) return require(p);
    }
    throw new Error('Puppeteer is not installed. Run "npm install puppeteer".');
  }
}

function resolveChromeExecutable() {
  if (process.env.CHROME_BIN && fs.existsSync(process.env.CHROME_BIN)) {
    return process.env.CHROME_BIN;
  }
  const standardPaths = [
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  ];
  for (const p of standardPaths) {
    if (fs.existsSync(p)) return p;
  }
  for (const bin of ['google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser']) {
    try {
      const found = cp.execSync(`which ${bin} 2>/dev/null`).toString().trim();
      if (found && fs.existsSync(found)) return found;
    } catch (_) {}
  }
  const puppeteerCacheDir = path.join(os.homedir(), '.cache', 'puppeteer', 'chrome');
  if (fs.existsSync(puppeteerCacheDir)) {
    const entries = fs.readdirSync(puppeteerCacheDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        const candidateLinux = path.join(puppeteerCacheDir, entry.name, 'chrome-linux64', 'chrome');
        if (fs.existsSync(candidateLinux)) return candidateLinux;
        const candidateMac = path.join(puppeteerCacheDir, entry.name, 'chrome-mac-x64', 'Google Chrome for Testing.app', 'Contents', 'MacOS', 'Google Chrome for Testing');
        if (fs.existsSync(candidateMac)) return candidateMac;
      }
    }
  }
  return undefined;
}

const puppeteer = requirePuppeteer();

const EXT_PATH = path.join(__dirname, '..', 'extension');
const EXT_ID = 'hmfkankhnneijoaagpgpdcccmoadjaep';

const TOP_5_USA = [
  'www.google.com',
  'www.youtube.com',
  'www.amazon.com',
  'www.wikipedia.org',
  'www.reddit.com'
];

const TOP_5_INDIA = [
  'www.indiatimes.com',
  'www.flipkart.com',
  'www.ndtv.com',
  'www.hdfcbank.com',
  'www.icicibank.com'
];

function logPass(msg) {
  console.log(`\x1b[32m[PASS]\x1b[0m ${msg}`);
}

function logInfo(msg) {
  console.log(`\x1b[36m[INFO]\x1b[0m ${msg}`);
}

function logFail(msg, err) {
  console.error(`\x1b[31m[FAIL]\x1b[0m ${msg}`, err || '');
}

async function runTests() {
  logInfo('Launching Chromium with Indy extension...');

  const chromeExecutable = resolveChromeExecutable();

  const browser = await puppeteer.launch({
    executablePath: chromeExecutable,
    headless: 'new',
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      `--disable-extensions-except=${EXT_PATH}`,
      `--load-extension=${EXT_PATH}`
    ]
  });

  try {
    const page = await browser.newPage();

    // 1. Load extension options page and verify database bootstrap
    logInfo('Step 1: Verifying extension bootstrap and system roots loading...');
    const optionsUrl = `chrome-extension://${EXT_ID}/options/options.html`;
    await page.goto(optionsUrl, { waitUntil: 'networkidle0' });

    // Wait for the stats to populate
    await page.waitForFunction(() => {
      const roots = document.getElementById('stat-roots');
      return roots && parseInt(roots.textContent, 10) > 50;
    }, { timeout: 10000 });

    const stats = await page.evaluate(() => {
      return {
        roots: document.getElementById('stat-roots').textContent,
        intermediates: document.getElementById('stat-intermediates').textContent,
        accept: document.getElementById('stat-accept').textContent,
        ask: document.getElementById('stat-ask').textContent,
        deny: document.getElementById('stat-deny').textContent
      };
    });

    logPass(`Bootstrapped ${stats.roots} system roots from OS store`);
    if (parseInt(stats.roots, 10) < 50) {
      throw new Error(`Expected at least 50 system roots, got ${stats.roots}`);
    }

    // 2. Test "indy" Root CA existence and search in Options UI
    logInfo('Step 2: Testing "indy" Root CA search and policy management...');
    await page.type('#search-input', 'indy');
    await new Promise(r => setTimeout(r, 400));

    const indyFound = await page.evaluate(() => {
      const rows = Array.from(document.querySelectorAll('#cert-tbody tr'));
      return rows.some(r => r.dataset.commonName === 'indy');
    });

    if (!indyFound) {
      throw new Error('Root certificate "indy" not found in database view');
    }
    logPass('Root certificate "indy" verified in booted database table');

    // 3. Test Root & Intermediate CA chain inspection via background service worker
    logInfo('Step 3: Testing "indy" simulated host chain (Root + Intermediate + Leaf)...');
    const indyInspection = await page.evaluate(async () => {
      return await chrome.runtime.sendMessage({
        action: 'inspect_host',
        host: 'indy.test.local',
        port: 443
      });
    });

    if (!indyInspection.ok) {
      throw new Error(`Simulated chain failed: ${indyInspection.error}`);
    }
    const { evaluation: indyEval } = indyInspection;
    if (indyEval.root.commonName !== 'indy') {
      throw new Error(`Expected root "indy", got "${indyEval.root.commonName}"`);
    }
    if (indyEval.intermediates.length < 1 || indyEval.intermediates[0].commonName !== 'indy-intermediate') {
      throw new Error('Expected intermediate "indy-intermediate" in chain');
    }
    logPass(`Chain resolved: Leaf (${indyEval.leaf.commonName}) -> Intermediate (${indyEval.intermediates[0].commonName}) -> Root (${indyEval.root.commonName})`);
    logPass(`Default policy decision for "indy" chain: ${indyEval.decision.toUpperCase()}`);

    // 4. Test "Accept" policy toggle on "indy" Root CA
    logInfo('Step 4: Testing policy transition "ask" -> "accept" on "indy" Root CA...');
    await page.evaluate(async () => {
      await chrome.runtime.sendMessage({
        action: 'set_cert_policy',
        commonName: 'indy',
        policy: 'accept'
      });
      await chrome.runtime.sendMessage({
        action: 'set_cert_policy',
        commonName: 'indy-intermediate',
        policy: 'accept'
      });
    });

    const indyAccepted = await page.evaluate(async () => {
      return await chrome.runtime.sendMessage({
        action: 'inspect_host',
        host: 'indy.test.local',
        port: 443
      });
    });
    if (indyAccepted.evaluation.decision !== 'accept') {
      throw new Error(`Expected decision 'accept', got '${indyAccepted.evaluation.decision}'`);
    }
    logPass('Updated "indy" and intermediate to "accept" -> Chain decision is ACCEPT');

    // 5. Test "Deny" policy toggle on "indy" Root CA
    logInfo('Step 5: Testing policy transition "accept" -> "deny" on "indy" Root CA...');
    await page.evaluate(async () => {
      await chrome.runtime.sendMessage({
        action: 'set_cert_policy',
        commonName: 'indy',
        policy: 'deny'
      });
    });

    const indyDenied = await page.evaluate(async () => {
      return await chrome.runtime.sendMessage({
        action: 'inspect_host',
        host: 'indy.test.local',
        port: 443
      });
    });
    if (indyDenied.evaluation.decision !== 'deny') {
      throw new Error(`Expected decision 'deny', got '${indyDenied.evaluation.decision}'`);
    }
    logPass('Updated "indy" to "deny" -> Chain decision is DENY');

    // 6. Test Top 5 USA Websites live TLS chain resolution & database registration
    logInfo('Step 6: Testing Top 5 USA websites TLS chain (Root + Intermediaries)...');
    const usaResults = [];
    for (const host of TOP_5_USA) {
      const res = await page.evaluate(async (targetHost) => {
        return await chrome.runtime.sendMessage({
          action: 'inspect_host',
          host: targetHost,
          port: 443
        });
      }, host);

      if (!res.ok) {
        throw new Error(`Failed resolving TLS chain for USA host ${host}: ${res.error}`);
      }
      const rootCn = res.evaluation.root.commonName;
      const intCns = res.evaluation.intermediates.map(i => i.commonName).join(' -> ');
      usaResults.push({ host, root: rootCn, intermediates: intCns, decision: res.evaluation.decision });
      logPass(`USA [${host}]: Root="${rootCn}" | Intermediate="${intCns || 'None'}" | Decision=${res.evaluation.decision.toUpperCase()}`);
    }

    // 7. Test Top 5 Indian Websites live TLS chain resolution & database registration
    logInfo('Step 7: Testing Top 5 Indian websites TLS chain (Root + Intermediaries)...');
    const indResults = [];
    for (const host of TOP_5_INDIA) {
      const res = await page.evaluate(async (targetHost) => {
        return await chrome.runtime.sendMessage({
          action: 'inspect_host',
          host: targetHost,
          port: 443
        });
      }, host);

      if (!res.ok) {
        throw new Error(`Failed resolving TLS chain for India host ${host}: ${res.error}`);
      }
      const rootCn = res.evaluation.root.commonName;
      const intCns = res.evaluation.intermediates.map(i => i.commonName).join(' -> ');
      indResults.push({ host, root: rootCn, intermediates: intCns, decision: res.evaluation.decision });
      logPass(`IND [${host}]: Root="${rootCn}" | Intermediate="${intCns || 'None'}" | Decision=${res.evaluation.decision.toUpperCase()}`);
    }

    // 8. Test Intermediate CA specific policy control
    // Example: reddit.com (USA) and hdfcbank.com (IND) both anchor to DigiCert Global Root G2,
    // but use different Intermediate CAs!
    logInfo('Step 8: Testing Root vs. Intermediate CA differentiation (reddit vs. hdfcbank)...');
    await page.evaluate(async () => {
      // Accept root DigiCert Global Root G2
      await chrome.runtime.sendMessage({
        action: 'set_cert_policy',
        commonName: 'DigiCert Global Root G2',
        policy: 'accept'
      });
      // Accept reddit's intermediate
      await chrome.runtime.sendMessage({
        action: 'set_cert_policy',
        commonName: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1',
        policy: 'accept'
      });
      // Deny hdfcbank's intermediate
      await chrome.runtime.sendMessage({
        action: 'set_cert_policy',
        commonName: 'GeoTrust TLS RSA CA G1',
        policy: 'deny'
      });
    });

    const redditCheck = await page.evaluate(async () => {
      return await chrome.runtime.sendMessage({
        action: 'inspect_host',
        host: 'www.reddit.com',
        port: 443
      });
    });

    const hdfcCheck = await page.evaluate(async () => {
      return await chrome.runtime.sendMessage({
        action: 'inspect_host',
        host: 'www.hdfcbank.com',
        port: 443
      });
    });

    if (redditCheck.evaluation.decision !== 'accept') {
      throw new Error(`Expected reddit.com to be ACCEPT, got ${redditCheck.evaluation.decision}`);
    }
    if (hdfcCheck.evaluation.decision !== 'deny') {
      throw new Error(`Expected hdfcbank.com to be DENY (due to intermediate CA), got ${hdfcCheck.evaluation.decision}`);
    }
    logPass('Intermediary differentiation verified: reddit.com -> ACCEPT, hdfcbank.com -> DENY via intermediate CA');

    // 9. Verify Interstitial Prompt UI loading
    logInfo('Step 9: Testing prompt.html page rendering with chain hierarchy...');
    const promptUrl = `chrome-extension://${EXT_ID}/prompt/prompt.html?target=https%3A%2F%2Findy.test.local&host=indy.test.local&port=443`;
    await page.goto(promptUrl, { waitUntil: 'networkidle0' });

    await page.waitForSelector('.cert-card');
    const cardCount = await page.evaluate(() => document.querySelectorAll('.cert-card').length);
    logPass(`Prompt UI rendered ${cardCount} certificates in the chain hierarchy`);

    // 10. Verify Blocked Page UI rendering
    logInfo('Step 10: Testing blocked.html page rendering...');
    const blockedUrl = `chrome-extension://${EXT_ID}/blocked/blocked.html?target=https%3A%2F%2Findy.test.local&host=indy.test.local&port=443`;
    await page.goto(blockedUrl, { waitUntil: 'networkidle0' });

    await page.waitForSelector('.cert-item');
    const blockedReason = await page.evaluate(() => document.getElementById('blocked-reason').textContent);
    logPass(`Blocked UI rendered: "${blockedReason}"`);

    // 11. Verify real browser navigation interception on HTTP->HTTPS redirect (aliexpress.com)
    logInfo('Step 11: Testing real browser tab navigation interception on HTTP redirect (aliexpress.com)...');
    const liveNavTab = await browser.newPage();
    try {
      await liveNavTab.goto('http://aliexpress.com', { waitUntil: 'load', timeout: 15000 });
    } catch (_) {
      // Aborted by redirect to prompt.html is expected
    }
    const finalNavUrl = liveNavTab.url();
    if (!finalNavUrl.includes('prompt/prompt.html')) {
      throw new Error(`Expected navigation to redirect to prompt.html, got: ${finalNavUrl}`);
    }
    logPass(`Live tab intercepted & redirected to Indy prompt: ${finalNavUrl}`);
    await liveNavTab.close();

    console.log('\n\x1b[32m=======================================================');
    console.log('ALL INDY CHROME EXTENSION E2E TESTS PASSED SUCCESSFULLY');
    console.log('=======================================================\x1b[0m\n');

  } finally {
    await browser.close();
  }
}

runTests().catch((err) => {
  logFail('E2E Test Run Failed:', err);
  process.exit(1);
});
