#!/usr/bin/env node
/**
 * Capture high-DPI screenshots of Indy extension pages for documentation.
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
const OUT_DIR = path.join(__dirname, '..', 'docs', 'screenshots');

fs.mkdirSync(OUT_DIR, { recursive: true });

async function capture() {
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
    await page.setViewport({ width: 1200, height: 800, deviceScaleFactor: 2 });

    // 1. Capture Options / Database Manager
    console.log('Capturing options page...');
    await page.goto(`chrome-extension://${EXT_ID}/options/options.html`, { waitUntil: 'networkidle0' });
    await page.waitForFunction(() => {
      const el = document.getElementById('stat-roots');
      return el && parseInt(el.textContent, 10) > 50;
    }, { timeout: 10000 });
    // Let table render
    await new Promise(r => setTimeout(r, 600));
    const optionsPath = path.join(OUT_DIR, 'options.png');
    await page.screenshot({ path: optionsPath, fullPage: false });
    console.log(`Saved ${optionsPath}`);

    // 1b. Capture Upload Modal
    console.log('Capturing upload root certificate modal...');
    await page.click('#btn-open-upload');
    await page.waitForFunction(() => {
      const modal = document.getElementById('upload-modal');
      return modal && !modal.classList.contains('hidden');
    });
    // Add sample PEM text so preview shows in screenshot
    await page.evaluate(() => {
      const textarea = document.getElementById('pem-textarea');
      textarea.value = `-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIUS2d...SAMPLE ENTERPRISE ROOT CA...==\n-----END CERTIFICATE-----`;
    });
    await new Promise(r => setTimeout(r, 400));
    const modalPath = path.join(OUT_DIR, 'upload_modal.png');
    await page.screenshot({ path: modalPath, fullPage: false });
    console.log(`Saved ${modalPath}`);
    await page.click('#btn-close-modal');
    await new Promise(r => setTimeout(r, 300));

    // 2. Capture Interstitial Prompt UI
    console.log('Capturing prompt page...');
    await page.setViewport({ width: 1000, height: 820, deviceScaleFactor: 2 });
    const promptUrl = `chrome-extension://${EXT_ID}/prompt/prompt.html?target=https%3A%2F%2Fwww.google.com&host=www.google.com&port=443`;
    await page.goto(promptUrl, { waitUntil: 'networkidle0' });
    await page.waitForSelector('.cert-card');
    await new Promise(r => setTimeout(r, 600));
    const promptPath = path.join(OUT_DIR, 'prompt.png');
    await page.screenshot({ path: promptPath, fullPage: false });
    console.log(`Saved ${promptPath}`);

    // 3. Capture Blocked UI
    console.log('Capturing blocked page...');
    const blockedUrl = `chrome-extension://${EXT_ID}/blocked/blocked.html?target=https%3A%2F%2Findy.test.local&host=indy.test.local&port=443`;
    await page.goto(blockedUrl, { waitUntil: 'networkidle0' });
    await page.waitForSelector('.cert-item');
    await new Promise(r => setTimeout(r, 600));
    const blockedPath = path.join(OUT_DIR, 'blocked.png');
    await page.screenshot({ path: blockedPath, fullPage: false });
    console.log(`Saved ${blockedPath}`);

    // 4. Capture Popup UI
    console.log('Capturing popup page...');
    await page.setViewport({ width: 420, height: 500, deviceScaleFactor: 2 });
    await page.goto(`chrome-extension://${EXT_ID}/popup/popup.html`, { waitUntil: 'networkidle0' });
    await new Promise(r => setTimeout(r, 800));
    const popupPath = path.join(OUT_DIR, 'popup.png');
    await page.screenshot({ path: popupPath, fullPage: false });
    console.log(`Saved ${popupPath}`);

    console.log('All screenshots captured successfully.');
  } finally {
    await browser.close();
  }
}

capture().catch(err => {
  console.error('Screenshot capture failed:', err);
  process.exit(1);
});
