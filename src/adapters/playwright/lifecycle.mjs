import path from 'node:path';
import fs from 'node:fs';
import { spawn, execSync } from 'node:child_process';
import { chromium } from 'playwright';
import {
  RUNTIME_ROOT,
  ROLES,
  RESOURCE_ROLES,
  REGISTRATION_SOURCES,
  S2_5_PLAYWRIGHT_CONFIG
} from '../../core/config.mjs';
import {
  getProcessSnapshot,
  checkProcessAlive
} from '../../core/identity.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Finds direct child PIDs of a given parent process using pgrep.
 *
 * @param {number} ppid
 * @returns {number[]}
 */
export function getChildPids(ppid) {
  if (typeof ppid !== 'number' || ppid <= 0) return [];
  try {
    const out = execSync(`pgrep -P ${ppid}`, { stdio: ['pipe', 'pipe', 'ignore'] }).toString().trim();
    if (!out) return [];
    return out.split('\n').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n) && n > 0);
  } catch (e) {
    return [];
  }
}

/**
 * Launches a new test Playwright browser in either persistent or background mode.
 * Enforces dedicated test profile isolation and Broker creation-time attestation.
 *
 * @param {string} sessionId
 * @param {Object} broker - Active SupervisorBroker instance
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function launchTestBrowser(sessionId, broker, options = {}) {
  const mode = options.mode || 'background'; // 'background' or 'persistent'
  const profileName = options.profileName || `playwright-profile-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`;
  const userDataDir = options.userDataDir || (
    options.useResourcesRoot
      ? path.join(RUNTIME_ROOT, 'sessions', sessionId, 'resources', 'playwright-profile', profileName)
      : path.join(RUNTIME_ROOT, 'sessions', sessionId, profileName)
  );
  fs.mkdirSync(userDataDir, { recursive: true });

  const launcherPid = process.pid;

  // 1. Pre-authorize launch with Broker
  const ticketRes = broker.requestLaunchIntent({
    launcherCapabilityToken: broker.launcherCapabilityToken,
    launcherPid,
    role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
    ttlMs: 15000
  });

  if (!ticketRes.success) {
    throw new Error(`Failed to get launch ticket from broker: ${ticketRes.error}`);
  }

  const ticketId = ticketRes.ticketId;
  let browser = null;
  let context = null;
  let page = null;
  let mainPid = null;

  const priorChildren = new Set(getChildPids(launcherPid));

  if (mode === 'persistent') {
    context = await chromium.launchPersistentContext(userDataDir, {
      headless: true,
      args: ['--no-sandbox']
    });
    page = context.pages().length > 0 ? context.pages()[0] : await context.newPage();
    // In persistent context, chromium process is a child of our node process
    const children = getChildPids(launcherPid);
    // Find the new chromium process among children
    for (const c of children) {
      if (priorChildren.has(c)) continue;
      const snap = getProcessSnapshot(c);
      if (snap && (/chrome/i.test(snap.comm) || /chrome/i.test(snap.canonicalExecutable))) {
        mainPid = c;
        break;
      }
    }
  } else {
    // Background / Ephemeral mode
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox']
    });
    context = await browser.newContext();
    page = await context.newPage();
    const children = getChildPids(launcherPid);
    for (const c of children) {
      if (priorChildren.has(c)) continue;
      const snap = getProcessSnapshot(c);
      if (snap && (/chrome/i.test(snap.comm) || /chrome/i.test(snap.canonicalExecutable))) {
        mainPid = c;
        break;
      }
    }
  }

  if (!mainPid) {
    throw new Error('Failed to identify Chromium main process PID');
  }

  // 2. Attest Main Browser with Broker
  const attestRes = broker.attestSpawn({
    ticketId,
    pid: mainPid,
    role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
    safeToKill: true
  });

  if (!attestRes.success) {
    throw new Error(`Failed to attest browser main with broker: ${attestRes.error}`);
  }

  // Give Chromium a brief moment to initialize GPU/utility helpers
  await sleep(150);

  // 3. Discover and attest helper children
  const helperPids = getChildPids(mainPid);
  const helperRecords = [];

  for (const hPid of helperPids) {
    const hRes = broker.attestPlaywrightHelper({
      launcherCapabilityToken: broker.launcherCapabilityToken,
      parentBrowserPid: mainPid,
      helperPid: hPid,
      role: ROLES.PLAYWRIGHT_HELPER
    });
    if (hRes.success) {
      helperRecords.push(hRes.record);
    }
  }

  let profileReceipt = null;
  if (options.attestProfile && typeof broker.attestResourceReceipt === 'function') {
    const pRes = broker.attestResourceReceipt({
      targetPath: userDataDir,
      resourceRole: RESOURCE_ROLES.PLAYWRIGHT_TEST_PROFILE,
      creatorPid: mainPid,
      creationSource: 'PLAYWRIGHT_TEST_CREATED',
      owningPid: mainPid
    });
    if (pRes.success) {
      profileReceipt = pRes.receipt;
    }
  }

  return {
    mode,
    browser,
    context,
    page,
    mainPid,
    helperPids,
    helperRecords,
    record: attestRes.record,
    userDataDir,
    profileReceipt,
    launcherPid,
    async close() {
      if (context) await context.close();
      if (browser) await browser.close();
    }
  };
}

/**
 * Resolves the path to the pure POSIX chrome-headless-shell binary if installed by Playwright.
 * On macOS, Google Chrome for Testing is a Cocoa app bundle that ignores POSIX signals when detached,
 * whereas chrome-headless-shell cleanly responds to standard POSIX SIGTERM.
 *
 * @returns {string}
 */
export function getChromiumHeadlessShellPath() {
  const exe = chromium.executablePath();
  const shell = exe.replace('chromium-', 'chromium_headless_shell-').replace(
    'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing',
    'chrome-headless-shell-mac-arm64/chrome-headless-shell'
  );
  if (fs.existsSync(shell)) return shell;
  return exe;
}

/**
 * Spawns an orphaned test Playwright Chromium instance where the launcher process exits immediately.
 * This simulates a real-world launcher crash where Chromium remains as an orphan (PPID=1).
 *
 * @param {string} sessionId
 * @param {Object} broker - Active SupervisorBroker instance
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function launchOrphanTestBrowser(sessionId, broker, options = {}) {
  const profileName = options.profileName || `playwright-orphan-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`;
  const userDataDir = path.join(RUNTIME_ROOT, 'sessions', sessionId, profileName);
  fs.mkdirSync(userDataDir, { recursive: true });

  const exePath = getChromiumHeadlessShellPath();

  // Launcher child process that starts detached Chromium and exits immediately
  return new Promise((resolve, reject) => {
    // 1. Pre-register launcher intent
    const launcherScript = `
      const { spawn } = require('child_process');
      const fs = require('fs');

      const child = spawn(process.env.TEST_CHROME_EXE, [
        '--headless',
        '--user-data-dir=' + process.env.TEST_USER_DATA_DIR,
        '--no-sandbox',
        '--disable-gpu',
        '--remote-debugging-port=0'
      ], {
        detached: true,
        stdio: 'ignore'
      });

      console.log('ORPHAN_MAIN_PID:' + child.pid);
      // Exit after giving parent time to read PID
      setTimeout(() => { process.exit(0); }, 100);
    `;

    const launcher = spawn(process.execPath, ['-e', launcherScript], {
      stdio: ['pipe', 'pipe', 'inherit'],
      env: {
        ...process.env,
        TEST_CHROME_EXE: exePath,
        TEST_USER_DATA_DIR: userDataDir
      }
    });

    const launcherPid = launcher.pid;

    // Pre-authorize with Broker using the launcher PID
    const ticketRes = broker.requestLaunchIntent({
      launcherCapabilityToken: broker.launcherCapabilityToken,
      launcherPid,
      role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
      ttlMs: 15000
    });

    if (!ticketRes.success) {
      launcher.kill('SIGKILL');
      return reject(new Error(`Failed to get launch ticket: ${ticketRes.error}`));
    }

    const ticketId = ticketRes.ticketId;

    launcher.stdout.on('data', async (data) => {
      const match = data.toString().match(/ORPHAN_MAIN_PID:(\d+)/);
      if (match) {
        const mainPid = parseInt(match[1], 10);

        // Attest spawn with Broker
        const attestRes = broker.attestSpawn({
          ticketId,
          pid: mainPid,
          role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
          safeToKill: true
        });

        if (!attestRes.success) {
          return reject(new Error(`Attest orphan failed: ${attestRes.error}`));
        }

        // Wait for launcher to exit naturally
        await sleep(300);

        // Verify launcher is dead
        const launcherAlive = checkProcessAlive(launcherPid);
        // Discover any sub-helpers
        const helperPids = getChildPids(mainPid);

        resolve({
          mainPid,
          helperPids,
          record: attestRes.record,
          userDataDir,
          launcherPid,
          launcherDead: !launcherAlive
        });
      }
    });

    launcher.on('error', reject);
  });
}

/**
 * Detects whether the Playwright Chromium binary is available locally.
 *
 * @returns {boolean}
 */
export function isPlaywrightChromiumInstalled() {
  try {
    const execPath = chromium.executablePath();
    return Boolean(execPath && fs.existsSync(execPath));
  } catch (_) {
    return false;
  }
}
