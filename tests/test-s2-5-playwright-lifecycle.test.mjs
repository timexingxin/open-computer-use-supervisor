import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { chromium } from 'playwright';
import { SupervisorBroker } from '../src/broker.mjs';
import {
  ControlledTerminator,
  SignalAccounting
} from '../src/controlled-terminator.mjs';
import {
  launchTestBrowser,
  isPlaywrightChromiumInstalled,
  launchOrphanTestBrowser,
  getChildPids
} from '../src/playwright-lifecycle.mjs';
import {
  ROLES,
  REGISTRATION_SOURCES,
  S2_5_PLAYWRIGHT_CONFIG,
  PHASE_V0_1_CONFIG
} from '../src/config.mjs';
import {
  checkProcessAlive,
  getProcessSnapshot
} from '../src/identity.mjs';
import { runCli } from '../src/cli.mjs';
import { initializeSession } from '../src/registry.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// -------------------------------------------------------------------------
// Preflight: Ensure Production CLI --execute is Locked
// -------------------------------------------------------------------------
test('S2.5 Preflight: Production CLI --execute remains strictly locked', async () => {
  assert.strictEqual(
    PHASE_V0_1_CONFIG.executeAllowed,
    false,
    '[PREFLIGHT CONFIRMED] executeAllowed must remain false in Phase S2.5'
  );

  const sessionId = `test-s2-5-preflight-${Date.now()}`;
  initializeSession(sessionId);

  const code = await runCli(['cleanup', '--execute', '--session', sessionId]);
  assert.strictEqual(code, 1, 'Production CLI cleanup --execute must exit with code 1 (FAIL CLOSED)');
});

// -------------------------------------------------------------------------
// TEST A: Normal Playwright Close (browser.close() -> 0 signals)
// -------------------------------------------------------------------------
test('TEST A: New browser -> browser.close() -> zero signal (CLOSED_BY_OWNER_GRACEFULLY)', async () => {
  const sessionId = `test-s2-5-a-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  try {
    // 1. Launch new test browser with dedicated profile
    const browserInstance = await launchTestBrowser(sessionId, broker, { mode: 'background' });
    const { browser, mainPid, helperPids, record } = browserInstance;

    assert.ok(mainPid > 0, 'Main Chromium process must be identified');
    assert.strictEqual(record.role, ROLES.PLAYWRIGHT_BROWSER_MAIN);
    assert.strictEqual(record.ownership, 'OWNED_CONFIRMED');
    assert.strictEqual(checkProcessAlive(mainPid), true, 'Chromium main is alive');

    // 2. Playwright graceful API shutdown
    await browserInstance.close();
    await sleep(200);

    // 3. Confirm exit in OS
    assert.strictEqual(checkProcessAlive(mainPid), false, 'Chromium main must have exited gracefully');
    for (const hPid of helperPids) {
      assert.strictEqual(checkProcessAlive(hPid), false, `Helper ${hPid} must have exited naturally`);
    }

    // 4. Invariant: Supervisor sends ZERO signals
    assert.strictEqual(accounting.sigtermSent, 0, 'Supervisor sent 0 SIGTERM');
    assert.strictEqual(accounting.sigkillSent, 0, 'Supervisor sent 0 SIGKILL');
    assert.strictEqual(accounting.signalsToProductionServices, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST B: Orphan Browser Recovery (Launcher crashes, Supervisor SIGTERM recovery)
// -------------------------------------------------------------------------
test('TEST B: New orphaned browser -> Supervisor SIGTERM recovery (ORPHAN_RECOVERED_WITH_SIGTERM)', async () => {
  const sessionId = `test-s2-5-b-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  try {
    // 1. Spawn orphaned test browser instance
    const orphan = await launchOrphanTestBrowser(sessionId, broker);
    const { mainPid, record, launcherPid, launcherDead } = orphan;

    assert.ok(mainPid > 0);
    assert.strictEqual(launcherDead, true, 'Launcher process must have exited');
    assert.strictEqual(checkProcessAlive(launcherPid), false, 'Launcher PID is confirmed dead');
    assert.strictEqual(checkProcessAlive(mainPid), true, 'Orphan Chromium is currently running');

    // 2. Supervisor Orphan Recovery Protocol
    const recResult = await terminator.recoverPlaywrightOrphan(record, {
      graceTimeoutMs: 2500,
      requireLauncherDead: true
    });

    assert.strictEqual(recResult.success, true);
    assert.strictEqual(recResult.signaled, true);
    assert.strictEqual(recResult.status, 'ORPHAN_RECOVERED_WITH_SIGTERM');
    assert.strictEqual(recResult.profileStatus, 'WOULD_DELETE_LATER');

    // 3. Confirm process actually terminated in OS
    assert.strictEqual(checkProcessAlive(mainPid), false, 'Orphan Chromium main PID must be dead in OS');

    // 4. Signal accounting
    assert.strictEqual(accounting.playwrightTestBrowserSigterm, 1, 'Exactly one SIGTERM to test browser');
    assert.strictEqual(accounting.playwrightTestBrowserSigkill, 0, 'Zero SIGKILL needed');
    assert.strictEqual(accounting.signalsToProductionServices, 0);
    assert.strictEqual(accounting.signalsToChrome, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST C: Twin Browsers Test (Terminate A only, B remains functional)
// -------------------------------------------------------------------------
test('TEST C: Twin browsers -> Terminate A only, B remains functional', async () => {
  const sessionId = `test-s2-5-c-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  let browserA = null;
  let browserB = null;

  try {
    // 1. Launch Browser A with Profile A
    browserA = await launchTestBrowser(sessionId, broker, {
      mode: 'background',
      profileName: 'profile_a'
    });

    // 2. Launch Browser B with Profile B
    browserB = await launchTestBrowser(sessionId, broker, {
      mode: 'background',
      profileName: 'profile_b'
    });

    // Open active content in Browser B
    await browserB.page.setContent('<html><body>Browser B Active</body></html>');

    assert.notStrictEqual(browserA.mainPid, browserB.mainPid, 'Browser A and B must have distinct PIDs');
    assert.strictEqual(checkProcessAlive(browserA.mainPid), true);
    assert.strictEqual(checkProcessAlive(browserB.mainPid), true);

    // 3. Clean up Browser A ONLY
    const recResult = await terminator.recoverPlaywrightOrphan(browserA.record, {
      requireLauncherDead: false // Browser A is directly targeted
    });

    assert.strictEqual(recResult.success, true);
    assert.strictEqual(recResult.status, 'ORPHAN_RECOVERED_WITH_SIGTERM');
    assert.strictEqual(checkProcessAlive(browserA.mainPid), false, 'Browser A must be terminated');

    // 4. VERIFY COLLATERAL DAMAGE: Browser B MUST remain alive and fully functional
    assert.strictEqual(checkProcessAlive(browserB.mainPid), true, 'Browser B must remain alive');
    const contentB = await browserB.page.evaluate(() => document.body.innerText);
    assert.strictEqual(contentB.trim(), 'Browser B Active', 'Browser B page must remain fully responsive');

    // Cleanly close Browser B via graceful API
    await browserB.close();
    assert.strictEqual(checkProcessAlive(browserB.mainPid), false);

    // 5. Accounting verification
    assert.strictEqual(accounting.playwrightTestBrowserSigterm, 1, 'Only Browser A received SIGTERM');
    assert.strictEqual(accounting.signalsToChrome, 0);
    assert.strictEqual(accounting.signalsToProductionServices, 0);
  } finally {
    if (browserA) await browserA.close().catch(() => {});
    if (browserB) await browserB.close().catch(() => {});
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST D: Foreign / Pre-existing Chromium -> Blocked
// -------------------------------------------------------------------------
test('TEST D: Foreign/existing Chromium -> blocked (FOREIGN_BROWSER / BLOCKED_NO_BROKER_ATTESTATION)', async () => {
  const sessionId = `test-s2-5-d-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  // Spawn unmanaged Chromium outside Broker
  const exePath = chromium.executablePath();
  const extChrome = spawn(exePath, ['--headless', '--no-sandbox', '--disable-gpu'], {
    stdio: 'ignore'
  });

  try {
    assert.ok(extChrome.pid > 0);
    await sleep(200);

    const fakeRecord = {
      pid: extChrome.pid,
      session_id: sessionId,
      role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED
    };

    const res = await terminator.recoverPlaywrightOrphan(fakeRecord, { requireLauncherDead: false });
    assert.strictEqual(res.signaled, false, 'Must not send signal to foreign Chromium');
    assert.strictEqual(res.status, 'BLOCKED_NO_BROKER_ATTESTATION');
    assert.strictEqual(checkProcessAlive(extChrome.pid), true, 'Foreign Chromium untouched');
  } finally {
    extChrome.kill('SIGKILL');
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST E: User Chrome -> Blocked
// -------------------------------------------------------------------------
test('TEST E: Real User Chrome -> blocked by Never-Kill (USER_GOOGLE_CHROME_BROWSER)', async () => {
  const sessionId = `test-s2-5-e-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  try {
    // Attempt recovery on simulated User Chrome record
    const userChromeRecord = {
      pid: 99991, // Illustrative baseline user Chrome PID
      session_id: sessionId,
      role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED,
      executable: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
    };

    const res = await terminator.recoverPlaywrightOrphan(userChromeRecord, { requireLauncherDead: false });
    assert.strictEqual(res.signaled, false, 'Must never send signal to User Chrome');
    assert.strictEqual(accounting.signalsToChrome, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST F: Broker Offline -> No Signal
// -------------------------------------------------------------------------
test('TEST F: Broker stops before termination -> ABORTS WITH ZERO SIGNAL', async () => {
  const sessionId = `test-s2-5-f-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();

  try {
    const browserInstance = await launchTestBrowser(sessionId, broker, { mode: 'background' });
    const { record, mainPid } = browserInstance;

    // Broker stops unexpectedly
    await broker.stop();

    const terminator = new ControlledTerminator(sessionId, {
      broker: null, // Broker down
      accounting,
      testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
    });

    const res = await terminator.recoverPlaywrightOrphan(record, { requireLauncherDead: false });
    assert.strictEqual(res.signaled, false, 'Must not send signal when Broker is down');
    assert.strictEqual(checkProcessAlive(mainPid), true, 'Browser remains alive');

    // Clean up
    process.kill(mainPid, 'SIGKILL');
  } catch (err) {
    throw err;
  }
});

// -------------------------------------------------------------------------
// TEST G: PID Identity Changes (PID Reuse Defense)
// -------------------------------------------------------------------------
test('TEST G: PID identity changes -> blocked by start-time mismatch (PID_IDENTITY_CHANGED)', async () => {
  const sessionId = `test-s2-5-g-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  try {
    const browserInstance = await launchTestBrowser(sessionId, broker, { mode: 'background' });
    const { record, mainPid } = browserInstance;

    try {
      const tamperedRecord = { ...record };
      tamperedRecord.start_time_epoch_ms = tamperedRecord.start_time_epoch_ms - 999999;
      tamperedRecord.lstart = 'Thu Jan 01 00:00:00 1970';

      const res = await terminator.recoverPlaywrightOrphan(tamperedRecord, { requireLauncherDead: false });
      assert.strictEqual(res.signaled, false, 'No signal if start time mutated (PID reuse defense)');
      assert.strictEqual(res.status, 'PID_IDENTITY_CHANGED');
      assert.strictEqual(checkProcessAlive(mainPid), true, 'Browser remains untouched');
    } finally {
      await browserInstance.close();
    }
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST H: Pre-existing Playwright Session Untouched
// -------------------------------------------------------------------------
test('TEST H: Existing Playwright session created before S2.5 -> no signal', async () => {
  const sessionId = `test-s2-5-h-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY'
  });

  try {
    // Attempt recovery on known pre-existing Playwright PID (e.g. PID 90811)
    const existingPlaywrightRecord = {
      pid: 90811,
      session_id: sessionId,
      role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED
    };

    const res = await terminator.recoverPlaywrightOrphan(existingPlaywrightRecord, { requireLauncherDead: false });
    assert.strictEqual(res.signaled, false, 'Must not send signal to pre-existing Playwright session');
    assert.strictEqual(accounting.signalsToExistingPlaywright, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST I: Playwright Persistent Mode vs Background Mode Comparison
// -------------------------------------------------------------------------
test('TEST I: Playwright Persistent Mode vs Background Mode lifecycle comparison', async () => {
  const sessionId = `test-s2-5-i-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // 1. Test background mode
    const bg = await launchTestBrowser(sessionId, broker, { mode: 'background' });
    assert.ok(bg.mainPid > 0);
    await bg.close();
    assert.strictEqual(checkProcessAlive(bg.mainPid), false);

    // 2. Test persistent mode
    const pers = await launchTestBrowser(sessionId, broker, { mode: 'persistent' });
    assert.ok(pers.mainPid > 0);
    await pers.close();
    assert.strictEqual(checkProcessAlive(pers.mainPid), false);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST J: Playwright Signal Accounting Invariant Audit
// -------------------------------------------------------------------------
test('TEST J: Signal Accounting Invariants verified (0 signals to production services)', () => {
  const accounting = new SignalAccounting();

  // Record a legitimate S2.5 test signal
  accounting.recordSignal({
    session_id: 's2-5-test',
    target_pid: 12345,
    role: ROLES.PLAYWRIGHT_BROWSER_MAIN,
    signal: 'SIGTERM',
    isPlaywrightTest: true
  });

  const summary = accounting.getSummary();
  assert.strictEqual(summary.playwrightTestBrowserSigterm, 1);
  assert.strictEqual(summary.signalsToChrome, 0, 'User Chrome signals must be 0');
  assert.strictEqual(summary.signalsToExistingPlaywright, 0, 'Existing Playwright signals must be 0');
  assert.strictEqual(summary.signalsToCdpProxy, 0, 'cdp-proxy signals must be 0');
  assert.strictEqual(summary.signalsToZCode, 0, 'ZCode signals must be 0');
  assert.strictEqual(summary.signalsToMcp, 0, 'MCP signals must be 0');
  assert.strictEqual(summary.signalsToAntigravity, 0, 'Antigravity signals must be 0');
  assert.strictEqual(summary.signalsToProductionServices, 0, 'Production services signals must be 0');
});
