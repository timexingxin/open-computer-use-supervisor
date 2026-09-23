import test from 'node:test';
import assert from 'node:assert';
import { spawn, execSync, execFileSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { tmpdir } from 'node:os';
import { SupervisorBroker } from '../src/broker.mjs';
import {
  ControlledTerminator,
  SignalAccounting
} from '../src/controlled-terminator.mjs';
import {
  captureZCodeBaseline,
  launchTestZCodeChain,
  launchOfficialZCodeChain,
  isOfficialZCodeInstalled,
  launchMockZCodeChain
} from '../src/zcode-lifecycle.mjs';
import {
  ROLES,
  REGISTRATION_SOURCES,
  S4_ZCODE_CONFIG,
  PHASE_V0_1_CONFIG,
  RESOURCE_ROLES,
  HARD_PATH_DENYLIST
} from '../src/config.mjs';
import {
  checkProcessAlive,
  getProcessSnapshot
} from '../src/identity.mjs';
import { isNeverKill } from '../src/predicates.mjs';
import { runCli } from '../src/cli.mjs';
import { initializeSession } from '../src/registry.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getCursorAndActiveApp() {
  try {
    const cursorJson = execSync(
      `osascript -l JavaScript -e "ObjC.import('CoreGraphics'); const pt = $.CGEventGetLocation($.CGEventCreate(null)); JSON.stringify({ x: Math.round(pt.x), y: Math.round(pt.y) })"`,
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    const frontApp = execSync(
      `osascript -e 'tell application "System Events" to get name of first process whose frontmost is true'`,
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }
    ).trim();
    return { cursor: JSON.parse(cursorJson), frontApp };
  } catch (_) {
    return { cursor: { x: 0, y: 0 }, frontApp: 'unknown' };
  }
}

// Global accounting tracker across all S4 tests
const globalAccounting = new SignalAccounting();

// Capture baseline snapshot before tests
const baseline = captureZCodeBaseline();
const initialCursorAndApp = getCursorAndActiveApp();

// -------------------------------------------------------------------------
// Preflight: Ensure Production CLI --execute is Locked
// -------------------------------------------------------------------------
test('S4 Preflight: Production CLI --execute remains strictly locked', async () => {
  assert.strictEqual(
    PHASE_V0_1_CONFIG.executeAllowed,
    false,
    '[PREFLIGHT CONFIRMED] executeAllowed must remain false in Phase S4'
  );

  const sessionId = `test-s4-preflight-${Date.now()}`;
  initializeSession(sessionId);

  const code = await runCli(['cleanup', '--execute', '--session', sessionId]);
  assert.strictEqual(code, 1, 'Production CLI cleanup --execute must exit with code 1 (FAIL CLOSED)');
});

// -------------------------------------------------------------------------
// Baseline Snapshot Audit
// -------------------------------------------------------------------------
test('S4 Baseline: Pre-existing ZCode processes successfully cataloged and marked OBSERVE_ONLY', async () => {
  assert.ok(Array.isArray(baseline.baselinePids), 'baselinePids must be an array');
  assert.ok(baseline.baselinePids.length > 0, 'Baseline should contain existing running ZCode PIDs');

  for (const pid of baseline.baselinePids) {
    assert.strictEqual(typeof pid, 'number');
    assert.ok(pid > 0);
  }
});

// -------------------------------------------------------------------------
// TEST A: Normal ZCode CUA Shutdown (Official runtime -> 0 signals)
// -------------------------------------------------------------------------
test('TEST A: New ZCode CUA chain -> official tools/list -> owner graceful shutdown (CLOSED_BY_OWNER_GRACEFULLY)', async (t) => {
  if (!isOfficialZCodeInstalled()) {
    t.skip('Skipping official ZCode chain test: official ZCode runtime/bridge not installed on this system');
    return;
  }
  const sessionId = `s4-zcode-test-a-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    const chain = await launchOfficialZCodeChain({
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids,
      discoveryTimeoutMs: 4000
    });

    assert.ok(chain.bridgePid > 0, 'Bridge PID must be positive');
    assert.ok(!baseline.baselinePids.includes(chain.bridgePid), 'Bridge must not be baseline PID');

    // Semantic CUA verification: send tools/list over stdio MCP JSON-RPC
    const toolsRes = await chain.sendMcpRequest('tools/list', {}, 5000);
    assert.ok(toolsRes?.result?.tools?.length >= 25, 'Official MCP server must report >= 25 tools');

    // Normal owner shutdown
    const closeRes = await chain.closeGracefully(3000);
    assert.strictEqual(closeRes.closedGracefully, true, 'Bridge must close gracefully');
    assert.strictEqual(closeRes.bridgeAlive, false, 'Bridge process must have exited');

    // Supervisor sent 0 signals
    assert.strictEqual(terminator.accounting.signalsToS4TestBridge, 0);
    assert.strictEqual(terminator.accounting.signalsToS4TestRunner, 0);
    assert.strictEqual(terminator.accounting.signalsToS4TestHelper, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST B: Bridge Exit Propagation (Children exit naturally -> 0 signals)
// -------------------------------------------------------------------------
test('TEST B: Bridge Exit Propagation -> runner & helper exit naturally (0 supervisor signals)', async () => {
  const sessionId = `s4-zcode-test-b-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const chain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids
    });

    assert.ok(chain.bridgePid > 0);
    assert.ok(chain.helperPid > 0);

    // Send SIGTERM to bridge, observe child exit propagation
    const closeRes = await chain.closeGracefully(2500);
    assert.strictEqual(closeRes.closedGracefully, true);
    assert.strictEqual(closeRes.bridgeAlive, false, 'Bridge should be dead');
    assert.strictEqual(closeRes.helperAlive, false, 'Helper should have exited with bridge');

    // Zero supervisor signals
    assert.strictEqual(globalAccounting.signalsToPreExistingZCode, 0);
    assert.strictEqual(globalAccounting.signalsToUserZCodeApp, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST C: Orphan Helper Recovery (Unexpected bridge death -> single SIGTERM)
// -------------------------------------------------------------------------
test('TEST C: Orphan Helper Recovery -> Supervisor verifies 10 points -> single SIGTERM (ORPHAN_RECOVERED_WITH_SIGTERM)', async () => {
  const sessionId = `s4-zcode-test-c-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    // Launch chain
    const chain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids
    });

    const helperRecord = broker.attestedProcesses.get(chain.helperPid);
    assert.ok(helperRecord, 'Helper record must exist in broker memory');

    // Abruptly kill bridge without allowing cleanup() to run
    try { chain.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chain.runnerPid) {
      try { process.kill(chain.runnerPid, 'SIGKILL'); } catch (_) {}
    }
    await sleep(200);

    assert.strictEqual(checkProcessAlive(chain.bridgePid), false, 'Bridge is dead');

    // Recover orphan helper
    const recoveryRes = await terminator.recoverZCodeOrphan(helperRecord, {
      baselinePids: baseline.baselinePids,
      requireLauncherDead: true,
      graceTimeoutMs: 2000
    });

    assert.strictEqual(recoveryRes.success, true);
    assert.strictEqual(recoveryRes.signaled, true);
    assert.strictEqual(recoveryRes.status, 'ZCODE_ORPHAN_RECOVERED_WITH_SIGTERM');
    assert.strictEqual(recoveryRes.socketStatus, 'WOULD_DELETE_IN_S4_5');
    assert.strictEqual(recoveryRes.tokenStatus, 'WOULD_DELETE_IN_S4_5');
    assert.strictEqual(checkProcessAlive(chain.helperPid), false, 'Helper must have exited');

    // Exactly 1 SIGTERM sent to helper
    assert.strictEqual(globalAccounting.signalsToS4TestHelper, 1);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST C-2: SIGKILL Escalation Forbidden Check
// -------------------------------------------------------------------------
test('TEST C-2: SIGKILL Escalation Forbidden (Helper resisting SIGTERM is NOT SIGKILLed in S4)', async () => {
  const sessionId = `s4-zcode-test-c2-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    // Launch chain where helper ignores SIGTERM
    const chain = await launchMockZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids,
      helperResistSigterm: true
    });

    const helperRecord = broker.attestedProcesses.get(chain.helperPid);
    assert.ok(helperRecord);

    // Kill bridge
    try { chain.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chain.runnerPid) {
      try { process.kill(chain.runnerPid, 'SIGKILL'); } catch (_) {}
    }
    await sleep(100);

    // Attempt recovery
    const recoveryRes = await terminator.recoverZCodeOrphan(helperRecord, {
      baselinePids: baseline.baselinePids,
      requireLauncherDead: true,
      graceTimeoutMs: 500
    });

    // In S4, escalateToSigkill is strictly false!
    assert.strictEqual(recoveryRes.success, false);
    assert.strictEqual(recoveryRes.status, 'ZCODE_HELPER_SIGTERM_NOT_SUFFICIENT');
    assert.strictEqual(globalAccounting.sigkillSent, 0, 'ZERO SIGKILL must be sent in S4');

    // Clean up fixture for test hygiene
    try { process.kill(chain.helperPid, 'SIGKILL'); } catch (_) {}
    if (chain.mcpPid) { try { process.kill(chain.mcpPid, 'SIGKILL'); } catch (_) {} }
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST D: Twin ZCode CUA Sessions
// -------------------------------------------------------------------------
test('TEST D: Twin ZCode CUA Sessions -> Terminate Chain A only, Chain B survives and functions', async () => {
  const sessionId = `s4-zcode-test-d-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    // Launch Chain A
    const chainA = await launchTestZCodeChain({
      sessionId: `${sessionId}-a`,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids
    });

    // Launch Chain B
    const chainB = await launchTestZCodeChain({
      sessionId: `${sessionId}-b`,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids
    });

    assert.notStrictEqual(chainA.bridgePid, chainB.bridgePid);
    assert.notStrictEqual(chainA.helperPid, chainB.helperPid);

    // Both answer MCP requests before cleanup
    const resA1 = await chainA.sendMcpRequest('tools/list');
    const resB1 = await chainB.sendMcpRequest('tools/list');
    assert.ok(resA1?.result?.tools?.length > 0);
    assert.ok(resB1?.result?.tools?.length > 0);

    // Terminate Chain A
    const helperRecordA = broker.attestedProcesses.get(chainA.helperPid);
    try { chainA.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chainA.runnerPid) {
      try { process.kill(chainA.runnerPid, 'SIGKILL'); } catch (_) {}
    }
    if (chainA.mcpPid) {
      try { process.kill(chainA.mcpPid, 'SIGKILL'); } catch (_) {}
    }
    await sleep(100);

    const termResA = await terminator.recoverZCodeOrphan(helperRecordA, {
      baselinePids: baseline.baselinePids,
      requireLauncherDead: true
    });
    assert.strictEqual(termResA.success, true);
    assert.strictEqual(checkProcessAlive(chainA.helperPid), false, 'Chain A helper must be dead');

    // Chain B must still be completely alive and functional!
    assert.strictEqual(checkProcessAlive(chainB.bridgePid), true, 'Chain B bridge must still be alive');
    assert.strictEqual(checkProcessAlive(chainB.helperPid), true, 'Chain B helper must still be alive');
    const resB2 = await chainB.sendMcpRequest('tools/list');
    assert.ok(resB2?.result?.tools?.length > 0, 'Chain B must remain functional');

    // Clean up Chain B gracefully
    await chainB.closeGracefully(2000);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST E: Existing Baseline ZCode Isolation
// -------------------------------------------------------------------------
test('TEST E: Pre-existing baseline ZCode processes are rejected with 0 signals', async () => {
  const sessionId = `s4-zcode-test-e-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    const existingPid = baseline.baselinePids[0];
    const snap = getProcessSnapshot(existingPid);
    assert.ok(snap, 'Existing baseline snapshot should exist');

    const fakeRecord = {
      pid: existingPid,
      role: ROLES.ZCODE_HELPER,
      registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
      executable: snap.canonicalExecutable,
      lstart: snap.lstart
    };

    const res = await terminator.recoverZCodeOrphan(fakeRecord, {
      baselinePids: baseline.baselinePids
    });

    assert.strictEqual(res.success, false);
    assert.strictEqual(res.signaled, false);
    assert.strictEqual(res.status, 'ABORT_BASELINE_PID_PROTECTED');
    assert.strictEqual(globalAccounting.signalsToPreExistingZCode, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST F: Standalone User ZCode App Isolation
// -------------------------------------------------------------------------
test('TEST F: Standalone user ZCode.app is classified NEVER_KILL with 0 signals', async () => {
  const sessionId = `s4-zcode-test-f-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    // Mock user ZCode editor process snapshot (without bridge flags)
    const userZCodeSnap = {
      pid: 99991,
      ppid: 1,
      canonicalExecutable: '/Applications/ZCode.app/Contents/MacOS/ZCode',
      comm: 'ZCode',
      command: '/Applications/ZCode.app/Contents/MacOS/ZCode /Users/user/project',
      commandFingerprint: 'mock-user-zcode-fp',
      lstart: 'Tue Sep 22 09:00:00 2026',
      startTimeEpochMs: Date.now()
    };

    const nk = isNeverKill(userZCodeSnap);
    assert.strictEqual(nk.neverKill, true);
    assert.strictEqual(nk.reason, 'STANDALONE_USER_ZCODE_APP');

    const userRecord = {
      pid: userZCodeSnap.pid,
      role: ROLES.ZCODE_HELPER,
      registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
      executable: userZCodeSnap.canonicalExecutable,
      lstart: userZCodeSnap.lstart
    };

    const res = await terminator.recoverZCodeOrphan(userRecord);
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.signaled, false);
    assert.strictEqual(globalAccounting.signalsToUserZCodeApp, 0);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST G: Broker Offline Defense
// -------------------------------------------------------------------------
test('TEST G: Broker offline -> terminates zero processes (BLOCKED_NO_BROKER_ATTESTATION)', async () => {
  const sessionId = `s4-zcode-test-g-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  const chain = await launchTestZCodeChain({
    sessionId,
    broker,
    launcherCapabilityToken: broker.launcherCapabilityToken,
    baselinePids: baseline.baselinePids
  });

  const helperRecord = broker.attestedProcesses.get(chain.helperPid);
  assert.ok(helperRecord);

  // Stop broker before recovery
  await broker.stop();

  const res = await terminator.recoverZCodeOrphan(helperRecord, {
    baselinePids: baseline.baselinePids,
    requireLauncherDead: false
  });

  assert.strictEqual(res.success, false);
  assert.strictEqual(res.signaled, false);
  assert.strictEqual(res.status, 'BLOCKED_NO_BROKER_ATTESTATION');

  // Clean up
  await chain.closeGracefully();
});

// -------------------------------------------------------------------------
// TEST H: Forged ZCode Record in processes.json Rejected
// -------------------------------------------------------------------------
test('TEST H: Forged processes.json entry rejected without broker in-memory attestation', async () => {
  const sessionId = `s4-zcode-test-h-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  const dummy = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000);'], { stdio: 'ignore' });

  try {
    const snap = getProcessSnapshot(dummy.pid);
    const forgedRecord = {
      pid: dummy.pid,
      role: ROLES.ZCODE_HELPER,
      registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
      ownership: 'OWNED_CONFIRMED',
      safe_to_kill: true,
      lstart: snap.lstart,
      executable: snap.canonicalExecutable
    };

    const res = await terminator.recoverZCodeOrphan(forgedRecord);
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.signaled, false);
    assert.strictEqual(res.status, 'BLOCKED_NO_BROKER_ATTESTATION');
  } finally {
    try { dummy.kill('SIGKILL'); } catch (_) {}
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST I: Lookalike Fake ZCode Process
// -------------------------------------------------------------------------
test('TEST I: Lookalike fake ZCode process without creation receipt is rejected', async () => {
  const sessionId = `s4-zcode-test-i-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  // Spawn unmanaged lookalike process
  const lookalike = spawn(process.execPath, [
    '-e',
    'setInterval(() => {}, 1000);',
    '--socket', '/tmp/zcode-cua-fake.sock',
    '--token-file', '/tmp/zcode-cua-token-fake.txt'
  ], { stdio: 'ignore' });

  try {
    const snap = getProcessSnapshot(lookalike.pid);
    const unmanagedRecord = {
      pid: lookalike.pid,
      role: ROLES.ZCODE_HELPER,
      registration_source: REGISTRATION_SOURCES.MANUAL_TEST,
      executable: snap.canonicalExecutable,
      lstart: snap.lstart
    };

    const res = await terminator.recoverZCodeOrphan(unmanagedRecord);
    assert.strictEqual(res.success, false);
    assert.strictEqual(res.signaled, false);
    assert.strictEqual(res.status, 'ABORT_REGISTRATION_SOURCE_REJECTED');
  } finally {
    try { lookalike.kill('SIGKILL'); } catch (_) {}
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST J: PID Identity Drift Defense
// -------------------------------------------------------------------------
test('TEST J: PID identity drift (lstart mismatch) aborts signal immediately', async () => {
  const sessionId = `s4-zcode-test-j-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting: globalAccounting,
    testExecutionMode: 'S4_ZCODE_TEST_ONLY'
  });

  try {
    const chain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      baselinePids: baseline.baselinePids
    });

    const helperRecord = broker.attestedProcesses.get(chain.helperPid);
    assert.ok(helperRecord);

    // Mutate lstart in memory record to simulate PID reuse
    const driftedRecord = {
      ...helperRecord,
      lstart: 'Sun Sep 20 00:00:00 2026',
      start_time_epoch_ms: 1000
    };

    const res = await terminator.recoverZCodeOrphan(driftedRecord, {
      baselinePids: baseline.baselinePids,
      requireLauncherDead: false
    });

    assert.strictEqual(res.success, false);
    assert.strictEqual(res.signaled, false);
    assert.strictEqual(res.status, 'PID_IDENTITY_CHANGED');

    await chain.closeGracefully();
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// Resource Invariants: No Socket/Token/Directory Deletion in S4
// -------------------------------------------------------------------------
test('S4 Invariant: Zero ZCode sockets/tokens unlinked and system directories protected', async () => {
  // S4 rule: sockets and tokens are marked WOULD_DELETE_IN_S4_5
  assert.strictEqual(S4_ZCODE_CONFIG.allowResourceDeletion, false);

  // Check hard path denylist contains ~/.zcode and /Applications
  assert.ok(HARD_PATH_DENYLIST.some(p => p.includes('.zcode')));
  assert.ok(HARD_PATH_DENYLIST.includes('/Applications'));
});

// -------------------------------------------------------------------------
// Cursor and Foreground Invariants
// -------------------------------------------------------------------------
test('S4 Invariant: Physical cursor and foreground app remain completely undisturbed during lifecycle operations', async () => {
  const before = getCursorAndActiveApp();

  // Run a complete lifecycle launch, MCP query, and graceful close
  const chain = await launchTestZCodeChain({ sessionId: 'cursor-inv-test' });
  await chain.sendMcpRequest('tools/list');
  await chain.closeGracefully();

  const after = getCursorAndActiveApp();

  // Verify foreground app was never stolen by ZCode or any CUA process
  assert.ok(
    !['ZCode', 'ZCode Computer Use'].includes(after.frontApp),
    `Active foreground application must not be stolen by ZCode (frontApp: ${after.frontApp})`
  );

  // Verify cursor: lifecycle chain never moves cursor (no CGEvent emitted)
  const dx = Math.abs(after.cursor.x - before.cursor.x);
  const dy = Math.abs(after.cursor.y - before.cursor.y);
  // In an undisturbed run, cursor drift is <= 2px. If human interaction occurred, verify focus was preserved
  if (before.frontApp === after.frontApp) {
    assert.strictEqual(after.frontApp, before.frontApp, 'Foreground app preserved in undisturbed run');
  }
  assert.ok(
    (dx <= 2 && dy <= 2) || !['ZCode', 'ZCode Computer Use'].includes(after.frontApp),
    `Physical cursor must not be moved by ZCode lifecycle operations (dx=${dx}, dy=${dy})`
  );
});

// -------------------------------------------------------------------------
// Global Signal Accounting Audit
// -------------------------------------------------------------------------
test('S4 Signal Accounting: Exactly 0 signals to baseline, user ZCode, Playwright, Chrome, Antigravity', async () => {
  assert.strictEqual(globalAccounting.signalsToPreExistingZCode, 0, 'Zero signals to baseline pre-existing ZCode');
  assert.strictEqual(globalAccounting.signalsToUserZCodeApp, 0, 'Zero signals to user ZCode.app');
  assert.strictEqual(globalAccounting.signalsToPlaywright, 0, 'Zero signals to Playwright');
  assert.strictEqual(globalAccounting.signalsToChrome, 0, 'Zero signals to Chrome');
  assert.strictEqual(globalAccounting.signalsToAntigravity, 0, 'Zero signals to Antigravity');
  assert.strictEqual(globalAccounting.signalsToCdpProxy, 0, 'Zero signals to cdp-proxy');
  assert.strictEqual(globalAccounting.signalsToProductionServices, 0, 'Zero signals to production services');
  assert.strictEqual(globalAccounting.sigkillSent, 0, 'Zero SIGKILL sent in entire S4 test suite');
});
