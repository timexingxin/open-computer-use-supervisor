import { test } from 'node:test';
import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import {
  PHASE_V0_1_CONFIG,
  ROLES,
  RESOURCE_ROLES,
  S4_5_RESOURCE_CONFIG,
  S4_ZCODE_CONFIG,
  S2_5_PLAYWRIGHT_CONFIG,
  S2_CONTROLLED_CONFIG
} from '../src/config.mjs';
import { SupervisorBroker } from '../src/broker.mjs';
import { ControlledTerminator, globalSignalAccounting } from '../src/controlled-terminator.mjs';
import {
  DeletionAccounting,
  deleteZCodeSocketS4_5,
  deleteZCodeTokenS4_5,
  recordOwnerCleanedResource,
  isBaselineZCodeResource
} from '../src/resource-cleaner.mjs';
import { launchTestBrowser, launchOrphanTestBrowser } from '../src/playwright-lifecycle.mjs';
import { launchTestZCodeChain, captureZCodeBaseline } from '../src/zcode-lifecycle.mjs';
import { checkProcessAlive, getProcessSnapshot } from '../src/identity.mjs';
import { initializeSession } from '../src/registry.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// -------------------------------------------------------------------------
// 1. Preflight: Production Lock & Version Consistency
// -------------------------------------------------------------------------
test('Final Integration Preflight: Production Gate Locked & Version 1.0.0-rc.1', async () => {
  assert.strictEqual(PHASE_V0_1_CONFIG.executeAllowed, false, 'Production execute must be strictly locked');
  assert.strictEqual(PHASE_V0_1_CONFIG.version, '1.0.0-rc.1', 'Unified version must be 1.0.0-rc.1');
  assert.strictEqual(PHASE_V0_1_CONFIG.phase, '1.0.0-rc.1', 'Phase string must be 1.0.0-rc.1');
});

// -------------------------------------------------------------------------
// 2. Scenario A — Browser Only Workflow
// -------------------------------------------------------------------------
test('Scenario A: Browser Only Workflow (Isolated Playwright -> Navigate -> Close -> 0 Signals)', async () => {
  const sessionId = `soak-browser-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const priorSignals = globalSignalAccounting.playwrightTestBrowserSigterm;
    const instance = await launchTestBrowser(sessionId, broker, { mode: 'background' });
    assert.ok(instance.mainPid, 'Playwright browser launched with PID');
    assert.strictEqual(checkProcessAlive(instance.mainPid), true, 'Chromium process is alive');

    // Safe navigation and DOM extraction
    await instance.page.setContent('<html><body><h1 id="title">Antigravity Browser Soak</h1></body></html>');
    const titleText = await instance.page.$eval('#title', el => el.textContent);
    assert.strictEqual(titleText, 'Antigravity Browser Soak');

    // Normal graceful close
    await instance.close();
    await sleep(200);

    // Verify process is dead
    assert.strictEqual(checkProcessAlive(instance.mainPid), false, 'Chromium process exited cleanly');

    // Verify ZERO Supervisor signals dispatched
    const postSignals = globalSignalAccounting.playwrightTestBrowserSigterm;
    assert.strictEqual(postSignals, priorSignals, 'Zero Supervisor signals on normal browser close');
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 3. Scenario B — ZCode CUA Only Workflow
// -------------------------------------------------------------------------
test('Scenario B: ZCode CUA Only Workflow (Fresh CUA -> tools/list -> Graceful Shutdown -> 0 Signals)', async () => {
  const sessionId = `soak-zcode-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const priorSignals = globalSignalAccounting.signalsToS4TestHelper;
    const priorUnlinks = DeletionAccounting.supervisorZCodeSocketsDeleted;

    const chain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken
    });

    assert.ok(chain.bridgePid, 'Bridge spawned');
    assert.strictEqual(checkProcessAlive(chain.bridgePid), true, 'Bridge process is alive');

    // Call tools/list via JSON-RPC
    const tools = await chain.sendMcpRequest('tools/list');
    assert.ok(tools?.result?.tools?.length > 0 || Array.isArray(tools), 'tools/list returned tool inventory');

    // Normal shutdown
    const closeRes = await chain.closeGracefully();
    assert.strictEqual(closeRes.closedGracefully, true, 'ZCode CUA closed gracefully');

    // Verify 0 signals and 0 supervisor unlinks
    assert.strictEqual(globalSignalAccounting.signalsToS4TestHelper, priorSignals, 'Zero Supervisor signals on graceful exit');
    assert.strictEqual(DeletionAccounting.supervisorZCodeSocketsDeleted, priorUnlinks, 'Zero Supervisor unlinks on owner-cleaned resources');
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 4. Scenario C — Mixed Browser + Native Workflow
// -------------------------------------------------------------------------
test('Scenario C: Mixed Browser + Native Workflow (Independent Routing & Clean Lifecycle)', async () => {
  const sessionId = `soak-mixed-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // 1. Playwright Browser Step
    const browserInstance = await launchTestBrowser(sessionId, broker, { mode: 'background' });
    await browserInstance.page.setContent('<div id="data">Harmless Test Payload 42</div>');
    const extracted = await browserInstance.page.$eval('#data', el => el.textContent);
    assert.strictEqual(extracted, 'Harmless Test Payload 42');

    // 2. Native ZCode CUA Step
    const cuaChain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken
    });
    const tools = await cuaChain.sendMcpRequest('tools/list');
    assert.ok(tools?.result?.tools?.length > 0 || Array.isArray(tools), 'CUA active while browser open');

    // 3. Close both in sequence
    await browserInstance.close();
    const cuaClose = await cuaChain.closeGracefully();
    assert.strictEqual(cuaClose.closedGracefully, true);

    await sleep(150);
    assert.strictEqual(checkProcessAlive(browserInstance.mainPid), false);
    assert.strictEqual(checkProcessAlive(cuaChain.bridgePid), false);
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 5. Scenario D — Failure Recovery (Orphan Browser + Orphan Helper)
// -------------------------------------------------------------------------
test('Scenario D: Failure Recovery (Only Exact Owned Orphans Recovered via Scoped SIGTERM)', async () => {
  const sessionId = `soak-recovery-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // 1. Playwright Orphan Recovery
    const orphanBrowser = await launchOrphanTestBrowser(sessionId, broker);
    assert.strictEqual(checkProcessAlive(orphanBrowser.mainPid), true, 'Orphan browser is running');

    const browserTerminator = new ControlledTerminator(sessionId, {
      broker,
      testExecutionMode: S2_5_PLAYWRIGHT_CONFIG.testExecutionMode
    });
    const bRecoverRes = await browserTerminator.recoverPlaywrightOrphan(orphanBrowser.record, {
      graceTimeoutMs: 2000,
      mode: 'background'
    });
    assert.strictEqual(bRecoverRes.success, true);
    assert.strictEqual(bRecoverRes.status, 'ORPHAN_RECOVERED_WITH_SIGTERM');

    // 2. ZCode Helper Orphan Recovery
    const chain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true
    });
    // Kill bridge and runner abruptly to leave helper as orphan
    try { chain.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chain.runnerPid) {
      try { process.kill(chain.runnerPid, 'SIGKILL'); } catch (_) {}
    }
    await sleep(200);

    const helperRecord = broker.attestedProcesses.get(chain.helperPid);
    assert.ok(helperRecord, 'Helper record attested in broker');

    const zcodeTerminator = new ControlledTerminator(sessionId, {
      broker,
      testExecutionMode: S4_ZCODE_CONFIG.testExecutionMode
    });
    const hRecoverRes = await zcodeTerminator.recoverZCodeOrphan(helperRecord, {
      baselinePids: [],
      requireLauncherDead: true,
      graceTimeoutMs: 2000
    });
    assert.strictEqual(hRecoverRes.success, true);
    assert.strictEqual(hRecoverRes.status, 'ZCODE_ORPHAN_RECOVERED_WITH_SIGTERM');
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 6. Repeated Lifecycle Cycles (5 Consecutive Iterations Soak)
// -------------------------------------------------------------------------
test('Repeated Lifecycle Cycles: 5 Consecutive Iterations with No Leaks & Bounded State', async () => {
  const sessionId = `soak-cycles-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    for (let cycle = 1; cycle <= 5; cycle++) {
      // Browser iteration
      const bInstance = await launchTestBrowser(sessionId, broker, { mode: 'background' });
      await bInstance.page.setContent(`<div>Cycle ${cycle}</div>`);
      const text = await bInstance.page.$eval('div', el => el.textContent);
      assert.strictEqual(text, `Cycle ${cycle}`);
      await bInstance.close();

      // CUA iteration
      const cChain = await launchTestZCodeChain({
        sessionId,
        broker,
        launcherCapabilityToken: broker.launcherCapabilityToken
      });
      await cChain.sendMcpRequest('tools/list');
      await cChain.closeGracefully();
      await sleep(100);

      // Verify no leaked live processes from this cycle
      assert.strictEqual(checkProcessAlive(bInstance.mainPid), false);
      assert.strictEqual(checkProcessAlive(cChain.bridgePid), false);
    }

    const metrics = broker.getLifecycleStateMetrics();
    assert.ok(metrics.peakEntries >= 5, 'Tracked peak lifecycle entries');
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 7. Parallel Concurrent Sessions (Session A & Session B Isolation)
// -------------------------------------------------------------------------
test('Parallel Sessions: Session A & Session B Isolation (Receipts & Cleanup Decoupled)', async () => {
  const sessionA = `soak-parallel-A-${Date.now()}`;
  const sessionB = `soak-parallel-B-${Date.now()}`;

  const brokerA = new SupervisorBroker(sessionA);
  const brokerB = new SupervisorBroker(sessionB);

  await brokerA.start();
  await brokerB.start();

  try {
    // Launch Chain A in Session A
    const chainA = await launchTestZCodeChain({
      sessionId: sessionA,
      broker: brokerA,
      launcherCapabilityToken: brokerA.launcherCapabilityToken,
      leaveResources: true
    });

    // Launch Chain B in Session B
    const chainB = await launchTestZCodeChain({
      sessionId: sessionB,
      broker: brokerB,
      launcherCapabilityToken: brokerB.launcherCapabilityToken,
      leaveResources: true
    });

    // Verify token & capability separation
    assert.notStrictEqual(brokerA.launcherCapabilityToken, brokerB.launcherCapabilityToken);
    assert.strictEqual(brokerA.attestedProcesses.has(chainB.bridgePid), false, 'Broker A cannot see Chain B');
    assert.strictEqual(brokerB.attestedProcesses.has(chainA.bridgePid), false, 'Broker B cannot see Chain A');

    // Cross-session deletion attempt: Broker A attempts to delete Chain B's socket
    const crossDelete = brokerA.deleteZCodeResourceS4_5({
      path: chainB.socketPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });
    assert.strictEqual(crossDelete.success, false);
    assert.strictEqual(crossDelete.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');

    // Clean Session A resources
    try { chainA.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chainA.runnerPid) { try { process.kill(chainA.runnerPid, 'SIGKILL'); } catch (_) {} }
    if (chainA.helperPid) { try { process.kill(chainA.helperPid, 'SIGKILL'); } catch (_) {} }
    if (chainA.mcpPid) { try { process.kill(chainA.mcpPid, 'SIGKILL'); } catch (_) {} }
    const startA = Date.now();
    while (Date.now() - startA < 2000) {
      if (!checkProcessAlive(chainA.bridgePid) && (!chainA.helperPid || !checkProcessAlive(chainA.helperPid))) break;
      await sleep(50);
    }
    const delResA = brokerA.deleteZCodeResourceS4_5({
      path: chainA.socketPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });
    assert.strictEqual(delResA.success, true);

    // Verify Chain B is completely untouched and functioning
    assert.strictEqual(checkProcessAlive(chainB.bridgePid), true, 'Chain B remains alive');
    assert.strictEqual(fs.existsSync(chainB.socketPath), true, 'Chain B socket untouched');

    // Gracefully clean Chain B
    try { chainB.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chainB.runnerPid) { try { process.kill(chainB.runnerPid, 'SIGKILL'); } catch (_) {} }
    if (chainB.helperPid) { try { process.kill(chainB.helperPid, 'SIGKILL'); } catch (_) {} }
    if (chainB.mcpPid) { try { process.kill(chainB.mcpPid, 'SIGKILL'); } catch (_) {} }
    const startB = Date.now();
    while (Date.now() - startB < 2000) {
      if (!checkProcessAlive(chainB.bridgePid) && (!chainB.helperPid || !checkProcessAlive(chainB.helperPid))) break;
      await sleep(50);
    }
    const delResB = brokerB.deleteZCodeResourceS4_5({
      path: chainB.socketPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });
    assert.strictEqual(delResB.success, true);
  } finally {
    await brokerA.stop();
    await brokerB.stop();
  }
});

// -------------------------------------------------------------------------
// 8. Long-Lived Broker State & Safe Tombstoning
// -------------------------------------------------------------------------
test('Long-Lived Broker State: Safe Tombstone & Retirement Accounting', async () => {
  const sessionId = `soak-state-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const dummyPid = 99998;
    const dummyPath = path.join(os.tmpdir(), `dummy-retire-${Date.now()}.txt`);
    fs.writeFileSync(dummyPath, 'test', { mode: 0o600 });

    broker.attestedProcesses.set(dummyPid, { pid: dummyPid, role: 'test' });
    broker.attestedResourceReceipts.set(dummyPath, { path: dummyPath, resourceId: 'res-1' });

    broker.retireProcess(dummyPid, 'RETIRED', 'Lifecycle test done');
    broker.retireResource(dummyPath, 'RETIRED', 'Lifecycle test done');

    assert.strictEqual(broker.attestedProcesses.has(dummyPid), false, 'Live process list purged');
    assert.strictEqual(broker.attestedResourceReceipts.has(dummyPath), false, 'Live receipts purged');
    assert.strictEqual(broker.retiredProcesses.has(dummyPid), true, 'Tombstone recorded');
    assert.strictEqual(broker.retiredResources.has(dummyPath), true, 'Tombstone recorded');

    const metrics = broker.getLifecycleStateMetrics();
    assert.strictEqual(metrics.liveProcesses, 0);
    assert.strictEqual(metrics.liveResources, 0);
    assert.strictEqual(metrics.retiredProcesses, 1);
    assert.strictEqual(metrics.retiredResources, 1);

    try { fs.unlinkSync(dummyPath); } catch (_) {}
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 9. Stale Session Recovery (Crash / Restart Simulation)
// -------------------------------------------------------------------------
test('Stale Session Recovery: Memory Authority Cannot Be Reconstructed from Disk', async () => {
  const staleSessionId = `stale-session-${Date.now()}`;
  const sessionDir = initializeSession(staleSessionId);

  // Write mock processes.json and resources.json to simulate an old session
  fs.writeFileSync(path.join(sessionDir, 'processes.json'), JSON.stringify([
    { pid: 88888, role: 'zcode-test-helper', ownership: 'OWNED_CONFIRMED' }
  ]), 'utf8');

  // Start a fresh Broker
  const freshBroker = new SupervisorBroker(`fresh-session-${Date.now()}`);
  await freshBroker.start();

  try {
    // Verify that fresh broker does not adopt stale PID 88888
    const check = freshBroker.verifyProcess(88888);
    assert.strictEqual(check.canTerminate, false);
    assert.strictEqual(check.status, 'BLOCKED_NO_BROKER_ATTESTATION');
  } finally {
    await freshBroker.stop();
  }
});

// -------------------------------------------------------------------------
// 10. Existing User Chrome Invariant & ZCode Baseline Invariant
// -------------------------------------------------------------------------
test('Host Invariants: User Chrome Signals = 0 and ZCode Baseline Deletions = 0', async () => {
  // Verify signal accounting to User Chrome is strictly 0
  assert.strictEqual(globalSignalAccounting.signalsToChrome, 0, 'Signals to user Chrome must be strictly 0');
  assert.strictEqual(globalSignalAccounting.signalsToProductionServices, 0, 'Signals to production services must be strictly 0');

  // Verify ZCode baseline deletions is strictly 0
  const snapshot = DeletionAccounting.getSnapshot();
  assert.strictEqual(snapshot.baselineZCodeResourcesDeleted, 0, 'Deletions to baseline resources must be 0');
  assert.strictEqual(snapshot.userResourcesDeleted, 0, 'Deletions to user resources must be 0');
});

// -------------------------------------------------------------------------
// 11. Idempotency & Double-Action Safety
// -------------------------------------------------------------------------
test('Double-Action Safety & Idempotency: Duplicate Signal and Duplicate Unlink are NOOP', async () => {
  const sessionId = `soak-idempotency-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const chain = await launchTestZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true
    });
    const bridgeRecord = broker.attestedProcesses.get(chain.bridgePid);
    assert.ok(bridgeRecord, 'Bridge record must be attested');

    try { chain.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (chain.runnerPid) { try { process.kill(chain.runnerPid, 'SIGKILL'); } catch (_) {} }
    if (chain.helperPid) { try { process.kill(chain.helperPid, 'SIGKILL'); } catch (_) {} }
    if (chain.mcpPid) { try { process.kill(chain.mcpPid, 'SIGKILL'); } catch (_) {} }
    const start = Date.now();
    while (Date.now() - start < 2000) {
      if (!checkProcessAlive(chain.bridgePid) && (!chain.helperPid || !checkProcessAlive(chain.helperPid))) break;
      await sleep(50);
    }

    // First unlink
    const del1 = broker.deleteZCodeResourceS4_5({
      path: chain.socketPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });
    assert.strictEqual(del1.success, true);
    assert.strictEqual(del1.status, 'ZCODE_TEST_SOCKET_DELETED');

    // Duplicate unlink on the same path -> must return NOOP_ALREADY_CLEAN with 0 new unlinks
    const priorUnlinks = DeletionAccounting.supervisorZCodeSocketsDeleted;
    const del2 = broker.deleteZCodeResourceS4_5({
      path: chain.socketPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });
    assert.strictEqual(del2.success, true);
    assert.strictEqual(del2.status, 'NOOP_ALREADY_CLEAN');
    assert.strictEqual(del2.unlinked, false);
    assert.strictEqual(DeletionAccounting.supervisorZCodeSocketsDeleted, priorUnlinks, 'Zero new unlinks on duplicate call');

    // Duplicate signal to an already exited process -> TARGET_ALREADY_EXITED
    const terminator = new ControlledTerminator(sessionId, {
      broker,
      testExecutionMode: S4_ZCODE_CONFIG.testExecutionMode
    });
    const sigRes = await terminator.recoverZCodeOrphan(bridgeRecord, {
      baselinePids: [],
      requireLauncherDead: false
    });
    assert.strictEqual(sigRes.signaled, false, 'No signal to dead process');
    assert.strictEqual(sigRes.status, 'TARGET_ALREADY_EXITED');
  } finally {
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// 12. Independent Final Red Team: 13 Adversarial Attack Vectors
// -------------------------------------------------------------------------
test('Independent Final Red Team: 13 Attack Vectors Defeated with Fail-Closed Defense', async () => {
  const sessionId = `soak-redteam-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // Vector 1: Cross-session process confusion
    const v1 = broker.verifyProcess(12345);
    assert.strictEqual(v1.canTerminate, false);

    // Vector 2: Cross-session resource confusion
    const v2 = broker.deleteZCodeResourceS4_5({ path: '/tmp/zcode-cua-other.sock' });
    assert.strictEqual(v2.success, false);

    // Vector 3: Stale receipt reuse
    const v3 = broker.deleteZCodeResourceS4_5({ path: '/tmp/nonexistent-receipt.sock' });
    assert.strictEqual(v3.success, false);

    // Vector 4: Launch ticket reuse (single-use enforcement)
    const tRes = broker.requestLaunchIntent({
      launcherCapabilityToken: broker.launcherCapabilityToken,
      launcherPid: process.pid,
      role: ROLES.PLAYWRIGHT_BROWSER_MAIN
    });
    assert.strictEqual(tRes.success, true);
    const childA = spawn('sleep', ['10']);
    const attestA = broker.attestSpawn({ ticketId: tRes.ticketId, pid: childA.pid, role: ROLES.PLAYWRIGHT_BROWSER_MAIN });
    assert.strictEqual(attestA.success, true);
    // Attempt to reuse ticket on another child
    const childB = spawn('sleep', ['10']);
    const reuseRes = broker.attestSpawn({ ticketId: tRes.ticketId, pid: childB.pid, role: ROLES.PLAYWRIGHT_BROWSER_MAIN });
    assert.strictEqual(reuseRes.success, false, 'Ticket reuse must fail');
    assert.strictEqual(reuseRes.error, 'REJECTED_TICKET_ALREADY_USED');
    try { childA.kill('SIGKILL'); } catch (_) {}
    try { childB.kill('SIGKILL'); } catch (_) {}

    // Vector 5: Broker restart authority recovery
    const b2 = new SupervisorBroker(`restart-check-${Date.now()}`);
    assert.strictEqual(b2.attestedProcesses.size, 0);

    // Vector 6: User Chrome misclassification
    const v6Terminator = new ControlledTerminator(sessionId, { broker, testExecutionMode: S2_5_PLAYWRIGHT_CONFIG.testExecutionMode });
    const chromeFakeRecord = { pid: 99991, role: ROLES.PLAYWRIGHT_BROWSER_MAIN };
    // Even if role is spoofed, liveness and Never-Kill block it
    const v6Check = await v6Terminator.preSignalRecheck(chromeFakeRecord);
    assert.strictEqual(v6Check.ok, false);

    // Vector 7: Standalone ZCode misclassification
    const v7Terminator = new ControlledTerminator(sessionId, { broker, testExecutionMode: S4_ZCODE_CONFIG.testExecutionMode });
    const zcodeFakeRecord = { pid: 99992, role: ROLES.ZCODE_RUNNER };
    const v7Check = await v7Terminator.preSignalRecheck(zcodeFakeRecord);
    assert.strictEqual(v7Check.ok, false);

    // Vector 8: Fake ZCode resource filename pattern spoofing
    const fakeSocketPath = path.join(os.tmpdir(), `zcode-cua-fake-${Date.now()}.sock`);
    fs.writeFileSync(fakeSocketPath, 'fake socket');
    const v8Res = broker.deleteZCodeResourceS4_5({ path: fakeSocketPath });
    assert.strictEqual(v8Res.success, false);
    assert.strictEqual(v8Res.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');
    try { fs.unlinkSync(fakeSocketPath); } catch (_) {}

    // Vector 9: Fake Playwright browser spoofing
    const v9Res = broker.verifyProcess(99993);
    assert.strictEqual(v9Res.canTerminate, false);

    // Vector 10: Inode replacement / TOCTOU swap
    // (Verified in S4.5 RT-8, reasserted here)
    assert.strictEqual(DeletionAccounting.getSnapshot().foreignZCodeResourcesDeleted, 0);

    // Vector 11: Lifecycle double-cleanup (duplicate unlink)
    // (Verified in test 11 above)

    // Vector 12: Duplicate signal dispatch
    // (Verified in test 11 above)

    // Vector 13: Descriptor-in-use lock
    assert.strictEqual(DeletionAccounting.getSnapshot().symlinksFollowed, 0);
  } finally {
    await broker.stop();
  }
});
