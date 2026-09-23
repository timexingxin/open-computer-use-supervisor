import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import {
  initializeSession,
  spawnAttestedProcess,
  loadSessionData,
  getSessionDir
} from '../src/registry.mjs';
import { SupervisorBroker } from '../src/broker.mjs';
import {
  ControlledTerminator,
  SignalAccounting
} from '../src/controlled-terminator.mjs';
import { runCli } from '../src/cli.mjs';
import {
  S2_CONTROLLED_CONFIG,
  REGISTRATION_SOURCES,
  PHASE_V0_1_CONFIG
} from '../src/config.mjs';
import { checkProcessAlive } from '../src/identity.mjs';

test('S2 Preflight & S2.14: Production CLI --execute remains strictly locked', async () => {
  assert.strictEqual(
    PHASE_V0_1_CONFIG.executeAllowed,
    false,
    '[PREFLIGHT CONFIRMED] executeAllowed must be false in Phase S2'
  );

  const sessionId = `test-s2-preflight-${Date.now()}`;
  initializeSession(sessionId);

  const code = await runCli(['cleanup', '--execute', '--session', sessionId]);
  assert.strictEqual(code, 1, 'Production CLI cleanup --execute must exit with code 1 (FAIL CLOSED)');
});

test('S2.1 Role & Source Gate: Rejects BRIDGE_ATTESTED, PLAYWRIGHT_ATTESTED, and Non-Disposable Roles', async () => {
  const sessionId = `test-s2-gate-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  try {
    // 1. Rejects BRIDGE_ATTESTED
    const bridgeRecord = {
      pid: process.pid,
      session_id: sessionId,
      role: S2_CONTROLLED_CONFIG.disposableRole,
      registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
      safe_to_kill: true
    };
    const res1 = await terminator.terminateDisposableChild(bridgeRecord);
    assert.strictEqual(res1.success, false);
    assert.strictEqual(res1.signaled, false);
    assert.strictEqual(res1.status, 'ABORT_REGISTRATION_SOURCE_REJECTED');

    // 2. Rejects PLAYWRIGHT_ATTESTED
    const pwRecord = {
      pid: process.pid,
      session_id: sessionId,
      role: S2_CONTROLLED_CONFIG.disposableRole,
      registration_source: REGISTRATION_SOURCES.PLAYWRIGHT_ATTESTED,
      safe_to_kill: true
    };
    const res2 = await terminator.terminateDisposableChild(pwRecord);
    assert.strictEqual(res2.success, false);
    assert.strictEqual(res2.signaled, false);
    assert.strictEqual(res2.status, 'ABORT_REGISTRATION_SOURCE_REJECTED');

    // 3. Rejects Non-Disposable Role (e.g. zcode-bridge-helper)
    const otherRoleRecord = {
      pid: process.pid,
      session_id: sessionId,
      role: 'zcode-bridge-helper',
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED,
      safe_to_kill: true
    };
    const res3 = await terminator.terminateDisposableChild(otherRoleRecord);
    assert.strictEqual(res3.success, false);
    assert.strictEqual(res3.signaled, false);
    assert.strictEqual(res3.status, 'ABORT_ROLE_NOT_S2_DISPOSABLE');

    // 4. Rejects when not in TEST_EXECUTION_MODE
    const unmodeTerminator = new ControlledTerminator(sessionId, {
      broker,
      accounting,
      testExecutionMode: null
    });
    const res4 = await unmodeTerminator.terminateDisposableChild(bridgeRecord);
    assert.strictEqual(res4.status, 'ABORT_NOT_IN_TEST_EXECUTION_MODE');
  } finally {
    await broker.stop();
  }
});

test('TEST A (S2.2 First Real SIGTERM Test): Supervisor-spawned normal sleep gracefully terminated', async () => {
  const sessionId = `test-s2-a-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  try {
    // 1. Spawn attested disposable child
    const { success, child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: S2_CONTROLLED_CONFIG.disposableRole,
      safeToKill: true
    });

    assert.strictEqual(success, true, 'Spawn attestation must succeed');
    assert.ok(child.pid > 0);
    assert.strictEqual(record.role, S2_CONTROLLED_CONFIG.disposableRole);
    assert.strictEqual(record.ownership, 'OWNED_CONFIRMED');

    // 2. Controlled termination via SIGTERM
    const termResult = await terminator.terminateDisposableChild(record, { graceTimeoutMs: 1500 });

    assert.strictEqual(termResult.success, true);
    assert.strictEqual(termResult.signaled, true);
    assert.strictEqual(termResult.status, 'TERMINATED_GRACEFULLY');
    assert.deepStrictEqual(termResult.signals, ['SIGTERM']);
    assert.strictEqual(termResult.pid, child.pid);

    // 3. Confirm process actually dead in OS
    assert.strictEqual(checkProcessAlive(child.pid), false, 'Child process must be dead in OS');

    // 4. Signal accounting checks
    assert.strictEqual(accounting.sigtermSent, 1, 'Exactly one SIGTERM sent');
    assert.strictEqual(accounting.sigkillSent, 0, 'Zero SIGKILL sent for graceful exit');
    assert.strictEqual(accounting.signalsToDisposableTestChildren, 1);
    assert.strictEqual(accounting.signalsToProductionServices, 0);
  } finally {
    await broker.stop();
  }
});

test('TEST B (S2.6 Controlled SIGKILL Escalation): SIGTERM-resistant fixture escalates to SIGKILL', async () => {
  const sessionId = `test-s2-b-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  try {
    // Spawn Node fixture that ignores SIGTERM
    const resistantCode = 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000);';
    const { success, child, record } = await spawnAttestedProcess(
      sessionId,
      () => spawn('node', ['-e', resistantCode]),
      {
        role: S2_CONTROLLED_CONFIG.disposableRole,
        safeToKill: true
      }
    );

    assert.strictEqual(success, true);
    assert.ok(child.pid > 0);

    // Terminate with short grace period (300ms) to trigger escalation
    const termResult = await terminator.terminateDisposableChild(record, {
      graceTimeoutMs: 300,
      allowKillEscalation: true
    });

    assert.strictEqual(termResult.success, true);
    assert.strictEqual(termResult.signaled, true);
    assert.strictEqual(termResult.escalated, true);
    assert.strictEqual(termResult.status, 'ESCALATED_TO_SIGKILL');
    assert.deepStrictEqual(termResult.signals, ['SIGTERM', 'SIGKILL']);

    // Confirm dead
    assert.strictEqual(checkProcessAlive(child.pid), false, 'Child must be dead after SIGKILL');

    // Accounting checks
    assert.strictEqual(accounting.sigtermSent, 1);
    assert.strictEqual(accounting.sigkillSent, 1);
    assert.strictEqual(accounting.signalsToDisposableTestChildren, 2);
    assert.strictEqual(accounting.signalsToProductionServices, 0);
  } finally {
    await broker.stop();
  }
});

test('TEST C (S2.10 Foreign Sleep Test): External sleep rejected with NO_SIGNAL', async () => {
  const sessionId = `test-s2-c-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  // Spawn unmanaged external sleep process
  const extProc = spawn('sleep', ['60']);
  try {
    const unmanagedRecord = {
      pid: extProc.pid,
      session_id: sessionId,
      role: S2_CONTROLLED_CONFIG.disposableRole,
      registration_source: REGISTRATION_SOURCES.MANUAL_TEST,
      safe_to_kill: true
    };

    const res = await terminator.terminateDisposableChild(unmanagedRecord);
    assert.strictEqual(res.signaled, false, 'External process must NEVER receive signal');
    assert.strictEqual(res.status, 'ABORT_REGISTRATION_SOURCE_REJECTED');

    // Confirm external process is still alive and untouched
    assert.strictEqual(checkProcessAlive(extProc.pid), true);
    assert.strictEqual(accounting.sigtermSent, 0);
    assert.strictEqual(accounting.sigkillSent, 0);
  } finally {
    extProc.kill('SIGKILL');
    await broker.stop();
  }
});

test('TEST D (S2.11 Two Identical Children): Terminate Child A only; Child B remains untouched', async () => {
  const sessionId = `test-s2-d-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  try {
    // Child A
    const procA = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: S2_CONTROLLED_CONFIG.disposableRole,
      safeToKill: true
    });
    // Child B (Identical command line and executable)
    const procB = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: S2_CONTROLLED_CONFIG.disposableRole,
      safeToKill: true
    });

    assert.ok(procA.child.pid > 0);
    assert.ok(procB.child.pid > 0);
    assert.notStrictEqual(procA.child.pid, procB.child.pid);

    // Target Child A ONLY
    const termResult = await terminator.terminateDisposableChild(procA.record, { graceTimeoutMs: 1500 });
    assert.strictEqual(termResult.status, 'TERMINATED_GRACEFULLY');
    assert.strictEqual(termResult.pid, procA.child.pid);

    // VERIFY ISOLATION: Child A dead, Child B ALIVE
    assert.strictEqual(checkProcessAlive(procA.child.pid), false, 'Child A must be dead');
    assert.strictEqual(checkProcessAlive(procB.child.pid), true, 'Child B must remain ALIVE (No collateral damage)');

    // Only one SIGTERM recorded
    assert.strictEqual(accounting.sigtermSent, 1);
    assert.strictEqual(accounting.sigkillSent, 0);
    assert.strictEqual(accounting.signalsToDisposableTestChildren, 1);

    procB.child.kill('SIGKILL');
  } finally {
    await broker.stop();
  }
});

test('TEST E (S2.5 & S2.8 Race & PID Mutation): Process exit before signal or mutation aborts signal', async () => {
  const sessionId = `test-s2-e-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  try {
    // E1: Process exits before signal
    const proc1 = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: S2_CONTROLLED_CONFIG.disposableRole,
      safeToKill: true
    });
    // Kill child immediately
    proc1.child.kill('SIGKILL');
    await new Promise(r => setTimeout(r, 100));

    const res1 = await terminator.terminateDisposableChild(proc1.record);
    assert.strictEqual(res1.signaled, false, 'No signal if target already exited');
    assert.strictEqual(res1.status, 'TARGET_ALREADY_EXITED');

    // E2: Start identity mutation (simulated PID reuse)
    const proc2 = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: S2_CONTROLLED_CONFIG.disposableRole,
      safeToKill: true
    });

    try {
      const tamperedRecord = { ...proc2.record };
      tamperedRecord.start_time_epoch_ms = tamperedRecord.start_time_epoch_ms - 80000;
      tamperedRecord.lstart = 'Mon Sep 21 10:00:00 2026';

      const res2 = await terminator.terminateDisposableChild(tamperedRecord);
      assert.strictEqual(res2.signaled, false, 'No signal if start time mutated (PID reuse defense)');
      assert.strictEqual(res2.status, 'PID_IDENTITY_CHANGED');
      assert.strictEqual(checkProcessAlive(proc2.child.pid), true, 'Process remains untouched');
    } finally {
      proc2.child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('TEST F (S2.15 Test F): Broker stops before termination -> ABORTS WITH ZERO SIGNAL', async () => {
  const sessionId = `test-s2-f-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();

  try {
    const { child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: S2_CONTROLLED_CONFIG.disposableRole,
      safeToKill: true
    });

    // Broker crashes / stops before termination attempt
    await broker.stop();

    // Terminator attempts without broker instance (falling back to IPC)
    const terminator = new ControlledTerminator(sessionId, {
      broker: null, // Broker is dead
      accounting,
      testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
    });

    const res = await terminator.terminateDisposableChild(record);
    assert.strictEqual(res.signaled, false, 'Must not send signal when Broker is down');
    assert.match(res.status, /BLOCKED_NO_BROKER_ATTESTATION|BROKER_UNAVAILABLE/);
    assert.strictEqual(checkProcessAlive(child.pid), true, 'Child untouched');

    child.kill('SIGKILL');
  } catch (err) {
    throw err;
  }
});

test('TEST G (S2.9 Forged Record Test): Forged processes.json rejected with ZERO SIGNAL', async () => {
  const sessionId = `test-s2-g-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const accounting = new SignalAccounting();
  const terminator = new ControlledTerminator(sessionId, {
    broker,
    accounting,
    testExecutionMode: 'S2_DISPOSABLE_CHILD_ONLY'
  });

  const extProc = spawn('sleep', ['60']);
  try {
    // Attacker fabricates record in processes.json claiming OWNED_CONFIRMED and disposable role
    const forgedRecord = {
      pid: extProc.pid,
      session_id: sessionId,
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED,
      ownership: 'OWNED_CONFIRMED',
      safe_to_kill: true,
      role: S2_CONTROLLED_CONFIG.disposableRole
    };

    const { sessionDir, processes } = loadSessionData(sessionId);
    processes.push(forgedRecord);
    fs.writeFileSync(path.join(sessionDir, 'processes.json'), JSON.stringify(processes, null, 2), 'utf8');

    const res = await terminator.terminateDisposableChild(forgedRecord);
    assert.strictEqual(res.signaled, false, 'Forged record must not receive signal');
    assert.strictEqual(res.status, 'BLOCKED_NO_BROKER_ATTESTATION');
    assert.strictEqual(checkProcessAlive(extProc.pid), true, 'External process untouched');
  } finally {
    extProc.kill('SIGKILL');
    await broker.stop();
  }
});

test('S2.16 Signal Accounting Audit: Verified zero signals to production services', () => {
  const accounting = new SignalAccounting();

  // Record a disposable child signal
  accounting.recordSignal({
    session_id: 's2-test',
    target_pid: 12345,
    role: S2_CONTROLLED_CONFIG.disposableRole,
    signal: 'SIGTERM',
    executable: '/bin/sleep'
  });

  const summary = accounting.getSummary();
  assert.strictEqual(summary.signalsToDisposableTestChildren, 1);
  assert.strictEqual(summary.signalsToProductionServices, 0);
  assert.strictEqual(summary.signalsToChrome, 0);
  assert.strictEqual(summary.signalsToZCode, 0);
  assert.strictEqual(summary.signalsToPlaywright, 0);
  assert.strictEqual(summary.signalsToMcp, 0);
});
