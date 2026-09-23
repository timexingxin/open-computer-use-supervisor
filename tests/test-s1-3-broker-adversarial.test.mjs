import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import * as RegistryModule from '../src/registry.mjs';
import { initializeSession, loadSessionData, getSessionDir } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { verifyResourceSafety } from '../src/resource-verifier.mjs';
import { planSessionCleanup } from '../src/planner.mjs';
import { SupervisorBroker } from '../src/broker.mjs';
import { sendBrokerRequest } from '../src/ipc.mjs';
import { getProcessSnapshot } from '../src/identity.mjs';
import { SYSTEM_ROOT_PIDS, REGISTRATION_SOURCES } from '../src/config.mjs';

test('RED TEAM DEFENSE 1: Privileged API module export is ELIMINATED and unauthenticated IPC attestation is REJECTED', async () => {
  // 1. Assert privileged function is no longer exported by registry module
  assert.strictEqual(
    RegistryModule.registerAttestedBridgeProcess,
    undefined,
    '[DEFENSE CONFIRMED] registerAttestedBridgeProcess must NOT be exported as a public module function'
  );

  // 2. Test IPC barrier: Attacker tries to attest an arbitrary process without prior ticket intent
  const sessionId = `test-rt-def1-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const victimProc = spawn('sleep', ['60']);
  try {
    // Attacker sends forged ATTEST_SPAWN with non-existent ticket
    const res = await sendBrokerRequest(broker.socketPath, {
      action: 'ATTEST_SPAWN',
      sessionId,
      params: {
        ticketId: 'fake-ticket-exploit',
        pid: victimProc.pid,
        safeToKill: true
      }
    });

    assert.strictEqual(res.success, false);
    assert.match(res.error, /INVALID_OR_MISSING_LAUNCH_TICKET/);

    // Verify victim process cannot terminate
    const v = broker.verifyProcess(victimProc.pid);
    assert.strictEqual(v.canTerminate, false);
    assert.strictEqual(v.status, 'BLOCKED_NO_BROKER_ATTESTATION');
  } finally {
    victimProc.kill('SIGKILL');
    await broker.stop();
  }
});

test('RED TEAM DEFENSE 2: Zero Disk Secret enforced; session.json has NO secret, offline forgery impossible', async () => {
  const sessionId = `test-rt-def2-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const sessionDir = getSessionDir(sessionId);
    const sessionFile = path.join(sessionDir, 'session.json');
    assert.ok(fs.existsSync(sessionFile), 'session.json must exist');

    const sessionContent = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));

    // SECURITY CHECK: session_secret must NOT be written to disk
    assert.strictEqual(
      sessionContent.session_secret,
      undefined,
      '[DEFENSE CONFIRMED] session_secret is strictly memory-only and absent from disk'
    );

    // Verify no regular file in session directory leaks secret
    const allFiles = fs.readdirSync(sessionDir);
    for (const f of allFiles) {
      const filePath = path.join(sessionDir, f);
      const stat = fs.lstatSync(filePath);
      if (stat.isFile()) {
        const content = fs.readFileSync(filePath, 'utf8');
        assert.strictEqual(
          content.includes(broker.sessionSecret),
          false,
          `[DEFENSE CONFIRMED] File ${f} must not contain in-memory session secret`
        );
      }
    }

    // Attacker injects offline HMAC forgery into processes.json
    const victimProc = spawn('sleep', ['60']);
    try {
      const snap = getProcessSnapshot(victimProc.pid);
      const forgedRecord = {
        pid: victimProc.pid,
        session_id: sessionId,
        registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED,
        ownership: 'OWNED_CONFIRMED',
        safe_to_kill: true,
        start_time_epoch_ms: snap.startTimeEpochMs,
        lstart: snap.lstart,
        executable: snap.canonicalExecutable,
        comm: snap.comm,
        command: snap.command,
        command_fingerprint: snap.commandFingerprint,
        launch_nonce: 'forged-nonce-1234',
        attestation_sig: 'forged-offline-hmac-signature-deadbeef',
        role: 'forged-worker'
      };

      const { sessionDir, processes } = loadSessionData(sessionId);
      processes.push(forgedRecord);
      fs.writeFileSync(path.join(sessionDir, 'processes.json'), JSON.stringify(processes, null, 2), 'utf8');

      // Verifier checks with live broker
      const v = await verifyProcessOwnership(forgedRecord, sessionId, { broker });
      assert.strictEqual(v.canTerminate, false, 'Forged offline record must be BLOCKED');
      assert.strictEqual(v.status, 'BLOCKED_NO_BROKER_ATTESTATION');
    } finally {
      victimProc.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('RED TEAM DEFENSE 3: Active Ancestry Traversal executed; unlinked parentage is strictly REJECTED', async () => {
  const sessionId = `test-rt-def3-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  // Spawn victim child
  const child = spawn('sleep', ['60']);
  try {
    const snap = getProcessSnapshot(child.pid);
    assert.ok(snap, 'Must capture snapshot of live child');

    // Register record claiming false launcherPid that doesn't exist in ancestry
    const fakeRecord = {
      pid: child.pid,
      session_id: sessionId,
      launcher_pid: 99998, // arbitrary non-ancestor PID
      ppid: 99998,
      start_time_epoch_ms: snap.startTimeEpochMs,
      lstart: snap.lstart,
      executable: snap.canonicalExecutable,
      comm: snap.comm,
      command: snap.command,
      command_fingerprint: snap.commandFingerprint,
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED,
      ownership: 'OWNED_CONFIRMED',
      safe_to_kill: true,
      role: 'fake-child'
    };

    // Verifier executes real getProcessAncestry
    const v = await verifyProcessOwnership(fakeRecord, sessionId, { broker });
    assert.strictEqual(v.canTerminate, false);
    // Ancestry traversal returned real array of ancestor PIDs
    assert.ok(Array.isArray(v.ancestry), 'Verifier must return live ancestry array');
    assert.ok(v.ancestry.length > 0, 'Ancestry chain must contain live ancestor PIDs');
    // Must be blocked because fake launcherPid 99998 is not in the ancestor chain
    assert.strictEqual(v.status, 'REJECTED_ANCESTRY_BROKEN');
  } finally {
    child.kill('SIGKILL');
    await broker.stop();
  }
});

test('RED TEAM DEFENSE 4: Session Root Hijacking to PID 1 is STRICTLY REJECTED by Broker and Verifier', async () => {
  const sessionId = `test-rt-def4-${Date.now()}`;
  initializeSession(sessionId);

  // Manually tamper session.json to bind root_pid to 1 (launchd)
  const sessionDir = getSessionDir(sessionId);
  const sessionFile = path.join(sessionDir, 'session.json');
  const meta = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
  meta.root_pid = 1;
  meta.root_executable = '/sbin/launchd';
  fs.writeFileSync(sessionFile, JSON.stringify(meta, null, 2), 'utf8');

  // Verify validateSessionRoot rejects PID 1
  const rootCheck = RegistryModule.validateSessionRoot(sessionId);
  assert.strictEqual(rootCheck.valid, false, 'Binding to PID 1 must be rejected');
  assert.match(rootCheck.reason, /SESSION_ROOT_PID_INVALID_OR_SYSTEM_PID/);

  // Verify verifyProcessOwnership blocks all actions under hijacked session root
  const v = await verifyProcessOwnership({ pid: process.pid, session_id: sessionId }, sessionId, { skipIpc: true });
  assert.strictEqual(v.canTerminate, false);
  assert.strictEqual(v.status, 'BLOCKED_SESSION_ROOT_INVALID');
});

test('RED TEAM DEFENSE 5: Arbitrary external /tmp file claim is REJECTED as UNTRUSTED_EXTERNAL_RESOURCE', async () => {
  const sessionId = `test-rt-def5-${Date.now()}`;
  initializeSession(sessionId);

  // External arbitrary file created without session nonce
  const extFilePath = path.join('/tmp', `external-unrelated-${Date.now()}.sock`);
  fs.writeFileSync(extFilePath, 'data');

  try {
    const unverifiedResource = {
      path: extFilePath,
      type: 'unix_socket',
      owning_pid: 99999, // dead PID
      session_id: sessionId,
      broker_attested: false
    };

    // Verifier checks resource safety
    const v = await verifyResourceSafety(unverifiedResource, sessionId, { skipIpc: true });
    assert.strictEqual(v.canDelete, false, 'External unverified file must NOT be deletable');
    assert.strictEqual(v.status, 'UNTRUSTED_EXTERNAL_RESOURCE');
  } finally {
    if (fs.existsSync(extFilePath)) {
      fs.unlinkSync(extFilePath);
    }
  }
});

test('RED TEAM DEFENSE 6 (Crash-Safety): If Broker exits, state degrades to OBSERVE_ONLY; zero kills occur', async () => {
  const sessionId = `test-rt-def6-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  // Spawn attested process while broker is alive
  const { child, record } = await RegistryModule.spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']));

  try {
    // 1. While broker is alive, child is verified terminable
    const vAlive = await verifyProcessOwnership(record, sessionId, { broker });
    assert.strictEqual(vAlive.canTerminate, true);
    assert.strictEqual(vAlive.status, 'CONFIRMED_OWNED_TERMINABLE');

    // 2. Broker crashes / exits
    await broker.stop();

    // 3. Verifier checks without running broker (IPC fails)
    const vDead = await verifyProcessOwnership(record, sessionId);
    assert.strictEqual(vDead.canTerminate, false, '[FAIL_CLOSED] Must degrade to non-terminable when broker is down');
    assert.strictEqual(vDead.status, 'BLOCKED_BROKER_OFFLINE_OBSERVE_ONLY');

    // 4. Cleanup planner also treats dead broker as observe only
    const plan = await planSessionCleanup(sessionId, { dryRun: true });
    assert.strictEqual(plan.summary.processesWouldTerminate, 0);
    assert.strictEqual(plan.processes[0].action, 'BLOCKED');
  } finally {
    child.kill('SIGKILL');
  }
});
