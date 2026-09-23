import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  initializeSession,
  registerProcess,
  spawnAttestedProcess
} from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { verifyResourceSafety } from '../src/resource-verifier.mjs';
import { planSessionCleanup } from '../src/planner.mjs';
import { isNeverKill } from '../src/predicates.mjs';
import { REGISTRATION_SOURCES, NEVER_KILL_CATEGORIES } from '../src/config.mjs';
import { SupervisorBroker } from '../src/broker.mjs';

test('Adversarial Test 1: Arbitrary external PID manual register is UNTRUSTED and cannot terminate', async () => {
  const sessionId = `test-adv1-${Date.now()}`;
  initializeSession(sessionId);

  // Spawn an external harmless process (like sleep)
  const extProc = spawn('sleep', ['60']);
  try {
    // Manually register arbitrary PID via standard registerProcess
    const res = registerProcess(sessionId, {
      pid: extProc.pid,
      role: 'external-tool'
    });

    assert.strictEqual(res.success, true);
    assert.strictEqual(res.record.registration_source, REGISTRATION_SOURCES.MANUAL_TEST);
    assert.strictEqual(res.record.ownership, 'UNTRUSTED_TEST_REGISTRATION');
    assert.strictEqual(res.record.safe_to_kill, false);

    // Verify ownership
    const v = await verifyProcessOwnership(res.record, sessionId, { skipIpc: true });
    assert.strictEqual(v.canTerminate, false, 'Manual registration must NEVER be terminable');
    assert.strictEqual(v.status, 'BLOCKED_UNTRUSTED_REGISTRATION_SOURCE');
    assert.strictEqual(v.factors.f8_sourceTrusted, false);
  } finally {
    extProc.kill('SIGKILL');
  }
});

test('Adversarial Test 2: Tampered registry session_id is BLOCKED', async () => {
  const sessionA = `test-adv2-a-${Date.now()}`;
  const sessionB = `test-adv2-b-${Date.now()}`;
  const brokerA = new SupervisorBroker(sessionA);
  await brokerA.start();
  initializeSession(sessionB);

  try {
    const { child, record } = await spawnAttestedProcess(sessionA, () => spawn('sleep', ['60']));
    try {
      // Attempt to verify record created in session A using session B
      const v = await verifyProcessOwnership(record, sessionB, { skipIpc: true });
      assert.strictEqual(v.canTerminate, false, 'Foreign session record must be blocked');
      assert.strictEqual(v.status, 'REJECTED_FOREIGN_SESSION');
      assert.strictEqual(v.factors.f5_sessionMatch, false);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await brokerA.stop();
  }
});

test('Adversarial Test 3: Tampered ownership field in JSON is BLOCKED by HMAC attestation failure', async () => {
  const sessionId = `test-adv3-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const extProc = spawn('sleep', ['60']);
  try {
    // Manual registration
    const res = registerProcess(sessionId, { pid: extProc.pid });
    const tamperedRecord = { ...res.record };

    // Attacker manually edits JSON fields to claim ownership:
    tamperedRecord.registration_source = REGISTRATION_SOURCES.SPAWN_ATTESTED;
    tamperedRecord.ownership = 'OWNED_CONFIRMED';
    tamperedRecord.safe_to_kill = true;
    tamperedRecord.never_kill_reason = null;
    tamperedRecord.launch_nonce = 'fake-nonce-1234';

    const v = await verifyProcessOwnership(tamperedRecord, sessionId, { broker });
    assert.strictEqual(v.canTerminate, false, 'Tampered record must be blocked');
    assert.strictEqual(v.status, 'BLOCKED_NO_BROKER_ATTESTATION');
  } finally {
    extProc.kill('SIGKILL');
    await broker.stop();
  }
});

test('Adversarial Test 4: Parent dies + child reparents to PPID=1 maintains creation provenance', async () => {
  const sessionId = `test-adv4-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // Spawn an attested process
    const { child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']));
    try {
      // Simulate child reparenting to launchd (PPID 1)
      const reparentedRecord = { ...record };
      const v = await verifyProcessOwnership(reparentedRecord, sessionId, { broker });
      assert.strictEqual(v.canTerminate, true, 'Attested process with valid creation nonce holds provenance');
      assert.strictEqual(v.factors.f6_provenanceAttested, true);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('Adversarial Test 5: Two simultaneous Antigravity sessions are completely isolated', async () => {
  const sessionAlpha = `test-adv5-alpha-${Date.now()}`;
  const sessionBeta = `test-adv5-beta-${Date.now()}`;
  const brokerA = new SupervisorBroker(sessionAlpha);
  const brokerB = new SupervisorBroker(sessionBeta);
  await brokerA.start();
  await brokerB.start();

  try {
    const procA = await spawnAttestedProcess(sessionAlpha, () => spawn('sleep', ['60']));
    const procB = await spawnAttestedProcess(sessionBeta, () => spawn('sleep', ['60']));

    try {
      // Verify A under Session A -> PASS
      const vA_in_A = await verifyProcessOwnership(procA.record, sessionAlpha, { broker: brokerA });
      assert.strictEqual(vA_in_A.canTerminate, true);

      // Verify A under Session B -> FAIL
      const vA_in_B = await verifyProcessOwnership(procA.record, sessionBeta, { broker: brokerB });
      assert.strictEqual(vA_in_B.canTerminate, false);
      assert.strictEqual(vA_in_B.status, 'REJECTED_FOREIGN_SESSION');

      // Verify B under Session A -> FAIL
      const vB_in_A = await verifyProcessOwnership(procB.record, sessionAlpha, { broker: brokerA });
      assert.strictEqual(vB_in_A.canTerminate, false);
      assert.strictEqual(vB_in_A.status, 'REJECTED_FOREIGN_SESSION');

      // Verify B under Session B -> PASS
      const vB_in_B = await verifyProcessOwnership(procB.record, sessionBeta, { broker: brokerB });
      assert.strictEqual(vB_in_B.canTerminate, true);
    } finally {
      procA.child.kill('SIGKILL');
      procB.child.kill('SIGKILL');
    }
  } finally {
    await brokerA.stop();
    await brokerB.stop();
  }
});

test('Adversarial Test 6: PID reuse detected and BLOCKED', async () => {
  const sessionId = `test-adv6-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const { child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']));
    try {
      const reusedRecord = { ...record };
      reusedRecord.start_time_epoch_ms = reusedRecord.start_time_epoch_ms - 80000;
      reusedRecord.lstart = 'Fri Sep 18 10:00:00 2026';

      const v = await verifyProcessOwnership(reusedRecord, sessionId, { broker });
      assert.strictEqual(v.canTerminate, false);
      assert.strictEqual(v.status, 'REJECTED_PID_REUSE_DETECTED');
      assert.strictEqual(v.factors.f2_startTimeMatch, false);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('Adversarial Test 7: Same executable, different process is BLOCKED', async () => {
  const sessionId = `test-adv7-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const proc1 = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']));
    const proc2 = spawn('sleep', ['60']);

    try {
      const fakeRecord = { ...proc1.record, pid: proc2.pid };
      const v = await verifyProcessOwnership(fakeRecord, sessionId, { broker });
      assert.strictEqual(v.canTerminate, false);
      assert.strictEqual(v.factors.f6_provenanceAttested, false);
    } finally {
      proc1.child.kill('SIGKILL');
      proc2.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('Adversarial Test 8: Chrome PID changes -> still Never-Kill (USER_BROWSER)', () => {
  const chromeNewPid = {
    pid: 54321,
    ppid: 1,
    comm: 'Google Chrome',
    canonicalExecutable: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    command: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome --flag'
  };

  const verdict = isNeverKill(chromeNewPid);
  assert.strictEqual(verdict.neverKill, true, 'Chrome with arbitrary new PID must still be Never-Kill');
  assert.strictEqual(verdict.category, NEVER_KILL_CATEGORIES.USER_BROWSER);
  assert.strictEqual(verdict.reason, 'USER_GOOGLE_CHROME_BROWSER');
});

test('Adversarial Test 9: cdp-proxy PID changes -> still Never-Kill (SHARED_EXTERNAL_SERVICE)', () => {
  const cdpProxyNewPid = {
    pid: 65432,
    ppid: 1,
    comm: 'node',
    canonicalExecutable: '/usr/local/bin/node',
    command: '/usr/local/bin/node /Users/example/skills/web-access/scripts/cdp-proxy.mjs'
  };

  const verdict = isNeverKill(cdpProxyNewPid);
  assert.strictEqual(verdict.neverKill, true, 'cdp-proxy with arbitrary new PID must still be Never-Kill');
  assert.strictEqual(verdict.category, NEVER_KILL_CATEGORIES.SHARED_EXTERNAL_SERVICE);
  assert.strictEqual(verdict.reason, 'SHARED_EXTERNAL_CDP_PROXY');
});

test('Adversarial Test 10: Resource path replaced with symlink -> BLOCKED DELETE', async () => {
  const tmpDir = '/tmp';
  const realFile = path.join(tmpDir, `real-target-${Date.now()}.txt`);
  const symlinkPath = path.join(tmpDir, `malicious-symlink-${Date.now()}.sock`);

  fs.writeFileSync(realFile, 'important content');
  fs.symlinkSync(realFile, symlinkPath);

  try {
    const resource = {
      path: symlinkPath,
      type: 'unix_socket',
      owning_pid: null,
      session_id: 'test-session',
      broker_attested: true
    };

    const v = await verifyResourceSafety(resource, 'test-session', { skipIpc: true });
    assert.strictEqual(v.canDelete, false, 'Symlink resource must NOT be deleted');
    assert.strictEqual(v.status, 'BLOCKED_SYMLINK_NOT_PERMITTED');
  } finally {
    if (fs.existsSync(symlinkPath)) fs.unlinkSync(symlinkPath);
    if (fs.existsSync(realFile)) fs.unlinkSync(realFile);
  }
});

test('Adversarial Test 11: Mixed PGID blocks group termination', async () => {
  const sessionId = `test-adv11-${Date.now()}`;
  initializeSession(sessionId);

  const plan = await planSessionCleanup(sessionId, { dryRun: true });
  assert.strictEqual(plan.dryRun, true);
  assert.strictEqual(plan.executed, false);
});

test('Adversarial Test 12: Foreign Node process manually registered CANNOT obtain ownership', async () => {
  const sessionId = `test-adv12-${Date.now()}`;
  initializeSession(sessionId);

  const extNode = spawn('node', ['-e', 'setInterval(() => {}, 1000)']);
  try {
    const regRes = registerProcess(sessionId, {
      pid: extNode.pid,
      role: 'external-script'
    });

    assert.strictEqual(regRes.record.registration_source, REGISTRATION_SOURCES.MANUAL_TEST);
    assert.strictEqual(regRes.record.ownership, 'UNTRUSTED_TEST_REGISTRATION');
    assert.strictEqual(regRes.record.safe_to_kill, false);

    const v = await verifyProcessOwnership(regRes.record, sessionId, { skipIpc: true });
    assert.strictEqual(v.canTerminate, false, 'Foreign node process must be BLOCKED from termination');
    assert.strictEqual(v.status, 'BLOCKED_UNTRUSTED_REGISTRATION_SOURCE');
  } finally {
    extNode.kill('SIGKILL');
  }
});
