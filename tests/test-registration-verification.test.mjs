import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { spawnAttestedProcess, loadSessionData } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { SupervisorBroker } from '../src/broker.mjs';

test('Registration & Verification: correctly registers and verifies owned child process with creation attestation', async (t) => {
  const sessionId = `test-reg-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // Use trusted spawn wrapper via Broker
    const { success, child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: 'temp-worker',
      safeToKill: true
    });

    assert.strictEqual(success, true, 'Spawn attestation must succeed');

    try {
      assert.ok(child.pid, 'Child process must have a PID');
      assert.strictEqual(record.pid, child.pid);
      assert.strictEqual(record.ownership, 'OWNED_CONFIRMED');
      assert.strictEqual(record.safe_to_kill, true);

      // 2. Load from registry audit log
      const data = loadSessionData(sessionId);
      assert.strictEqual(data.processes.length, 1);
      const recorded = data.processes[0];

      // 3. Multi-factor ownership verification (8 factors + Ancestry)
      const verification = await verifyProcessOwnership(recorded, sessionId, { broker });
      assert.strictEqual(verification.canTerminate, true, 'Attested owned child must be terminable in verification');
      assert.strictEqual(verification.status, 'CONFIRMED_OWNED_TERMINABLE');
      assert.strictEqual(verification.factors.f1_exists, true);
      assert.strictEqual(verification.factors.f2_startTimeMatch, true);
      assert.strictEqual(verification.factors.f3_executableMatch, true);
      assert.strictEqual(verification.factors.f4_commandMatch, true);
      assert.strictEqual(verification.factors.f5_sessionMatch, true);
      assert.strictEqual(verification.factors.f6_provenanceAttested, true);
      assert.strictEqual(verification.factors.f7_neverKillExempt, true);
      assert.strictEqual(verification.factors.f8_sourceTrusted, true);
      assert.ok(verification.ancestry.length >= 0);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});
