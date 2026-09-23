import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { spawnAttestedProcess } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { SupervisorBroker } from '../src/broker.mjs';

test('PID Reuse Defense: detects start-time mismatch and blocks signal', async (t) => {
  const sessionId = `test-reuse-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const { child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: 'temp-worker'
    });

    try {
      const tamperedRecord = { ...record };

      // Tamper start time to simulate PID reuse by a newer process
      tamperedRecord.start_time_epoch_ms = tamperedRecord.start_time_epoch_ms - 50000;
      tamperedRecord.lstart = "Fri Sep 18 10:00:00 2026";

      const verification = await verifyProcessOwnership(tamperedRecord, sessionId, { broker });
      assert.strictEqual(verification.canTerminate, false, 'Must not be terminable if PID was reused');
      assert.strictEqual(verification.status, 'REJECTED_PID_REUSE_DETECTED');
      assert.strictEqual(verification.factors.f2_startTimeMatch, false);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});
