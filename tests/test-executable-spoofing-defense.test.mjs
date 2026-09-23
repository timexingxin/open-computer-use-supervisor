import test from 'node:test';
import assert from 'node:assert';
import { spawn } from 'node:child_process';
import { spawnAttestedProcess } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { SupervisorBroker } from '../src/broker.mjs';

test('Executable Spoofing Defense: rejects if live binary differs from registered executable', async (t) => {
  const sessionId = `test-exe-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const { child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: 'temp-worker'
    });

    try {
      const tamperedRecord = { ...record };

      // Tamper executable to simulate binary spoofing
      tamperedRecord.executable = '/usr/bin/curl';
      tamperedRecord.comm = 'curl';

      const verification = await verifyProcessOwnership(tamperedRecord, sessionId, { broker });
      assert.strictEqual(verification.canTerminate, false, 'Must reject mismatched executable');
      assert.strictEqual(verification.status, 'REJECTED_EXECUTABLE_MISMATCH');
      assert.strictEqual(verification.factors.f3_executableMatch, false);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});
