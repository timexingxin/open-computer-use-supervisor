import test from 'node:test';
import assert from 'node:assert';
import { initializeSession } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';

test('Foreign & Unmanaged: rejects processes belonging to other sessions', async () => {
  const sessionAlpha = `session-alpha-${Date.now()}`;
  const sessionBeta = `session-beta-${Date.now()}`;
  initializeSession(sessionAlpha);
  initializeSession(sessionBeta);

  const foreignRecord = {
    pid: process.pid,
    session_id: sessionAlpha,
    safe_to_kill: true
  };

  const verification = await verifyProcessOwnership(foreignRecord, sessionBeta, { skipIpc: true });
  assert.strictEqual(verification.canTerminate, false);
  assert.strictEqual(verification.status, 'REJECTED_FOREIGN_SESSION');
});

test('Foreign & Unmanaged: null or unmanaged records fail closed', async () => {
  const session = `session-test-${Date.now()}`;
  initializeSession(session);

  const result = await verifyProcessOwnership(null, session, { skipIpc: true });
  assert.strictEqual(result.canTerminate, false);
  assert.strictEqual(result.status, 'REJECTED_INVALID_RECORD');
});
