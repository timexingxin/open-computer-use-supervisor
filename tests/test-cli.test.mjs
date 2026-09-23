import test from 'node:test';
import assert from 'node:assert';
import { runCli } from '../src/cli.mjs';
import { initializeSession } from '../src/registry.mjs';

test('CLI Test Suite: verify status, verify, cleanup --dry-run and locked --execute', async () => {
  const sessionId = `test-cli-${Date.now()}`;
  initializeSession(sessionId);

  // 1. Status command
  const statusCode = await runCli(['status', '--session', sessionId]);
  assert.strictEqual(statusCode, 0);

  // 2. Verify command
  const verifyCode = await runCli(['verify', '--session', sessionId]);
  assert.strictEqual(verifyCode, 0);

  // 3. Cleanup dry-run command
  const dryRunCode = await runCli(['cleanup', '--dry-run', '--session', sessionId]);
  assert.strictEqual(dryRunCode, 0);

  // 4. Cleanup execute command (MUST FAIL CLOSED)
  const executeCode = await runCli(['cleanup', '--execute', '--session', sessionId]);
  assert.strictEqual(executeCode, 1, '--execute must exit with code 1 in Phase S1.1');
});
