import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { verifyResourceSafety } from '../src/resource-verifier.mjs';

test('Socket In-Use Defense: blocks deletion when owning process is alive or handle open', async (t) => {
  const socketPath = path.join('/tmp', `test-sock-${Date.now()}.sock`);
  const server = net.createServer();

  await new Promise((resolve) => {
    server.listen(socketPath, () => resolve());
  });

  try {
    const resource = {
      path: socketPath,
      type: 'unix_socket',
      owning_pid: process.pid, // current process is running
      session_id: 'test-session',
      broker_attested: true // simulate attested resource
    };

    const verification = await verifyResourceSafety(resource, 'test-session', { skipIpc: true });
    assert.strictEqual(verification.canDelete, false, 'Must not delete socket while owner is alive');
    assert.match(verification.status, /BLOCKED_OWNER_STILL_ALIVE|BLOCKED_RESOURCE_IN_USE/);
  } finally {
    server.close();
    if (fs.existsSync(socketPath)) {
      fs.unlinkSync(socketPath);
    }
  }
});

test('Socket Defense: blocks paths outside approved temporary directories', async () => {
  const illegalResource = {
    path: '/Applications/ZCode.app/Contents/Resources/test.txt',
    type: 'token_file',
    owning_pid: null,
    session_id: 'test-session',
    broker_attested: true
  };

  // Even if non-existent or existing, unsafe path must fail
  const verification = await verifyResourceSafety(illegalResource, 'test-session', { skipIpc: true });
  assert.strictEqual(verification.canDelete, false);
});
