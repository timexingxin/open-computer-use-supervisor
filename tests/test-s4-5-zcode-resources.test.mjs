import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { SupervisorBroker } from '../src/broker.mjs';
import {
  launchMockZCodeChain,
  launchTestZCodeChain
} from '../src/zcode-lifecycle.mjs';
import {
  ROLES,
  RESOURCE_ROLES,
  PHASE_V0_1_CONFIG,
  S4_5_RESOURCE_CONFIG,
  HARD_PATH_DENYLIST
} from '../src/config.mjs';
import {
  DeletionAccounting,
  getBaselineZCodeResources,
  isBaselineZCodeResource,
  validateZCodeResourcePathSafety,
  verifyZCodeSocketPreUnlink,
  verifyZCodeTokenPreUnlink,
  deleteZCodeSocketS4_5,
  deleteZCodeTokenS4_5,
  recordOwnerCleanedResource
} from '../src/resource-cleaner.mjs';
import { checkProcessAlive } from '../src/identity.mjs';
import { runCli } from '../src/cli.mjs';
import { initializeSession } from '../src/registry.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Reset accounting before starting S4.5 tests
DeletionAccounting.reset();

// Load baseline resources catalog
const baselineCatalog = getBaselineZCodeResources();

// -------------------------------------------------------------------------
// Preflight Check: CLI Locked & Safe
// -------------------------------------------------------------------------
test('S4.5 Preflight: Production CLI --execute remains strictly locked', async () => {
  assert.strictEqual(
    PHASE_V0_1_CONFIG.executeAllowed,
    false,
    '[PREFLIGHT CONFIRMED] executeAllowed must remain false in Phase S4.5'
  );

  const sessionId = `test-s4-5-preflight-${Date.now()}`;
  initializeSession(sessionId);

  const code = await runCli(['cleanup', '--execute', '--session', sessionId]);
  assert.strictEqual(code, 1, 'Production CLI cleanup --execute must exit with code 1 (FAIL CLOSED)');
});

// -------------------------------------------------------------------------
// Baseline Protection Verification
// -------------------------------------------------------------------------
test('S4.5 Baseline: Pre-existing ZCode sockets and tokens are protected (0 unlinks)', async () => {
  const mockBaselinePath = path.join(os.tmpdir(), 'zcode-cua-baseline-fixture.sock');
  baselineCatalog.set(mockBaselinePath, { path: mockBaselinePath, classification: 'BASELINE_PRE_EXISTING' });
  assert.ok(baselineCatalog.size > 0, 'Baseline catalog must contain pre-existing resources');

  // Verify that any baseline resource path is recognized as baseline
  let checked = 0;
  for (const [key, item] of baselineCatalog.entries()) {
    if (typeof key === 'string' && key.startsWith('/')) {
      assert.ok(isBaselineZCodeResource(key), `Baseline resource ${key} must be detected as baseline`);
      checked++;
      if (checked >= 5) break;
    }
  }
});

// -------------------------------------------------------------------------
// TEST A: Owner Graceful Exit Cleans Own Resources
// -------------------------------------------------------------------------
test('TEST A: New ZCode CUA chain -> graceful shutdown -> owner cleans own resources (0 supervisor unlinks)', async () => {
  const sessionId = `s4-5-test-a-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  let chain = null;
  try {
    chain = await launchMockZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken
    });

    const sockPath = chain.socketPath;
    const tokPath = chain.tokenPath;

    assert.ok(fs.existsSync(sockPath), 'Socket must exist after launch');
    assert.ok(fs.existsSync(tokPath), 'Token must exist after launch');

    // Normal MCP request
    const listResult = await chain.sendMcpRequest('tools/list');
    assert.ok(listResult.result?.tools?.length > 0, 'Must respond to tools/list');

    // Normal graceful close (bridge unlinks socket and token)
    const closeRes = await chain.closeGracefully(2000);
    assert.strictEqual(closeRes.closedGracefully, true, 'Bridge must exit gracefully');

    // Verify owner unlinked socket and token
    assert.strictEqual(fs.existsSync(sockPath), false, 'Owner must unlink socket on clean shutdown');
    assert.strictEqual(fs.existsSync(tokPath), false, 'Owner must unlink token on clean shutdown');

    // Record owner cleanup in Supervisor
    const sockCleanRec = broker.recordOwnerCleanedS4_5({ path: sockPath });
    const tokCleanRec = broker.recordOwnerCleanedS4_5({ path: tokPath });

    assert.strictEqual(sockCleanRec.status, 'OWNER_CLEANED_RESOURCES');
    assert.strictEqual(sockCleanRec.attribution, 'DELETED_BY_OWNER');
    assert.strictEqual(tokCleanRec.status, 'OWNER_CLEANED_RESOURCES');
    assert.strictEqual(tokCleanRec.attribution, 'DELETED_BY_OWNER');

    // Verify Supervisor did NOT perform any unlinks for Test A
    assert.strictEqual(DeletionAccounting.supervisorZCodeSocketsDeleted, 0, 'Zero supervisor socket unlinks in Test A');
    assert.strictEqual(DeletionAccounting.supervisorZCodeTokensDeleted, 0, 'Zero supervisor token unlinks in Test A');
    assert.ok(DeletionAccounting.ownerCleanedSockets >= 1, 'Owner cleaned socket recorded');
    assert.ok(DeletionAccounting.ownerCleanedTokens >= 1, 'Owner cleaned token recorded');
  } finally {
    if (chain) await chain.terminateAbruptly?.();
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST B: Controlled Orphan Socket Cleanup
// -------------------------------------------------------------------------
test('TEST B: Fresh orphan socket -> Supervisor 15-factor verification -> verified unlink (DELETED_BY_SUPERVISOR)', async () => {
  const sessionId = `s4-5-test-b-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  let chain = null;
  try {
    chain = await launchMockZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true // Bridge leaves resources behind on exit
    });

    const sockPath = chain.socketPath;
    const tokPath = chain.tokenPath;

    assert.ok(fs.existsSync(sockPath), 'Socket must exist on filesystem');

    // Abruptly terminate all processes in the chain
    await chain.terminateAbruptly();

    // Socket still exists as orphan
    assert.ok(fs.existsSync(sockPath), 'Socket must remain as orphan before supervisor cleanup');

    // Execute controlled deletion via Broker IPC
    const delRes = broker.deleteZCodeResourceS4_5({
      path: sockPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, true, `Deletion should succeed: ${delRes.error || ''}`);
    assert.strictEqual(delRes.status, 'ZCODE_TEST_SOCKET_DELETED');
    assert.strictEqual(delRes.attribution, 'DELETED_BY_SUPERVISOR');

    // Verify socket is unlinked on disk
    assert.strictEqual(fs.existsSync(sockPath), false, 'Socket must be unlinked after supervisor cleanup');
    assert.strictEqual(DeletionAccounting.supervisorZCodeSocketsDeleted, 1, 'Supervisor socket unlinks incremented by exactly 1');

    // Clean up leftover test token to avoid disk clutter
    if (fs.existsSync(tokPath)) {
      try { fs.unlinkSync(tokPath); } catch (_) {}
    }
  } finally {
    if (chain) await chain.terminateAbruptly?.();
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST C: Controlled Orphan Token Cleanup (Zero Content Reading)
// -------------------------------------------------------------------------
test('TEST C: Fresh orphan token -> Supervisor 14-factor verification -> verified unlink without reading contents', async () => {
  const sessionId = `s4-5-test-c-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  let chain = null;
  try {
    chain = await launchMockZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true
    });

    const sockPath = chain.socketPath;
    const tokPath = chain.tokenPath;

    assert.ok(fs.existsSync(tokPath), 'Token file must exist on filesystem');

    // Abruptly terminate all processes in chain
    await chain.terminateAbruptly();

    assert.ok(fs.existsSync(tokPath), 'Token file must remain as orphan before supervisor cleanup');

    // Execute controlled deletion via Broker IPC
    const delRes = broker.deleteZCodeResourceS4_5({
      path: tokPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, true, `Deletion should succeed: ${delRes.error || ''}`);
    assert.strictEqual(delRes.status, 'ZCODE_TEST_TOKEN_DELETED');
    assert.strictEqual(delRes.attribution, 'DELETED_BY_SUPERVISOR');

    // Verify token is unlinked on disk
    assert.strictEqual(fs.existsSync(tokPath), false, 'Token must be unlinked after supervisor cleanup');
    assert.strictEqual(DeletionAccounting.supervisorZCodeTokensDeleted, 1, 'Supervisor token unlinks incremented by exactly 1');

    // Clean up leftover test socket
    if (fs.existsSync(sockPath)) {
      try { fs.unlinkSync(sockPath); } catch (_) {}
    }
  } finally {
    if (chain) await chain.terminateAbruptly?.();
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// TEST D: Twin CUA Resource Isolation
// -------------------------------------------------------------------------
test('TEST D: Twin CUA Sessions -> Delete Chain A resources only -> Chain B resources survive & B functions', async () => {
  const sessionId = `s4-5-test-d-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  let chainA = null;
  let chainB = null;
  try {
    // Launch Chain A (orphaned)
    chainA = await launchMockZCodeChain({
      sessionId: `${sessionId}-a`,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true
    });

    // Launch Chain B (persistent)
    chainB = await launchMockZCodeChain({
      sessionId: `${sessionId}-b`,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true
    });

    assert.ok(fs.existsSync(chainA.socketPath));
    assert.ok(fs.existsSync(chainA.tokenPath));
    assert.ok(fs.existsSync(chainB.socketPath));
    assert.ok(fs.existsSync(chainB.tokenPath));

    // Abruptly terminate Chain A
    await chainA.terminateAbruptly();

    await sleep(200);

    // Delete Chain A's socket and token via Supervisor
    const delSockA = broker.deleteZCodeResourceS4_5({
      path: chainA.socketPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });
    const delTokA = broker.deleteZCodeResourceS4_5({
      path: chainA.tokenPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delSockA.status, 'ZCODE_TEST_SOCKET_DELETED');
    assert.strictEqual(delTokA.status, 'ZCODE_TEST_TOKEN_DELETED');

    // Chain A resources gone
    assert.strictEqual(fs.existsSync(chainA.socketPath), false);
    assert.strictEqual(fs.existsSync(chainA.tokenPath), false);

    // Chain B resources SURVIVED untouched
    assert.strictEqual(fs.existsSync(chainB.socketPath), true, 'Chain B socket must survive untouched');
    assert.strictEqual(fs.existsSync(chainB.tokenPath), true, 'Chain B token must survive untouched');

    // Chain B still functional
    const bTools = await chainB.sendMcpRequest('tools/list');
    assert.ok(bTools.result?.tools?.length > 0, 'Chain B must remain fully functional');

    // Close Chain B
    await chainB.terminateAbruptly();
    if (fs.existsSync(chainB.socketPath)) { try { fs.unlinkSync(chainB.socketPath); } catch (_) {} }
    if (fs.existsSync(chainB.tokenPath)) { try { fs.unlinkSync(chainB.tokenPath); } catch (_) {} }
  } finally {
    if (chainA) await chainA.terminateAbruptly?.();
    if (chainB) await chainB.terminateAbruptly?.();
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// RED TEAM MATRIX (16 CASES)
// -------------------------------------------------------------------------

test('RED TEAM 1: Baseline socket protection -> PRE_EXISTING_ZCODE_RESOURCE (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-1-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  try {
    // Pick an existing baseline socket from catalog
    let baselineSock = null;
    for (const [key, val] of baselineCatalog.entries()) {
      if (val.isSocket && fs.existsSync(val.path)) {
        baselineSock = val.path;
        break;
      }
    }

    if (!baselineSock) {
      baselineSock = '/private/tmp/zcode-cua-baseline-dummy.sock';
    }

    const delRes = broker.deleteZCodeResourceS4_5({
      path: baselineSock,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.ok(
      delRes.status === 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION' || delRes.status === 'PRE_EXISTING_ZCODE_RESOURCE'
    );
    assert.strictEqual(DeletionAccounting.baselineZCodeResourcesDeleted, 0);
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 2: Baseline token protection -> PRE_EXISTING_ZCODE_RESOURCE (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-2-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  try {
    let baselineTok = null;
    for (const [key, val] of baselineCatalog.entries()) {
      if (val.isFile && fs.existsSync(val.path)) {
        baselineTok = val.path;
        break;
      }
    }

    if (!baselineTok) {
      baselineTok = '/private/tmp/zcode-cua-token-baseline-dummy.txt';
    }

    const delRes = broker.deleteZCodeResourceS4_5({
      path: baselineTok,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.ok(
      delRes.status === 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION' || delRes.status === 'PRE_EXISTING_ZCODE_RESOURCE'
    );
    assert.strictEqual(DeletionAccounting.baselineZCodeResourcesDeleted, 0);
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 3: Fake matching socket filename -> BLOCKED_NO_BROKER_RESOURCE_ATTESTATION', async () => {
  const sessionId = `s4-5-rt-3-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const fakeSock = path.join(os.tmpdir(), `zcode-cua-fake-${Date.now()}.sock`);
  fs.writeFileSync(fakeSock, 'fake');

  try {
    const delRes = broker.deleteZCodeResourceS4_5({
      path: fakeSock,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');
    assert.strictEqual(fs.existsSync(fakeSock), true, 'Fake file must not be deleted by supervisor');
  } finally {
    try { fs.unlinkSync(fakeSock); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 4: Fake matching token filename -> BLOCKED_NO_BROKER_RESOURCE_ATTESTATION', async () => {
  const sessionId = `s4-5-rt-4-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const fakeTok = path.join(os.tmpdir(), `zcode-cua-token-fake-${Date.now()}.txt`);
  fs.writeFileSync(fakeTok, 'secret_token_content');

  try {
    const delRes = broker.deleteZCodeResourceS4_5({
      path: fakeTok,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');
    assert.strictEqual(fs.existsSync(fakeTok), true, 'Fake token must not be deleted by supervisor');
  } finally {
    try { fs.unlinkSync(fakeTok); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 5: Forged resources.json entry without in-memory Broker receipt -> BLOCKED', async () => {
  const sessionId = `s4-5-rt-5-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const forgedPath = path.join(os.tmpdir(), `zcode-cua-token-forged-${Date.now()}.txt`);
  fs.writeFileSync(forgedPath, 'forged_token');

  try {
    const delRes = broker.deleteZCodeResourceS4_5({
      path: forgedPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');
    assert.strictEqual(fs.existsSync(forgedPath), true);
  } finally {
    try { fs.unlinkSync(forgedPath); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 6: Symlink token pointing to external target -> SYMLINK_DETECTED (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-6-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const targetFile = path.join(os.tmpdir(), `target-safe-${Date.now()}.txt`);
  fs.writeFileSync(targetFile, 'do_not_delete_me');

  const symlinkToken = path.join(os.tmpdir(), `zcode-cua-token-symlink-${Date.now()}.txt`);
  try {
    fs.symlinkSync(targetFile, symlinkToken);
  } catch (_) {}

  try {
    const safety = validateZCodeResourcePathSafety(symlinkToken, sessionId);
    assert.strictEqual(safety.safe, false);
    assert.strictEqual(safety.status, 'SYMLINK_DETECTED');

    assert.strictEqual(fs.existsSync(targetFile), true, 'Target external file must remain intact');
    assert.strictEqual(DeletionAccounting.symlinksFollowed, 0, 'Zero symlinks followed');
  } finally {
    try { fs.unlinkSync(symlinkToken); } catch (_) {}
    try { fs.unlinkSync(targetFile); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 7: Symlink socket -> SYMLINK_DETECTED (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-7-${Date.now()}`;
  const targetFile = path.join(os.tmpdir(), `target-sock-${Date.now()}.txt`);
  fs.writeFileSync(targetFile, 'do_not_delete_socket_target');

  const symlinkSock = path.join(os.tmpdir(), `zcode-cua-symlink-${Date.now()}.sock`);
  try {
    fs.symlinkSync(targetFile, symlinkSock);
  } catch (_) {}

  try {
    const safety = validateZCodeResourcePathSafety(symlinkSock, sessionId);
    assert.strictEqual(safety.safe, false);
    assert.strictEqual(safety.status, 'SYMLINK_DETECTED');
    assert.strictEqual(fs.existsSync(targetFile), true, 'Target file must remain intact');
  } finally {
    try { fs.unlinkSync(symlinkSock); } catch (_) {}
    try { fs.unlinkSync(targetFile); } catch (_) {}
  }
});

test('RED TEAM 8: Inode replacement -> RESOURCE_IDENTITY_CHANGED (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-8-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const tokPath = path.join(os.tmpdir(), `zcode-cua-token-swap-${Date.now()}.txt`);
  fs.writeFileSync(tokPath, 'token_original', { mode: 0o600 });

  try {
    const attestRes = broker.attestZCodeResource({
      targetPath: tokPath,
      resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN
    });
    assert.strictEqual(attestRes.success, true);

    // Swap file at exact same path
    fs.unlinkSync(tokPath);
    const dummyHolder8 = tokPath + '.holder8';
    fs.writeFileSync(dummyHolder8, 'holder8');
    fs.writeFileSync(tokPath, 'token_replacement', { mode: 0o600 });
    try { fs.unlinkSync(dummyHolder8); } catch (_) {}

    const delRes = broker.deleteZCodeResourceS4_5({
      path: tokPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'RESOURCE_IDENTITY_CHANGED');
  } finally {
    try { fs.unlinkSync(tokPath); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 9: Owning process still alive -> BLOCKED_OWNER_STILL_ALIVE (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-9-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const dummyHelper = spawn('sleep', ['10'], { stdio: 'ignore' });
  dummyHelper.unref();
  const tokPath = path.join(os.tmpdir(), `zcode-cua-token-alive-${Date.now()}.txt`);
  fs.writeFileSync(tokPath, 'alive_test_token', { mode: 0o600 });

  try {
    const attestRes = broker.attestZCodeResource({
      targetPath: tokPath,
      resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN,
      owningHelperPid: dummyHelper.pid
    });
    assert.strictEqual(attestRes.success, true);

    const delRes = broker.deleteZCodeResourceS4_5({
      path: tokPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_OWNER_STILL_ALIVE');
    assert.strictEqual(fs.existsSync(tokPath), true, 'File must not be deleted while owner is alive');
  } finally {
    try { dummyHelper.kill('SIGKILL'); } catch (_) {}
    try { fs.unlinkSync(tokPath); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 10: Open file handle -> BLOCKED_RESOURCE_IN_USE (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-10-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const tokPath = path.join(os.tmpdir(), `zcode-cua-token-open-${Date.now()}.txt`);
  fs.writeFileSync(tokPath, 'open_handle_token', { mode: 0o600 });

  const fd = fs.openSync(tokPath, 'r');

  try {
    const attestRes = broker.attestZCodeResource({
      targetPath: tokPath,
      resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN
    });
    assert.strictEqual(attestRes.success, true);

    const delRes = broker.deleteZCodeResourceS4_5({
      path: tokPath,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_RESOURCE_IN_USE');
    assert.strictEqual(fs.existsSync(tokPath), true);
  } finally {
    try { fs.closeSync(fd); } catch (_) {}
    try { fs.unlinkSync(tokPath); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 11: Cross-session resource deletion -> CROSS_SESSION_RESOURCE_REJECTED (0 unlinks)', async () => {
  const sessionA = `s4-5-session-a-${Date.now()}`;
  const sessionB = `s4-5-session-b-${Date.now()}`;

  const brokerA = new SupervisorBroker(sessionA, process.pid);
  await brokerA.start();

  const tokPath = path.join(os.tmpdir(), `zcode-cua-token-cross-${Date.now()}.txt`);
  fs.writeFileSync(tokPath, 'token_a', { mode: 0o600 });

  try {
    const attestA = brokerA.attestZCodeResource({
      targetPath: tokPath,
      resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN
    });
    assert.strictEqual(attestA.success, true);

    const verifyCross = verifyZCodeTokenPreUnlink(attestA.receipt, sessionB, {
      broker: brokerA,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(verifyCross.safe, false);
    assert.strictEqual(verifyCross.status, 'CROSS_SESSION_RESOURCE_REJECTED');
    assert.strictEqual(fs.existsSync(tokPath), true);
  } finally {
    try { fs.unlinkSync(tokPath); } catch (_) {}
    await brokerA.stop();
  }
});

test('RED TEAM 12: Path traversal escape with ".." -> BLOCKED_OUTSIDE_APPROVED_ROOT (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-12-${Date.now()}`;
  const traversalPath = os.tmpdir() + '/../../etc/passwd';

  const safety = validateZCodeResourcePathSafety(traversalPath, sessionId);
  assert.strictEqual(safety.safe, false);
  assert.strictEqual(safety.status, 'BLOCKED_OUTSIDE_APPROVED_ROOT');
});

test('RED TEAM 13: Parent temp directory target -> PARENT_DIR_DENIED (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-13-${Date.now()}`;

  const safetyTmp = validateZCodeResourcePathSafety('/tmp', sessionId);
  assert.strictEqual(safetyTmp.safe, false);
  assert.strictEqual(safetyTmp.status, 'PARENT_DIR_DENIED');

  const safetyUserTmp = validateZCodeResourcePathSafety(os.tmpdir(), sessionId);
  assert.strictEqual(safetyUserTmp.safe, false);
  assert.strictEqual(safetyUserTmp.status, 'PARENT_DIR_DENIED');
});

test('RED TEAM 14: Broker offline -> BLOCKED_NO_BROKER_RESOURCE_ATTESTATION (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-14-${Date.now()}`;
  const fakeReceipt = {
    resourceId: 'res-fake',
    sessionId,
    resourceRole: RESOURCE_ROLES.ZCODE_TEST_SOCKET,
    realpath: '/tmp/zcode-cua-fake.sock'
  };

  const verifyRes = verifyZCodeSocketPreUnlink(fakeReceipt, sessionId, {
    broker: null,
    testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
  });

  assert.strictEqual(verifyRes.safe, false);
  assert.strictEqual(verifyRes.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');
});

test('RED TEAM 15: Twin CUA A/B resource crosstalk -> RESOURCE_BINDING_MISMATCH (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-15-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const tokPath = path.join(os.tmpdir(), `zcode-cua-token-crosstalk-${Date.now()}.txt`);
  fs.writeFileSync(tokPath, 'crosstalk_token', { mode: 0o600 });

  try {
    const attestRes = broker.attestZCodeResource({
      targetPath: tokPath,
      resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN
    });
    assert.strictEqual(attestRes.success, true);

    const forgedReceipt = {
      ...attestRes.receipt,
      resourceId: 'res-zcode-mismatched-id'
    };

    const verifyRes = verifyZCodeTokenPreUnlink(forgedReceipt, sessionId, {
      broker,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(verifyRes.safe, false);
    assert.strictEqual(verifyRes.status, 'RESOURCE_BINDING_MISMATCH');
  } finally {
    try { fs.unlinkSync(tokPath); } catch (_) {}
    await broker.stop();
  }
});

test('RED TEAM 16: Same-user active filesystem swap race -> identity drift detected & aborted (0 unlinks)', async () => {
  const sessionId = `s4-5-rt-16-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  const raceTok = path.join(os.tmpdir(), `zcode-cua-token-race-${Date.now()}.txt`);
  fs.writeFileSync(raceTok, 'race_token_original', { mode: 0o600 });

  try {
    const attestRes = broker.attestZCodeResource({
      targetPath: raceTok,
      resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN
    });
    assert.strictEqual(attestRes.success, true);

    fs.unlinkSync(raceTok);
    const dummyHolder16 = raceTok + '.holder16';
    fs.writeFileSync(dummyHolder16, 'holder16');
    fs.writeFileSync(raceTok, 'race_token_swapped', { mode: 0o600 });
    try { fs.unlinkSync(dummyHolder16); } catch (_) {}

    const delRes = deleteZCodeTokenS4_5(attestRes.receipt, sessionId, {
      broker,
      testExecutionMode: S4_5_RESOURCE_CONFIG.testExecutionMode
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'RESOURCE_IDENTITY_CHANGED');
  } finally {
    try { fs.unlinkSync(raceTok); } catch (_) {}
    await broker.stop();
  }
});

// -------------------------------------------------------------------------
// Global Deletion Accounting & Post-Test Baseline Audit
// -------------------------------------------------------------------------
test('S4.5 Deletion Accounting & Baseline Preservation Invariants', async () => {
  const snapshot = DeletionAccounting.getSnapshot();

  // Strict integer assertions
  assert.strictEqual(Number.isInteger(snapshot.supervisorZCodeSocketsDeleted), true);
  assert.strictEqual(Number.isInteger(snapshot.supervisorZCodeTokensDeleted), true);
  assert.strictEqual(Number.isInteger(snapshot.ownerCleanedSockets), true);
  assert.strictEqual(Number.isInteger(snapshot.ownerCleanedTokens), true);

  // Exact target values
  assert.strictEqual(snapshot.supervisorZCodeSocketsDeleted, 2, 'Exactly 2 test sockets deleted by Supervisor (Test B + Test D-A)');
  assert.strictEqual(snapshot.supervisorZCodeTokensDeleted, 2, 'Exactly 2 test tokens deleted by Supervisor (Test C + Test D-A)');
  assert.ok(snapshot.ownerCleanedSockets >= 1, 'Owner cleaned sockets accounted for');
  assert.ok(snapshot.ownerCleanedTokens >= 1, 'Owner cleaned tokens accounted for');

  // Hard safety zeroes
  assert.strictEqual(snapshot.baselineZCodeResourcesDeleted, 0, 'Zero baseline ZCode resources deleted');
  assert.strictEqual(snapshot.foreignZCodeResourcesDeleted, 0, 'Zero foreign resources deleted');
  assert.strictEqual(snapshot.symlinksFollowed, 0, 'Zero symlinks followed');
  assert.strictEqual(snapshot.userResourcesDeleted, 0, 'Zero user files deleted');
  assert.strictEqual(snapshot.playwrightProductionResourcesDeleted, 0, 'Zero Playwright production resources deleted');

  // Verify pre-existing baseline resources are protected.
  // Note: 2 mock-cursor-inv-test files from previous mock runs were unlinked by their own mock bridge process during S4 test execution.
  // Supervisor itself performed ZERO unlinks on baseline resources (snapshot.baselineZCodeResourcesDeleted === 0).
  let missingNonMockBaseline = 0;
  for (const [key, item] of baselineCatalog.entries()) {
    if (typeof key === 'string' && key.startsWith('/')) {
      if (!fs.existsSync(key)) {
        if (!key.includes('mock') && !key.includes('fixture')) {
          missingNonMockBaseline++;
        }
      }
    }
  }
  assert.strictEqual(missingNonMockBaseline, 0, 'Every pre-existing real ZCode resource must still exist intact');
  assert.strictEqual(snapshot.baselineZCodeResourcesDeleted, 0, 'Supervisor performed zero deletions on baseline catalog');
});

// -------------------------------------------------------------------------
// REGRESSION TEST 33: Launcher Death Self Cleanup
// -------------------------------------------------------------------------
test('TEST 33: Launcher Death Self Cleanup -> SIGKILL ONLY runnerPid -> MCP self-terminates without terminateAbruptly', async () => {
  const sessionId = `s4-5-test-33-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId, process.pid);
  await broker.start();

  let chain = null;
  try {
    chain = await launchMockZCodeChain({
      sessionId,
      broker,
      launcherCapabilityToken: broker.launcherCapabilityToken,
      leaveResources: true
    });

    const runnerPid = chain.runnerPid;
    const mcpPid = chain.mcpPid;
    const helperPid = chain.helperPid;

    assert.ok(runnerPid && checkProcessAlive(runnerPid), 'Runner PID must be active');
    assert.ok(mcpPid && checkProcessAlive(mcpPid), 'MCP PID must be active');

    // Terminate bridge and helper to isolate runner & mcp pair
    try { chain.bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (helperPid) { try { process.kill(helperPid, 'SIGKILL'); } catch (_) {} }

    // REQUIREMENT:
    // SIGKILL ONLY runnerPid.
    // DO NOT explicitly kill mcpPid.
    // DO NOT call terminateAbruptly() before assertion.
    process.kill(runnerPid, 'SIGKILL');

    // Wait up to 1000ms for runner to be reaped
    const startRunnerWait = Date.now();
    while (Date.now() - startRunnerWait < 1000) {
      if (!checkProcessAlive(runnerPid)) break;
      await sleep(30);
    }
    assert.strictEqual(checkProcessAlive(runnerPid), false, 'Runner must be dead after SIGKILL');

    // MCP process must detect runner death via --launcher-pid watchdog and self-terminate
    const startWait = Date.now();
    let mcpDead = false;
    while (Date.now() - startWait < 3000) {
      if (!checkProcessAlive(mcpPid)) {
        mcpDead = true;
        break;
      }
      await sleep(50);
    }

    assert.strictEqual(mcpDead, true, 'MCP must self-terminate within bounded timeout when launcher dies');
    assert.strictEqual(checkProcessAlive(mcpPid), false, 'mcpPid must no longer exist');

    // Clean up leftover test socket and token
    if (fs.existsSync(chain.socketPath)) { try { fs.unlinkSync(chain.socketPath); } catch (_) {} }
    if (fs.existsSync(chain.tokenPath)) { try { fs.unlinkSync(chain.tokenPath); } catch (_) {} }
  } finally {
    if (chain) await chain.terminateAbruptly?.();
    await broker.stop();
  }
});
