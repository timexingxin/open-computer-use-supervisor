import test from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn } from 'node:child_process';
import { SupervisorBroker } from '../src/broker.mjs';
import {
  PHASE_V0_1_CONFIG,
  S3_RESOURCE_CONFIG,
  RESOURCE_ROLES,
  SESSIONS_ROOT,
  RUNTIME_ROOT
} from '../src/config.mjs';
import {
  DeletionAccounting,
  validateResourcePathSafety,
  verifyFilePreUnlink,
  deleteDisposableFile,
  deleteDisposableEmptyDirectory,
  deleteDisposableDirectoryTree
} from '../src/resource-cleaner.mjs';
import { launchTestBrowser } from '../src/playwright-lifecycle.mjs';
import { checkProcessAlive } from '../src/identity.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

test('S3 Preflight: Production CLI --execute remains strictly locked', async () => {
  assert.strictEqual(
    PHASE_V0_1_CONFIG.executeAllowed,
    false,
    '[PREFLIGHT HARD GATE] executeAllowed must remain strictly false in Phase S3'
  );
  assert.strictEqual(
    S3_RESOURCE_CONFIG.allowGeneralResourceDeletion,
    false,
    '[PREFLIGHT HARD GATE] allowGeneralResourceDeletion must remain false'
  );
});

test('TEST A: Single Disposable File creation and verified deletion', async () => {
  const sessionId = `test-s3-a-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const res = broker.createTestResource({
      subPath: 'temp/test-file.txt',
      content: 'Hello Antigravity S3 disposable file',
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    assert.strictEqual(res.success, true);
    assert.ok(res.receipt);
    assert.strictEqual(fs.existsSync(res.receipt.realpath), true);

    // Verify 14-point check passes
    const check = verifyFilePreUnlink(res.receipt, sessionId);
    assert.strictEqual(check.canDelete, true);
    assert.strictEqual(check.status, 'CONFIRMED_DELETABLE');

    // Execute S3 controlled deletion
    const delRes = broker.deleteResourceS3({
      path: res.receipt.realpath,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, true);
    assert.strictEqual(delRes.status, 'DELETED_VERIFIED_RESOURCE');
    assert.strictEqual(fs.existsSync(res.receipt.realpath), false, 'File must be physically removed');
  } finally {
    await broker.stop();
  }
});

test('TEST B: Disposable Empty Directory creation and verified rmdir', async () => {
  const sessionId = `test-s3-b-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const res = broker.createTestResource({
      subPath: 'temp/empty-dir',
      isDirectory: true,
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    assert.strictEqual(res.success, true);
    assert.ok(res.receipt);
    assert.strictEqual(fs.existsSync(res.receipt.realpath), true);

    const delRes = broker.deleteResourceS3({
      path: res.receipt.realpath,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, true);
    assert.strictEqual(delRes.status, 'DELETED_VERIFIED_DIRECTORY');
    assert.strictEqual(fs.existsSync(res.receipt.realpath), false, 'Empty directory must be physically removed');
  } finally {
    await broker.stop();
  }
});

test('TEST C: Controlled Directory Tree safe bottom-up cleanup', async () => {
  const sessionId = `test-s3-c-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const treeRes = broker.createTestResource({
      subPath: 'temp/tree',
      isDirectory: true,
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    assert.strictEqual(treeRes.success, true);
    const rootPath = treeRes.receipt.realpath;

    // Create child files and nested directories
    fs.writeFileSync(path.join(rootPath, 'a.txt'), 'file a');
    fs.writeFileSync(path.join(rootPath, 'b.txt'), 'file b');
    fs.mkdirSync(path.join(rootPath, 'nested'), { recursive: true });
    fs.writeFileSync(path.join(rootPath, 'nested', 'c.txt'), 'file c');

    // Register child provenance in receipt childReceipts
    const childMap = new Map();
    childMap.set('a.txt', { type: 'file' });
    childMap.set('b.txt', { type: 'file' });
    childMap.set('nested', { type: 'directory' });
    childMap.set(path.join('nested', 'c.txt'), { type: 'file' });
    treeRes.receipt.childReceipts = childMap;

    const delRes = broker.deleteResourceS3({
      path: rootPath,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, true);
    assert.strictEqual(delRes.status, 'DELETED_VERIFIED_DIRECTORY_TREE');
    assert.strictEqual(delRes.filesUnlinked, 3);
    assert.strictEqual(delRes.directoriesRemoved, 2); // nested + root
    assert.strictEqual(fs.existsSync(rootPath), false, 'Directory tree must be completely removed');
  } finally {
    await broker.stop();
  }
});

test('TEST D: Foreign File submission is rejected with NO DELETE', async () => {
  const sessionId = `test-s3-d-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const foreignFile = path.join(os.tmpdir(), `foreign-file-${Date.now()}.txt`);
  fs.writeFileSync(foreignFile, 'untrusted content');

  try {
    const delRes = broker.deleteResourceS3({
      path: foreignFile,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, false);
    assert.ok(
      delRes.status === 'BLOCKED_OUTSIDE_APPROVED_SESSION_RESOURCE_ROOT' ||
      delRes.status === 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      `Expected safety rejection, got: ${delRes.status}`
    );
    assert.strictEqual(fs.existsSync(foreignFile), true, 'Foreign file must NOT be deleted');
  } finally {
    try { fs.unlinkSync(foreignFile); } catch (_) {}
    await broker.stop();
  }
});

test('TEST E: Forged Registry entry rejected without Broker in-memory attestation', async () => {
  const sessionId = `test-s3-e-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const resourcesRoot = path.join(broker.sessionDir, 'resources');
  fs.mkdirSync(resourcesRoot, { recursive: true });
  const forgedFile = path.join(resourcesRoot, 'forged.txt');
  fs.writeFileSync(forgedFile, 'forged content');

  // Manually write forged entry directly to resources.json
  const resFile = path.join(broker.sessionDir, 'resources.json');
  const forgedRecord = {
    id: 'res-forged-1234',
    type: 'file',
    path: forgedFile,
    session_id: sessionId,
    owned: true,
    safe_to_delete: true
  };
  fs.writeFileSync(resFile, JSON.stringify([forgedRecord], null, 2), 'utf8');

  try {
    const delRes = broker.deleteResourceS3({
      path: forgedFile,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION');
    assert.strictEqual(fs.existsSync(forgedFile), true, 'Forged file must NOT be deleted');
  } finally {
    try { fs.unlinkSync(forgedFile); } catch (_) {}
    await broker.stop();
  }
});

test('TEST F: Symlink Escape aborts directory cleanup and protects external target', async () => {
  const sessionId = `test-s3-f-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  const externalTarget = path.join(os.tmpdir(), `s3-external-target-${Date.now()}.txt`);
  fs.writeFileSync(externalTarget, 'critical external content');

  try {
    const treeRes = broker.createTestResource({
      subPath: 'temp/symlink-dir',
      isDirectory: true,
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    const dirPath = treeRes.receipt.realpath;
    const symlinkPath = path.join(dirPath, 'escape-link');
    fs.symlinkSync(externalTarget, symlinkPath);

    const delRes = broker.deleteResourceS3({
      path: dirPath,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'SYMLINK_DETECTED');
    assert.strictEqual(fs.existsSync(externalTarget), true, 'External target must survive unharmed');
    assert.strictEqual(fs.existsSync(dirPath), true, 'Directory deletion must be completely aborted');
  } finally {
    try { fs.unlinkSync(externalTarget); } catch (_) {}
    await broker.stop();
  }
});

test('TEST G: Inode Replacement / TOCTOU defense blocks deletion', async () => {
  const sessionId = `test-s3-g-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const res = broker.createTestResource({
      subPath: 'temp/inode-swap.txt',
      content: 'original file A',
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    const targetPath = res.receipt.realpath;
    const originalInode = res.receipt.inode;

    // Simulate attacker replacing file A with file B at same path
    fs.unlinkSync(targetPath);
    fs.writeFileSync(targetPath, 'substituted file B with new inode');
    const newLstat = fs.lstatSync(targetPath);

    // Verify inode changed
    assert.notStrictEqual(newLstat.ino, originalInode);

    const delRes = broker.deleteResourceS3({
      path: targetPath,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'RESOURCE_IDENTITY_CHANGED');
    assert.strictEqual(fs.existsSync(targetPath), true, 'Substituted file must NOT be deleted');
  } finally {
    await broker.stop();
  }
});

test('TEST H: Resource with alive owner process is blocked from deletion', async () => {
  const sessionId = `test-s3-h-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  // Spawn an innocent child process to act as active owner
  const child = spawn('sleep', ['10'], { stdio: 'ignore' });
  const ownerPid = child.pid;

  try {
    const res = broker.createTestResource({
      subPath: 'temp/owner-alive.txt',
      content: 'protected file',
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: ownerPid,
      owningPid: ownerPid
    });

    assert.strictEqual(checkProcessAlive(ownerPid), true);

    const delRes = broker.deleteResourceS3({
      path: res.receipt.realpath,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_OWNER_STILL_ALIVE');
    assert.strictEqual(fs.existsSync(res.receipt.realpath), true, 'File must remain untouched while owner lives');
  } finally {
    try { child.kill('SIGKILL'); } catch (_) {}
    await broker.stop();
  }
});

test('TEST I: Playwright Profile After Clean Exit is safely deleted', async () => {
  const sessionId = `test-s3-i-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // Launch test browser with profile in resources/playwright-profile/
    const { browser, mainPid, userDataDir, profileReceipt, close } = await launchTestBrowser(sessionId, broker, {
      mode: 'background',
      useResourcesRoot: true,
      attestProfile: true
    });

    assert.ok(profileReceipt, 'Profile receipt must be registered');
    assert.strictEqual(fs.existsSync(userDataDir), true);

    // Gracefully close browser
    await close();
    await sleep(200);

    // Verify main PID is dead
    assert.strictEqual(checkProcessAlive(mainPid), false);

    // Attest profile directory contents for safe tree cleanup
    const pReceipt = broker.attestedResourceReceipts.get(userDataDir);
    assert.ok(pReceipt);

    // Delete verified profile directory tree
    const delRes = broker.deleteResourceS3({
      path: userDataDir,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, true);
    assert.ok(
      delRes.status === 'PLAYWRIGHT_TEST_PROFILE_DELETED' ||
      delRes.status === 'DELETED_VERIFIED_DIRECTORY_TREE',
      `Expected profile deleted status, got: ${delRes.status}`
    );
    assert.strictEqual(fs.existsSync(userDataDir), false, 'Playwright test profile must be deleted');
  } finally {
    await broker.stop();
  }
});

test('TEST J: Twin Profile Test removes Profile A while Profile B survives and Browser B functions', async () => {
  const sessionId = `test-s3-j-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  let browserA = null;
  let browserB = null;

  try {
    browserA = await launchTestBrowser(sessionId, broker, {
      mode: 'background',
      useResourcesRoot: true,
      attestProfile: true,
      profileName: `twin-profile-a-${Date.now()}`
    });

    browserB = await launchTestBrowser(sessionId, broker, {
      mode: 'background',
      useResourcesRoot: true,
      attestProfile: true,
      profileName: `twin-profile-b-${Date.now()}`
    });

    assert.strictEqual(fs.existsSync(browserA.userDataDir), true);
    assert.strictEqual(fs.existsSync(browserB.userDataDir), true);

    // Close Browser A only
    await browserA.close();
    await sleep(200);
    assert.strictEqual(checkProcessAlive(browserA.mainPid), false);
    assert.strictEqual(checkProcessAlive(browserB.mainPid), true);

    // Delete Profile A only
    const delRes = broker.deleteResourceS3({
      path: browserA.userDataDir,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, true);
    assert.strictEqual(fs.existsSync(browserA.userDataDir), false, 'Profile A must be deleted');

    // VERIFY COLLATERAL PROTECTION: Profile B must still exist
    assert.strictEqual(fs.existsSync(browserB.userDataDir), true, 'Profile B must remain completely intact');

    // VERIFY FUNCTIONAL INTEGRITY: Browser B must remain alive and responsive
    assert.strictEqual(checkProcessAlive(browserB.mainPid), true);
    await browserB.page.goto('data:text/html,<html><head><title>Twin Profile Live</title></head><body>OK</body></html>');
    const title = await browserB.page.title();
    assert.strictEqual(title, 'Twin Profile Live', 'Browser B must remain fully operational');
  } finally {
    if (browserB) {
      try { await browserB.close(); } catch (_) {}
    }
    await broker.stop();
  }
});

test('RED TEAM 1: Open file handle blocks deletion (BLOCKED_RESOURCE_IN_USE)', async () => {
  const sessionId = `test-s3-rt1-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const res = broker.createTestResource({
      subPath: 'temp/open-handle.txt',
      content: 'held open content',
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    // Hold file open with descriptor
    const fd = fs.openSync(res.receipt.realpath, 'r');

    try {
      const delRes = broker.deleteResourceS3({
        path: res.receipt.realpath,
        testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
      });

      assert.strictEqual(delRes.success, false);
      assert.strictEqual(delRes.status, 'BLOCKED_RESOURCE_IN_USE');
      assert.strictEqual(fs.existsSync(res.receipt.realpath), true, 'File held open must NOT be deleted');
    } finally {
      fs.closeSync(fd);
    }
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 2: Attempt to delete ZCode resources is hard-blocked (ZCODE_RESOURCE)', async () => {
  const sessionId = `test-s3-rt2-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const zcodePaths = [
      '/tmp/zcode-cua-test.sock',
      path.join(os.homedir(), '.zcode', 'test.txt')
    ];

    for (const zPath of zcodePaths) {
      const safety = validateResourcePathSafety(zPath, sessionId);
      assert.strictEqual(safety.safe, false);
      assert.strictEqual(safety.status, 'ZCODE_RESOURCE');

      const delRes = broker.deleteResourceS3({
        path: zPath,
        testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
      });
      assert.strictEqual(delRes.success, false);
      assert.strictEqual(delRes.status, 'ZCODE_RESOURCE');
    }
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 3: Hard path denylist blocks root and system paths', async () => {
  const sessionId = `test-s3-rt3-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const criticalTargets = ['/', os.homedir(), '/tmp', path.join(os.homedir(), 'Documents')];

    for (const target of criticalTargets) {
      const safety = validateResourcePathSafety(target, sessionId);
      assert.strictEqual(safety.safe, false);
      assert.ok(
        safety.status === 'BLOCKED_HARD_PATH_DENYLIST' ||
        safety.status === 'BLOCKED_OUTSIDE_APPROVED_SESSION_RESOURCE_ROOT' ||
        safety.status === 'SYMLINK_DETECTED',
        `Expected safe: false rejection, got: ${safety.status}`
      );

      const delRes = broker.deleteResourceS3({
        path: target,
        isDirectory: true,
        testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
      });
      assert.strictEqual(delRes.success, false);
    }
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 4: Pre-existing Playwright cache is immune (PRE_EXISTING_RESOURCE)', async () => {
  const sessionId = `test-s3-rt4-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const cachePath = path.join(os.homedir(), 'Library', 'Caches', 'ms-playwright');
    const safety = validateResourcePathSafety(cachePath, sessionId);
    assert.strictEqual(safety.safe, false);
    assert.strictEqual(safety.status, 'PRE_EXISTING_RESOURCE');

    const delRes = broker.deleteResourceS3({
      path: cachePath,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });
    assert.strictEqual(delRes.success, false);
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 5: Cross-session resource deletion is rejected (CROSS_SESSION_RESOURCE_REJECTED)', async () => {
  const session1 = `test-s3-session1-${Date.now()}`;
  const session2 = `test-s3-session2-${Date.now()}`;
  const broker1 = new SupervisorBroker(session1);
  const broker2 = new SupervisorBroker(session2);
  await broker1.start();
  await broker2.start();

  try {
    // Create resource in Session 1
    const res1 = broker1.createTestResource({
      subPath: 'temp/session1-file.txt',
      content: 'session 1 data',
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    assert.strictEqual(res1.success, true);

    // Attempt to delete Session 1 file through Session 2 Broker
    const delRes2 = broker2.deleteResourceS3({
      path: res1.receipt.realpath,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes2.success, false);
    assert.ok(
      delRes2.status === 'BLOCKED_OUTSIDE_APPROVED_SESSION_RESOURCE_ROOT' ||
      delRes2.status === 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION'
    );
    assert.strictEqual(fs.existsSync(res1.receipt.realpath), true, 'Session 1 resource must survive Session 2 attempt');
  } finally {
    await broker1.stop();
    await broker2.stop();
  }
});

test('RED TEAM 6: Unknown child in directory aborts cleanup (BLOCKED_UNEXPECTED_CHILD)', async () => {
  const sessionId = `test-s3-rt6-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const treeRes = broker.createTestResource({
      subPath: 'temp/unprovenanced-dir',
      isDirectory: true,
      resourceRole: RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid: process.pid
    });

    const rootPath = treeRes.receipt.realpath;

    // Create a legitimate file
    fs.writeFileSync(path.join(rootPath, 'legit.txt'), 'legit');

    // Register only legit.txt
    const childMap = new Map();
    childMap.set('legit.txt', { type: 'file' });
    treeRes.receipt.childReceipts = childMap;

    // External process drops an unexpected file
    fs.writeFileSync(path.join(rootPath, 'rogue.txt'), 'unexpected rogue file');

    const delRes = broker.deleteResourceS3({
      path: rootPath,
      isDirectory: true,
      testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
    });

    assert.strictEqual(delRes.success, false);
    assert.strictEqual(delRes.status, 'BLOCKED_UNEXPECTED_CHILD');
    assert.strictEqual(fs.existsSync(rootPath), true, 'Entire directory must be preserved when unknown child appears');
    assert.strictEqual(fs.existsSync(path.join(rootPath, 'legit.txt')), true);
    assert.strictEqual(fs.existsSync(path.join(rootPath, 'rogue.txt')), true);
  } finally {
    await broker.stop();
  }
});

test('RED TEAM 7: Path traversal escape with ".." is rejected', async () => {
  const sessionId = `test-s3-rt7-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const traversalPaths = [
      path.join(broker.sessionDir, 'resources', '..', '..', '..', 'escaped.txt'),
      path.join(broker.sessionDir, 'resources', 'temp', '..', '..', 'session.json'),
      '../../../etc/hosts'
    ];

    for (const tPath of traversalPaths) {
      const safety = validateResourcePathSafety(tPath, sessionId);
      assert.strictEqual(safety.safe, false);
      assert.ok(
        safety.status === 'BLOCKED_OUTSIDE_APPROVED_SESSION_RESOURCE_ROOT' ||
        safety.status === 'BLOCKED_HARD_PATH_DENYLIST'
      );

      const delRes = broker.deleteResourceS3({
        path: tPath,
        testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE'
      });
      assert.strictEqual(delRes.success, false);
    }
  } finally {
    await broker.stop();
  }
});

test('DELETION ACCOUNTING AUDIT: Verifies strict invariants', () => {
  const snapshot = DeletionAccounting.getSnapshot();

  assert.strictEqual(snapshot.symlinksFollowed, 0, 'In-flight symlinks followed must be strictly 0');
  assert.strictEqual(snapshot.foreignResourcesDeleted, 0, 'Foreign resources deleted must be strictly 0');
  assert.strictEqual(snapshot.userResourcesDeleted, 0, 'User resources deleted must be strictly 0');
  assert.strictEqual(snapshot.playwrightProductionResourcesDeleted, 0, 'Production Playwright resources deleted must be strictly 0');
  assert.strictEqual(snapshot.zcodeResourcesDeleted, 0, 'ZCode resources deleted must be strictly 0');
  assert.ok(snapshot.filesUnlinked > 0, 'Files unlinked counter must be positive for verified test files');
  assert.ok(snapshot.directoriesRemoved > 0, 'Directories removed counter must be positive for verified test directories');
});
