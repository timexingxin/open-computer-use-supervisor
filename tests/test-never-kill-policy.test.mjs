import test from 'node:test';
import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import { isNeverKill } from '../src/predicates.mjs';
import { getProcessSnapshot } from '../src/identity.mjs';
import { initializeSession } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { NEVER_KILL_CATEGORIES } from '../src/config.mjs';

test('Never-Kill Safety Gate: Hard-blocks system and user critical processes', async () => {
  // Test PID 1 (launchd / init) which is always running on any POSIX system
  const p1Snapshot = getProcessSnapshot(1);
  if (p1Snapshot) {
    const verdict = isNeverKill(p1Snapshot);
    assert.strictEqual(verdict.neverKill, true);
    assert.strictEqual(verdict.category, NEVER_KILL_CATEGORIES.SYSTEM_CRITICAL);

    const sessionId = `test-neverkill-p1-${Date.now()}`;
    initializeSession(sessionId);

    const mockRecord = {
      pid: 1,
      session_id: sessionId,
      safe_to_kill: true,
      registration_source: 'SPAWN_ATTESTED',
      start_time_epoch_ms: p1Snapshot.startTimeEpochMs,
      lstart: p1Snapshot.lstart,
      executable: p1Snapshot.canonicalExecutable,
      comm: p1Snapshot.comm
    };
    const verification = await verifyProcessOwnership(mockRecord, sessionId, { skipIpc: true });
    assert.strictEqual(verification.canTerminate, false);
    assert.strictEqual(verification.status, 'BLOCKED_BY_NEVER_KILL_POLICY');
  }

  // Also test dynamic live Chrome if present
  let liveChromePid = null;
  try {
    const stdout = execFileSync('pgrep', ['-f', 'Google Chrome.app/Contents/MacOS/Google Chrome'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] });
    const pids = stdout.trim().split('\n').map(p => parseInt(p, 10)).filter(p => p > 0);
    if (pids.length > 0) liveChromePid = pids[0];
  } catch (_) {}

  if (liveChromePid) {
    const liveChrome = getProcessSnapshot(liveChromePid);
    if (liveChrome) {
      const verdict = isNeverKill(liveChrome);
      assert.strictEqual(verdict.neverKill, true);
      assert.strictEqual(verdict.category, NEVER_KILL_CATEGORIES.USER_BROWSER);

      const sessionId = `test-neverkill-chrome-${Date.now()}`;
      initializeSession(sessionId);

      const mockRecord = {
        pid: liveChromePid,
        session_id: sessionId,
        safe_to_kill: true,
        registration_source: 'SPAWN_ATTESTED',
        start_time_epoch_ms: liveChrome.startTimeEpochMs,
        lstart: liveChrome.lstart,
        executable: liveChrome.canonicalExecutable,
        comm: liveChrome.comm
      };
      const verification = await verifyProcessOwnership(mockRecord, sessionId, { skipIpc: true });
      assert.strictEqual(verification.canTerminate, false);
      assert.strictEqual(verification.status, 'BLOCKED_BY_NEVER_KILL_POLICY');
    }
  }
});

test('Never-Kill Safety Gate: Semantic independence from live PIDs (arbitrary PID testing)', () => {
  // PID 1
  const initVerdict = isNeverKill({ pid: 1, comm: 'launchd' });
  assert.strictEqual(initVerdict.neverKill, true);
  assert.strictEqual(initVerdict.category, NEVER_KILL_CATEGORIES.SYSTEM_CRITICAL);

  // Chrome on brand new dynamic PID 77777
  const chromeRandomPid = isNeverKill({
    pid: 77777,
    ppid: 1,
    comm: 'Google Chrome',
    canonicalExecutable: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    command: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
  });
  assert.strictEqual(chromeRandomPid.neverKill, true);
  assert.strictEqual(chromeRandomPid.category, NEVER_KILL_CATEGORIES.USER_BROWSER);

  // cdp-proxy on brand new dynamic PID 88888
  const cdpProxyRandomPid = isNeverKill({
    pid: 88888,
    ppid: 1,
    comm: 'node',
    canonicalExecutable: '/usr/local/bin/node',
    command: 'node /Users/example/skills/web-access/scripts/cdp-proxy.mjs'
  });
  assert.strictEqual(cdpProxyRandomPid.neverKill, true);
  assert.strictEqual(cdpProxyRandomPid.category, NEVER_KILL_CATEGORIES.SHARED_EXTERNAL_SERVICE);

  // Standalone ZCode (PPID=1, no bridge flags)
  const standaloneZCode = isNeverKill({
    pid: 54321,
    ppid: 1,
    comm: 'ZCode',
    canonicalExecutable: '/Applications/ZCode.app/Contents/MacOS/ZCode',
    command: '/Applications/ZCode.app/Contents/MacOS/ZCode'
  });
  assert.strictEqual(standaloneZCode.neverKill, true);
  assert.strictEqual(standaloneZCode.category, NEVER_KILL_CATEGORIES.STANDALONE_USER_ZCODE);
});
