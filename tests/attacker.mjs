#!/usr/bin/env node
/**
 * Standalone Same-User Attacker Script (Phase S1.4 Red-Team Attack).
 *
 * Runs as a completely independent process under the SAME macOS user.
 * Attempts to:
 * 1. Discover Broker socket path (actively probes for live responding broker)
 * 2. Connect to socket
 * 3. Request launch ticket (using own PID, forged root PID, guessed token)
 * 4. Try every publicly exposed IPC ticket operation
 * 5. Attempt to preauthorize a harmless `sleep 300`
 * 6. Attempt to convert that process into OWNED_CONFIRMED
 *
 * Expected outcome: All attempts fail with TICKET_ISSUANCE_DENIED / REJECTED.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { sendBrokerRequest } from '../src/ipc.mjs';
import { SupervisorBroker } from '../src/broker.mjs';
import { registerProcess } from '../src/registry.mjs';

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    socketPath: null,
    sessionId: null
  };
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--socket' && args[i + 1]) {
      opts.socketPath = args[++i];
    } else if (args[i] === '--sessionId' && args[i + 1]) {
      opts.sessionId = args[++i];
    }
  }
  return opts;
}

async function discoverActiveBroker() {
  const sessionsDir = path.join(os.homedir(), '.gemini', 'antigravity', 'runtime', 'sessions');
  if (!fs.existsSync(sessionsDir)) {
    return null;
  }

  const entries = fs.readdirSync(sessionsDir, { withFileTypes: true })
    .filter(d => d.isDirectory())
    .map(d => {
      const sock = path.join(sessionsDir, d.name, 'broker.sock');
      let mtime = 0;
      try {
        mtime = fs.statSync(sock).mtimeMs;
      } catch (_) {}
      return { id: d.name, sock, mtime };
    })
    .filter(e => e.mtime > 0)
    .sort((a, b) => b.mtime - a.mtime);

  // Probe candidates for a live responding broker
  for (const candidate of entries) {
    const ping = await sendBrokerRequest(candidate.sock, { action: 'PING' }, 500);
    if (ping.success && ping.pong) {
      return { socketPath: candidate.sock, sessionId: candidate.id };
    }
  }

  return null;
}

async function runAttack() {
  const opts = parseArgs();
  let socketPath = opts.socketPath;
  let sessionId = opts.sessionId;
  let spawnedBroker = null;

  // 1. Discover Broker socket if not provided explicitly
  if (!socketPath) {
    const discovered = await discoverActiveBroker();
    if (discovered) {
      socketPath = discovered.socketPath;
      sessionId = discovered.sessionId;
    } else {
      // No live broker running on the system: start a live session broker as target
      sessionId = `test-atk-live-${Date.now()}`;
      spawnedBroker = new SupervisorBroker(sessionId);
      await spawnedBroker.start();
      socketPath = spawnedBroker.socketPath;
    }
  }

  if (!socketPath || !fs.existsSync(socketPath)) {
    console.error('[ATTACKER_FATAL] Unable to discover or start active Broker socket');
    process.exit(2);
  }

  try {
    const results = {
      socketDiscovered: socketPath,
      sessionId,
      attacks: []
    };

    // Read session.json to discover root_pid
    let rootPid = null;
    const sessionDir = path.dirname(socketPath);
    const sessionFile = path.join(sessionDir, 'session.json');
    if (fs.existsSync(sessionFile)) {
      try {
        const meta = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
        rootPid = meta.root_pid;
      } catch (_) {}
    }

    // Attack 1: Request launch ticket using attacker's own PID without capability token
    const res1 = await sendBrokerRequest(socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherPid: process.pid,
        role: 'attacker-rogue-launcher',
        expectedExecutable: 'sleep'
      }
    });
    results.attacks.push({
      name: 'REQUEST_TICKET_OWN_PID_NO_CAP',
      success: res1.success,
      error: res1.error,
      blocked: res1.success === false && res1.error?.includes('TICKET_ISSUANCE_DENIED')
    });

    // Attack 2: Request launch ticket claiming real language_server PID without capability token
    const res2 = await sendBrokerRequest(socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherPid: rootPid || 99999,
        role: 'attacker-impersonating-root',
        expectedExecutable: 'sleep'
      }
    });
    results.attacks.push({
      name: 'REQUEST_TICKET_CLAIMING_ROOT_PID_NO_CAP',
      success: res2.success,
      error: res2.error,
      blocked: res2.success === false && res2.error?.includes('TICKET_ISSUANCE_DENIED')
    });

    // Attack 3: Request launch ticket with forged / guessed capability token
    const res3 = await sendBrokerRequest(socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        launcherPid: process.pid,
        role: 'attacker-guessed-cap',
        expectedExecutable: 'sleep'
      }
    });
    results.attacks.push({
      name: 'REQUEST_TICKET_GUESSED_CAPABILITY_TOKEN',
      success: res3.success,
      error: res3.error,
      blocked: res3.success === false && res3.error?.includes('TICKET_ISSUANCE_DENIED')
    });

    // Attack 4a: Try to register attacker as a trusted launcher without capability
    const res4a = await sendBrokerRequest(socketPath, {
      action: 'REGISTER_TRUSTED_LAUNCHER',
      sessionId,
      params: {
        pid: process.pid,
        role: 'attacker-launcher'
      }
    });
    results.attacks.push({
      name: 'REGISTER_TRUSTED_LAUNCHER_NO_CAP',
      success: res4a.success,
      error: res4a.error,
      blocked: res4a.success === false && res4a.error?.includes('TICKET_ISSUANCE_DENIED')
    });

    // Attack 4b: Try ATTEST_SPAWN with non-existent / fabricated ticket
    const res4b = await sendBrokerRequest(socketPath, {
      action: 'ATTEST_SPAWN',
      sessionId,
      params: {
        ticketId: 'tkt-fake-stolen-12345',
        pid: process.pid,
        safeToKill: true
      }
    });
    results.attacks.push({
      name: 'ATTEST_SPAWN_FABRICATED_TICKET',
      success: res4b.success,
      error: res4b.error,
      blocked: res4b.success === false && res4b.error?.includes('INVALID_OR_MISSING_LAUNCH_TICKET')
    });

    // Attack 4c: Try cross-session request spoofing
    const res4c = await sendBrokerRequest(socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId: 'foreign-session-tampered',
      params: {
        launcherPid: process.pid,
        expectedExecutable: 'sleep'
      }
    });
    results.attacks.push({
      name: 'REQUEST_TICKET_CROSS_SESSION_SPOOF',
      success: res4c.success,
      error: res4c.error,
      blocked: res4c.success === false && res4c.error?.includes('CROSS_SESSION_REQUEST_REJECTED')
    });

    // Attack 5: Attempt to preauthorize a harmless sleep 300
    const res5 = await sendBrokerRequest(socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherPid: process.pid,
        role: 'attacker-preauth-sleep',
        expectedExecutable: 'sleep'
      }
    });
    results.attacks.push({
      name: 'ATTEMPT_PREAUTHORIZE_HARMLESS_SLEEP_300',
      success: res5.success,
      error: res5.error,
      blocked: res5.success === false && res5.error?.includes('TICKET_ISSUANCE_DENIED')
    });

    // Attack 6: Attempt to convert that process into OWNED_CONFIRMED
    const sleepProc = spawn('sleep', ['300']);
    try {
      const attestAttempt = await sendBrokerRequest(socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId: res5.ticketId || 'tkt-unauthorized-sleep-intent',
          pid: sleepProc.pid,
          safeToKill: true
        }
      });

      const verifyAttempt = await sendBrokerRequest(socketPath, {
        action: 'VERIFY_PROCESS',
        sessionId,
        params: {
          pid: sleepProc.pid
        }
      });

      // Try manual registration injection into registry
      registerProcess(sessionId, {
        pid: sleepProc.pid,
        role: 'attacker-injected-sleep'
      });

      const verifyAfterManual = await sendBrokerRequest(socketPath, {
        action: 'VERIFY_PROCESS',
        sessionId,
        params: {
          pid: sleepProc.pid
        }
      });

      results.attacks.push({
        name: 'ATTEMPT_CONVERT_SLEEP_TO_OWNED_CONFIRMED',
        attestSuccess: attestAttempt.success,
        verifyCanTerminate: verifyAttempt.canTerminate,
        verifyStatus: verifyAttempt.status,
        verifyAfterManualCanTerminate: verifyAfterManual.canTerminate,
        blocked: (attestAttempt.success === false) &&
                 (verifyAttempt.canTerminate === false) &&
                 (verifyAfterManual.canTerminate === false)
      });
    } finally {
      sleepProc.kill('SIGKILL');
    }

    // Print results as JSON
    console.log(JSON.stringify(results, null, 2));

    // Assert all attacks were strictly blocked
    const allBlocked = results.attacks.every(a => a.blocked === true);
    if (!allBlocked) {
      process.exit(1);
    }
    process.exit(0);
  } finally {
    if (spawnedBroker) {
      await spawnedBroker.stop();
    }
  }
}

runAttack().catch(err => {
  console.error('[ATTACKER_EXCEPTION]', err);
  process.exit(1);
});
