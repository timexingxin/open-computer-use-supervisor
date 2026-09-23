import test from 'node:test';
import assert from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import fs from 'node:fs';
import { SupervisorBroker } from '../src/broker.mjs';
import { sendBrokerRequest } from '../src/ipc.mjs';
import { spawnAttestedProcess } from '../src/registry.mjs';
import { verifyProcessOwnership } from '../src/verifier.mjs';
import { getProcessSnapshot } from '../src/identity.mjs';

function runAsyncProcess(cmd, args, options = {}) {
  return new Promise((resolve, reject) => {
    const cp = spawn(cmd, args, options);
    let stdout = '';
    let stderr = '';
    cp.stdout?.on('data', d => { stdout += d.toString(); });
    cp.stderr?.on('data', d => { stderr += d.toString(); });
    cp.on('close', code => resolve({ status: code, stdout, stderr }));
    cp.on('error', reject);
  });
}

test('S1.4 Case 1: same-user random Node process asks for ticket -> TICKET_ISSUANCE_DENIED', async () => {
  const sessionId = `test-s14-c1-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // Run external standalone attacker process with stripped environment (NO AGY_LAUNCHER_CAPABILITY*)
    const attackerScript = path.join(import.meta.dirname, 'attacker.mjs');
    const attacker = await runAsyncProcess(process.execPath, [attackerScript, '--socket', broker.socketPath, '--sessionId', sessionId], {
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME
        // Explicitly NO session capability tokens
      }
    });

    assert.strictEqual(
      attacker.status,
      0,
      `Attacker script must exit with 0 confirming all attacks were blocked. Output: ${attacker.stdout} ${attacker.stderr}`
    );

    const report = JSON.parse(attacker.stdout.trim());
    assert.strictEqual(report.attacks.length >= 6, true, 'Attacker must have executed at least 6 attack scenarios');
    for (const atk of report.attacks) {
      assert.strictEqual(atk.blocked, true, `Attack scenario ${atk.name} must be blocked`);
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 2: attacker claims real language_server PID without capability -> TICKET_ISSUANCE_DENIED', async () => {
  const sessionId = `test-s14-c2-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const realRootPid = broker.rootPid;
    assert.ok(realRootPid > 1, 'Valid session root PID must exist');

    // Attacker connects to broker socket directly claiming root PID without capability
    const res = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherPid: realRootPid,
        role: 'impersonating-language-server'
      }
    });

    assert.strictEqual(res.success, false, 'Ticket request claiming root PID without capability must fail');
    assert.match(res.error, /TICKET_ISSUANCE_DENIED: MISSING_LAUNCHER_CAPABILITY/);
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 3: attacker claims real bridge PID without capability -> TICKET_ISSUANCE_DENIED', async () => {
  const sessionId = `test-s14-c3-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const bridgeProc = spawn('sleep', ['60']);
    try {
      // Attacker claims bridge process PID without capability
      const res = await sendBrokerRequest(broker.socketPath, {
        action: 'REQUEST_LAUNCH_INTENT',
        sessionId,
        params: {
          launcherPid: bridgeProc.pid,
          role: 'impersonating-bridge'
        }
      });

      assert.strictEqual(res.success, false, 'Ticket request claiming bridge PID without capability must fail');
      assert.match(res.error, /TICKET_ISSUANCE_DENIED: MISSING_LAUNCHER_CAPABILITY/);
    } finally {
      bridgeProc.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 4: ticket replay -> REJECTED_TICKET_ALREADY_USED', async () => {
  const sessionId = `test-s14-c4-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // 1. Legitimate launcher requests ticket
    const capToken = broker.getLauncherCapabilityToken();
    const intentRes = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: capToken,
        launcherPid: process.pid,
        role: 'replay-test-launcher',
        expectedExecutable: 'sleep'
      }
    });
    assert.strictEqual(intentRes.success, true, 'Legitimate intent request must succeed');
    const ticketId = intentRes.ticketId;

    // 2. Spawn Child A and Child B
    const childA = spawn('sleep', ['60']);
    const childB = spawn('sleep', ['60']);
    try {
      // 3. First attestation with Child A succeeds
      const attestA = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId,
          pid: childA.pid,
          safeToKill: true
        }
      });
      assert.strictEqual(attestA.success, true, 'First attestation must succeed');
      assert.strictEqual(attestA.record.ownership, 'OWNED_CONFIRMED');

      // 4. Second attestation attempt with same ticket and Child A -> REJECTED_TICKET_ALREADY_USED
      const replayA = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId,
          pid: childA.pid,
          safeToKill: true
        }
      });
      assert.strictEqual(replayA.success, false, 'Replay attestation must fail');
      assert.strictEqual(replayA.error, 'REJECTED_TICKET_ALREADY_USED');

      // 5. Attempt to use consumed ticket on Child B -> REJECTED_TICKET_ALREADY_USED
      const replayB = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId,
          pid: childB.pid,
          safeToKill: true
        }
      });
      assert.strictEqual(replayB.success, false, 'Reusing consumed ticket on Child B must fail');
      assert.strictEqual(replayB.error, 'REJECTED_TICKET_ALREADY_USED');
    } finally {
      childA.kill('SIGKILL');
      childB.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 4b: ticket minted specifically for Child A, attempted for Child B prior to consumption -> PID_MISMATCH', async () => {
  const sessionId = `test-s14-c4b-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const childA = spawn('sleep', ['60']);
    const childB = spawn('sleep', ['60']);
    try {
      const capToken = broker.getLauncherCapabilityToken();
      const intentRes = await sendBrokerRequest(broker.socketPath, {
        action: 'REQUEST_LAUNCH_INTENT',
        sessionId,
        params: {
          launcherCapabilityToken: capToken,
          launcherPid: process.pid,
          role: 'child-a-launcher',
          expectedPid: childA.pid,
          expectedExecutable: 'sleep'
        }
      });
      assert.strictEqual(intentRes.success, true);
      const ticketId = intentRes.ticketId;

      // Attempt to attest Child B with ticket minted specifically for Child A
      const attestB = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId,
          pid: childB.pid,
          safeToKill: true
        }
      });

      assert.strictEqual(attestB.success, false, 'Using ticket on wrong child PID must be blocked');
      assert.match(attestB.error, /PID_MISMATCH/);
    } finally {
      childA.kill('SIGKILL');
      childB.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 5: ticket copied to another process (Ticket Theft) -> ANCESTRY_MISMATCH / BLOCK', async () => {
  const sessionId = `test-s14-c5-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // 1. Legitimate launcher mints ticket bound to process.pid
    const capToken = broker.getLauncherCapabilityToken();
    const intentRes = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: capToken,
        launcherPid: process.pid,
        role: 'legitimate-launcher'
      }
    });
    assert.strictEqual(intentRes.success, true);
    const stolenTicketId = intentRes.ticketId;

    const ipcPath = path.join(import.meta.dirname, '../src/ipc.mjs');
    const externalScript = `
      import { spawn } from 'node:child_process';
      import { sendBrokerRequest } from '${ipcPath}';

      const socketPath = process.argv[1];
      const sessionId = process.argv[2];
      const ticketId = process.argv[3];

      const child = spawn('sleep', ['60']);
      try {
        const res = await sendBrokerRequest(socketPath, {
          action: 'ATTEST_SPAWN',
          sessionId,
          params: { ticketId, pid: child.pid, safeToKill: true }
        });
        console.log(JSON.stringify(res));
      } finally {
        child.kill('SIGKILL');
      }
    `;

    const attackerRun = await runAsyncProcess(process.execPath, [
      '--input-type=module',
      '-e',
      externalScript,
      broker.socketPath,
      sessionId,
      stolenTicketId
    ]);

    const parsed = JSON.parse(attackerRun.stdout.trim());
    assert.strictEqual(parsed.success, false, 'Attacker attempting to use stolen ticket for its own child must fail');
    assert.match(parsed.error, /ANCESTRY_MISMATCH/, 'Must fail due to launcher PPID mismatch with ticket');
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 6: expired ticket -> LAUNCH_TICKET_EXPIRED', async () => {
  const sessionId = `test-s14-c6-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const capToken = broker.getLauncherCapabilityToken();
    // Mint ticket with 50ms TTL
    const intentRes = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: capToken,
        launcherPid: process.pid,
        role: 'short-lived-ticket',
        ttlMs: 50
      }
    });
    assert.strictEqual(intentRes.success, true);
    const ticketId = intentRes.ticketId;

    // Sleep 100ms to allow ticket to expire
    await new Promise(r => setTimeout(r, 100));

    const child = spawn('sleep', ['60']);
    try {
      const attestRes = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId,
          pid: child.pid,
          safeToKill: true
        }
      });

      assert.strictEqual(attestRes.success, false, 'Expired ticket attestation must fail');
      assert.strictEqual(attestRes.error, 'LAUNCH_TICKET_EXPIRED');
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 7: cross-session ticket -> CROSS_SESSION_TICKET_REJECTED / INVALID_OR_MISSING', async () => {
  const sessionA = `test-s14-c7a-${Date.now()}`;
  const sessionB = `test-s14-c7b-${Date.now()}`;
  const brokerA = new SupervisorBroker(sessionA);
  const brokerB = new SupervisorBroker(sessionB);
  await brokerA.start();
  await brokerB.start();

  try {
    // 1. Mint ticket in Session A
    const capA = brokerA.getLauncherCapabilityToken();
    const intentA = await sendBrokerRequest(brokerA.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId: sessionA,
      params: {
        launcherCapabilityToken: capA,
        launcherPid: process.pid,
        role: 'session-a-launcher'
      }
    });
    assert.strictEqual(intentA.success, true);
    const ticketA = intentA.ticketId;

    // 2. Attempt to use ticket A against Broker B
    const child = spawn('sleep', ['60']);
    try {
      const attestB = await sendBrokerRequest(brokerB.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId: sessionB,
        params: {
          ticketId: ticketA,
          pid: child.pid,
          safeToKill: true
        }
      });

      assert.strictEqual(attestB.success, false, 'Cross-session ticket must be rejected');
      assert.match(attestB.error, /INVALID_OR_MISSING_LAUNCH_TICKET|CROSS_SESSION_TICKET_REJECTED/);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await brokerA.stop();
    await brokerB.stop();
  }
});

test('S1.4 Case 8: ticket used for wrong executable -> EXECUTABLE_MISMATCH', async () => {
  const sessionId = `test-s14-c8-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const capToken = broker.getLauncherCapabilityToken();
    // Mint ticket explicitly requiring "sleep"
    const intentRes = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: capToken,
        launcherPid: process.pid,
        role: 'sleep-only-launcher',
        expectedExecutable: '/bin/sleep'
      }
    });
    assert.strictEqual(intentRes.success, true);
    const ticketId = intentRes.ticketId;

    // Launcher spawns cat instead of sleep
    const wrongChild = spawn('cat');
    try {
      const attestRes = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId,
          pid: wrongChild.pid,
          safeToKill: true
        }
      });

      assert.strictEqual(attestRes.success, false, 'Wrong executable must be rejected');
      assert.match(attestRes.error, /EXECUTABLE_MISMATCH/);
    } finally {
      wrongChild.kill('SIGKILL');
    }

    // Substring collision test: ticket specifies 'sh', child executes 'bash' -> must fail
    const shIntent = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: capToken,
        launcherPid: process.pid,
        role: 'sh-only-launcher',
        expectedExecutable: 'sh'
      }
    });
    assert.strictEqual(shIntent.success, true);
    const bashChild = spawn('bash', ['-c', 'sleep 60']);
    try {
      const bashAttest = await sendBrokerRequest(broker.socketPath, {
        action: 'ATTEST_SPAWN',
        sessionId,
        params: {
          ticketId: shIntent.ticketId,
          pid: bashChild.pid,
          safeToKill: true
        }
      });
      assert.strictEqual(bashAttest.success, false, 'Substring collision (sh matching bash) must be rejected');
      assert.match(bashAttest.error, /EXECUTABLE_MISMATCH/);
    } finally {
      bashChild.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 9: ticket used for wrong PID (unrelated foreign PID) -> ANCESTRY_MISMATCH / NEVER_KILL', async () => {
  const sessionId = `test-s14-c9-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const capToken = broker.getLauncherCapabilityToken();
    const intentRes = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId,
      params: {
        launcherCapabilityToken: capToken,
        launcherPid: process.pid,
        role: 'launcher-with-ticket'
      }
    });
    assert.strictEqual(intentRes.success, true);
    const ticketId = intentRes.ticketId;

    // Launcher attempts to attest process.ppid (parent) instead of spawned child
    const attestRes = await sendBrokerRequest(broker.socketPath, {
      action: 'ATTEST_SPAWN',
      sessionId,
      params: {
        ticketId,
        pid: process.ppid,
        safeToKill: true
      }
    });

    assert.strictEqual(attestRes.success, false, 'Attesting wrong foreign PID must fail');
    assert.match(attestRes.error, /ANCESTRY_MISMATCH|TARGET_IS_NEVER_KILL/);
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 10: legitimate trusted launcher flow -> PASS & OWNED_CONFIRMED', async () => {
  const sessionId = `test-s14-c10-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    // 1. Trusted launcher with inherited capability spawns harmless sleep
    const { success, child, record } = await spawnAttestedProcess(sessionId, () => spawn('sleep', ['60']), {
      role: 'trusted-playwright-worker',
      expectedExecutable: 'sleep',
      safeToKill: true,
      broker
    });

    assert.strictEqual(success, true, 'Legitimate spawn attestation must succeed');
    assert.ok(child.pid, 'Spawned child must have valid PID');
    assert.strictEqual(record.ownership, 'OWNED_CONFIRMED');
    assert.strictEqual(record.safe_to_kill, true);

    try {
      // 2. Verification confirms OWNED_CONFIRMED and terminable under dry-run
      const v = await verifyProcessOwnership(record, sessionId, { broker });
      assert.strictEqual(v.canTerminate, true, 'Owned confirmed process must be terminable');
      assert.strictEqual(v.status, 'CONFIRMED_OWNED_TERMINABLE');
      assert.strictEqual(v.factors.f6_provenanceAttested, true);
      assert.strictEqual(v.factors.f8_sourceTrusted, true);
    } finally {
      child.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 11: PID recycling on trusted launcher detected by lstart mismatch -> LAUNCHER_PID_RECYCLED', async () => {
  const sessionId = `test-s14-c11-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const dummyProc = spawn('sleep', ['60']);
    try {
      const capToken = broker.getLauncherCapabilityToken();
      // Register dummyProc as a trusted launcher
      const regRes = await sendBrokerRequest(broker.socketPath, {
        action: 'REGISTER_TRUSTED_LAUNCHER',
        sessionId,
        params: {
          launcherCapabilityToken: capToken,
          pid: dummyProc.pid,
          role: 'registered-launcher'
        }
      });
      assert.strictEqual(regRes.success, true);

      // Now tamper with the registered lstart in broker's trustedLaunchers map to simulate PID reuse
      const record = broker.trustedLaunchers.get(dummyProc.pid);
      record.lstart = 'Mon Jan 01 00:00:00 2020';

      // Request ticket claiming dummyProc.pid: must detect recycled PID
      const ticketRes = await sendBrokerRequest(broker.socketPath, {
        action: 'REQUEST_LAUNCH_INTENT',
        sessionId,
        params: {
          launcherCapabilityToken: capToken,
          launcherPid: dummyProc.pid,
          role: 'recycled-launcher'
        }
      });

      assert.strictEqual(ticketRes.success, false, 'Recycled launcher PID must be rejected');
      assert.match(ticketRes.error, /LAUNCHER_PID_\d+_RECYCLED/);
    } finally {
      dummyProc.kill('SIGKILL');
    }
  } finally {
    await broker.stop();
  }
});

test('S1.4 Case 12: cross-session request spoofing -> CROSS_SESSION_REQUEST_REJECTED', async () => {
  const sessionId = `test-s14-c12-${Date.now()}`;
  const broker = new SupervisorBroker(sessionId);
  await broker.start();

  try {
    const res = await sendBrokerRequest(broker.socketPath, {
      action: 'REQUEST_LAUNCH_INTENT',
      sessionId: 'completely-foreign-session-id',
      params: {
        launcherPid: process.pid
      }
    });

    assert.strictEqual(res.success, false, 'Cross-session request must be rejected');
    assert.match(res.error, /CROSS_SESSION_REQUEST_REJECTED/);
  } finally {
    await broker.stop();
  }
});
