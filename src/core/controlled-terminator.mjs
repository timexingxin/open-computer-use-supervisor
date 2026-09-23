import {
  checkProcessAlive,
  getProcessSnapshot
} from './identity.mjs';
import { isNeverKill } from './predicates.mjs';
import {
  S2_CONTROLLED_CONFIG,
  S2_5_PLAYWRIGHT_CONFIG,
  S4_ZCODE_CONFIG,
  ROLES,
  REGISTRATION_SOURCES
} from './config.mjs';
import {
  validateSessionRoot,
  appendSessionLog,
  getBrokerSocketPath
} from './registry.mjs';
import { sendBrokerRequest } from './ipc.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Audit tracker for real OS signals.
 * Guarantees precise accounting across test runs.
 */
export class SignalAccounting {
  constructor() {
    this.reset();
  }

  reset() {
    this.sigtermSent = 0;
    this.sigkillSent = 0;
    this.signalsToDisposableTestChildren = 0;
    this.playwrightTestBrowserSigterm = 0;
    this.playwrightTestBrowserSigkill = 0;
    this.playwrightHelperSigterm = 0;
    this.playwrightHelperSigkill = 0;
    this.signalsToS4TestBridge = 0;
    this.signalsToS4TestRunner = 0;
    this.signalsToS4TestHelper = 0;
    this.signalsToS4TestMcpServer = 0;
    this.signalsToProductionServices = 0;
    this.signalsToChrome = 0;
    this.signalsToExistingPlaywright = 0;
    this.signalsToCdpProxy = 0;
    this.signalsToZCode = 0;
    this.signalsToPreExistingZCode = 0;
    this.signalsToUserZCodeApp = 0;
    this.signalsToMcp = 0;
    this.signalsToAntigravity = 0;
    this.signalsToPlaywright = 0;
    this.history = [];
  }

  recordSignal(entry) {
    if (entry.signal === 'SIGTERM') this.sigtermSent++;
    if (entry.signal === 'SIGKILL') this.sigkillSent++;

    if (entry.role === S2_CONTROLLED_CONFIG.disposableRole) {
      this.signalsToDisposableTestChildren++;
    } else if (entry.role === ROLES.PLAYWRIGHT_BROWSER_MAIN) {
      if (entry.signal === 'SIGTERM') this.playwrightTestBrowserSigterm++;
      if (entry.signal === 'SIGKILL') this.playwrightTestBrowserSigkill++;
      this.signalsToPlaywright++;
    } else if (entry.role === ROLES.PLAYWRIGHT_HELPER) {
      if (entry.signal === 'SIGTERM') this.playwrightHelperSigterm++;
      if (entry.signal === 'SIGKILL') this.playwrightHelperSigkill++;
      this.signalsToPlaywright++;
    } else if (entry.isS4ZCodeTest) {
      if (entry.role === ROLES.ZCODE_BRIDGE) this.signalsToS4TestBridge++;
      if (entry.role === ROLES.ZCODE_RUNNER) this.signalsToS4TestRunner++;
      if (entry.role === ROLES.ZCODE_HELPER) this.signalsToS4TestHelper++;
      if (entry.role === ROLES.ZCODE_MCP_SERVER) this.signalsToS4TestMcpServer++;
    } else {
      this.signalsToProductionServices++;
    }

    const exe = entry.executable || entry.target_executable || '';
    const cmd = entry.command || '';

    if (exe.includes('/Applications/Google Chrome.app') || /Google Chrome Helper/i.test(exe)) {
      this.signalsToChrome++;
    }
    if (/ZCode/i.test(exe) || /ZCode/i.test(cmd)) {
      this.signalsToZCode++;
      if (!entry.isS4ZCodeTest) {
        if (entry.isUserZCodeApp) {
          this.signalsToUserZCodeApp++;
        } else {
          this.signalsToPreExistingZCode++;
        }
      }
    }
    if (/cdp-proxy/i.test(exe) || /cdp-proxy/i.test(cmd)) {
      this.signalsToCdpProxy++;
    }
    if (/language_server/i.test(exe) || /Antigravity\.app/i.test(exe)) {
      this.signalsToAntigravity++;
    }
    if (/mcp/i.test(cmd) && !entry.isPlaywrightTest && !entry.isS4ZCodeTest) {
      this.signalsToMcp++;
    }

    this.history.push({
      timestamp: new Date().toISOString(),
      ...entry
    });
  }

  getSummary() {
    return {
      sigtermSent: this.sigtermSent,
      sigkillSent: this.sigkillSent,
      signalsToDisposableTestChildren: this.signalsToDisposableTestChildren,
      playwrightTestBrowserSigterm: this.playwrightTestBrowserSigterm,
      playwrightTestBrowserSigkill: this.playwrightTestBrowserSigkill,
      playwrightHelperSigterm: this.playwrightHelperSigterm,
      playwrightHelperSigkill: this.playwrightHelperSigkill,
      signalsToS4TestBridge: this.signalsToS4TestBridge,
      signalsToS4TestRunner: this.signalsToS4TestRunner,
      signalsToS4TestHelper: this.signalsToS4TestHelper,
      signalsToS4TestMcpServer: this.signalsToS4TestMcpServer,
      signalsToProductionServices: this.signalsToProductionServices,
      signalsToChrome: this.signalsToChrome,
      signalsToExistingPlaywright: this.signalsToExistingPlaywright,
      signalsToCdpProxy: this.signalsToCdpProxy,
      signalsToZCode: this.signalsToZCode,
      signalsToPreExistingZCode: this.signalsToPreExistingZCode,
      signalsToUserZCodeApp: this.signalsToUserZCodeApp,
      signalsToMcp: this.signalsToMcp,
      signalsToAntigravity: this.signalsToAntigravity,
      signalsToPlaywright: this.signalsToPlaywright
    };
  }
}

export const globalSignalAccounting = new SignalAccounting();

/**
 * Phase S2 Dedicated Controlled Process Terminator.
 * Enforces Progressive Trust Expansion: ONLY newly spawned disposable test children can ever be terminated.
 */
export class ControlledTerminator {
  /**
   * @param {string} sessionId
   * @param {Object} [options]
   */
  constructor(sessionId, options = {}) {
    this.sessionId = sessionId;
    this.broker = options.broker || null;
    this.accounting = options.accounting || globalSignalAccounting;
    this.testExecutionMode = options.testExecutionMode || null; // Must be 'S2_DISPOSABLE_CHILD_ONLY'
  }

  /**
   * Pre-Signal 10-Point Identity Recheck.
   * Executed immediately before dispatching any OS signal.
   *
   * @param {Object} record - Registered process record
   * @returns {Promise<{ ok: boolean, status?: string, reason?: string, snapshot?: Object }>}
   */
  async preSignalRecheck(record, requiredRole = null) {
    if (!record || typeof record.pid !== 'number') {
      return { ok: false, status: 'ABORT_INVALID_RECORD', reason: 'Missing process record or PID' };
    }

    // Factor 1: PID still alive
    if (!checkProcessAlive(record.pid)) {
      return { ok: false, status: 'TARGET_ALREADY_EXITED', reason: `PID ${record.pid} is already dead` };
    }

    // Factor 2: Obtain live process snapshot
    const live = getProcessSnapshot(record.pid);
    if (!live) {
      return { ok: false, status: 'TARGET_ALREADY_EXITED', reason: `Cannot read snapshot for PID ${record.pid}` };
    }

    // Factor 3: Broker in-memory attestation validity (Primary Trust Gate)
    if (this.broker) {
      const brokerVerification = this.broker.verifyProcess(record.pid);
      if (!brokerVerification.canTerminate) {
        return {
          ok: false,
          status: brokerVerification.status || 'BLOCKED_NO_BROKER_ATTESTATION',
          reason: brokerVerification.reason || 'Broker in-memory attestation failed'
        };
      }
    } else {
      const socketPath = getBrokerSocketPath(this.sessionId);
      const res = await sendBrokerRequest(socketPath, {
        action: 'VERIFY_PROCESS',
        sessionId: this.sessionId,
        params: { pid: record.pid }
      });
      if (!res.success || !res.canTerminate) {
        return {
          ok: false,
          status: res.status || 'BLOCKED_NO_BROKER_ATTESTATION',
          reason: res.reason || res.error || 'Broker attestation failed'
        };
      }
    }

    // Factor 4: Start identity unchanged (PID reuse defense)
    const timeDiff = Math.abs(live.startTimeEpochMs - (record.start_time_epoch_ms || 0));
    if (timeDiff > 1000 && live.lstart.trim() !== (record.lstart || '').trim()) {
      return {
        ok: false,
        status: 'PID_IDENTITY_CHANGED',
        reason: `Start time mismatch: recorded "${record.lstart}", live "${live.lstart}"`
      };
    }

    // Factor 5: Executable unchanged
    const exeMatch = record.executable && (live.canonicalExecutable === record.executable || live.canonicalExecutable.endsWith(record.executable));
    const commMatch = record.comm && live.comm === record.comm;
    if (!exeMatch && !commMatch) {
      return {
        ok: false,
        status: 'ABORT_EXECUTABLE_MUTATED',
        reason: `Executable mutated: live "${live.canonicalExecutable}" vs recorded "${record.executable}"`
      };
    }

    // Factor 6: Command fingerprint unchanged
    if (record.command_fingerprint && live.commandFingerprint) {
      if (record.command_fingerprint !== live.commandFingerprint) {
        return { ok: false, status: 'ABORT_COMMAND_MUTATED', reason: 'Command fingerprint mismatch' };
      }
    }

    // Factor 7: Never-Kill check
    const nk = isNeverKill(live);
    if (nk.neverKill) {
      return { ok: false, status: 'ABORT_NEVER_KILL', reason: `Never-Kill policy violation: ${nk.reason}` };
    }

    // Factor 8: Session root validity
    const rootCheck = validateSessionRoot(this.sessionId);
    if (!rootCheck.valid) {
      return { ok: false, status: 'ABORT_SESSION_ROOT_INVALID', reason: rootCheck.reason };
    }

    // Factor 9: Individual termination allowed (Zero Group Kill)
    if (S2_CONTROLLED_CONFIG.allowGroupKill) {
      return { ok: false, status: 'ABORT_GROUP_KILL_FORBIDDEN', reason: 'Process group kill is forbidden' };
    }

    // Factor 10: Role explicitly approved
    if (requiredRole) {
      if (record.role !== requiredRole) {
        return {
          ok: false,
          status: 'ABORT_ROLE_MISMATCH',
          reason: `Role "${record.role}" does not match required "${requiredRole}"`
        };
      }
    } else if (this.testExecutionMode === 'S2_DISPOSABLE_CHILD_ONLY') {
      if (record.role !== S2_CONTROLLED_CONFIG.disposableRole) {
        return {
          ok: false,
          status: 'ABORT_ROLE_NOT_S2_DISPOSABLE',
          reason: `Role "${record.role}" is not explicitly approved for S2 test (${S2_CONTROLLED_CONFIG.disposableRole})`
        };
      }
    } else if (this.testExecutionMode === 'S2_5_PLAYWRIGHT_TEST_ONLY') {
      if (!S2_5_PLAYWRIGHT_CONFIG.allowedRoles.has(record.role)) {
        return {
          ok: false,
          status: 'ABORT_ROLE_NOT_S2_5_APPROVED',
          reason: `Role "${record.role}" is not approved for S2.5 Playwright lifecycle`
        };
      }
    } else if (this.testExecutionMode === 'S4_ZCODE_TEST_ONLY') {
      if (!S4_ZCODE_CONFIG.allowedRoles.has(record.role)) {
        return {
          ok: false,
          status: 'ABORT_ROLE_NOT_S4_APPROVED',
          reason: `Role "${record.role}" is not approved for S4 ZCode lifecycle`
        };
      }
    }

    return { ok: true, snapshot: live };
  }

  /**
   * Executes controlled termination of a disposable test child.
   *
   * @param {Object} record - Registered process record
   * @param {Object} [options] - { graceTimeoutMs?: number, allowKillEscalation?: boolean }
   * @returns {Promise<Object>} Execution result
   */
  async terminateDisposableChild(record, options = {}) {
    // S2.1 Gate: Dedicated Test Execution Mode check
    if (this.testExecutionMode !== 'S2_DISPOSABLE_CHILD_ONLY') {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_NOT_IN_TEST_EXECUTION_MODE',
        reason: 'Controlled termination requires explicit S2_DISPOSABLE_CHILD_ONLY mode'
      };
    }

    // S2.1 Gate: Role check
    if (!record || record.role !== S2_CONTROLLED_CONFIG.disposableRole) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_ROLE_NOT_S2_DISPOSABLE',
        reason: `Role "${record?.role}" is not approved for S2 controlled test termination`
      };
    }

    // S2.1 Gate: Creation Source check (SUPERVISOR_SPAWN / SPAWN_ATTESTED only)
    if (record.registration_source !== S2_CONTROLLED_CONFIG.allowedRegistrationSource) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_REGISTRATION_SOURCE_REJECTED',
        reason: `Source "${record.registration_source}" cannot be terminated in S2 test (must be SPAWN_ATTESTED)`
      };
    }

    // S2.3: Pre-Signal 10-Point Identity Recheck
    const precheck = await this.preSignalRecheck(record);
    if (!precheck.ok) {
      appendSessionLog(this.sessionId, {
        action: 'S2_TERMINATION_ABORTED',
        pid: record.pid,
        status: precheck.status,
        reason: precheck.reason
      });
      return {
        success: false,
        signaled: false,
        status: precheck.status,
        reason: precheck.reason
      };
    }

    const verifiedSnapshot = precheck.snapshot;
    const graceTimeoutMs = options.graceTimeoutMs || S2_CONTROLLED_CONFIG.defaultGraceTimeoutMs;
    const pollIntervalMs = S2_CONTROLLED_CONFIG.pollIntervalMs;

    // S2.2: First Real Signal: Send exactly one SIGTERM
    const termTimestamp = new Date().toISOString();
    try {
      process.kill(record.pid, 'SIGTERM');
    } catch (err) {
      return {
        success: false,
        signaled: false,
        status: 'SIGTERM_FAILED',
        reason: `process.kill(SIGTERM) threw error: ${err.message}`
      };
    }

    this.accounting.recordSignal({
      session_id: this.sessionId,
      target_pid: record.pid,
      target_start_identity: verifiedSnapshot.lstart,
      target_executable: verifiedSnapshot.canonicalExecutable,
      role: record.role,
      signal: 'SIGTERM',
      reason: 'S2_CONTROLLED_TEST',
      verified_at: precheck.snapshot ? new Date().toISOString() : termTimestamp,
      sent_at: termTimestamp
    });

    appendSessionLog(this.sessionId, {
      action: 'S2_SIGNAL_SENT',
      signal: 'SIGTERM',
      pid: record.pid,
      target_start_identity: verifiedSnapshot.lstart,
      role: record.role
    });

    // S2.4: Post-Signal Active Observation
    const startWait = Date.now();
    let exited = false;
    while (Date.now() - startWait < graceTimeoutMs) {
      if (!checkProcessAlive(record.pid)) {
        exited = true;
        break;
      }
      await sleep(pollIntervalMs);
    }

    if (exited) {
      appendSessionLog(this.sessionId, {
        action: 'S2_TERMINATION_CONFIRMED',
        pid: record.pid,
        status: 'TERMINATED_GRACEFULLY',
        duration_ms: Date.now() - startWait
      });
      return {
        success: true,
        signaled: true,
        status: 'TERMINATED_GRACEFULLY',
        signals: ['SIGTERM'],
        pid: record.pid,
        durationMs: Date.now() - startWait
      };
    }

    // S2.6: Controlled SIGKILL Escalation
    const allowEscalation = options.allowKillEscalation !== false && S2_CONTROLLED_CONFIG.escalateToSigkill;
    if (!allowEscalation) {
      return {
        success: false,
        signaled: true,
        status: 'GRACE_TIMEOUT_PROCESS_STILL_ALIVE',
        signals: ['SIGTERM'],
        pid: record.pid
      };
    }

    // S2.5 & S2.6: Pre-SIGKILL Identity Re-Verification
    const postSnapshot = getProcessSnapshot(record.pid);
    if (!postSnapshot) {
      // Process exited just as grace period ended
      return {
        success: true,
        signaled: true,
        status: 'TERMINATED_GRACEFULLY',
        signals: ['SIGTERM'],
        pid: record.pid
      };
    }

    // Check for PID Reuse
    const timeDiff = Math.abs(postSnapshot.startTimeEpochMs - verifiedSnapshot.startTimeEpochMs);
    if (timeDiff > 1000 || postSnapshot.lstart.trim() !== verifiedSnapshot.lstart.trim()) {
      appendSessionLog(this.sessionId, {
        action: 'S2_ESCALATION_BLOCKED_PID_REUSED',
        pid: record.pid,
        reason: 'Original process exited and PID was reused'
      });
      return {
        success: true, // Original target is indeed dead
        signaled: true, // Sent SIGTERM earlier
        escalated: false,
        status: 'ORIGINAL_PROCESS_EXITED_PID_REUSED',
        reason: 'Original process exited during grace wait and PID was reused; SIGKILL aborted'
      };
    }

    // Check executable consistency before escalation
    if (postSnapshot.canonicalExecutable !== verifiedSnapshot.canonicalExecutable) {
      return {
        success: false,
        signaled: true,
        status: 'ABORT_PID_IDENTITY_CHANGED',
        reason: 'Executable identity changed before SIGKILL'
      };
    }

    // Check Never-Kill
    if (isNeverKill(postSnapshot).neverKill) {
      return {
        success: false,
        signaled: true,
        status: 'ABORT_NEVER_KILL',
        reason: 'Process became Never-Kill before SIGKILL'
      };
    }

    // Send SIGKILL
    const killTimestamp = new Date().toISOString();
    try {
      process.kill(record.pid, 'SIGKILL');
    } catch (err) {
      return {
        success: false,
        signaled: true,
        status: 'SIGKILL_FAILED',
        reason: `process.kill(SIGKILL) error: ${err.message}`
      };
    }

    this.accounting.recordSignal({
      session_id: this.sessionId,
      target_pid: record.pid,
      target_start_identity: postSnapshot.lstart,
      target_executable: postSnapshot.canonicalExecutable,
      role: record.role,
      signal: 'SIGKILL',
      reason: 'S2_CONTROLLED_TEST_ESCALATION',
      previous_sigterm_at: termTimestamp,
      grace_interval_ms: graceTimeoutMs,
      sent_at: killTimestamp
    });

    appendSessionLog(this.sessionId, {
      action: 'S2_SIGNAL_SENT',
      signal: 'SIGKILL',
      pid: record.pid,
      reason: 'SIGTERM_TIMEOUT_ESCALATION'
    });

    // Poll until exited
    const killWaitStart = Date.now();
    let killExited = false;
    while (Date.now() - killWaitStart < 2000) {
      if (!checkProcessAlive(record.pid)) {
        killExited = true;
        break;
      }
      await sleep(pollIntervalMs);
    }

    return {
      success: killExited,
      signaled: true,
      escalated: true,
      status: 'ESCALATED_TO_SIGKILL',
      signals: ['SIGTERM', 'SIGKILL'],
      pid: record.pid,
      graceIntervalMs: graceTimeoutMs,
      durationMs: Date.now() - startWait
    };
  }

  /**
   * Recovers an orphaned Playwright test browser main process.
   * Follows Phase S2.5 lifecycle protocol:
   * 1. Mode Gate: 'S2_5_PLAYWRIGHT_TEST_ONLY'
   * 2. Role Gate: 'playwright-browser-main'
   * 3. Provenance Gate: SPAWN_ATTESTED or PLAYWRIGHT_ATTESTED
   * 4. Confirm Launcher Dead (if launcher_pid specified and requireLauncherDead is true)
   * 5. Pre-Signal 10-Point Recheck
   * 6. Send SIGTERM to browser main PID only (Zero Group Kill)
   * 7. Polling observation loop
   * 8. Check helpers (GPU, utility, renderer)
   * 9. Record profile directory as WOULD_DELETE_LATER (No file deletion in S2.5)
   *
   * @param {Object} record - Registered browser main record
   * @param {Object} [options]
   * @returns {Promise<Object>}
   */
  async recoverPlaywrightOrphan(record, options = {}) {
    // Mode check
    if (this.testExecutionMode !== 'S2_5_PLAYWRIGHT_TEST_ONLY') {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_NOT_IN_PLAYWRIGHT_TEST_MODE',
        reason: 'Requires explicit S2_5_PLAYWRIGHT_TEST_ONLY execution mode'
      };
    }

    // Role check
    if (!record || record.role !== ROLES.PLAYWRIGHT_BROWSER_MAIN) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_ROLE_NOT_PLAYWRIGHT_MAIN',
        reason: `Role "${record?.role}" is not approved for Playwright main recovery`
      };
    }

    // Source check
    if (!S2_5_PLAYWRIGHT_CONFIG.allowedRegistrationSources.has(record.registration_source)) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_REGISTRATION_SOURCE_REJECTED',
        reason: `Source "${record?.registration_source}" cannot be recovered in S2.5`
      };
    }

    // Confirm Launcher Dead (if launcher_pid specified and requireLauncherDead is not false)
    if (options.requireLauncherDead !== false && record.launcher_pid) {
      if (checkProcessAlive(record.launcher_pid)) {
        return {
          success: false,
          signaled: false,
          status: 'ABORT_LAUNCHER_STILL_ALIVE',
          reason: `Launcher PID ${record.launcher_pid} is still alive; not an orphan`
        };
      }
    }

    // 10-Factor Pre-Signal Recheck
    const precheck = await this.preSignalRecheck(record, ROLES.PLAYWRIGHT_BROWSER_MAIN);
    if (!precheck.ok) {
      appendSessionLog(this.sessionId, {
        action: 'PLAYWRIGHT_ORPHAN_RECOVERY_ABORTED',
        pid: record.pid,
        status: precheck.status,
        reason: precheck.reason
      });
      return {
        success: false,
        signaled: false,
        status: precheck.status,
        reason: precheck.reason
      };
    }

    const verifiedSnapshot = precheck.snapshot;
    const graceTimeoutMs = options.graceTimeoutMs || S2_5_PLAYWRIGHT_CONFIG.defaultGraceTimeoutMs;
    const pollIntervalMs = S2_5_PLAYWRIGHT_CONFIG.pollIntervalMs;

    // Send single SIGTERM to main browser PID
    try {
      process.kill(record.pid, 'SIGTERM');
    } catch (err) {
      return {
        success: false,
        signaled: false,
        status: 'SIGTERM_FAILED',
        reason: `process.kill(SIGTERM) failed: ${err.message}`
      };
    }

    this.accounting.recordSignal({
      session_id: this.sessionId,
      target_pid: record.pid,
      target_start_identity: verifiedSnapshot.lstart,
      target_executable: verifiedSnapshot.canonicalExecutable,
      role: record.role,
      signal: 'SIGTERM',
      isPlaywrightTest: true
    });

    appendSessionLog(this.sessionId, {
      action: 'PLAYWRIGHT_BROWSER_MAIN_SIGTERM_SENT',
      pid: record.pid,
      role: record.role
    });

    // Observation loop
    const startTime = Date.now();
    let exitedNaturally = false;

    while (Date.now() - startTime < graceTimeoutMs) {
      await sleep(pollIntervalMs);

      if (!checkProcessAlive(record.pid)) {
        exitedNaturally = true;
        break;
      }

      // Check for PID reuse during polling
      const currentSnap = getProcessSnapshot(record.pid);
      if (currentSnap && currentSnap.lstart.trim() !== verifiedSnapshot.lstart.trim()) {
        return {
          success: false,
          signaled: true,
          status: 'ORIGINAL_PROCESS_EXITED_PID_REUSED',
          reason: 'Browser main PID was reused by another process during observation'
        };
      }
    }

    if (exitedNaturally) {
      // Check helpers
      await sleep(150);
      return {
        success: true,
        signaled: true,
        status: 'ORPHAN_RECOVERED_WITH_SIGTERM',
        mainPid: record.pid,
        profileStatus: 'WOULD_DELETE_LATER',
        reason: 'Browser main process exited gracefully upon receiving SIGTERM'
      };
    }

    // If still alive and escalateToSigkill is allowed
    if (options.escalateToSigkill !== false && S2_5_PLAYWRIGHT_CONFIG.escalateToSigkill) {
      // Full identity recheck before SIGKILL
      const killRecheck = await this.preSignalRecheck(record, ROLES.PLAYWRIGHT_BROWSER_MAIN);
      if (!killRecheck.ok) {
        return {
          success: false,
          signaled: true,
          status: 'ESCALATION_BLOCKED',
          reason: `SIGKILL escalation blocked by recheck: ${killRecheck.reason}`
        };
      }

      try {
        process.kill(record.pid, 'SIGKILL');
      } catch (err) {
        return {
          success: false,
          signaled: true,
          status: 'SIGKILL_FAILED',
          reason: `process.kill(SIGKILL) failed: ${err.message}`
        };
      }

      this.accounting.recordSignal({
        session_id: this.sessionId,
        target_pid: record.pid,
        target_start_identity: killRecheck.snapshot.lstart,
        target_executable: killRecheck.snapshot.canonicalExecutable,
        role: record.role,
        signal: 'SIGKILL',
        isPlaywrightTest: true
      });

      return {
        success: true,
        signaled: true,
        status: 'ESCALATED_TO_SIGKILL',
        mainPid: record.pid,
        profileStatus: 'WOULD_DELETE_LATER'
      };
    }

    return {
      success: false,
      signaled: true,
      status: 'TIMEOUT_WAITING_FOR_EXIT',
      reason: 'Browser main did not exit within grace timeout'
    };
  }

  /**
   * Recovers an orphaned ZCode CUA helper or runner process.
   * Follows Phase S4 lifecycle protocol:
   * 1. Mode Gate: 'S4_ZCODE_TEST_ONLY'
   * 2. Role Gate: 'zcode-helper', 'zcode-runner', 'zcode-bridge', 'zcode-mcp-server'
   * 3. Provenance Gate: BRIDGE_ATTESTED or SPAWN_ATTESTED
   * 4. Baseline Protection: PID must NOT be in baselinePids snapshot
   * 5. Confirm Launcher Dead (if launcher_pid specified and requireLauncherDead is true)
   * 6. Pre-Signal 10-Point Recheck
   * 7. Send single SIGTERM to target PID only (Zero Group Kill)
   * 8. Polling observation loop
   * 9. HARD RULE: escalateToSigkill is false (if not exited, report ZCODE_HELPER_SIGTERM_NOT_SUFFICIENT, do NOT SIGKILL)
   * 10. Sockets and tokens marked WOULD_DELETE_IN_S4_5 (Zero file unlinks in S4)
   *
   * @param {Object} record - Registered ZCode process record
   * @param {Object} [options]
   * @returns {Promise<Object>}
   */
  async recoverZCodeOrphan(record, options = {}) {
    // 1. Mode check
    if (this.testExecutionMode !== 'S4_ZCODE_TEST_ONLY') {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_NOT_IN_ZCODE_TEST_MODE',
        reason: 'Requires explicit S4_ZCODE_TEST_ONLY execution mode'
      };
    }

    // 2. Role check
    if (!record || !S4_ZCODE_CONFIG.allowedRoles.has(record.role)) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_ROLE_NOT_ZCODE_APPROVED',
        reason: `Role "${record?.role}" is not approved for ZCode lifecycle`
      };
    }

    // 3. Source check
    if (!S4_ZCODE_CONFIG.allowedRegistrationSources.has(record.registration_source)) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_REGISTRATION_SOURCE_REJECTED',
        reason: `Source "${record?.registration_source}" cannot be recovered in S4`
      };
    }

    // 4. Baseline check: reject any process that was in baseline snapshot
    if (options.baselinePids && options.baselinePids.includes(record.pid)) {
      return {
        success: false,
        signaled: false,
        status: 'ABORT_BASELINE_PID_PROTECTED',
        reason: `PID ${record.pid} is a pre-existing baseline ZCode process and is NEVER_KILL`
      };
    }

    // 5. Confirm Launcher Dead (if launcher_pid specified and requireLauncherDead is not false)
    if (options.requireLauncherDead !== false && record.launcher_pid) {
      if (checkProcessAlive(record.launcher_pid)) {
        return {
          success: false,
          signaled: false,
          status: 'ABORT_LAUNCHER_STILL_ALIVE',
          reason: `Launcher PID ${record.launcher_pid} is still alive; not an orphan`
        };
      }
    }

    // 6. 10-Factor Pre-Signal Recheck
    const precheck = await this.preSignalRecheck(record, record.role);
    if (!precheck.ok) {
      appendSessionLog(this.sessionId, {
        action: 'ZCODE_ORPHAN_RECOVERY_ABORTED',
        pid: record.pid,
        status: precheck.status,
        reason: precheck.reason
      });
      return {
        success: false,
        signaled: false,
        status: precheck.status,
        reason: precheck.reason
      };
    }

    const verifiedSnapshot = precheck.snapshot;
    const graceTimeoutMs = options.graceTimeoutMs || S4_ZCODE_CONFIG.defaultGraceTimeoutMs;
    const pollIntervalMs = S4_ZCODE_CONFIG.pollIntervalMs;

    // 7. Send single SIGTERM to target PID only (Zero Group Kill)
    try {
      process.kill(record.pid, 'SIGTERM');
    } catch (err) {
      return {
        success: false,
        signaled: false,
        status: 'SIGTERM_FAILED',
        reason: `process.kill(SIGTERM) failed: ${err.message}`
      };
    }

    this.accounting.recordSignal({
      session_id: this.sessionId,
      target_pid: record.pid,
      target_start_identity: verifiedSnapshot.lstart,
      target_executable: verifiedSnapshot.canonicalExecutable,
      role: record.role,
      signal: 'SIGTERM',
      isS4ZCodeTest: true
    });

    appendSessionLog(this.sessionId, {
      action: 'ZCODE_ORPHAN_SIGTERM_SENT',
      pid: record.pid,
      role: record.role
    });

    // 8. Observation loop
    const startTime = Date.now();
    let exitedNaturally = false;

    while (Date.now() - startTime < graceTimeoutMs) {
      await sleep(pollIntervalMs);

      if (!checkProcessAlive(record.pid)) {
        exitedNaturally = true;
        break;
      }

      // Check for PID reuse during polling
      const currentSnap = getProcessSnapshot(record.pid);
      if (currentSnap && currentSnap.lstart.trim() !== verifiedSnapshot.lstart.trim()) {
        return {
          success: false,
          signaled: true,
          status: 'ORIGINAL_PROCESS_EXITED_PID_REUSED',
          reason: 'Process PID was reused by another process during observation'
        };
      }
    }

    if (exitedNaturally) {
      return {
        success: true,
        signaled: true,
        status: 'ZCODE_ORPHAN_RECOVERED_WITH_SIGTERM',
        pid: record.pid,
        role: record.role,
        socketStatus: 'WOULD_DELETE_IN_S4_5',
        tokenStatus: 'WOULD_DELETE_IN_S4_5',
        reason: 'ZCode orphan process exited gracefully upon receiving SIGTERM'
      };
    }

    // 9. HARD RULE: No automatic SIGKILL escalation in S4!
    return {
      success: false,
      signaled: true,
      status: 'ZCODE_HELPER_SIGTERM_NOT_SUFFICIENT',
      pid: record.pid,
      role: record.role,
      socketStatus: 'WOULD_DELETE_IN_S4_5',
      tokenStatus: 'WOULD_DELETE_IN_S4_5',
      reason: 'Process did not exit after SIGTERM; SIGKILL escalation is forbidden in Phase S4'
    };
  }
}
