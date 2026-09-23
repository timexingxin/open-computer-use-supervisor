import {
  getProcessSnapshot,
  checkProcessAlive,
  getProcessAncestry
} from './identity.mjs';
import { isNeverKill } from './predicates.mjs';
import { TERMINABLE_SOURCES, REGISTRATION_SOURCES } from './config.mjs';
import { validateSessionRoot, getBrokerSocketPath } from './registry.mjs';
import { sendBrokerRequest } from './ipc.mjs';

/**
 * Executes an 8-factor ownership provenance verification against a registered process record.
 * ACTIVELY traverses OS ancestry tree and verifies against Session Privileged Broker.
 *
 * @param {Object} record - Registered process record
 * @param {string} currentSessionId - Expected session ID
 * @param {Object} [options] - Optional context { broker, skipIpc }
 * @returns {Promise<{
 *   canTerminate: boolean,
 *   status: string,
 *   reason: string,
 *   ancestry: number[],
 *   factors: {
 *     f1_exists: boolean,
 *     f2_startTimeMatch: boolean,
 *     f3_executableMatch: boolean,
 *     f4_commandMatch: boolean,
 *     f5_sessionMatch: boolean,
 *     f6_provenanceAttested: boolean,
 *     f7_neverKillExempt: boolean,
 *     f8_sourceTrusted: boolean
 *   }
 * }>}
 */
export async function verifyProcessOwnership(record, currentSessionId, options = {}) {
  const factors = {
    f1_exists: false,
    f2_startTimeMatch: false,
    f3_executableMatch: false,
    f4_commandMatch: false,
    f5_sessionMatch: false,
    f6_provenanceAttested: false,
    f7_neverKillExempt: false,
    f8_sourceTrusted: false
  };

  if (!record || typeof record.pid !== 'number') {
    return {
      canTerminate: false,
      status: 'REJECTED_INVALID_RECORD',
      reason: 'Process record is null or missing PID',
      ancestry: [],
      factors
    };
  }

  // Pre-Check: Session Trust Root Verification
  const rootValidation = validateSessionRoot(currentSessionId);
  if (!rootValidation.valid) {
    return {
      canTerminate: false,
      status: 'BLOCKED_SESSION_ROOT_INVALID',
      reason: `Session trust root invalid: ${rootValidation.reason}`,
      ancestry: [],
      factors
    };
  }
  const session = rootValidation.session;

  // Factor 5: Session Registration Identity
  if (record.session_id !== currentSessionId) {
    return {
      canTerminate: false,
      status: 'REJECTED_FOREIGN_SESSION',
      reason: `Record session (${record.session_id}) does not match current session (${currentSessionId})`,
      ancestry: [],
      factors
    };
  }
  factors.f5_sessionMatch = true;

  // Factor 1: Live Existence
  const isAlive = checkProcessAlive(record.pid);
  if (!isAlive) {
    return {
      canTerminate: false,
      status: 'ALREADY_TERMINATED',
      reason: `Process PID ${record.pid} is no longer running`,
      ancestry: [],
      factors
    };
  }
  factors.f1_exists = true;

  const live = getProcessSnapshot(record.pid);
  if (!live) {
    return {
      canTerminate: false,
      status: 'ALREADY_TERMINATED',
      reason: `Unable to obtain process snapshot for PID ${record.pid}`,
      ancestry: [],
      factors
    };
  }

  // Factor 7: Dynamic Never-Kill Safety Gate
  const neverKillCheck = isNeverKill(live);
  if (neverKillCheck.neverKill) {
    return {
      canTerminate: false,
      status: 'BLOCKED_BY_NEVER_KILL_POLICY',
      reason: `Blocked by Never-Kill Policy: ${neverKillCheck.reason} (${neverKillCheck.category})`,
      ancestry: [],
      factors
    };
  }
  factors.f7_neverKillExempt = true;

  // Factor 8: Registration Source Trust
  if (!record.registration_source || !TERMINABLE_SOURCES.has(record.registration_source)) {
    return {
      canTerminate: false,
      status: 'BLOCKED_UNTRUSTED_REGISTRATION_SOURCE',
      reason: `Registration source is ${record.registration_source || 'UNKNOWN'}, which is not terminable (Observe Only)`,
      ancestry: [],
      factors
    };
  }
  if (record.safe_to_kill === false || record.ownership === 'UNTRUSTED_TEST_REGISTRATION') {
    return {
      canTerminate: false,
      status: 'BLOCKED_NOT_MARKED_SAFE_TO_KILL',
      reason: `Process is marked untrusted/safe_to_kill=false (${record.never_kill_reason || 'UNTRUSTED'})`,
      ancestry: [],
      factors
    };
  }
  factors.f8_sourceTrusted = true;

  // Factor 2: Start-Time Invariant (PID Reuse Defense, 1000ms resolution)
  const timeDiff = Math.abs(live.startTimeEpochMs - (record.start_time_epoch_ms || 0));
  const lstartExact = record.lstart ? (live.lstart.trim() === record.lstart.trim()) : false;
  if (!lstartExact && timeDiff > 1000) {
    return {
      canTerminate: false,
      status: 'REJECTED_PID_REUSE_DETECTED',
      reason: `PID ${record.pid} start time mismatch (recorded: "${record.lstart}", live: "${live.lstart}"). Potential PID reuse.`,
      ancestry: [],
      factors
    };
  }
  factors.f2_startTimeMatch = true;

  // Factor 3: Executable Integrity
  const recordExe = record.executable || '';
  const liveExe = live.canonicalExecutable || '';
  const commMatch = record.comm && live.comm && (record.comm === live.comm);
  const exeMatch = recordExe && liveExe && (recordExe === liveExe || liveExe.endsWith(recordExe) || recordExe.endsWith(liveExe));

  if (!exeMatch && !commMatch) {
    return {
      canTerminate: false,
      status: 'REJECTED_EXECUTABLE_MISMATCH',
      reason: `Executable mismatch for PID ${record.pid} (recorded: "${recordExe}", live: "${liveExe}")`,
      ancestry: [],
      factors
    };
  }
  factors.f3_executableMatch = true;

  // Factor 4: Command Fingerprint Invariant
  if (record.command_fingerprint && live.commandFingerprint) {
    if (record.command_fingerprint !== live.commandFingerprint) {
      return {
        canTerminate: false,
        status: 'REJECTED_COMMAND_MISMATCH',
        reason: `Command fingerprint mismatch for PID ${record.pid}`,
        ancestry: [],
        factors
      };
    }
  }
  factors.f4_commandMatch = true;

  // Factor 6: ACTIVE ANCESTRY TREE TRAVERSAL (Eliminating Dead Code)
  const ancestry = getProcessAncestry(record.pid);
  const launcherPid = record.launcher_pid;
  const rootPid = session.root_pid;

  let ancestryValid = false;
  if (launcherPid) {
    // If launcher_pid is recorded, ancestry MUST link to launcher_pid
    if (live.ppid === launcherPid || ancestry.includes(launcherPid)) {
      ancestryValid = true;
    }
  } else {
    // Direct spawn from session root
    if (live.ppid === rootPid || ancestry.includes(rootPid)) {
      ancestryValid = true;
    }
  }

  // If reparented to 1, requires creation-time attestation
  if (live.ppid === 1 && (record.ownership === 'OWNED_CONFIRMED' || record.registration_source === REGISTRATION_SOURCES.SPAWN_ATTESTED)) {
    ancestryValid = true;
  }

  if (!ancestryValid) {
    return {
      canTerminate: false,
      status: 'REJECTED_ANCESTRY_BROKEN',
      reason: `Process ancestry (${ancestry.join(' -> ')}) does not link to Launcher (${launcherPid}) or Root (${rootPid})`,
      ancestry,
      factors
    };
  }

  // BROKER ATTESTATION CHECK (In-memory verification)
  if (options.broker) {
    const brokerVerification = options.broker.verifyProcess(record.pid);
    if (!brokerVerification.canTerminate) {
      return {
        canTerminate: false,
        status: brokerVerification.status,
        reason: brokerVerification.reason,
        ancestry,
        factors
      };
    }
    factors.f6_provenanceAttested = true;
  } else if (!options.skipIpc) {
    const socketPath = getBrokerSocketPath(currentSessionId);
    const ipcRes = await sendBrokerRequest(socketPath, {
      action: 'VERIFY_PROCESS',
      sessionId: currentSessionId,
      params: { pid: record.pid }
    });

    if (!ipcRes.success) {
      // FAIL-CLOSED: If Broker is offline/unreachable, disk records CANNOT grant kill authority!
      return {
        canTerminate: false,
        status: 'BLOCKED_BROKER_OFFLINE_OBSERVE_ONLY',
        reason: `Session Broker is offline or unreachable (${ipcRes.error}). Disk records are audit-only.`,
        ancestry,
        factors
      };
    }

    if (!ipcRes.canTerminate) {
      return {
        canTerminate: false,
        status: ipcRes.status,
        reason: ipcRes.reason,
        ancestry,
        factors
      };
    }
    factors.f6_provenanceAttested = true;
  } else {
    // skipIpc without broker passed -> fail closed
    return {
      canTerminate: false,
      status: 'BLOCKED_UNVERIFIED_WITHOUT_BROKER',
      reason: 'Verification requires live Broker connection',
      ancestry,
      factors
    };
  }

  return {
    canTerminate: true,
    status: 'CONFIRMED_OWNED_TERMINABLE',
    reason: 'All 8 ownership provenance factors verified by Broker in-memory attestation and OS ancestry',
    ancestry,
    factors
  };
}
