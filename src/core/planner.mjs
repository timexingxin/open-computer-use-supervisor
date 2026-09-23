import { loadSessionData, appendSessionLog } from './registry.mjs';
import { verifyProcessOwnership } from './verifier.mjs';
import { verifyResourceSafety } from './resource-verifier.mjs';
import { getProcessesInPgid } from './identity.mjs';
import { isNeverKill } from './predicates.mjs';
import { PHASE_V0_1_CONFIG } from './config.mjs';

/**
 * Plans cleanup actions for a session.
 * Default behavior is ALWAYS dry-run.
 *
 * @param {string} sessionId
 * @param {Object} options - { dryRun?: boolean, execute?: boolean, broker?: Object, skipIpc?: boolean }
 * @returns {Promise<Object>} Structured plan
 */
export async function planSessionCleanup(sessionId, options = {}) {
  const { session, processes, resources } = loadSessionData(sessionId);

  const dryRun = options.dryRun !== false;
  const execute = options.execute === true;

  if (execute && !PHASE_V0_1_CONFIG.executeAllowed) {
    appendSessionLog(sessionId, {
      action: 'CLEANUP_EXECUTE_REJECTED',
      reason: PHASE_V0_1_CONFIG.lockReason,
      phase: PHASE_V0_1_CONFIG.phase
    });
    throw new Error(
      `[FAIL_CLOSED] Execution mode is strictly locked in ${PHASE_V0_1_CONFIG.phase} ` +
      `(${PHASE_V0_1_CONFIG.lockReason}). Only dry-run is permitted.`
    );
  }

  const plannedProcesses = [];
  for (const proc of processes) {
    const verification = await verifyProcessOwnership(proc, sessionId, options);
    let action = 'BLOCKED';
    if (verification.status === 'CONFIRMED_OWNED_TERMINABLE') {
      action = 'WOULD_TERMINATE';
    } else if (verification.status === 'ALREADY_TERMINATED') {
      action = 'NOOP_ALREADY_DEAD';
    }

    // PGID Safety Audit: Check if PGID contains mixed/unowned processes
    let pgidGroupStatus = 'SAFE_OR_NOT_GROUPED';
    if (action === 'WOULD_TERMINATE' && proc.pgid && proc.pgid > 1) {
      const peers = getProcessesInPgid(proc.pgid);
      const foreignPeers = peers.filter(peer => {
        const neverKill = isNeverKill(peer);
        if (neverKill.neverKill) return true;
        const inSession = processes.some(p => p.pid === peer.pid);
        return !inSession;
      });

      if (foreignPeers.length > 0) {
        pgidGroupStatus = 'BLOCKED_MIXED_PGID';
        appendSessionLog(sessionId, {
          action: 'PGID_GROUP_KILL_BLOCKED',
          pid: proc.pid,
          pgid: proc.pgid,
          reason: `PGID contains ${foreignPeers.length} foreign/never-kill processes. Group signal forbidden.`
        });
      }
    }

    plannedProcesses.push({
      pid: proc.pid,
      role: proc.role,
      registration_source: proc.registration_source,
      status: verification.status,
      reason: verification.reason,
      action,
      pgid_safety: pgidGroupStatus,
      ancestry: verification.ancestry,
      factors: verification.factors
    });
  }

  const plannedResources = [];
  for (const res of resources) {
    const verification = await verifyResourceSafety(res, sessionId, options);
    let action = 'BLOCKED';
    if (verification.status === 'CONFIRMED_ORPHANED_DELETABLE') {
      action = 'WOULD_DELETE';
    } else if (verification.status === 'ALREADY_REMOVED') {
      action = 'NOOP_ALREADY_REMOVED';
    }

    plannedResources.push({
      id: res.id,
      type: res.type,
      path: res.path,
      status: verification.status,
      reason: verification.reason,
      action,
      activeHandles: verification.activeHandles
    });
  }

  const plan = {
    sessionId,
    phase: PHASE_V0_1_CONFIG.phase,
    dryRun: true,
    executed: false,
    timestamp: new Date().toISOString(),
    summary: {
      totalProcesses: plannedProcesses.length,
      processesWouldTerminate: plannedProcesses.filter(p => p.action === 'WOULD_TERMINATE').length,
      processesBlocked: plannedProcesses.filter(p => p.action === 'BLOCKED').length,
      processesAlreadyDead: plannedProcesses.filter(p => p.action === 'NOOP_ALREADY_DEAD').length,
      totalResources: plannedResources.length,
      resourcesWouldDelete: plannedResources.filter(r => r.action === 'WOULD_DELETE').length,
      resourcesBlocked: plannedResources.filter(r => r.action === 'BLOCKED').length,
      resourcesAlreadyRemoved: plannedResources.filter(r => r.action === 'NOOP_ALREADY_REMOVED').length
    },
    processes: plannedProcesses,
    resources: plannedResources
  };

  appendSessionLog(sessionId, {
    action: 'CLEANUP_PLAN_GENERATED',
    dryRun: true,
    summary: plan.summary
  });

  return plan;
}
