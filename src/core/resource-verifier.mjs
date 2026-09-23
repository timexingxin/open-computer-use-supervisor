import fs from 'node:fs';
import path from 'node:path';
import { checkProcessAlive, getOpenHandles } from './identity.mjs';
import { isApprovedTempPath } from './predicates.mjs';
import { getBrokerSocketPath } from './registry.mjs';
import { sendBrokerRequest } from './ipc.mjs';

/**
 * Validates a registered resource before deciding whether it can be safely cleaned up.
 * Enforces Session Nonce binding, Inode invariants, Symlink defense, and Broker attestation.
 *
 * @param {Object} resource - Registered resource record
 * @param {string} sessionId - Expected session ID
 * @param {Object} [options] - Optional context { broker, skipIpc }
 * @returns {Promise<{
 *   canDelete: boolean,
 *   status: string,
 *   reason: string,
 *   activeHandles: number[]
 * }>}
 */
export async function verifyResourceSafety(resource, sessionId, options = {}) {
  if (!resource || !resource.path) {
    return {
      canDelete: false,
      status: 'REJECTED_INVALID_RESOURCE',
      reason: 'Resource record missing path',
      activeHandles: []
    };
  }

  const resolvedPath = path.resolve(resource.path);

  // 1. Check file existence
  if (!fs.existsSync(resolvedPath)) {
    return {
      canDelete: false,
      status: 'ALREADY_REMOVED',
      reason: `Resource ${resolvedPath} does not exist on filesystem`,
      activeHandles: []
    };
  }

  // 2. Symlink Defense
  let lstat;
  try {
    lstat = fs.lstatSync(resolvedPath);
    if (lstat.isSymbolicLink()) {
      return {
        canDelete: false,
        status: 'BLOCKED_SYMLINK_NOT_PERMITTED',
        reason: `Path ${resolvedPath} is a symbolic link. Deletion forbidden.`,
        activeHandles: []
      };
    }
  } catch (err) {
    return {
      canDelete: false,
      status: 'BLOCKED_LSTAT_ERROR',
      reason: `Failed to lstat ${resolvedPath}: ${err.message}`,
      activeHandles: []
    };
  }

  // 3. Approved temporary directory check
  try {
    const realpath = fs.realpathSync(resolvedPath);
    if (!isApprovedTempPath(realpath)) {
      return {
        canDelete: false,
        status: 'BLOCKED_UNSAFE_PATH',
        reason: `Realpath ${realpath} is outside approved temporary roots`,
        activeHandles: []
      };
    }
  } catch (err) {
    return {
      canDelete: false,
      status: 'BLOCKED_REALPATH_ERROR',
      reason: `Failed to resolve realpath for ${resolvedPath}: ${err.message}`,
      activeHandles: []
    };
  }

  // 4. Session Nonce / External Claim Defense
  // Path must be inside session directory OR contain the session nonce / session_id
  const hasSessionBinding = (sessionId && resolvedPath.includes(sessionId)) ||
    (resource.session_nonce && resolvedPath.includes(resource.session_nonce));

  if (!hasSessionBinding && !resource.broker_attested) {
    return {
      canDelete: false,
      status: 'UNTRUSTED_EXTERNAL_RESOURCE',
      reason: `Resource path lacks session nonce or session directory containment (Untrusted external file claim)`,
      activeHandles: []
    };
  }

  // 5. Inode invariant check
  if (resource.ino !== undefined && resource.ino !== null) {
    if (lstat.ino !== resource.ino) {
      return {
        canDelete: false,
        status: 'REJECTED_INODE_MISMATCH',
        reason: `Inode mismatch (recorded: ${resource.ino}, live: ${lstat.ino}). File was substituted.`,
        activeHandles: []
      };
    }
  }

  // 6. Check owning process
  if (typeof resource.owning_pid === 'number' && resource.owning_pid > 0) {
    const ownerAlive = checkProcessAlive(resource.owning_pid);
    if (ownerAlive) {
      return {
        canDelete: false,
        status: 'BLOCKED_OWNER_STILL_ALIVE',
        reason: `Owning process PID ${resource.owning_pid} is still actively running`,
        activeHandles: [resource.owning_pid]
      };
    }
  }

  // 7. Check open handles with lsof
  const handles = getOpenHandles(resolvedPath);
  if (handles.length > 0) {
    return {
      canDelete: false,
      status: 'BLOCKED_RESOURCE_IN_USE',
      reason: `Resource is currently held open by PID(s): ${handles.join(', ')}`,
      activeHandles: handles
    };
  }

  // 8. Broker verification
  if (options.broker) {
    return options.broker.verifyResource(resolvedPath);
  }

  if (!options.skipIpc && sessionId) {
    const socketPath = getBrokerSocketPath(sessionId);
    const brokerRes = await sendBrokerRequest(socketPath, {
      action: 'VERIFY_RESOURCE',
      sessionId,
      params: { path: resolvedPath }
    });

    if (brokerRes.success) {
      return brokerRes;
    }
  }

  // All checks passed
  return {
    canDelete: true,
    status: 'CONFIRMED_ORPHANED_DELETABLE',
    reason: 'Resource verified safe, owner terminated, session-bound, no open handles',
    activeHandles: []
  };
}
