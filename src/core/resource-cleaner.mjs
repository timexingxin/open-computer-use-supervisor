import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  SESSIONS_ROOT,
  HARD_PATH_DENYLIST,
  S3_RESOURCE_CONFIG,
  S4_5_RESOURCE_CONFIG,
  PHASE_V0_1_CONFIG,
  RESOURCE_ROLES
} from './config.mjs';
import { checkProcessAlive, getOpenHandles, computeAttestationSig } from './identity.mjs';

/**
 * Exact Deletion Accounting Tracker across all S3 and S4.5 test operations.
 */
export const DeletionAccounting = {
  filesUnlinked: 0,
  directoriesRemoved: 0,
  symlinksFollowed: 0,
  foreignResourcesDeleted: 0,
  userResourcesDeleted: 0,
  playwrightProductionResourcesDeleted: 0,
  zcodeResourcesDeleted: 0,
  // S4.5 additions:
  supervisorZCodeSocketsDeleted: 0,
  supervisorZCodeTokensDeleted: 0,
  ownerCleanedSockets: 0,
  ownerCleanedTokens: 0,
  baselineZCodeResourcesDeleted: 0,
  foreignZCodeResourcesDeleted: 0,

  reset() {
    this.filesUnlinked = 0;
    this.directoriesRemoved = 0;
    this.symlinksFollowed = 0;
    this.foreignResourcesDeleted = 0;
    this.userResourcesDeleted = 0;
    this.playwrightProductionResourcesDeleted = 0;
    this.zcodeResourcesDeleted = 0;
    this.supervisorZCodeSocketsDeleted = 0;
    this.supervisorZCodeTokensDeleted = 0;
    this.ownerCleanedSockets = 0;
    this.ownerCleanedTokens = 0;
    this.baselineZCodeResourcesDeleted = 0;
    this.foreignZCodeResourcesDeleted = 0;
  },

  getSnapshot() {
    return {
      filesUnlinked: this.filesUnlinked,
      directoriesRemoved: this.directoriesRemoved,
      symlinksFollowed: this.symlinksFollowed,
      foreignResourcesDeleted: this.foreignResourcesDeleted,
      userResourcesDeleted: this.userResourcesDeleted,
      playwrightProductionResourcesDeleted: this.playwrightProductionResourcesDeleted,
      zcodeResourcesDeleted: this.zcodeResourcesDeleted,
      supervisorZCodeSocketsDeleted: this.supervisorZCodeSocketsDeleted,
      supervisorZCodeTokensDeleted: this.supervisorZCodeTokensDeleted,
      ownerCleanedSockets: this.ownerCleanedSockets,
      ownerCleanedTokens: this.ownerCleanedTokens,
      baselineZCodeResourcesDeleted: this.baselineZCodeResourcesDeleted,
      foreignZCodeResourcesDeleted: this.foreignZCodeResourcesDeleted
    };
  }
};

/**
 * Validates whether a resource path is structurally safe and strictly bounded
 * to the active session's approved resources root:
 * ~/.gemini/antigravity/runtime/sessions/<sessionId>/resources/
 *
 * @param {string} targetPath
 * @param {string} sessionId
 * @returns {{ safe: boolean, realpath?: string, status?: string, reason?: string }}
 */
export function validateResourcePathSafety(targetPath, sessionId) {
  if (!targetPath || typeof targetPath !== 'string') {
    return { safe: false, status: 'INVALID_RESOURCE_PATH', reason: 'Resource path is empty or non-string' };
  }

  if (!sessionId || typeof sessionId !== 'string') {
    return { safe: false, status: 'INVALID_SESSION_ID', reason: 'Session ID is missing' };
  }

  const resolved = path.resolve(targetPath);

  // 1. ZCode Resource Check: Absolutely never touch ZCode resources in S3
  const lowerPath = resolved.toLowerCase();
  const baseName = path.basename(resolved).toLowerCase();
  if (lowerPath.includes('.zcode') || baseName.startsWith('zcode-cua-') || baseName.includes('zcode')) {
    return {
      safe: false,
      status: 'ZCODE_RESOURCE',
      reason: `ZCode resource detected (${resolved}). Excluded from Phase S3 cleanup scope (BLOCKED_S3_SCOPE).`
    };
  }

  // 2. User Chrome / Playwright Production / Global Cache Check
  if (lowerPath.includes('application support/google') || lowerPath.includes('ms-playwright')) {
    return {
      safe: false,
      status: 'PRE_EXISTING_RESOURCE',
      reason: `Path touches user Chrome or global Playwright cache (${resolved}). Must remain OBSERVE_ONLY.`
    };
  }

  // 3. Symlink check on target path if exists
  if (fs.existsSync(resolved)) {
    try {
      const lstat = fs.lstatSync(resolved);
      if (lstat.isSymbolicLink()) {
        return {
          safe: false,
          status: 'SYMLINK_DETECTED',
          reason: `Target path is a symbolic link. Following or deleting symlinks is strictly forbidden.`
        };
      }
    } catch (e) {
      return { safe: false, status: 'STAT_ERROR', reason: `Failed to lstat path: ${e.message}` };
    }
  }

  // 4. Resolve realpath
  let realpath;
  try {
    if (fs.existsSync(resolved)) {
      realpath = fs.realpathSync(resolved);
    } else {
      // If file doesn't exist, resolve parent's realpath
      const parent = path.dirname(resolved);
      if (fs.existsSync(parent)) {
        realpath = path.join(fs.realpathSync(parent), path.basename(resolved));
      } else {
        realpath = resolved;
      }
    }
  } catch (e) {
    return { safe: false, status: 'REALPATH_RESOLUTION_FAILED', reason: e.message };
  }

  // 5. Hard Path Denylist Enforcement
  for (const denied of HARD_PATH_DENYLIST) {
    let deniedRealpath;
    try {
      deniedRealpath = fs.existsSync(denied) ? fs.realpathSync(denied) : path.resolve(denied);
    } catch (_) {
      deniedRealpath = path.resolve(denied);
    }

    if (realpath === deniedRealpath) {
      return {
        safe: false,
        status: 'BLOCKED_HARD_PATH_DENYLIST',
        reason: `Target path matches hard denylist entry: ${denied}`
      };
    }

    // Check if target is a parent of denied (e.g. attempting to delete / or ~)
    if (deniedRealpath.startsWith(realpath + path.sep)) {
      return {
        safe: false,
        status: 'BLOCKED_HARD_PATH_DENYLIST',
        reason: `Target path is parent of critical path: ${denied}`
      };
    }
  }

  // 6. Approved Session Resource Root Enforcement
  // Must be strictly under ~/.gemini/antigravity/runtime/sessions/<sessionId>/resources/
  const approvedSessionRoot = path.join(SESSIONS_ROOT, sessionId);
  const approvedResourcesRoot = path.join(approvedSessionRoot, 'resources');

  let canonicalResourcesRoot;
  try {
    if (fs.existsSync(approvedResourcesRoot)) {
      canonicalResourcesRoot = fs.realpathSync(approvedResourcesRoot);
    } else if (fs.existsSync(approvedSessionRoot)) {
      canonicalResourcesRoot = path.join(fs.realpathSync(approvedSessionRoot), 'resources');
    } else {
      canonicalResourcesRoot = path.resolve(approvedResourcesRoot);
    }
  } catch (_) {
    canonicalResourcesRoot = path.resolve(approvedResourcesRoot);
  }

  // Target must strictly start with canonicalResourcesRoot + path.sep
  if (!realpath.startsWith(canonicalResourcesRoot + path.sep)) {
    return {
      safe: false,
      status: 'BLOCKED_OUTSIDE_APPROVED_SESSION_RESOURCE_ROOT',
      reason: `Path "${realpath}" is outside approved session resource root: "${canonicalResourcesRoot}"`
    };
  }

  return { safe: true, realpath };
}

/**
 * Executes 14-Point Pre-Unlink Gate for a single file.
 *
 * @param {Object} receipt - Broker in-memory creation receipt
 * @param {string} sessionId
 * @param {Object} [options]
 * @returns {{ canDelete: boolean, status: string, reason: string }}
 */
export function verifyFilePreUnlink(receipt, sessionId, options = {}) {
  // 1. Broker in-memory attestation exists
  if (!receipt || !receipt.resourceId || !receipt.creationNonce) {
    return {
      canDelete: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      reason: 'No in-memory Broker creation receipt found for resource'
    };
  }

  // 2. Current session matches
  if (receipt.sessionId !== sessionId) {
    return {
      canDelete: false,
      status: 'CROSS_SESSION_RESOURCE_REJECTED',
      reason: `Receipt session "${receipt.sessionId}" does not match active session "${sessionId}"`
    };
  }

  // 3. Resource role approved
  if (!S3_RESOURCE_CONFIG.allowedRoles.has(receipt.resourceRole)) {
    return {
      canDelete: false,
      status: 'BLOCKED_ROLE_NOT_DISPOSABLE',
      reason: `Resource role "${receipt.resourceRole}" is not approved for S3 deletion`
    };
  }

  const targetPath = receipt.realpath || receipt.originalPath;

  // 4. File existence & initial lstat
  let lstat1;
  try {
    lstat1 = fs.lstatSync(targetPath);
  } catch (err) {
    return {
      canDelete: false,
      status: 'ALREADY_REMOVED',
      reason: `Target file cannot be lstat'd: ${err.message}`
    };
  }

  // 5. Reject symlink
  if (lstat1.isSymbolicLink()) {
    return {
      canDelete: false,
      status: 'SYMLINK_DETECTED',
      reason: 'Target is a symbolic link. Symlink deletion is strictly prohibited.'
    };
  }

  // 6. Realpath resolution
  let realpath;
  try {
    realpath = fs.realpathSync(targetPath);
  } catch (err) {
    return {
      canDelete: false,
      status: 'REALPATH_ERROR',
      reason: `Failed to resolve realpath: ${err.message}`
    };
  }

  if (realpath !== receipt.realpath) {
    return {
      canDelete: false,
      status: 'RESOURCE_IDENTITY_CHANGED',
      reason: `Resolved realpath "${realpath}" does not match receipt realpath "${receipt.realpath}"`
    };
  }

  // 7. Path safety boundary check
  const pathCheck = validateResourcePathSafety(realpath, sessionId);
  if (!pathCheck.safe) {
    return {
      canDelete: false,
      status: pathCheck.status,
      reason: pathCheck.reason
    };
  }

  // 8. Device invariant check
  if (receipt.device !== undefined && receipt.device !== null && lstat1.dev !== receipt.device) {
    return {
      canDelete: false,
      status: 'RESOURCE_IDENTITY_CHANGED',
      reason: `Filesystem device mismatch (recorded: ${receipt.device}, live: ${lstat1.dev})`
    };
  }

  // 9. Inode invariant check
  if (receipt.inode !== undefined && receipt.inode !== null && lstat1.ino !== receipt.inode) {
    return {
      canDelete: false,
      status: 'RESOURCE_IDENTITY_CHANGED',
      reason: `Inode mismatch (recorded: ${receipt.inode}, live: ${lstat1.ino}). File was substituted.`
    };
  }

  // 10. Type match check
  if (receipt.type === 'directory' || lstat1.isDirectory()) {
    return {
      canDelete: false,
      status: 'TYPE_MISMATCH',
      reason: 'Target is a directory; file unlink forbidden'
    };
  }

  // 11. Owner process liveness check
  const ownerPid = (typeof receipt.owningPid === 'number' && receipt.owningPid > 0)
    ? receipt.owningPid
    : (receipt.creationSource !== 'SUPERVISOR_CREATED' && typeof receipt.creatorPid === 'number' && receipt.creatorPid > 0 && receipt.creatorPid !== process.pid)
      ? receipt.creatorPid
      : null;

  if (typeof ownerPid === 'number' && ownerPid > 0 && checkProcessAlive(ownerPid)) {
    return {
      canDelete: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning process PID ${ownerPid} is still running`
    };
  }

  // 12. Open handle check with lsof
  const openHandles = getOpenHandles(realpath);
  if (openHandles.length > 0) {
    return {
      canDelete: false,
      status: 'BLOCKED_RESOURCE_IN_USE',
      reason: `File is held open by active PID(s): ${openHandles.join(', ')}`
    };
  }

  // 13. Immediate second lstat (anti-TOCTOU)
  let lstat2;
  try {
    lstat2 = fs.lstatSync(realpath);
  } catch (err) {
    return {
      canDelete: false,
      status: 'TOCTOU_LSTAT_FAILED',
      reason: `Second lstat failed: ${err.message}`
    };
  }

  // 14. Inode & device invariant still strictly unchanged
  if (lstat2.ino !== receipt.inode || lstat2.dev !== receipt.device) {
    return {
      canDelete: false,
      status: 'RESOURCE_IDENTITY_CHANGED',
      reason: `Immediate second lstat detected identity swap (ino: ${lstat2.ino} vs ${receipt.inode})`
    };
  }

  return {
    canDelete: true,
    status: 'CONFIRMED_DELETABLE',
    reason: 'All 14 pre-unlink verification points passed'
  };
}

/**
 * Safely unlinks a single verified disposable file in S3 Test Mode.
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} [options]
 * @returns {Object}
 */
export function deleteDisposableFile(receipt, sessionId, options = {}) {
  const mode = options.testExecutionMode || S3_RESOURCE_CONFIG.testExecutionMode;
  if (mode !== 'S3_TEST_RESOURCE_DELETE_MODE') {
    return {
      success: false,
      status: 'BLOCKED_EXECUTION_MODE',
      error: `Resource deletion only permitted in S3_TEST_RESOURCE_DELETE_MODE (current: ${mode})`
    };
  }

  const check = verifyFilePreUnlink(receipt, sessionId, options);
  if (!check.canDelete) {
    return {
      success: false,
      status: check.status,
      error: check.reason
    };
  }

  try {
    fs.unlinkSync(receipt.realpath);
    DeletionAccounting.filesUnlinked++;

    return {
      success: true,
      status: 'DELETED_VERIFIED_RESOURCE',
      path: receipt.realpath,
      resourceId: receipt.resourceId
    };
  } catch (err) {
    return {
      success: false,
      status: 'UNLINK_FAILED',
      error: err.message
    };
  }
}

/**
 * Safely removes a verified empty directory with rmdir.
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} [options]
 * @returns {Object}
 */
export function deleteDisposableEmptyDirectory(receipt, sessionId, options = {}) {
  const mode = options.testExecutionMode || S3_RESOURCE_CONFIG.testExecutionMode;
  if (mode !== 'S3_TEST_RESOURCE_DELETE_MODE') {
    return {
      success: false,
      status: 'BLOCKED_EXECUTION_MODE',
      error: 'Directory deletion only permitted in S3_TEST_RESOURCE_DELETE_MODE'
    };
  }

  if (!receipt || !receipt.resourceId) {
    return {
      success: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      error: 'No Broker creation receipt for directory'
    };
  }

  const pathCheck = validateResourcePathSafety(receipt.realpath, sessionId);
  if (!pathCheck.safe) {
    return { success: false, status: pathCheck.status, error: pathCheck.reason };
  }

  let lstat;
  try {
    lstat = fs.lstatSync(receipt.realpath);
    if (!lstat.isDirectory()) {
      return { success: false, status: 'NOT_A_DIRECTORY', error: 'Target is not a directory' };
    }
    if (lstat.isSymbolicLink()) {
      return { success: false, status: 'SYMLINK_DETECTED', error: 'Target is a symlink' };
    }
    if (receipt.inode && lstat.ino !== receipt.inode) {
      return { success: false, status: 'RESOURCE_IDENTITY_CHANGED', error: 'Directory inode mismatch' };
    }
  } catch (err) {
    return { success: false, status: 'STAT_ERROR', error: err.message };
  }

  // Check owner liveness
  const ownerPid = (typeof receipt.owningPid === 'number' && receipt.owningPid > 0)
    ? receipt.owningPid
    : (receipt.creationSource !== 'SUPERVISOR_CREATED' && typeof receipt.creatorPid === 'number' && receipt.creatorPid > 0 && receipt.creatorPid !== process.pid)
      ? receipt.creatorPid
      : null;

  if (typeof ownerPid === 'number' && ownerPid > 0 && checkProcessAlive(ownerPid)) {
    return {
      success: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      error: `Owning process PID ${ownerPid} is still alive`
    };
  }

  // Verify directory is actually empty
  const entries = fs.readdirSync(receipt.realpath);
  if (entries.length > 0) {
    return {
      success: false,
      status: 'DIRECTORY_NOT_EMPTY',
      error: `Directory contains ${entries.length} items. Use tree cleaner.`
    };
  }

  try {
    fs.rmdirSync(receipt.realpath);
    DeletionAccounting.directoriesRemoved++;

    const status = (receipt.resourceRole === RESOURCE_ROLES.PLAYWRIGHT_TEST_PROFILE)
      ? 'PLAYWRIGHT_TEST_PROFILE_DELETED'
      : 'DELETED_VERIFIED_DIRECTORY';

    return {
      success: true,
      status,
      path: receipt.realpath,
      resourceId: receipt.resourceId
    };
  } catch (err) {
    return { success: false, status: 'RMDIR_FAILED', error: err.message };
  }
}

/**
 * Safely cleans up a verified directory tree bottom-up:
 * 1. Checks Broker receipt
 * 2. Checks Path safety and boundary containment
 * 3. Recursively gathers all descendants
 * 4. Rejects symlinks (ABORT_DIRECTORY_CLEANUP)
 * 5. Rejects unknown/unprovenanced children (BLOCKED_UNEXPECTED_CHILD -> ABORT)
 * 6. Checks open handles
 * 7. Deletes regular files bottom-up with unlink
 * 8. Deletes empty directories bottom-up with rmdir
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} [options]
 * @returns {Object}
 */
export function deleteDisposableDirectoryTree(receipt, sessionId, options = {}) {
  const mode = options.testExecutionMode || S3_RESOURCE_CONFIG.testExecutionMode;
  if (mode !== 'S3_TEST_RESOURCE_DELETE_MODE') {
    return {
      success: false,
      status: 'BLOCKED_EXECUTION_MODE',
      error: 'Directory tree deletion only permitted in S3_TEST_RESOURCE_DELETE_MODE'
    };
  }

  if (!receipt || !receipt.resourceId) {
    return {
      success: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      error: 'No Broker creation receipt for directory tree'
    };
  }

  if (receipt.sessionId !== sessionId) {
    return {
      success: false,
      status: 'CROSS_SESSION_RESOURCE_REJECTED',
      error: 'Receipt session ID mismatch'
    };
  }

  const rootPath = receipt.realpath || receipt.originalPath;
  const pathCheck = validateResourcePathSafety(rootPath, sessionId);
  if (!pathCheck.safe) {
    return { success: false, status: pathCheck.status, error: pathCheck.reason };
  }

  let rootLstat;
  try {
    rootLstat = fs.lstatSync(rootPath);
    if (!rootLstat.isDirectory()) {
      return { success: false, status: 'NOT_A_DIRECTORY', error: 'Target is not a directory' };
    }
    if (rootLstat.isSymbolicLink()) {
      return { success: false, status: 'SYMLINK_DETECTED', error: 'Root directory is a symlink' };
    }
    if (receipt.inode && rootLstat.ino !== receipt.inode) {
      return { success: false, status: 'RESOURCE_IDENTITY_CHANGED', error: 'Root directory inode mismatch' };
    }
  } catch (err) {
    return { success: false, status: 'STAT_ERROR', error: err.message };
  }

  // Check owner liveness
  const ownerPid = (typeof receipt.owningPid === 'number' && receipt.owningPid > 0)
    ? receipt.owningPid
    : (receipt.creationSource !== 'SUPERVISOR_CREATED' && typeof receipt.creatorPid === 'number' && receipt.creatorPid > 0 && receipt.creatorPid !== process.pid)
      ? receipt.creatorPid
      : null;

  if (typeof ownerPid === 'number' && ownerPid > 0 && checkProcessAlive(ownerPid)) {
    return {
      success: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      error: `Owning process PID ${ownerPid} is still alive`
    };
  }

  // Enumerate all descendants recursively
  const allFiles = []; // Array of relative paths
  const allDirs = [];  // Array of relative paths

  function scanDir(currentRel) {
    const currentAbs = currentRel ? path.join(rootPath, currentRel) : rootPath;
    const entries = fs.readdirSync(currentAbs, { withFileTypes: true });

    for (const ent of entries) {
      const entRel = currentRel ? path.join(currentRel, ent.name) : ent.name;
      const entAbs = path.join(rootPath, entRel);

      // Check symlink immediately with lstat
      const lstat = fs.lstatSync(entAbs);
      if (lstat.isSymbolicLink()) {
        return { abort: true, status: 'SYMLINK_DETECTED', reason: `Symlink detected at ${entRel}` };
      }

      // Check realpath boundary containment
      const entRealpath = fs.realpathSync(entAbs);
      if (!entRealpath.startsWith(rootPath + path.sep)) {
        return { abort: true, status: 'PATH_ESCAPE_REJECTED', reason: `Path escape detected at ${entRel}` };
      }

      // Unknown Child Policy:
      // If receipt specifies childReceipts, every child must be registered in childReceipts
      if (receipt.childReceipts && receipt.childReceipts instanceof Map) {
        if (!receipt.childReceipts.has(entRel)) {
          return {
            abort: true,
            status: 'BLOCKED_UNEXPECTED_CHILD',
            reason: `Unexpected unprovenanced child detected in tree: "${entRel}". Directory cleanup aborted for safety.`
          };
        }
      }

      // Open handles check
      const openHandles = getOpenHandles(entRealpath);
      if (openHandles.length > 0) {
        return {
          abort: true,
          status: 'BLOCKED_RESOURCE_IN_USE',
          reason: `Child "${entRel}" is held open by active PID(s): ${openHandles.join(', ')}`
        };
      }

      if (lstat.isDirectory()) {
        allDirs.push(entRel);
        const subRes = scanDir(entRel);
        if (subRes && subRes.abort) return subRes;
      } else {
        allFiles.push(entRel);
      }
    }
    return null;
  }

  const scanResult = scanDir('');
  if (scanResult && scanResult.abort) {
    return {
      success: false,
      status: scanResult.status,
      error: scanResult.reason
    };
  }

  // Sort files and dirs for bottom-up deletion: deepest first
  allFiles.sort((a, b) => b.split(path.sep).length - a.split(path.sep).length);
  allDirs.sort((a, b) => b.split(path.sep).length - a.split(path.sep).length);

  let unlinkedCount = 0;
  let rmdirCount = 0;

  try {
    // 1. Delete files bottom-up
    for (const rel of allFiles) {
      const fileAbs = path.join(rootPath, rel);
      const lstat = fs.lstatSync(fileAbs);
      if (lstat.isSymbolicLink()) {
        throw new Error(`Symlink appeared during unlink: ${rel}`);
      }
      fs.unlinkSync(fileAbs);
      unlinkedCount++;
      DeletionAccounting.filesUnlinked++;
    }

    // 2. Rmdir subdirectories bottom-up
    for (const rel of allDirs) {
      const dirAbs = path.join(rootPath, rel);
      fs.rmdirSync(dirAbs);
      rmdirCount++;
      DeletionAccounting.directoriesRemoved++;
    }

    // 3. Rmdir root directory
    fs.rmdirSync(rootPath);
    rmdirCount++;
    DeletionAccounting.directoriesRemoved++;

    const finalStatus = (receipt.resourceRole === RESOURCE_ROLES.PLAYWRIGHT_TEST_PROFILE)
      ? 'PLAYWRIGHT_TEST_PROFILE_DELETED'
      : (unlinkedCount === 0 && rmdirCount === 1)
        ? 'DELETED_VERIFIED_DIRECTORY'
        : 'DELETED_VERIFIED_DIRECTORY_TREE';

    return {
      success: true,
      status: finalStatus,
      path: rootPath,
      resourceId: receipt.resourceId,
      filesUnlinked: unlinkedCount,
      directoriesRemoved: rmdirCount
    };
  } catch (err) {
    return {
      success: false,
      status: 'DIRECTORY_TREE_CLEANUP_FAILED',
      error: err.message,
      filesUnlinked: unlinkedCount,
      directoriesRemoved: rmdirCount
    };
  }
}

// =========================================================================
// PHASE S4.5: ZCODE EPHEMERAL RESOURCE CLEANUP IMPLEMENTATION
// =========================================================================

const BASELINE_SNAPSHOT_PATH = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../baseline_zcode_resources.json');
let baselineResourcesCache = null;

/**
 * Loads baseline pre-existing ZCode resources recorded before Phase S4.5.
 * Dynamically discovers baseline resources from approved temp directories if no snapshot file.
 *
 * @returns {Map<string, Object>}
 */
export function getBaselineZCodeResources() {
  if (!baselineResourcesCache) {
    baselineResourcesCache = new Map();
    const candidatePaths = [
      BASELINE_SNAPSHOT_PATH,
      path.join(path.dirname(fileURLToPath(import.meta.url)), '../baseline_zcode_resources.json')
    ];
    for (const p of candidatePaths) {
      if (fs.existsSync(p)) {
        try {
          const raw = fs.readFileSync(p, 'utf8');
          const items = JSON.parse(raw);
          for (const it of items) {
            baselineResourcesCache.set(it.path, it);
            if (it.dev && it.ino) {
              baselineResourcesCache.set(`${it.dev}:${it.ino}`, it);
            }
          }
        } catch (_) {}
        break;
      }
    }
  }
  return baselineResourcesCache;
}

export function isBaselineZCodeResource(targetPath, lstat = null) {
  const baseline = getBaselineZCodeResources();
  const resolved = path.resolve(targetPath);
  if (baseline.has(resolved)) return true;
  try {
    const real = fs.realpathSync(resolved);
    if (baseline.has(real)) return true;
  } catch (_) {}
  if (lstat && lstat.dev && lstat.ino) {
    if (baseline.has(`${lstat.dev}:${lstat.ino}`)) return true;
  }
  return false;
}

/**
 * Validates path safety specifically for ZCode ephemeral sockets and token files.
 *
 * @param {string} targetPath
 * @param {string} sessionId
 * @param {Object} [options]
 * @returns {{ safe: boolean, status?: string, reason?: string, resolved?: string, realpath?: string, parentRealpath?: string, lstat?: fs.Stats }}
 */
export function validateZCodeResourcePathSafety(targetPath, sessionId, options = {}) {
  if (!targetPath || typeof targetPath !== 'string') {
    return { safe: false, status: 'INVALID_RESOURCE_PATH', reason: 'Resource path is empty or non-string' };
  }

  if (!sessionId || typeof sessionId !== 'string') {
    return { safe: false, status: 'INVALID_SESSION_ID', reason: 'Session ID is missing' };
  }

  // 1. Path traversal escape check: no ".." allowed anywhere in raw targetPath
  if (targetPath.includes('..') || path.normalize(targetPath).split(path.sep).includes('..')) {
    return {
      safe: false,
      status: 'BLOCKED_OUTSIDE_APPROVED_ROOT',
      reason: `Path traversal escape detected ("..") in target path: ${targetPath}`
    };
  }

  const resolved = path.resolve(targetPath);

  // 2. Parent directory / root target check: cannot delete root or temp directory itself!
  const isTempRootOrDir = S4_5_RESOURCE_CONFIG.approvedTempRoots.some(root => {
    try {
      const approvedReal = fs.realpathSync(root);
      return resolved === root || resolved === approvedReal;
    } catch (_) {
      return resolved === root;
    }
  }) || resolved === '/tmp' || resolved === '/private/tmp' || resolved === os.tmpdir() || (fs.existsSync(resolved) && fs.lstatSync(resolved).isDirectory());

  if (isTempRootOrDir) {
    return {
      safe: false,
      status: 'PARENT_DIR_DENIED',
      reason: `Target path is a directory or parent temp root (${resolved}). Parent directories cannot be deleted.`
    };
  }

  // 3. Symlink check: NEVER follow or delete symlinks!
  try {
    const rawLstat = fs.lstatSync(resolved);
    if (rawLstat.isSymbolicLink()) {
      return {
        safe: false,
        status: 'SYMLINK_DETECTED',
        reason: `Resource at ${resolved} is a symbolic link. Following or deleting symlinks is strictly forbidden.`
      };
    }
  } catch (err) {
    if (err.code !== 'ENOENT') {
      return { safe: false, status: 'STAT_ERROR', reason: `Failed to lstat resource: ${err.message}` };
    }
  }

  // 4. Hard Denylist check: system directories, applications, user root, etc.
  for (const denied of HARD_PATH_DENYLIST) {
    if (resolved === denied || resolved.startsWith(denied + path.sep)) {
      if (
        denied === '/' ||
        denied === '/private' ||
        denied === '/var' ||
        denied === '/private/var' ||
        denied === '/tmp' ||
        denied === '/private/tmp'
      ) {
        if (
          resolved.startsWith('/tmp/') ||
          resolved.startsWith('/private/tmp/') ||
          resolved.startsWith('/var/folders/') ||
          resolved.startsWith('/private/var/folders/')
        ) {
          continue; // Allowed inside approved temp subtree
        }
      }
      return {
        safe: false,
        status: 'DENYLISTED_PATH',
        reason: `Target path touches denylisted system/user hierarchy (${denied})`
      };
    }
  }

  // 5. Parent directory check: parent must exist and be inside approved temp roots
  const parentDir = path.dirname(resolved);
  let parentRealpath = null;
  try {
    parentRealpath = fs.realpathSync(parentDir);
  } catch (err) {
    return {
      safe: false,
      status: 'PARENT_DIR_NOT_FOUND',
      reason: `Parent directory "${parentDir}" cannot be resolved: ${err.message}`
    };
  }

  if (parentRealpath === resolved) {
    return {
      safe: false,
      status: 'PARENT_DIR_DENIED',
      reason: 'Target is parent directory'
    };
  }

  const isInsideApprovedTemp = S4_5_RESOURCE_CONFIG.approvedTempRoots.some(root => {
    try {
      const approvedReal = fs.realpathSync(root);
      return parentRealpath === approvedReal || parentRealpath.startsWith(approvedReal + path.sep);
    } catch (_) {
      return false;
    }
  });

  if (!isInsideApprovedTemp) {
    return {
      safe: false,
      status: 'BLOCKED_OUTSIDE_APPROVED_ROOT',
      reason: `Resource parent directory "${parentRealpath}" is outside approved temp roots`
    };
  }

  // 4. Check if file exists on disk
  if (!fs.existsSync(resolved)) {
    return {
      safe: false,
      status: 'RESOURCE_NOT_FOUND',
      reason: `Target path does not exist on filesystem: ${resolved}`
    };
  }

  let lstat;
  try {
    lstat = fs.lstatSync(resolved);
  } catch (err) {
    return { safe: false, status: 'STAT_ERROR', reason: `Failed to lstat resource: ${err.message}` };
  }

  // 5. Symlink check: NEVER follow or delete symlinks!
  if (lstat.isSymbolicLink()) {
    return {
      safe: false,
      status: 'SYMLINK_DETECTED',
      reason: `Resource at ${resolved} is a symbolic link. Following or deleting symlinks is strictly forbidden.`
    };
  }

  // 6. Directory check: ZCode sockets and tokens are NEVER directories
  if (lstat.isDirectory()) {
    return {
      safe: false,
      status: 'PARENT_DIR_DENIED',
      reason: `Target path is a directory (${resolved}). S4.5 only cleans leaf socket/token files.`
    };
  }

  // 7. Baseline check: must NOT be pre-existing before S4.5
  if (isBaselineZCodeResource(resolved, lstat)) {
    return {
      safe: false,
      status: 'PRE_EXISTING_ZCODE_RESOURCE',
      reason: `Resource ${resolved} existed before Phase S4.5 baseline. Must remain OBSERVE_ONLY (0 unlink).`
    };
  }

  let realpath = null;
  try {
    realpath = fs.realpathSync(resolved);
  } catch (_) {
    realpath = resolved;
  }

  return {
    safe: true,
    resolved,
    realpath,
    parentRealpath,
    lstat
  };
}

/**
 * 15-Factor Pre-Unlink Verification for ZCode Ephemeral Unix Sockets.
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} options
 * @returns {Object}
 */
export function verifyZCodeSocketPreUnlink(receipt, sessionId, options = {}) {
  const mode = options.testExecutionMode || options.mode;
  if (mode !== S4_5_RESOURCE_CONFIG.testExecutionMode) {
    return {
      safe: false,
      status: 'BLOCKED_EXECUTION_MODE',
      reason: `ZCode socket deletion is only permitted in ${S4_5_RESOURCE_CONFIG.testExecutionMode} (got: ${mode})`
    };
  }

  if (PHASE_V0_1_CONFIG.executeAllowed !== false) {
    return {
      safe: false,
      status: 'BLOCKED_SECURITY_INVARIANT',
      reason: 'executeAllowed must remain false in Phase S4.5'
    };
  }

  if (!receipt || typeof receipt !== 'object') {
    return { safe: false, status: 'INVALID_RECEIPT', reason: 'Receipt is missing or invalid' };
  }

  // Role check
  if (receipt.resourceRole !== RESOURCE_ROLES.ZCODE_TEST_SOCKET && receipt.resourceRole !== RESOURCE_ROLES.TEST_SOCKET) {
    return {
      safe: false,
      status: 'ROLE_MISMATCH',
      reason: `Receipt role "${receipt.resourceRole}" does not match approved ZCode socket role`
    };
  }

  // Session binding
  if (receipt.sessionId !== sessionId) {
    return {
      safe: false,
      status: 'CROSS_SESSION_RESOURCE_REJECTED',
      reason: `Resource session "${receipt.sessionId}" does not match active session "${sessionId}"`
    };
  }

  // Broker in-memory attestation check
  const broker = options.broker;
  if (!broker) {
    return {
      safe: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      reason: 'Broker is offline or null. In-memory attestation required.'
    };
  }

  const targetPath = receipt.realpath || receipt.originalPath || receipt.path;
  const brokerReceipt = broker.attestedResourceReceipts?.get(targetPath);
  if (!brokerReceipt) {
    return {
      safe: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      reason: `Socket "${targetPath}" has no in-memory creation receipt in Broker`
    };
  }

  // Cross-talk / binding check: ensure receipt matches the exact resource
  if (receipt.resourceId && brokerReceipt.resourceId && receipt.resourceId !== brokerReceipt.resourceId) {
    return {
      safe: false,
      status: 'RESOURCE_BINDING_MISMATCH',
      reason: `Receipt ID ${receipt.resourceId} does not match Broker recorded ID ${brokerReceipt.resourceId}`
    };
  }

  // Attestation signature verification
  if (brokerReceipt.attestation_sig && brokerReceipt.attestationPayload) {
    const recomputed = computeAttestationSig(broker.sessionSecret, brokerReceipt.attestationPayload);
    if (recomputed !== brokerReceipt.attestation_sig) {
      return {
        safe: false,
        status: 'ATTESTATION_SIG_INVALID',
        reason: 'HMAC signature verification failed for socket receipt'
      };
    }
  }

  // Path safety validation
  const safety = validateZCodeResourcePathSafety(targetPath, sessionId, options);
  if (!safety.safe) {
    return safety;
  }

  // Must be Unix domain socket
  if (!safety.lstat.isSocket()) {
    return {
      safe: false,
      status: 'NOT_A_UNIX_SOCKET',
      reason: `Resource ${targetPath} is not a Unix domain socket`
    };
  }

  // Identity preservation (dev, ino, uid)
  if (safety.lstat.dev !== receipt.device || safety.lstat.ino !== receipt.inode) {
    return {
      safe: false,
      status: 'RESOURCE_IDENTITY_CHANGED',
      reason: `Socket inode or device mismatch (expected dev=${receipt.device}, ino=${receipt.inode}; actual dev=${safety.lstat.dev}, ino=${safety.lstat.ino})`
    };
  }

  // Owner process lifecycle: helper, runner, and bridge must all be dead
  const owningHelper = receipt.owningHelperPid || brokerReceipt.owningHelperPid;
  if (owningHelper && checkProcessAlive(owningHelper)) {
    return {
      safe: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning ZCode helper process (${owningHelper}) is still alive`
    };
  }

  const owningRunner = receipt.owningRunnerPid || brokerReceipt.owningRunnerPid;
  if (owningRunner && checkProcessAlive(owningRunner)) {
    return {
      safe: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning ZCode runner process (${owningRunner}) is still alive`
    };
  }

  const owningBridge = receipt.owningBridgePid || brokerReceipt.owningBridgePid;
  if (owningBridge && checkProcessAlive(owningBridge)) {
    return {
      safe: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning ZCode bridge process (${owningBridge}) is still alive`
    };
  }

  // Open handle check
  const handles = getOpenHandles(safety.realpath);
  if (handles && handles.length > 0) {
    return {
      safe: false,
      status: 'BLOCKED_RESOURCE_IN_USE',
      reason: `Socket is held open by process(es): ${handles.join(', ')}`
    };
  }

  // Filename pattern classification check
  const base = path.basename(safety.realpath);
  if (!base.startsWith('zcode-cua-') || !base.endsWith('.sock')) {
    return {
      safe: false,
      status: 'INVALID_SOCKET_PATTERN',
      reason: `Socket basename "${base}" does not match pattern zcode-cua-*.sock`
    };
  }

  return {
    safe: true,
    realpath: safety.realpath,
    receipt: brokerReceipt
  };
}

/**
 * 14-Factor Pre-Unlink Verification for ZCode Ephemeral Token Files.
 * CRITICAL INVARIANT: NEVER READS OR LOGS TOKEN CONTENTS!
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} options
 * @returns {Object}
 */
export function verifyZCodeTokenPreUnlink(receipt, sessionId, options = {}) {
  const mode = options.testExecutionMode || options.mode;
  if (mode !== S4_5_RESOURCE_CONFIG.testExecutionMode) {
    return {
      safe: false,
      status: 'BLOCKED_EXECUTION_MODE',
      reason: `ZCode token deletion is only permitted in ${S4_5_RESOURCE_CONFIG.testExecutionMode} (got: ${mode})`
    };
  }

  if (PHASE_V0_1_CONFIG.executeAllowed !== false) {
    return {
      safe: false,
      status: 'BLOCKED_SECURITY_INVARIANT',
      reason: 'executeAllowed must remain false in Phase S4.5'
    };
  }

  if (!receipt || typeof receipt !== 'object') {
    return { safe: false, status: 'INVALID_RECEIPT', reason: 'Receipt is missing or invalid' };
  }

  // Role check
  if (receipt.resourceRole !== RESOURCE_ROLES.ZCODE_TEST_TOKEN && receipt.resourceRole !== RESOURCE_ROLES.TEST_TOKEN) {
    return {
      safe: false,
      status: 'ROLE_MISMATCH',
      reason: `Receipt role "${receipt.resourceRole}" does not match approved ZCode token role`
    };
  }

  // Session binding
  if (receipt.sessionId !== sessionId) {
    return {
      safe: false,
      status: 'CROSS_SESSION_RESOURCE_REJECTED',
      reason: `Resource session "${receipt.sessionId}" does not match active session "${sessionId}"`
    };
  }

  // Broker in-memory attestation check
  const broker = options.broker;
  if (!broker) {
    return {
      safe: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      reason: 'Broker is offline or null. In-memory attestation required.'
    };
  }

  const targetPath = receipt.realpath || receipt.originalPath || receipt.path;
  const brokerReceipt = broker.attestedResourceReceipts?.get(targetPath);
  if (!brokerReceipt) {
    return {
      safe: false,
      status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
      reason: `Token "${targetPath}" has no in-memory creation receipt in Broker`
    };
  }

  // Cross-talk / binding check: ensure receipt matches the exact resource
  if (receipt.resourceId && brokerReceipt.resourceId && receipt.resourceId !== brokerReceipt.resourceId) {
    return {
      safe: false,
      status: 'RESOURCE_BINDING_MISMATCH',
      reason: `Receipt ID ${receipt.resourceId} does not match Broker recorded ID ${brokerReceipt.resourceId}`
    };
  }

  // Attestation signature verification
  if (brokerReceipt.attestation_sig && brokerReceipt.attestationPayload) {
    const recomputed = computeAttestationSig(broker.sessionSecret, brokerReceipt.attestationPayload);
    if (recomputed !== brokerReceipt.attestation_sig) {
      return {
        safe: false,
        status: 'ATTESTATION_SIG_INVALID',
        reason: 'HMAC signature verification failed for token receipt'
      };
    }
  }

  // Path safety validation
  const safety = validateZCodeResourcePathSafety(targetPath, sessionId, options);
  if (!safety.safe) {
    return safety;
  }

  // Must be regular file
  if (!safety.lstat.isFile()) {
    return {
      safe: false,
      status: 'NOT_A_REGULAR_FILE',
      reason: `Resource ${targetPath} is not a regular file`
    };
  }

  // Permissions check: must be 0600 or 0400 (strict user-only access)
  const modeOctal = safety.lstat.mode & 0o777;
  if (modeOctal !== 0o600 && modeOctal !== 0o400) {
    return {
      safe: false,
      status: 'PERMISSIONS_TOO_OPEN',
      reason: `Token file permissions too open (mode: 0${modeOctal.toString(8)}, expected 0600/0400)`
    };
  }

  // Size bound check: tokens are small ephemeral secrets, never huge files
  if (safety.lstat.size > S4_5_RESOURCE_CONFIG.maxTokenBytes) {
    return {
      safe: false,
      status: 'FILE_TOO_LARGE',
      reason: `Token file size (${safety.lstat.size}B) exceeds maximum allowable token size (${S4_5_RESOURCE_CONFIG.maxTokenBytes}B)`
    };
  }

  // Identity preservation (dev, ino, uid)
  if (safety.lstat.dev !== receipt.device || safety.lstat.ino !== receipt.inode) {
    return {
      safe: false,
      status: 'RESOURCE_IDENTITY_CHANGED',
      reason: `Token inode or device mismatch (expected dev=${receipt.device}, ino=${receipt.inode}; actual dev=${safety.lstat.dev}, ino=${safety.lstat.ino})`
    };
  }

  // Owner process lifecycle: helper, runner, and bridge must all be dead
  const owningHelper = receipt.owningHelperPid || brokerReceipt.owningHelperPid;
  if (owningHelper && checkProcessAlive(owningHelper)) {
    return {
      safe: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning ZCode helper process (${owningHelper}) is still alive`
    };
  }

  const owningRunner = receipt.owningRunnerPid || brokerReceipt.owningRunnerPid;
  if (owningRunner && checkProcessAlive(owningRunner)) {
    return {
      safe: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning ZCode runner process (${owningRunner}) is still alive`
    };
  }

  const owningBridge = receipt.owningBridgePid || brokerReceipt.owningBridgePid;
  if (owningBridge && checkProcessAlive(owningBridge)) {
    return {
      safe: false,
      status: 'BLOCKED_OWNER_STILL_ALIVE',
      reason: `Owning ZCode bridge process (${owningBridge}) is still alive`
    };
  }

  // Open handle check
  const handles = getOpenHandles(safety.realpath);
  if (handles && handles.length > 0) {
    return {
      safe: false,
      status: 'BLOCKED_RESOURCE_IN_USE',
      reason: `Token file is held open by process(es): ${handles.join(', ')}`
    };
  }

  // Filename pattern classification check
  const base = path.basename(safety.realpath);
  if (!base.startsWith('zcode-cua-token-') || !base.endsWith('.txt')) {
    return {
      safe: false,
      status: 'INVALID_TOKEN_PATTERN',
      reason: `Token basename "${base}" does not match pattern zcode-cua-token-*.txt`
    };
  }

  return {
    safe: true,
    realpath: safety.realpath,
    receipt: brokerReceipt
  };
}

/**
 * Controlled physical deletion of an attested ZCode Unix domain socket.
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} options
 * @returns {Object}
 */
export function deleteZCodeSocketS4_5(receipt, sessionId, options = {}) {
  const check = verifyZCodeSocketPreUnlink(receipt, sessionId, options);
  if (!check.safe) {
    if (check.status === 'RESOURCE_NOT_FOUND') {
      return {
        success: true,
        status: 'ALREADY_GONE',
        noop: true,
        unlinked: false,
        path: receipt?.realpath || receipt?.path || receipt?.originalPath
      };
    }
    return {
      success: false,
      status: check.status,
      error: check.reason,
      path: receipt?.realpath || receipt?.path || receipt?.originalPath
    };
  }

  const realpath = check.realpath;

  // TOCTOU-hardened pre-unlink verification immediately before filesystem unlink
  try {
    const preUnlink = fs.lstatSync(realpath);
    if (preUnlink.isSymbolicLink() || preUnlink.ino !== receipt.inode || preUnlink.dev !== receipt.device) {
      return {
        success: false,
        status: 'RESOURCE_IDENTITY_CHANGED',
        error: 'Filesystem identity drift detected immediately before unlink',
        path: realpath
      };
    }
    fs.unlinkSync(realpath);
  } catch (err) {
    return {
      success: false,
      status: 'SOCKET_UNLINK_FAILED',
      error: err.message,
      path: realpath
    };
  }

  DeletionAccounting.supervisorZCodeSocketsDeleted++;
  DeletionAccounting.filesUnlinked++;

  return {
    success: true,
    status: 'ZCODE_TEST_SOCKET_DELETED',
    attribution: 'DELETED_BY_SUPERVISOR',
    resourceId: receipt.resourceId,
    path: realpath
  };
}

/**
 * Controlled physical deletion of an attested ZCode Token file.
 * CRITICAL INVARIANT: NEVER READS OR LOGS TOKEN CONTENTS!
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @param {Object} options
 * @returns {Object}
 */
export function deleteZCodeTokenS4_5(receipt, sessionId, options = {}) {
  const check = verifyZCodeTokenPreUnlink(receipt, sessionId, options);
  if (!check.safe) {
    if (check.status === 'RESOURCE_NOT_FOUND') {
      return {
        success: true,
        status: 'ALREADY_GONE',
        noop: true,
        unlinked: false,
        path: receipt?.realpath || receipt?.path || receipt?.originalPath
      };
    }
    return {
      success: false,
      status: check.status,
      error: check.reason,
      path: receipt?.realpath || receipt?.path || receipt?.originalPath
    };
  }

  const realpath = check.realpath;

  // TOCTOU-hardened pre-unlink verification immediately before filesystem unlink
  try {
    const preUnlink = fs.lstatSync(realpath);
    if (preUnlink.isSymbolicLink() || preUnlink.ino !== receipt.inode || preUnlink.dev !== receipt.device) {
      return {
        success: false,
        status: 'RESOURCE_IDENTITY_CHANGED',
        error: 'Filesystem identity drift detected immediately before unlink',
        path: realpath
      };
    }
    fs.unlinkSync(realpath);
  } catch (err) {
    return {
      success: false,
      status: 'TOKEN_UNLINK_FAILED',
      error: err.message,
      path: realpath
    };
  }

  DeletionAccounting.supervisorZCodeTokensDeleted++;
  DeletionAccounting.filesUnlinked++;

  return {
    success: true,
    status: 'ZCODE_TEST_TOKEN_DELETED',
    attribution: 'DELETED_BY_SUPERVISOR',
    resourceId: receipt.resourceId,
    path: realpath
  };
}

/**
 * Records normal owner-initiated cleanup of ephemeral resources.
 *
 * @param {Object} receipt
 * @param {string} sessionId
 * @returns {Object}
 */
export function recordOwnerCleanedResource(receipt, sessionId) {
  if (!receipt) return { success: false, error: 'MISSING_RECEIPT' };
  const role = receipt.resourceRole || receipt.role;
  if (role === RESOURCE_ROLES.ZCODE_TEST_SOCKET || role === RESOURCE_ROLES.TEST_SOCKET) {
    DeletionAccounting.ownerCleanedSockets++;
  } else if (role === RESOURCE_ROLES.ZCODE_TEST_TOKEN || role === RESOURCE_ROLES.TEST_TOKEN) {
    DeletionAccounting.ownerCleanedTokens++;
  }
  return {
    success: true,
    status: 'OWNER_CLEANED_RESOURCES',
    attribution: 'DELETED_BY_OWNER',
    path: receipt.realpath || receipt.path
  };
}
