import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  SESSIONS_ROOT,
  SYSTEM_ROOT_PIDS,
  REGISTRATION_SOURCES,
  BROKER_CONFIG,
  PHASE_V0_1_CONFIG
} from './config.mjs';
import {
  getProcessSnapshot,
  checkProcessAlive
} from './identity.mjs';
import { isNeverKill, isApprovedTempPath } from './predicates.mjs';
import { sendBrokerRequest } from './ipc.mjs';

/**
 * Generates a unique Antigravity session ID.
 *
 * @returns {string}
 */
export function generateSessionId() {
  return `agy-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
}

/**
 * Resolves the session directory path.
 *
 * @param {string} sessionId
 * @returns {string}
 */
export function getSessionDir(sessionId) {
  return path.join(SESSIONS_ROOT, sessionId);
}

/**
 * Returns the path to the session's broker Unix Domain Socket.
 *
 * @param {string} sessionId
 * @returns {string}
 */
export function getBrokerSocketPath(sessionId) {
  return path.join(getSessionDir(sessionId), BROKER_CONFIG.socketName);
}

/**
 * Discovers the most recently active session or creates a new one.
 *
 * @param {string} [requestedSessionId]
 * @returns {string} Active session ID
 */
export function resolveActiveSessionId(requestedSessionId) {
  if (requestedSessionId && typeof requestedSessionId === 'string') {
    return requestedSessionId;
  }

  if (fs.existsSync(SESSIONS_ROOT)) {
    const entries = fs.readdirSync(SESSIONS_ROOT, { withFileTypes: true })
      .filter(d => d.isDirectory() && d.name.startsWith('agy-'))
      .map(d => ({
        id: d.name,
        ctime: fs.statSync(path.join(SESSIONS_ROOT, d.name)).ctimeMs
      }))
      .sort((a, b) => b.ctime - a.ctime);

    if (entries.length > 0) {
      return entries[0].id;
    }
  }

  return generateSessionId();
}

/**
 * Discovers the session root PID by strictly inspecting process.ppid.
 * Hard-rejects any attempt to bind to PID 0 or 1.
 *
 * @returns {number}
 */
export function discoverSessionRootPid() {
  const ppid = process.ppid;
  if (!ppid || SYSTEM_ROOT_PIDS.has(ppid)) {
    throw new Error(`[TRUST_ROOT_ERROR] Parent PID (${ppid}) is invalid or a system root PID (0 or 1).`);
  }

  const parentSnap = getProcessSnapshot(ppid);
  if (!parentSnap || SYSTEM_ROOT_PIDS.has(parentSnap.pid)) {
    throw new Error(`[TRUST_ROOT_ERROR] Parent snapshot invalid or PID <= 1.`);
  }

  return ppid;
}

/**
 * Ensures session directory and initialized registry files exist with verified root.
 * ZERO DISK SECRET: session_secret is NEVER written to disk.
 *
 * @param {string} sessionId
 * @returns {string} Session directory path
 */
export function initializeSession(sessionId) {
  const sessionDir = getSessionDir(sessionId);
  if (!fs.existsSync(sessionDir)) {
    fs.mkdirSync(sessionDir, { recursive: true, mode: 0o700 });
  }
  try {
    fs.chmodSync(sessionDir, 0o700);
  } catch (_) {}

  const sessionFile = path.join(sessionDir, 'session.json');
  if (!fs.existsSync(sessionFile)) {
    const rootPid = discoverSessionRootPid();
    const rootSnapshot = getProcessSnapshot(rootPid);

    // Metadata ONLY. NO session_secret on disk.
    const initialSession = {
      sessionId,
      sessionNonce: crypto.randomBytes(8).toString('hex'),
      startedAt: new Date().toISOString(),
      root_pid: rootSnapshot ? rootSnapshot.pid : rootPid,
      root_start_time: rootSnapshot ? rootSnapshot.lstart : new Date().toUTCString(),
      root_start_epoch_ms: rootSnapshot ? rootSnapshot.startTimeEpochMs : Date.now(),
      root_executable: rootSnapshot ? rootSnapshot.canonicalExecutable : process.execPath,
      status: 'ACTIVE',
      version: PHASE_V0_1_CONFIG.version
    };
    fs.writeFileSync(sessionFile, JSON.stringify(initialSession, null, 2), 'utf8');
  }

  const procFile = path.join(sessionDir, 'processes.json');
  if (!fs.existsSync(procFile)) {
    fs.writeFileSync(procFile, '[]', 'utf8');
  }

  const resFile = path.join(sessionDir, 'resources.json');
  if (!fs.existsSync(resFile)) {
    fs.writeFileSync(resFile, '[]', 'utf8');
  }

  const logFile = path.join(sessionDir, 'cleanup.log');
  if (!fs.existsSync(logFile)) {
    fs.writeFileSync(logFile, '', 'utf8');
  }

  return sessionDir;
}

/**
 * Validates the integrity of the Session Trust Root against live OS state.
 * Hard-rejects PID <= 1.
 *
 * @param {string} sessionId
 * @returns {{ valid: boolean, session?: Object, reason?: string }}
 */
export function validateSessionRoot(sessionId) {
  const sessionDir = getSessionDir(sessionId);
  const sessionFile = path.join(sessionDir, 'session.json');
  if (!fs.existsSync(sessionFile)) {
    return { valid: false, reason: 'SESSION_FILE_NOT_FOUND' };
  }

  let session;
  try {
    session = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
  } catch (err) {
    return { valid: false, reason: 'SESSION_FILE_CORRUPT' };
  }

  if (!session.root_pid || SYSTEM_ROOT_PIDS.has(session.root_pid)) {
    return { valid: false, reason: 'SESSION_ROOT_PID_INVALID_OR_SYSTEM_PID' };
  }

  const isAlive = checkProcessAlive(session.root_pid);
  if (!isAlive) {
    return { valid: false, reason: 'SESSION_ROOT_PROCESS_DEAD', session };
  }

  const liveRoot = getProcessSnapshot(session.root_pid);
  if (!liveRoot) {
    return { valid: false, reason: 'SESSION_ROOT_PROCESS_UNREADABLE', session };
  }

  if (SYSTEM_ROOT_PIDS.has(liveRoot.pid)) {
    return { valid: false, reason: 'SESSION_ROOT_REJECTED_SYSTEM_PID', session };
  }

  const timeDiff = Math.abs(liveRoot.startTimeEpochMs - (session.root_start_epoch_ms || 0));
  if (timeDiff > 1000 && liveRoot.lstart !== session.root_start_time) {
    return { valid: false, reason: 'SESSION_ROOT_PID_REUSED', session };
  }

  return { valid: true, session };
}

/**
 * Appends a structured log entry into session cleanup.log
 *
 * @param {string} sessionId
 * @param {Object} entry
 */
export function appendSessionLog(sessionId, entry) {
  const sessionDir = initializeSession(sessionId);
  const logFile = path.join(sessionDir, 'cleanup.log');
  const line = JSON.stringify({
    timestamp: new Date().toISOString(),
    ...entry
  }) + '\n';
  fs.appendFileSync(logFile, line, 'utf8');
}

/**
 * Loads all session data (session.json, processes.json, resources.json)
 *
 * @param {string} sessionId
 * @returns {{ session: Object, processes: Array, resources: Array, sessionDir: string }}
 */
export function loadSessionData(sessionId) {
  const sessionDir = initializeSession(sessionId);
  const session = JSON.parse(fs.readFileSync(path.join(sessionDir, 'session.json'), 'utf8'));
  const processes = JSON.parse(fs.readFileSync(path.join(sessionDir, 'processes.json'), 'utf8'));
  const resources = JSON.parse(fs.readFileSync(path.join(sessionDir, 'resources.json'), 'utf8'));
  return { session, processes, resources, sessionDir };
}

/**
 * Creation-Time Registration Wrapper using Broker IPC and Launch Tickets.
 *
 * @param {string} sessionId
 * @param {Function} spawnFn - () => ChildProcess
 * @param {Object} meta - { role, safeToKill }
 * @returns {Promise<{ success: boolean, child: Object, record: Object }>}
 */
export async function spawnAttestedProcess(sessionId, spawnFn, meta = {}) {
  const socketPath = getBrokerSocketPath(sessionId);

  const launcherCapabilityToken = meta.launcherCapabilityToken ||
    process.env[`AGY_LAUNCHER_CAPABILITY_${sessionId}`] ||
    process.env.AGY_LAUNCHER_CAPABILITY_TOKEN ||
    meta.broker?.getLauncherCapabilityToken();

  // 1. Request launch intent ticket from Broker
  const intentRes = await sendBrokerRequest(socketPath, {
    action: 'REQUEST_LAUNCH_INTENT',
    sessionId,
    params: {
      launcherCapabilityToken,
      launcherPid: process.pid,
      role: meta.role || 'spawn-worker',
      expectedPid: meta.expectedPid || null,
      expectedExecutable: meta.expectedExecutable || null,
      expectedCommandFingerprint: meta.expectedCommandFingerprint || null,
      ttlMs: meta.ttlMs || null
    }
  });

  if (!intentRes.success) {
    // If Broker is unavailable, Fail-Closed: child spawns but is permanently safe_to_kill = false
    const child = spawnFn();
    appendSessionLog(sessionId, {
      action: 'SPAWN_UNATTESTED_BROKER_UNAVAILABLE',
      pid: child?.pid,
      reason: intentRes.error
    });
    return {
      success: false,
      child,
      error: `BROKER_UNAVAILABLE: ${intentRes.error}`
    };
  }

  // 2. Spawn child process
  const child = spawnFn();
  if (!child || !child.pid) {
    throw new Error('[SPAWN_FAILED] spawnFn failed to return a child with PID');
  }

  // 3. Attest spawn with Broker using single-use ticket
  const attestRes = await sendBrokerRequest(socketPath, {
    action: 'ATTEST_SPAWN',
    sessionId,
    params: {
      ticketId: intentRes.ticketId,
      pid: child.pid,
      safeToKill: meta.safeToKill !== false
    }
  });

  if (!attestRes.success) {
    appendSessionLog(sessionId, {
      action: 'SPAWN_ATTESTATION_REJECTED',
      pid: child.pid,
      reason: attestRes.error
    });
    return {
      success: false,
      child,
      error: attestRes.error
    };
  }

  return { success: true, child, record: attestRes.record };
}

/**
 * Manual / External Registration (CLI register-process).
 * STRICT RULE: All manual registrations are marked UNTRUSTED_TEST_REGISTRATION
 * and are permanently safe_to_kill = false.
 *
 * @param {string} sessionId
 * @param {Object} input - { pid, role }
 * @returns {{ success: boolean, record?: Object, error?: string }}
 */
export function registerProcess(sessionId, input) {
  if (!input || typeof input.pid !== 'number') {
    return { success: false, error: 'INVALID_PID' };
  }

  const snapshot = getProcessSnapshot(input.pid);
  if (!snapshot) {
    return { success: false, error: `PROCESS_PID_${input.pid}_NOT_RUNNING_AT_REGISTRATION` };
  }

  const neverKillCheck = isNeverKill(snapshot);

  const record = {
    pid: snapshot.pid,
    ppid: snapshot.ppid,
    pgid: snapshot.pgid,
    executable: snapshot.canonicalExecutable,
    comm: snapshot.comm,
    command: snapshot.command,
    command_fingerprint: snapshot.commandFingerprint,
    lstart: snapshot.lstart,
    start_time_epoch_ms: snapshot.startTimeEpochMs,
    registered_at: new Date().toISOString(),
    session_id: sessionId,
    registration_source: REGISTRATION_SOURCES.MANUAL_TEST,
    ownership: 'UNTRUSTED_TEST_REGISTRATION',
    launch_nonce: null,
    role: input.role || 'manual-registered-test',
    safe_to_kill: false, // HARD RULE: Never terminable
    never_kill_reason: neverKillCheck.neverKill ? neverKillCheck.reason : 'UNTRUSTED_MANUAL_REGISTRATION'
  };

  const { sessionDir, processes } = loadSessionData(sessionId);
  const filtered = processes.filter(p => p.pid !== record.pid);
  filtered.push(record);
  fs.writeFileSync(path.join(sessionDir, 'processes.json'), JSON.stringify(filtered, null, 2), 'utf8');

  appendSessionLog(sessionId, {
    action: 'REGISTER_MANUAL_PROCESS_UNTRUSTED',
    pid: record.pid,
    role: record.role,
    ownership: record.ownership,
    safe_to_kill: false
  });

  return { success: true, record };
}

/**
 * Registers a resource with Session Nonce validation.
 *
 * @param {string} sessionId
 * @param {Object} input - { type, path, owningPid, cleanupPolicy }
 * @returns {Promise<{ success: boolean, record?: Object, error?: string }>}
 */
export async function registerResource(sessionId, input) {
  if (!input || !input.path || typeof input.path !== 'string') {
    return { success: false, error: 'INVALID_RESOURCE_PATH' };
  }

  const resolvedPath = path.resolve(input.path);
  const socketPath = getBrokerSocketPath(sessionId);

  // Route through Broker IPC if available
  const brokerRes = await sendBrokerRequest(socketPath, {
    action: 'REGISTER_RESOURCE_INTENT',
    sessionId,
    params: {
      path: resolvedPath,
      type: input.type,
      owningPid: input.owningPid
    }
  });

  if (brokerRes.success) {
    return { success: true, record: brokerRes.record };
  }

  // Fallback: Register as unverified audit-only record
  const isApproved = isApprovedTempPath(resolvedPath);
  let dev = null;
  let ino = null;
  if (fs.existsSync(resolvedPath)) {
    try {
      const stat = fs.lstatSync(resolvedPath);
      dev = stat.dev;
      ino = stat.ino;
    } catch (_) {}
  }

  const record = {
    id: `res-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
    type: input.type || 'unix_socket',
    path: resolvedPath,
    owning_pid: typeof input.owningPid === 'number' ? input.owningPid : null,
    session_id: sessionId,
    cleanup_policy: input.cleanupPolicy || 'on_session_end',
    is_approved_temp_path: isApproved,
    dev,
    ino,
    registered_at: new Date().toISOString(),
    broker_attested: false
  };

  const { sessionDir, resources } = loadSessionData(sessionId);
  const filtered = resources.filter(r => r.path !== record.path);
  filtered.push(record);
  fs.writeFileSync(path.join(sessionDir, 'resources.json'), JSON.stringify(filtered, null, 2), 'utf8');

  return { success: true, record };
}
