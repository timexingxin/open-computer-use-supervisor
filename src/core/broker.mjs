import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  SESSIONS_ROOT,
  SYSTEM_ROOT_PIDS,
  REGISTRATION_SOURCES,
  ROLES,
  RESOURCE_ROLES,
  BROKER_CONFIG,
  PHASE_V0_1_CONFIG,
  S3_RESOURCE_CONFIG,
  S4_5_RESOURCE_CONFIG
} from './config.mjs';
import {
  getProcessSnapshot,
  checkProcessAlive,
  computeAttestationSig,
  getProcessAncestry,
  getProcessesInPgid,
  getOpenHandles
} from './identity.mjs';
import { isNeverKill, isApprovedTempPath } from './predicates.mjs';
import { createBrokerServer } from './ipc.mjs';
import {
  validateResourcePathSafety,
  verifyFilePreUnlink,
  deleteDisposableFile,
  deleteDisposableEmptyDirectory,
  deleteDisposableDirectoryTree,
  DeletionAccounting,
  validateZCodeResourcePathSafety,
  verifyZCodeSocketPreUnlink,
  verifyZCodeTokenPreUnlink,
  deleteZCodeSocketS4_5,
  deleteZCodeTokenS4_5,
  recordOwnerCleanedResource,
  isBaselineZCodeResource
} from './resource-cleaner.mjs';

/**
 * Session-Scoped Privileged Supervisor Broker.
 * Maintains all high-security attestation secrets and state exclusively in memory.
 */
export class SupervisorBroker {
  /**
   * @param {string} sessionId
   * @param {Object} [options]
   */
  constructor(sessionId, options = {}) {
    this.sessionId = sessionId || `agy-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    this.sessionDir = path.join(SESSIONS_ROOT, this.sessionId);
    this.socketPath = path.join(this.sessionDir, BROKER_CONFIG.socketName);

    // SECURITY CRITICAL: In-Memory Only CSPRNG Secret (NEVER written to disk)
    this.sessionSecret = crypto.randomBytes(32).toString('hex');
    this.sessionNonce = crypto.randomBytes(8).toString('hex');

    // SECURITY CRITICAL (S1.4): In-Memory Only Capability Token for minting tickets (NEVER written to disk)
    this.launcherCapabilityToken = options.launcherCapabilityToken || crypto.randomBytes(32).toString('hex');

    // In-memory state tracking
    this.launchTickets = new Map(); // ticketId -> LaunchTicket
    this.attestedProcesses = new Map(); // pid -> AttestationRecord
    this.attestedResources = new Map(); // path -> ResourceAttestationRecord
    this.attestedResourceReceipts = new Map(); // realpath -> ResourceCreationReceipt (S3)
    this.trustedLaunchers = new Map(); // pid -> TrustedLauncherRecord
    this.retiredProcesses = new Map(); // pid -> RetiredProcessRecord (Tombstones)
    this.retiredResources = new Map(); // path -> RetiredResourceRecord (Tombstones)
    this.peakEntries = 0;

    this.server = null;
    this.status = 'INITIALIZED';
    this.rootPid = null;
    this.rootSnapshot = null;
  }

  /**
   * Returns the in-memory unforgeable capability token required to mint tickets.
   * STRICT: NEVER written to disk or logged.
   */
  getLauncherCapabilityToken() {
    return this.launcherCapabilityToken;
  }

  /**
   * Derives session trust root strictly from process.ppid.
   * Hard-rejects any PID <= 1 (launchd / kernel).
   *
   * @returns {Object} Root process snapshot
   */
  deriveSessionRoot() {
    const ppid = process.ppid;
    if (!ppid || SYSTEM_ROOT_PIDS.has(ppid)) {
      throw new Error(`[TRUST_ROOT_REJECTED] process.ppid (${ppid}) is invalid or a system root PID (PID 0 or 1).`);
    }

    const snapshot = getProcessSnapshot(ppid);
    if (!snapshot) {
      throw new Error(`[TRUST_ROOT_UNREADABLE] Unable to obtain snapshot for parent PID ${ppid}.`);
    }

    if (SYSTEM_ROOT_PIDS.has(snapshot.pid)) {
      throw new Error(`[TRUST_ROOT_REJECTED] Session root cannot be PID <= 1 (${snapshot.command}).`);
    }

    this.rootPid = snapshot.pid;
    this.rootSnapshot = snapshot;

    // Anchor Session Root as initial Trusted Launcher
    this.trustedLaunchers.set(snapshot.pid, {
      pid: snapshot.pid,
      role: 'SESSION_ROOT',
      executable: snapshot.canonicalExecutable,
      lstart: snapshot.lstart,
      registeredAt: new Date().toISOString()
    });

    // If Broker host process is separate from root, register Broker host as well
    if (process.pid !== snapshot.pid) {
      this.trustedLaunchers.set(process.pid, {
        pid: process.pid,
        role: 'BROKER_HOST',
        executable: process.execPath,
        lstart: getProcessSnapshot(process.pid)?.lstart,
        registeredAt: new Date().toISOString()
      });
    }

    return snapshot;
  }

  /**
   * Starts the Session Broker:
   * 1. Prepares 0700 session directory
   * 2. Writes non-secret session.json
   * 3. Starts Unix domain socket server with 0600 permissions
   */
  async start() {
    if (this.status === 'RUNNING') return;

    if (!fs.existsSync(this.sessionDir)) {
      fs.mkdirSync(this.sessionDir, { recursive: true, mode: 0o700 });
    }
    try {
      fs.chmodSync(this.sessionDir, 0o700);
    } catch (_) {}

    this.deriveSessionRoot();

    // Write NON-SECRET metadata only (session_secret is strictly excluded)
    const sessionFile = path.join(this.sessionDir, 'session.json');
    const metadata = {
      sessionId: this.sessionId,
      sessionNonce: this.sessionNonce,
      startedAt: new Date().toISOString(),
      root_pid: this.rootSnapshot.pid,
      root_start_time: this.rootSnapshot.lstart,
      root_start_epoch_ms: this.rootSnapshot.startTimeEpochMs,
      root_executable: this.rootSnapshot.canonicalExecutable,
      broker_pid: process.pid,
      status: 'ACTIVE',
      version: PHASE_V0_1_CONFIG.version
    };
    fs.writeFileSync(sessionFile, JSON.stringify(metadata, null, 2), 'utf8');

    // Initialize audit log files if missing
    const procFile = path.join(this.sessionDir, 'processes.json');
    if (!fs.existsSync(procFile)) {
      fs.writeFileSync(procFile, '[]', 'utf8');
    }
    const resFile = path.join(this.sessionDir, 'resources.json');
    if (!fs.existsSync(resFile)) {
      fs.writeFileSync(resFile, '[]', 'utf8');
    }
    const logFile = path.join(this.sessionDir, 'cleanup.log');
    if (!fs.existsSync(logFile)) {
      fs.writeFileSync(logFile, '', 'utf8');
    }

    // Start Unix Domain Socket server
    const { server, close } = await createBrokerServer(this.socketPath, (req) => this.handleIpcRequest(req));
    this.server = server;
    this._closeServer = close;
    this.status = 'RUNNING';

    // Set in-memory session environment for child processes spawned within this session hierarchy
    process.env[`AGY_LAUNCHER_CAPABILITY_${this.sessionId}`] = this.launcherCapabilityToken;
    if (!process.env.AGY_LAUNCHER_CAPABILITY_TOKEN) {
      process.env.AGY_LAUNCHER_CAPABILITY_TOKEN = this.launcherCapabilityToken;
    }

    this.appendLog({
      action: 'BROKER_STARTED',
      broker_pid: process.pid,
      root_pid: this.rootPid,
      sessionId: this.sessionId
    });
  }

  /**
   * Stops the Broker and cleans up socket file.
   */
  async stop() {
    if (this.status === 'STOPPED') return;
    this.status = 'STOPPED';

    delete process.env[`AGY_LAUNCHER_CAPABILITY_${this.sessionId}`];
    if (process.env.AGY_LAUNCHER_CAPABILITY_TOKEN === this.launcherCapabilityToken) {
      delete process.env.AGY_LAUNCHER_CAPABILITY_TOKEN;
    }

    if (this._closeServer) {
      await this._closeServer();
    }

    const sessionFile = path.join(this.sessionDir, 'session.json');
    if (fs.existsSync(sessionFile)) {
      try {
        const meta = JSON.parse(fs.readFileSync(sessionFile, 'utf8'));
        meta.status = 'TERMINATED';
        fs.writeFileSync(sessionFile, JSON.stringify(meta, null, 2), 'utf8');
      } catch (_) {}
    }

    this.launchTickets.clear();
    this.attestedProcesses.clear();
    this.attestedResources.clear();
    this.attestedResourceReceipts.clear();
    this.trustedLaunchers.clear();
  }

  /**
   * Central IPC Request Router.
   *
   * @param {Object} req
   * @returns {Promise<Object>}
   */
  async handleIpcRequest(req) {
    if (!req || typeof req.action !== 'string') {
      return { success: false, error: 'INVALID_IPC_REQUEST' };
    }

    // STRICT SESSION BINDING: Cross-session requests are blocked
    if (req.sessionId && typeof req.sessionId === 'string' && req.sessionId !== this.sessionId) {
      return {
        success: false,
        error: `CROSS_SESSION_REQUEST_REJECTED: Mismatched session ID "${req.sessionId}" for broker session "${this.sessionId}"`
      };
    }

    const params = { ...(req.params || {}) };
    if (req.sessionId && !params.sessionId) {
      params.sessionId = req.sessionId;
    }

    switch (req.action) {
      case 'PING':
        return {
          success: true,
          pong: true,
          sessionId: this.sessionId,
          brokerPid: process.pid,
          status: this.status
        };

      case 'REQUEST_LAUNCH_INTENT':
        return this.requestLaunchIntent(params);

      case 'ATTEST_SPAWN':
        return this.attestSpawn(params);

      case 'ATTEST_PLAYWRIGHT_HELPER':
        return this.attestPlaywrightHelper(params);

      case 'ATTEST_ZCODE_CHAIN':
        return this.attestZCodeChain(params);

      case 'REGISTER_TRUSTED_LAUNCHER':
        return this.registerTrustedLauncher(params);

      case 'REGISTER_RESOURCE_INTENT':
        return this.registerResourceIntent(params);

      case 'CREATE_TEST_RESOURCE':
        return this.createTestResource(params);

      case 'ATTEST_RESOURCE_RECEIPT':
        return this.attestResourceReceipt(params);

      case 'DELETE_TEST_RESOURCE_S3':
        return this.deleteResourceS3(params);

      case 'ATTEST_ZCODE_RESOURCE':
        return this.attestZCodeResource(params);

      case 'DELETE_ZCODE_RESOURCE_S4_5':
        return this.deleteZCodeResourceS4_5(params);

      case 'RECORD_OWNER_CLEANED_S4_5':
        return this.recordOwnerCleanedS4_5(params);

      case 'VERIFY_PROCESS':
        return this.verifyProcess(params?.pid);

      case 'VERIFY_RESOURCE':
        return this.verifyResource(params?.path);

      case 'GET_STATUS':
        return this.getStatus();

      default:
        return { success: false, error: `UNKNOWN_ACTION: ${req.action}` };
    }
  }

  /**
   * Registers a process as a trusted launcher.
   * Requires possession of the in-memory launcherCapabilityToken and
   * proof of descent from session root in OS process tree.
   *
   * @param {Object} params - { launcherCapabilityToken, pid, role }
   * @returns {Object}
   */
  registerTrustedLauncher(params) {
    const { launcherCapabilityToken, pid, role } = params;
    if (!launcherCapabilityToken || typeof launcherCapabilityToken !== 'string') {
      return { success: false, error: 'TICKET_ISSUANCE_DENIED: MISSING_LAUNCHER_CAPABILITY' };
    }
    const expectedBuf = Buffer.from(this.launcherCapabilityToken);
    const actualBuf = Buffer.from(launcherCapabilityToken);
    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
      return { success: false, error: 'TICKET_ISSUANCE_DENIED: INVALID_LAUNCHER_CAPABILITY' };
    }

    if (typeof pid !== 'number' || pid <= 0) {
      return { success: false, error: 'TICKET_ISSUANCE_DENIED: INVALID_LAUNCHER_PID' };
    }

    const snap = getProcessSnapshot(pid);
    if (!snap) {
      return { success: false, error: `TICKET_ISSUANCE_DENIED: LAUNCHER_PID_${pid}_NOT_ALIVE` };
    }

    const nk = isNeverKill(snap);
    if (nk.neverKill) {
      return { success: false, error: `TICKET_ISSUANCE_DENIED: LAUNCHER_IS_NEVER_KILL: ${nk.reason}` };
    }

    // Must be session root or in session root ancestry tree
    if (pid !== this.rootPid) {
      const ancestry = getProcessAncestry(pid);
      if (!ancestry.includes(this.rootPid)) {
        return {
          success: false,
          error: `TICKET_ISSUANCE_DENIED: LAUNCHER_${pid}_NOT_IN_SESSION_TREE`
        };
      }
    }

    this.trustedLaunchers.set(pid, {
      pid,
      role: role || 'TRUSTED_LAUNCHER',
      executable: snap.canonicalExecutable,
      lstart: snap.lstart,
      registeredAt: new Date().toISOString()
    });

    return {
      success: true,
      pid,
      role: role || 'TRUSTED_LAUNCHER'
    };
  }

  /**
   * Step 1 of Pre-Authorization: Launcher claims a single-use launch ticket.
   * STRICT ACCESS CONTROL (S1.4):
   * 1. Requires unforgeable in-memory launcherCapabilityToken (inherited capability).
   * 2. Requires caller/launcher PID to be a verified TRUSTED_LAUNCHER or descendant of session root.
   * 3. Requires launcher process to be alive, not never-kill, and not PID-recycled.
   * 4. Binds ticket to session, launcher identity, executable, fingerprint, TTL, single-use nonce.
   *
   * @param {Object} params - { launcherCapabilityToken, launcherPid, role, expectedExecutable, expectedCommandFingerprint, ttlMs }
   * @returns {Object}
   */
  requestLaunchIntent(params) {
    const { launcherCapabilityToken, launcherPid } = params;

    // 1. FACTOR 1: Inherited Capability Token Verification
    if (!launcherCapabilityToken || typeof launcherCapabilityToken !== 'string') {
      return { success: false, error: 'TICKET_ISSUANCE_DENIED: MISSING_LAUNCHER_CAPABILITY' };
    }
    const expectedBuf = Buffer.from(this.launcherCapabilityToken);
    const actualBuf = Buffer.from(launcherCapabilityToken);
    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
      return { success: false, error: 'TICKET_ISSUANCE_DENIED: INVALID_LAUNCHER_CAPABILITY' };
    }

    // 2. FACTOR 2: Launcher PID Validation & Liveness
    if (typeof launcherPid !== 'number' || launcherPid <= 0) {
      return { success: false, error: 'TICKET_ISSUANCE_DENIED: INVALID_LAUNCHER_PID' };
    }

    if (!checkProcessAlive(launcherPid)) {
      return { success: false, error: `TICKET_ISSUANCE_DENIED: LAUNCHER_PID_${launcherPid}_NOT_ALIVE` };
    }

    const launcherSnap = getProcessSnapshot(launcherPid);
    if (!launcherSnap) {
      return { success: false, error: `TICKET_ISSUANCE_DENIED: CANNOT_READ_LAUNCHER_SNAPSHOT_${launcherPid}` };
    }

    // 3. FACTOR 3: Never-Kill Verification on Launcher
    const nk = isNeverKill(launcherSnap);
    if (nk.neverKill) {
      return { success: false, error: `TICKET_ISSUANCE_DENIED: LAUNCHER_IS_NEVER_KILL: ${nk.reason}` };
    }

    // 4. FACTOR 4: Session Hierarchy & PID Reuse Verification
    const isRegistered = this.trustedLaunchers.has(launcherPid);
    if (isRegistered) {
      const trustedRecord = this.trustedLaunchers.get(launcherPid);
      if (trustedRecord && trustedRecord.lstart && trustedRecord.lstart.trim() !== launcherSnap.lstart.trim()) {
        return {
          success: false,
          error: `TICKET_ISSUANCE_DENIED: LAUNCHER_PID_${launcherPid}_RECYCLED (registered lstart "${trustedRecord.lstart}" != live "${launcherSnap.lstart}")`
        };
      }
    }
    const isRoot = (launcherPid === this.rootPid);
    if (!isRegistered && !isRoot) {
      const ancestry = getProcessAncestry(launcherPid);
      if (!ancestry.includes(this.rootPid)) {
        return {
          success: false,
          error: `TICKET_ISSUANCE_DENIED: LAUNCHER_${launcherPid}_NOT_IN_SESSION_TREE (Ancestry: ${ancestry.join(' -> ')} missing root ${this.rootPid})`
        };
      }
    }

    const ticketId = `tkt-${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
    const nonce = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + (params.ttlMs || BROKER_CONFIG.ticketTtlMs);

    const ticket = {
      ticketId,
      nonce,
      sessionId: this.sessionId,
      launcherPid,
      launcherLstart: launcherSnap.lstart,
      launcherExecutable: launcherSnap.canonicalExecutable,
      role: params.role || 'spawned-child',
      expectedPid: (typeof params.expectedPid === 'number' && params.expectedPid > 0) ? params.expectedPid : null,
      expectedExecutable: params.expectedExecutable || null,
      expectedCommandFingerprint: params.expectedCommandFingerprint || null,
      createdAt: Date.now(),
      expiresAt,
      maxUses: 1,
      useCount: 0,
      consumed: false,
      boundPid: null
    };

    this.launchTickets.set(ticketId, ticket);

    return {
      success: true,
      ticketId,
      launchNonce: nonce,
      expiresAt
    };
  }

  /**
   * Step 2 of Pre-Authorization: Launcher submits child PID + Ticket for verification.
   *
   * @param {Object} params - { ticketId, pid, safeToKill, sessionId }
   * @returns {Object}
   */
  attestSpawn(params) {
    const { ticketId, pid } = params;
    if (!ticketId || !this.launchTickets.has(ticketId)) {
      return { success: false, error: 'INVALID_OR_MISSING_LAUNCH_TICKET' };
    }

    const ticket = this.launchTickets.get(ticketId);

    // One-time ticket enforcement (Replay Defense)
    if (ticket.consumed || ticket.useCount >= ticket.maxUses) {
      return { success: false, error: 'REJECTED_TICKET_ALREADY_USED' };
    }

    // Check TTL (Expiry Defense)
    if (Date.now() > ticket.expiresAt) {
      return { success: false, error: 'LAUNCH_TICKET_EXPIRED' };
    }

    // Check Session Binding
    const reqSessionId = params.sessionId || ticket.sessionId;
    if (ticket.sessionId !== this.sessionId || reqSessionId !== this.sessionId) {
      return { success: false, error: 'CROSS_SESSION_TICKET_REJECTED' };
    }

    // Inspect live child process
    if (typeof pid !== 'number' || pid <= 0) {
      return { success: false, error: 'INVALID_TARGET_PID' };
    }

    // Expected PID Binding check (Different PID Defense)
    if (ticket.expectedPid && ticket.expectedPid !== pid) {
      return {
        success: false,
        error: `PID_MISMATCH: Ticket was issued for PID ${ticket.expectedPid}, attempted for PID ${pid}`
      };
    }

    const snapshot = getProcessSnapshot(pid);
    if (!snapshot) {
      return { success: false, error: `TARGET_PID_${pid}_NOT_RUNNING_AT_ATTESTATION` };
    }

    // STRICT ANCESTRY CHECK: Child PPID MUST match ticket.launcherPid (Launcher Binding)
    if (snapshot.ppid !== ticket.launcherPid) {
      return {
        success: false,
        error: `ANCESTRY_MISMATCH: Target PPID (${snapshot.ppid}) != Launcher PID (${ticket.launcherPid})`
      };
    }

    // Launcher identity & reuse check: Ensure launcher hasn't been recycled
    const launcherSnap = getProcessSnapshot(ticket.launcherPid);
    if (!launcherSnap || launcherSnap.lstart !== ticket.launcherLstart) {
      return {
        success: false,
        error: 'LAUNCHER_IDENTITY_INVALIDATED_OR_RECYCLED'
      };
    }

    // Check Never-Kill policy on child
    const neverKill = isNeverKill(snapshot);
    if (neverKill.neverKill) {
      return {
        success: false,
        error: `TARGET_IS_NEVER_KILL: ${neverKill.reason} (${neverKill.category})`
      };
    }

    // Executable match check if specified (Exact path or exact basename, NEVER loose substring)
    if (ticket.expectedExecutable) {
      const isExactPath = (snapshot.canonicalExecutable === ticket.expectedExecutable);
      const isExactBasename = (!ticket.expectedExecutable.includes('/') && path.basename(snapshot.canonicalExecutable) === ticket.expectedExecutable);
      if (!isExactPath && !isExactBasename) {
        return {
          success: false,
          error: `EXECUTABLE_MISMATCH: Expected "${ticket.expectedExecutable}", got "${snapshot.canonicalExecutable}"`
        };
      }
    }

    // Command fingerprint match check if specified
    if (ticket.expectedCommandFingerprint && snapshot.commandFingerprint !== ticket.expectedCommandFingerprint) {
      return {
        success: false,
        error: `COMMAND_FINGERPRINT_MISMATCH: Expected "${ticket.expectedCommandFingerprint}", got "${snapshot.commandFingerprint}"`
      };
    }

    // MARK TICKET CONSUMED (Single-use enforcement)
    ticket.consumed = true;
    ticket.useCount++;
    ticket.boundPid = pid;

    // Compute in-memory HMAC using the pure memory secret
    const payload = `${pid}:${snapshot.lstart}:${snapshot.canonicalExecutable}:${REGISTRATION_SOURCES.SPAWN_ATTESTED}:${ticket.nonce}`;
    const attestationSig = computeAttestationSig(this.sessionSecret, payload);

    const isSafe = (params.safeToKill !== false) && !neverKill.neverKill;

    const record = {
      pid,
      ppid: snapshot.ppid,
      pgid: snapshot.pgid,
      launcher_pid: ticket.launcherPid,
      executable: snapshot.canonicalExecutable,
      comm: snapshot.comm,
      command: snapshot.command,
      command_fingerprint: snapshot.commandFingerprint,
      lstart: snapshot.lstart,
      start_time_epoch_ms: snapshot.startTimeEpochMs,
      registered_at: new Date().toISOString(),
      session_id: this.sessionId,
      registration_source: REGISTRATION_SOURCES.SPAWN_ATTESTED,
      ownership: 'OWNED_CONFIRMED',
      launch_nonce: ticket.nonce,
      attestation_sig: attestationSig, // stored in broker memory
      role: ticket.role,
      safe_to_kill: isSafe,
      never_kill_reason: neverKill.neverKill ? neverKill.reason : null
    };

    // Store in Broker memory table
    this.attestedProcesses.set(pid, record);

    // Write sanitized audit log to disk (exclude secret, keep metadata)
    this.writeProcessAuditRecord(record);

    this.appendLog({
      action: 'SPAWN_ATTESTED_CONFIRMED',
      pid,
      launcher_pid: ticket.launcherPid,
      role: ticket.role,
      safe_to_kill: isSafe
    });

    return {
      success: true,
      record: {
        ...record,
        attestation_sig: '[IN_MEMORY_VERIFIED]'
      }
    };
  }

  /**
   * Attests a child helper process of a verified Playwright browser main process.
   * Requires:
   * 1. Valid launcherCapabilityToken
   * 2. parentBrowserPid must exist in this.attestedProcesses with role 'playwright-browser-main'
   * 3. helperPid must be alive and an OS descendant of parentBrowserPid
   * 4. Helper process must not be Never-Kill
   *
   * @param {Object} params - { launcherCapabilityToken, parentBrowserPid, helperPid, role }
   * @returns {Object}
   */
  attestPlaywrightHelper(params) {
    const { launcherCapabilityToken, parentBrowserPid, helperPid, role } = params || {};

    // 1. Verify capability token
    if (!launcherCapabilityToken || typeof launcherCapabilityToken !== 'string') {
      return { success: false, error: 'ATTEST_HELPER_DENIED: MISSING_LAUNCHER_CAPABILITY' };
    }
    const expectedBuf = Buffer.from(this.launcherCapabilityToken);
    const actualBuf = Buffer.from(launcherCapabilityToken);
    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
      return { success: false, error: 'ATTEST_HELPER_DENIED: INVALID_LAUNCHER_CAPABILITY' };
    }

    // 2. Verify parent browser process
    if (typeof parentBrowserPid !== 'number' || !this.attestedProcesses.has(parentBrowserPid)) {
      return { success: false, error: `ATTEST_HELPER_DENIED: PARENT_BROWSER_${parentBrowserPid}_NOT_ATTESTED` };
    }
    const parentRecord = this.attestedProcesses.get(parentBrowserPid);
    if (parentRecord.role !== ROLES.PLAYWRIGHT_BROWSER_MAIN) {
      return { success: false, error: `ATTEST_HELPER_DENIED: PARENT_${parentBrowserPid}_NOT_PLAYWRIGHT_MAIN` };
    }

    // 3. Verify helper PID
    if (typeof helperPid !== 'number' || helperPid <= 0) {
      return { success: false, error: 'ATTEST_HELPER_DENIED: INVALID_HELPER_PID' };
    }
    if (!checkProcessAlive(helperPid)) {
      return { success: false, error: `ATTEST_HELPER_DENIED: HELPER_PID_${helperPid}_NOT_ALIVE` };
    }
    const helperSnap = getProcessSnapshot(helperPid);
    if (!helperSnap) {
      return { success: false, error: `ATTEST_HELPER_DENIED: CANNOT_SNAPSHOT_HELPER_${helperPid}` };
    }

    // 4. Ancestry check: Helper PPID must match parent browser PID or be in its tree
    if (helperSnap.ppid !== parentBrowserPid) {
      const helperAncestry = getProcessAncestry(helperPid);
      if (!helperAncestry.includes(parentBrowserPid)) {
        return {
          success: false,
          error: `ATTEST_HELPER_DENIED: HELPER_${helperPid}_NOT_CHILD_OF_PARENT_${parentBrowserPid}`
        };
      }
    }

    // 5. Never-Kill verification
    const nk = isNeverKill(helperSnap);
    if (nk.neverKill) {
      return { success: false, error: `ATTEST_HELPER_DENIED: HELPER_IS_NEVER_KILL: ${nk.reason}` };
    }

    const payload = `${helperPid}:${helperSnap.lstart}:${helperSnap.canonicalExecutable}:${REGISTRATION_SOURCES.PLAYWRIGHT_ATTESTED}:${parentRecord.launch_nonce}`;
    const attestationSig = computeAttestationSig(this.sessionSecret, payload);

    const helperRecord = {
      pid: helperPid,
      ppid: helperSnap.ppid,
      pgid: helperSnap.pgid,
      parent_browser_pid: parentBrowserPid,
      launcher_pid: parentRecord.launcher_pid,
      executable: helperSnap.canonicalExecutable,
      comm: helperSnap.comm,
      command: helperSnap.command,
      command_fingerprint: helperSnap.commandFingerprint,
      lstart: helperSnap.lstart,
      start_time_epoch_ms: helperSnap.startTimeEpochMs,
      registered_at: new Date().toISOString(),
      session_id: this.sessionId,
      registration_source: REGISTRATION_SOURCES.PLAYWRIGHT_ATTESTED,
      ownership: 'OWNED_CONFIRMED',
      role: role || ROLES.PLAYWRIGHT_HELPER,
      safe_to_kill: true,
      attestation_sig: attestationSig
    };

    this.attestedProcesses.set(helperPid, helperRecord);
    this.writeProcessAuditRecord(helperRecord);

    this.appendLog({
      action: 'PLAYWRIGHT_HELPER_ATTESTED',
      pid: helperPid,
      parent_browser_pid: parentBrowserPid,
      role: helperRecord.role
    });

    return {
      success: true,
      record: {
        ...helperRecord,
        attestation_sig: '[IN_MEMORY_VERIFIED]'
      }
    };
  }

  /**
   * Attests a complete newly created ZCode CUA process chain (bridge, runner, helper, mcp).
   * Enforces:
   * 1. Valid launcherCapabilityToken.
   * 2. bridgePid: alive, non-Never-Kill, non-baseline, descended from session root or trusted launcher.
   * 3. runnerPid: (if present) alive, non-Never-Kill, non-baseline, child/descendant of bridgePid.
   * 4. helperPid: (if present) alive, non-Never-Kill, non-baseline, launcherPid matches runner or bridge, has --launcher-pid/--socket flags.
   * 5. mcpPid: (if present) alive, non-Never-Kill, non-baseline, descendant of runner/bridge.
   * 6. Sockets and tokens: recorded in resources with status WOULD_DELETE_IN_S4_5.
   * 7. Signs and registers each PID in this.attestedProcesses with role and HMAC.
   *
   * @param {Object} params
   * @returns {Object}
   */
  attestZCodeChain(params) {
    const {
      launcherCapabilityToken,
      bridgePid,
      runnerPid,
      helperPid,
      mcpPid,
      socketPath,
      tokenPath,
      baselinePids = []
    } = params || {};

    // 1. Verify capability token
    if (!launcherCapabilityToken || typeof launcherCapabilityToken !== 'string') {
      return { success: false, error: 'ATTEST_ZCODE_CHAIN_DENIED: MISSING_LAUNCHER_CAPABILITY' };
    }
    const expectedBuf = Buffer.from(this.launcherCapabilityToken);
    const actualBuf = Buffer.from(launcherCapabilityToken);
    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
      return { success: false, error: 'ATTEST_ZCODE_CHAIN_DENIED: INVALID_LAUNCHER_CAPABILITY' };
    }

    const baselineSet = new Set(baselinePids);

    // 2. Validate bridgePid
    if (typeof bridgePid !== 'number' || bridgePid <= 0) {
      return { success: false, error: 'ATTEST_ZCODE_CHAIN_DENIED: INVALID_BRIDGE_PID' };
    }
    if (baselineSet.has(bridgePid)) {
      return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: BRIDGE_PID_${bridgePid}_IS_BASELINE_PROCESS` };
    }
    if (!checkProcessAlive(bridgePid)) {
      return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: BRIDGE_PID_${bridgePid}_NOT_ALIVE` };
    }
    const bridgeSnap = getProcessSnapshot(bridgePid);
    if (!bridgeSnap) {
      return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: CANNOT_SNAPSHOT_BRIDGE_${bridgePid}` };
    }
    const bridgeNk = isNeverKill(bridgeSnap);
    if (bridgeNk.neverKill) {
      return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: BRIDGE_IS_NEVER_KILL: ${bridgeNk.reason}` };
    }
    if (bridgePid !== this.rootPid) {
      const ancestry = getProcessAncestry(bridgePid);
      if (!ancestry.includes(this.rootPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: BRIDGE_${bridgePid}_NOT_IN_SESSION_TREE` };
      }
    }

    const registeredRecords = {};
    const chainNonce = crypto.randomBytes(16).toString('hex');

    // Register bridge
    const bridgePayload = `${bridgePid}:${bridgeSnap.lstart}:${bridgeSnap.canonicalExecutable}:${REGISTRATION_SOURCES.BRIDGE_ATTESTED}:${chainNonce}`;
    const bridgeSig = computeAttestationSig(this.sessionSecret, bridgePayload);
    const bridgeRecord = {
      pid: bridgePid,
      ppid: bridgeSnap.ppid,
      pgid: bridgeSnap.pgid,
      launcher_pid: bridgeSnap.ppid,
      executable: bridgeSnap.canonicalExecutable,
      comm: bridgeSnap.comm,
      command: bridgeSnap.command,
      command_fingerprint: bridgeSnap.commandFingerprint,
      lstart: bridgeSnap.lstart,
      start_time_epoch_ms: bridgeSnap.startTimeEpochMs,
      registered_at: new Date().toISOString(),
      session_id: this.sessionId,
      registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
      ownership: 'OWNED_CONFIRMED',
      role: ROLES.ZCODE_BRIDGE,
      safe_to_kill: true,
      launch_nonce: chainNonce,
      attestation_sig: bridgeSig
    };
    this.attestedProcesses.set(bridgePid, bridgeRecord);
    this.writeProcessAuditRecord(bridgeRecord);
    registeredRecords.bridge = bridgeRecord;

    // 3. Validate runnerPid if provided
    let verifiedRunnerPid = null;
    if (runnerPid) {
      if (typeof runnerPid !== 'number' || runnerPid <= 0) {
        return { success: false, error: 'ATTEST_ZCODE_CHAIN_DENIED: INVALID_RUNNER_PID' };
      }
      if (baselineSet.has(runnerPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: RUNNER_PID_${runnerPid}_IS_BASELINE_PROCESS` };
      }
      if (!checkProcessAlive(runnerPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: RUNNER_PID_${runnerPid}_NOT_ALIVE` };
      }
      const runnerSnap = getProcessSnapshot(runnerPid);
      if (!runnerSnap) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: CANNOT_SNAPSHOT_RUNNER_${runnerPid}` };
      }
      const runnerNk = isNeverKill(runnerSnap);
      if (runnerNk.neverKill) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: RUNNER_IS_NEVER_KILL: ${runnerNk.reason}` };
      }
      // Ancestry: runner must be child or descendant of bridgePid
      if (runnerSnap.ppid !== bridgePid && !getProcessAncestry(runnerPid).includes(bridgePid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: RUNNER_${runnerPid}_NOT_CHILD_OF_BRIDGE_${bridgePid}` };
      }
      const runnerPayload = `${runnerPid}:${runnerSnap.lstart}:${runnerSnap.canonicalExecutable}:${REGISTRATION_SOURCES.BRIDGE_ATTESTED}:${chainNonce}`;
      const runnerSig = computeAttestationSig(this.sessionSecret, runnerPayload);
      const runnerRecord = {
        pid: runnerPid,
        ppid: runnerSnap.ppid,
        pgid: runnerSnap.pgid,
        launcher_pid: bridgePid,
        executable: runnerSnap.canonicalExecutable,
        comm: runnerSnap.comm,
        command: runnerSnap.command,
        command_fingerprint: runnerSnap.commandFingerprint,
        lstart: runnerSnap.lstart,
        start_time_epoch_ms: runnerSnap.startTimeEpochMs,
        registered_at: new Date().toISOString(),
        session_id: this.sessionId,
        registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
        ownership: 'OWNED_CONFIRMED',
        role: ROLES.ZCODE_RUNNER,
        safe_to_kill: true,
        launch_nonce: chainNonce,
        attestation_sig: runnerSig
      };
      this.attestedProcesses.set(runnerPid, runnerRecord);
      this.writeProcessAuditRecord(runnerRecord);
      registeredRecords.runner = runnerRecord;
      verifiedRunnerPid = runnerPid;
    }

    // 4. Validate helperPid if provided
    if (helperPid) {
      if (typeof helperPid !== 'number' || helperPid <= 0) {
        return { success: false, error: 'ATTEST_ZCODE_CHAIN_DENIED: INVALID_HELPER_PID' };
      }
      if (baselineSet.has(helperPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: HELPER_PID_${helperPid}_IS_BASELINE_PROCESS` };
      }
      if (!checkProcessAlive(helperPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: HELPER_PID_${helperPid}_NOT_ALIVE` };
      }
      const helperSnap = getProcessSnapshot(helperPid);
      if (!helperSnap) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: CANNOT_SNAPSHOT_HELPER_${helperPid}` };
      }
      const helperNk = isNeverKill(helperSnap);
      if (helperNk.neverKill) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: HELPER_IS_NEVER_KILL: ${helperNk.reason}` };
      }

      // Check launcher relationship: PPID or --launcher-pid must match runner or bridge
      const expectedLauncherPid = verifiedRunnerPid || bridgePid;
      const hasLauncherFlag = helperSnap.command.includes(`--launcher-pid ${expectedLauncherPid}`) ||
                              helperSnap.command.includes(`--launcher-pid ${bridgePid}`) ||
                              (verifiedRunnerPid && helperSnap.command.includes(`--launcher-pid ${verifiedRunnerPid}`));
      const isDirectChild = helperSnap.ppid === expectedLauncherPid || helperSnap.ppid === bridgePid;

      if (!hasLauncherFlag && !isDirectChild) {
        return {
          success: false,
          error: `ATTEST_ZCODE_CHAIN_DENIED: HELPER_${helperPid}_NOT_LAUNCHED_BY_RUNNER_OR_BRIDGE`
        };
      }

      const helperPayload = `${helperPid}:${helperSnap.lstart}:${helperSnap.canonicalExecutable}:${REGISTRATION_SOURCES.BRIDGE_ATTESTED}:${chainNonce}`;
      const helperSig = computeAttestationSig(this.sessionSecret, helperPayload);
      const helperRecord = {
        pid: helperPid,
        ppid: helperSnap.ppid,
        pgid: helperSnap.pgid,
        launcher_pid: expectedLauncherPid,
        executable: helperSnap.canonicalExecutable,
        comm: helperSnap.comm,
        command: helperSnap.command,
        command_fingerprint: helperSnap.commandFingerprint,
        lstart: helperSnap.lstart,
        start_time_epoch_ms: helperSnap.startTimeEpochMs,
        registered_at: new Date().toISOString(),
        session_id: this.sessionId,
        registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
        ownership: 'OWNED_CONFIRMED',
        role: ROLES.ZCODE_HELPER,
        safe_to_kill: true,
        launch_nonce: chainNonce,
        attestation_sig: helperSig,
        socketPath: socketPath || null,
        tokenPath: tokenPath || null
      };
      this.attestedProcesses.set(helperPid, helperRecord);
      this.writeProcessAuditRecord(helperRecord);
      registeredRecords.helper = helperRecord;
    }

    // 5. Validate mcpPid if provided
    if (mcpPid) {
      if (typeof mcpPid !== 'number' || mcpPid <= 0) {
        return { success: false, error: 'ATTEST_ZCODE_CHAIN_DENIED: INVALID_MCP_PID' };
      }
      if (baselineSet.has(mcpPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: MCP_PID_${mcpPid}_IS_BASELINE_PROCESS` };
      }
      if (!checkProcessAlive(mcpPid)) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: MCP_PID_${mcpPid}_NOT_ALIVE` };
      }
      const mcpSnap = getProcessSnapshot(mcpPid);
      if (!mcpSnap) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: CANNOT_SNAPSHOT_MCP_${mcpPid}` };
      }
      const mcpNk = isNeverKill(mcpSnap);
      if (mcpNk.neverKill) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: MCP_IS_NEVER_KILL: ${mcpNk.reason}` };
      }
      const expectedLauncherPid = verifiedRunnerPid || bridgePid;
      const isDescendant = mcpSnap.ppid === expectedLauncherPid || getProcessAncestry(mcpPid).includes(bridgePid);
      if (!isDescendant) {
        return { success: false, error: `ATTEST_ZCODE_CHAIN_DENIED: MCP_${mcpPid}_NOT_DESCENDANT_OF_BRIDGE` };
      }
      const mcpPayload = `${mcpPid}:${mcpSnap.lstart}:${mcpSnap.canonicalExecutable}:${REGISTRATION_SOURCES.BRIDGE_ATTESTED}:${chainNonce}`;
      const mcpSig = computeAttestationSig(this.sessionSecret, mcpPayload);
      const mcpRecord = {
        pid: mcpPid,
        ppid: mcpSnap.ppid,
        pgid: mcpSnap.pgid,
        launcher_pid: expectedLauncherPid,
        executable: mcpSnap.canonicalExecutable,
        comm: mcpSnap.comm,
        command: mcpSnap.command,
        command_fingerprint: mcpSnap.commandFingerprint,
        lstart: mcpSnap.lstart,
        start_time_epoch_ms: mcpSnap.startTimeEpochMs,
        registered_at: new Date().toISOString(),
        session_id: this.sessionId,
        registration_source: REGISTRATION_SOURCES.BRIDGE_ATTESTED,
        ownership: 'OWNED_CONFIRMED',
        role: ROLES.ZCODE_MCP_SERVER,
        safe_to_kill: true,
        launch_nonce: chainNonce,
        attestation_sig: mcpSig
      };
      this.attestedProcesses.set(mcpPid, mcpRecord);
      this.writeProcessAuditRecord(mcpRecord);
      registeredRecords.mcp = mcpRecord;
    }

    // 6. Register resources (socket and token) if provided
    if (socketPath && isApprovedTempPath(socketPath)) {
      const sockReceipt = this.attestZCodeResource({
        targetPath: socketPath,
        resourceRole: RESOURCE_ROLES.ZCODE_TEST_SOCKET,
        owningHelperPid: helperPid || null,
        owningRunnerPid: verifiedRunnerPid || null,
        owningBridgePid: bridgePid,
        chainNonce
      });
      if (sockReceipt.success) {
        registeredRecords.socket = sockReceipt.receipt;
      }
    }
    if (tokenPath && isApprovedTempPath(tokenPath)) {
      const tokReceipt = this.attestZCodeResource({
        targetPath: tokenPath,
        resourceRole: RESOURCE_ROLES.ZCODE_TEST_TOKEN,
        owningHelperPid: helperPid || null,
        owningRunnerPid: verifiedRunnerPid || null,
        owningBridgePid: bridgePid,
        chainNonce
      });
      if (tokReceipt.success) {
        registeredRecords.token = tokReceipt.receipt;
      }
    }

    this.appendLog({
      action: 'ZCODE_CHAIN_ATTESTED',
      bridgePid,
      runnerPid: verifiedRunnerPid,
      helperPid: helperPid || null,
      mcpPid: mcpPid || null,
      socketPath: socketPath || null,
      tokenPath: tokenPath || null
    });

    return {
      success: true,
      records: registeredRecords
    };
  }

  /**
   * Registers a prospective resource with Session Nonce and Dev/Ino binding.
   *
   * @param {Object} params - { path, type, owningPid }
   * @returns {Object}
   */
  registerResourceIntent(params) {
    if (!params || !params.path || typeof params.path !== 'string') {
      return { success: false, error: 'INVALID_RESOURCE_PATH' };
    }

    const resolvedPath = path.resolve(params.path);

    if (!isApprovedTempPath(resolvedPath)) {
      return { success: false, error: 'RESOURCE_PATH_OUTSIDE_APPROVED_TEMP_DIRS' };
    }

    // Enforce session nonce in resource path for strong isolation
    if (!resolvedPath.includes(this.sessionNonce) && !resolvedPath.includes(this.sessionId)) {
      return {
        success: false,
        error: `RESOURCE_PATH_LACKS_SESSION_NONCE: Path must contain session nonce "${this.sessionNonce}"`
      };
    }

    let dev = null;
    let ino = null;
    if (fs.existsSync(resolvedPath)) {
      try {
        const lstat = fs.lstatSync(resolvedPath);
        if (lstat.isSymbolicLink()) {
          return { success: false, error: 'SYMLINK_RESOURCES_FORBIDDEN' };
        }
        dev = lstat.dev;
        ino = lstat.ino;
      } catch (err) {
        return { success: false, error: `STAT_ERROR: ${err.message}` };
      }
    }

    const resRecord = {
      id: `res-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      type: params.type || 'unix_socket',
      path: resolvedPath,
      owning_pid: typeof params.owningPid === 'number' ? params.owningPid : null,
      session_id: this.sessionId,
      session_nonce: this.sessionNonce,
      dev,
      ino,
      registered_at: new Date().toISOString()
    };

    this.attestedResources.set(resolvedPath, resRecord);
    this.writeResourceAuditRecord(resRecord);

    return { success: true, record: resRecord };
  }

  /**
   * Safely creates and cryptographically/structurally attests a disposable test resource.
   * Only allowed inside ~/.gemini/antigravity/runtime/sessions/<sessionId>/resources/.
   *
   * @param {Object} params - { subPath, content, isDirectory, resourceRole, creatorPid, owningPid, childReceipts }
   * @returns {Object}
   */
  createTestResource(params) {
    const {
      subPath,
      content = '',
      isDirectory = false,
      resourceRole = RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
      creatorPid = process.pid,
      owningPid = null,
      childReceipts = null
    } = params || {};

    if (!subPath || typeof subPath !== 'string') {
      return { success: false, error: 'INVALID_RESOURCE_SUBPATH' };
    }

    const resourcesRoot = path.join(this.sessionDir, 'resources');
    if (!fs.existsSync(resourcesRoot)) {
      fs.mkdirSync(resourcesRoot, { recursive: true, mode: 0o700 });
    }

    const targetPath = path.resolve(resourcesRoot, subPath);

    // Structural safety boundary check
    const safety = validateResourcePathSafety(targetPath, this.sessionId);
    if (!safety.safe) {
      return { success: false, status: safety.status, error: safety.reason };
    }

    // Ensure parent directory exists
    const parentDir = path.dirname(targetPath);
    if (!fs.existsSync(parentDir)) {
      fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
    }

    if (isDirectory) {
      if (!fs.existsSync(targetPath)) {
        fs.mkdirSync(targetPath, { recursive: true, mode: 0o700 });
      }
    } else {
      fs.writeFileSync(targetPath, content, 'utf8');
    }

    const realpath = fs.realpathSync(targetPath);
    const lstat = fs.lstatSync(realpath);
    const parentRealpath = fs.realpathSync(path.dirname(realpath));

    const resourceId = `res-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const creationNonce = crypto.randomBytes(16).toString('hex');
    const creatorSnapshot = creatorPid ? getProcessSnapshot(creatorPid) : null;

    const receipt = {
      resourceId,
      sessionId: this.sessionId,
      creatorPid,
      creatorStartIdentity: creatorSnapshot ? creatorSnapshot.lstart : null,
      resourceRole,
      creationSource: 'SUPERVISOR_CREATED',
      originalPath: targetPath,
      realpath,
      parentRealpath,
      device: lstat.dev,
      inode: lstat.ino,
      mode: lstat.mode,
      type: isDirectory ? 'directory' : 'file',
      createdAt: new Date().toISOString(),
      creationNonce,
      owningPid,
      childReceipts: childReceipts || (isDirectory ? new Map() : null)
    };

    this.attestedResourceReceipts.set(realpath, receipt);
    this.attestedResources.set(realpath, {
      id: resourceId,
      type: isDirectory ? 'directory' : 'file',
      path: realpath,
      owning_pid: owningPid,
      session_id: this.sessionId,
      session_nonce: this.sessionNonce,
      dev: lstat.dev,
      ino: lstat.ino,
      registered_at: receipt.createdAt
    });

    this.writeResourceAuditRecord(receipt);

    this.appendLog({
      action: 'RESOURCE_CREATED_ATTESTED',
      resourceId,
      realpath,
      role: resourceRole,
      type: receipt.type
    });

    return { success: true, receipt };
  }

  /**
   * Attests an externally-created resource within the session resources root
   * (e.g., Playwright test browser profile) with full creation receipt.
   *
   * @param {Object} params - { targetPath, resourceRole, creatorPid, creationSource, owningPid, childReceipts }
   * @returns {Object}
   */
  attestResourceReceipt(params) {
    const {
      targetPath,
      resourceRole = RESOURCE_ROLES.PLAYWRIGHT_TEST_PROFILE,
      creatorPid = process.pid,
      creationSource = 'PLAYWRIGHT_TEST_CREATED',
      owningPid = null,
      childReceipts = null
    } = params || {};

    if (!targetPath || typeof targetPath !== 'string') {
      return { success: false, error: 'INVALID_RESOURCE_PATH' };
    }

    if (!fs.existsSync(targetPath)) {
      return { success: false, error: 'TARGET_DOES_NOT_EXIST' };
    }

    const safety = validateResourcePathSafety(targetPath, this.sessionId);
    if (!safety.safe) {
      return { success: false, status: safety.status, error: safety.reason };
    }

    const realpath = fs.realpathSync(targetPath);
    const lstat = fs.lstatSync(realpath);
    const parentRealpath = fs.realpathSync(path.dirname(realpath));

    const resourceId = `res-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
    const creationNonce = crypto.randomBytes(16).toString('hex');
    const creatorSnapshot = creatorPid ? getProcessSnapshot(creatorPid) : null;

    const receipt = {
      resourceId,
      sessionId: this.sessionId,
      creatorPid,
      creatorStartIdentity: creatorSnapshot ? creatorSnapshot.lstart : null,
      resourceRole,
      creationSource,
      originalPath: targetPath,
      realpath,
      parentRealpath,
      device: lstat.dev,
      inode: lstat.ino,
      mode: lstat.mode,
      type: lstat.isDirectory() ? 'directory' : 'file',
      createdAt: new Date().toISOString(),
      creationNonce,
      owningPid,
      childReceipts: childReceipts || (lstat.isDirectory() ? new Map() : null)
    };

    this.attestedResourceReceipts.set(realpath, receipt);
    this.attestedResources.set(realpath, {
      id: resourceId,
      type: receipt.type,
      path: realpath,
      owning_pid: owningPid,
      session_id: this.sessionId,
      session_nonce: this.sessionNonce,
      dev: lstat.dev,
      ino: lstat.ino,
      registered_at: receipt.createdAt
    });

    this.writeResourceAuditRecord(receipt);

    this.appendLog({
      action: 'RESOURCE_RECEIPT_ATTESTED',
      resourceId,
      realpath,
      role: resourceRole,
      type: receipt.type
    });

    return { success: true, receipt };
  }

  /**
   * Dedicated S3 Resource Deletion Gateway.
   * Only callable in S3_TEST_RESOURCE_DELETE_MODE with verified in-memory receipt.
   *
   * @param {Object} params - { path, testExecutionMode, isDirectory }
   * @returns {Object}
   */
  deleteResourceS3(params) {
    const {
      path: targetPath,
      testExecutionMode = S3_RESOURCE_CONFIG.testExecutionMode,
      isDirectory = false
    } = params || {};

    if (testExecutionMode !== 'S3_TEST_RESOURCE_DELETE_MODE') {
      return {
        success: false,
        status: 'BLOCKED_EXECUTION_MODE',
        error: `Physical deletion only permitted in S3_TEST_RESOURCE_DELETE_MODE (got: ${testExecutionMode})`
      };
    }

    if (!targetPath) {
      return { success: false, error: 'MISSING_RESOURCE_PATH' };
    }

    const safety = validateResourcePathSafety(targetPath, this.sessionId);
    if (!safety.safe) {
      return { success: false, status: safety.status, error: safety.reason };
    }

    const realpath = safety.realpath;
    const receipt = this.attestedResourceReceipts.get(realpath);
    if (!receipt) {
      return {
        success: false,
        status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
        error: `Path "${realpath}" has no in-memory creation receipt in active Broker (Untrusted)`
      };
    }

    let result;
    if (receipt.type === 'directory' || isDirectory) {
      const entries = fs.existsSync(realpath) ? fs.readdirSync(realpath) : [];
      if (entries.length === 0) {
        result = deleteDisposableEmptyDirectory(receipt, this.sessionId, { testExecutionMode });
      } else {
        result = deleteDisposableDirectoryTree(receipt, this.sessionId, { testExecutionMode });
      }
    } else {
      result = deleteDisposableFile(receipt, this.sessionId, { testExecutionMode });
    }

    if (result.success) {
      this.attestedResourceReceipts.delete(realpath);
      this.appendLog({
        action: 'RESOURCE_DELETED_S3',
        resourceId: receipt.resourceId,
        realpath,
        status: result.status
      });
    }

    return result;
  }

  /**
   * Attests a ZCode ephemeral socket or token file with cryptographic signature,
   * dev/ino/uid binding, and owning process provenance.
   *
   * @param {Object} params - { targetPath, resourceRole, owningHelperPid, owningRunnerPid, owningBridgePid, chainNonce }
   * @returns {Object}
   */
  attestZCodeResource(params) {
    const {
      targetPath,
      resourceRole,
      owningHelperPid = null,
      owningRunnerPid = null,
      owningBridgePid = null,
      chainNonce = null
    } = params || {};

    if (!targetPath || typeof targetPath !== 'string') {
      return { success: false, error: 'INVALID_RESOURCE_PATH' };
    }

    const resolved = path.resolve(targetPath);
    let realpath = resolved;
    try {
      if (fs.existsSync(resolved)) realpath = fs.realpathSync(resolved);
    } catch (_) {}

    // Check if pre-existing baseline resource
    if (isBaselineZCodeResource(realpath)) {
      return {
        success: false,
        status: 'PRE_EXISTING_ZCODE_RESOURCE',
        error: `Resource ${realpath} is a baseline pre-existing resource. Cannot attest.`
      };
    }

    let lstat = null;
    if (fs.existsSync(realpath)) {
      try {
        lstat = fs.lstatSync(realpath);
      } catch (_) {}
    }

    const nonce = chainNonce || crypto.randomBytes(16).toString('hex');
    const resourceId = `res-zcode-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
    const dev = lstat ? lstat.dev : null;
    const ino = lstat ? lstat.ino : null;
    const uid = lstat ? lstat.uid : process.getuid();
    const mode = lstat ? lstat.mode : null;
    const type = lstat ? (lstat.isSocket() ? 'socket' : lstat.isDirectory() ? 'directory' : 'file') : (resourceRole?.includes('socket') ? 'socket' : 'file');

    const attestationPayload = `${realpath}:${dev}:${ino}:${uid}:${this.sessionId}:${nonce}`;
    const attestationSig = computeAttestationSig(this.sessionSecret, attestationPayload);

    const receipt = {
      resourceId,
      sessionId: this.sessionId,
      resourceRole: resourceRole || (type === 'socket' ? RESOURCE_ROLES.ZCODE_TEST_SOCKET : RESOURCE_ROLES.ZCODE_TEST_TOKEN),
      creationSource: 'ZCODE_TEST_CREATED',
      originalPath: targetPath,
      realpath,
      device: dev,
      inode: ino,
      uid,
      mode,
      type,
      owningHelperPid,
      owningRunnerPid,
      owningBridgePid,
      createdAt: new Date().toISOString(),
      creationNonce: nonce,
      attestationPayload,
      attestation_sig: attestationSig
    };

    this.attestedResourceReceipts.set(realpath, receipt);
    this.attestedResourceReceipts.set(resolved, receipt);
    this.attestedResources.set(realpath, {
      id: resourceId,
      type,
      path: realpath,
      session_id: this.sessionId,
      session_nonce: this.sessionNonce,
      dev,
      ino,
      registered_at: receipt.createdAt
    });

    this.writeResourceAuditRecord(receipt);

    this.appendLog({
      action: 'ZCODE_RESOURCE_ATTESTED',
      resourceId,
      realpath,
      role: receipt.resourceRole,
      type
    });

    return { success: true, receipt };
  }

  /**
   * Dedicated S4.5 ZCode Resource Deletion Gateway.
   * Only callable in S4_5_ZCODE_RESOURCE_TEST_ONLY with verified in-memory receipt.
   *
   * @param {Object} params - { path, testExecutionMode }
   * @returns {Object}
   */
  deleteZCodeResourceS4_5(params) {
    const {
      path: targetPath,
      testExecutionMode = S4_5_RESOURCE_CONFIG.testExecutionMode
    } = params || {};

    if (testExecutionMode !== S4_5_RESOURCE_CONFIG.testExecutionMode) {
      return {
        success: false,
        status: 'BLOCKED_EXECUTION_MODE',
        error: `Physical deletion only permitted in ${S4_5_RESOURCE_CONFIG.testExecutionMode} (got: ${testExecutionMode})`
      };
    }

    if (!targetPath) {
      return { success: false, error: 'MISSING_RESOURCE_PATH' };
    }

    const resolved = path.resolve(targetPath);
    let realpath = resolved;
    try {
      if (fs.existsSync(resolved)) {
        realpath = fs.realpathSync(resolved);
      } else {
        const parentDir = path.dirname(resolved);
        if (fs.existsSync(parentDir)) {
          realpath = path.join(fs.realpathSync(parentDir), path.basename(resolved));
        }
      }
    } catch (_) {}

    const receipt = this.attestedResourceReceipts.get(realpath) || this.attestedResourceReceipts.get(resolved);
    if (!receipt) {
      if (this.retiredResources.has(realpath) || this.retiredResources.has(resolved)) {
        return {
          success: true,
          status: 'NOOP_ALREADY_CLEAN',
          noop: true,
          alreadyClean: true,
          unlinked: false,
          reason: 'Resource was already cleaned and retired in active Broker'
        };
      }
      return {
        success: false,
        status: 'BLOCKED_NO_BROKER_RESOURCE_ATTESTATION',
        error: `Path "${targetPath}" has no in-memory creation receipt in active Broker (Untrusted)`
      };
    }

    let result;
    if (receipt.resourceRole === RESOURCE_ROLES.ZCODE_TEST_SOCKET || receipt.resourceRole === RESOURCE_ROLES.TEST_SOCKET || receipt.type === 'socket') {
      result = deleteZCodeSocketS4_5(receipt, this.sessionId, {
        broker: this,
        testExecutionMode
      });
    } else {
      result = deleteZCodeTokenS4_5(receipt, this.sessionId, {
        broker: this,
        testExecutionMode
      });
    }

    if (result.success) {
      this.retiredResources.set(realpath, {
        ...receipt,
        retiredAt: new Date().toISOString(),
        retirementStatus: result.status || 'DELETED_BY_SUPERVISOR'
      });
      this.retiredResources.set(resolved, {
        ...receipt,
        retiredAt: new Date().toISOString(),
        retirementStatus: result.status || 'DELETED_BY_SUPERVISOR'
      });
      this.attestedResourceReceipts.delete(realpath);
      this.attestedResourceReceipts.delete(resolved);
      this.attestedResources.delete(realpath);
      this.attestedResources.delete(resolved);
      this.appendLog({
        action: 'ZCODE_RESOURCE_DELETED_S4_5',
        resourceId: receipt.resourceId,
        realpath,
        status: result.status,
        attribution: result.attribution
      });
    }

    return result;
  }

  /**
   * Records normal owner-side cleanup of ZCode ephemeral socket or token file.
   *
   * @param {Object} params - { path }
   * @returns {Object}
   */
  recordOwnerCleanedS4_5(params) {
    const { path: targetPath } = params || {};
    if (!targetPath) return { success: false, error: 'MISSING_RESOURCE_PATH' };

    const resolved = path.resolve(targetPath);
    let realpath = resolved;
    try {
      if (fs.existsSync(resolved)) {
        realpath = fs.realpathSync(resolved);
      } else {
        const parentDir = path.dirname(resolved);
        if (fs.existsSync(parentDir)) {
          realpath = path.join(fs.realpathSync(parentDir), path.basename(resolved));
        }
      }
    } catch (_) {}

    const receipt = this.attestedResourceReceipts.get(realpath) || this.attestedResourceReceipts.get(resolved);
    if (!receipt) {
      if (this.retiredResources.has(realpath) || this.retiredResources.has(resolved)) {
        return {
          success: true,
          status: 'NOOP_ALREADY_CLEAN',
          noop: true,
          alreadyClean: true,
          reason: 'Resource was already cleaned and retired by owner in active Broker'
        };
      }
      return { success: false, status: 'NO_RECEIPT', error: 'No receipt found for owner cleanup' };
    }

    const result = recordOwnerCleanedResource(receipt, this.sessionId);
    this.retiredResources.set(realpath, {
      ...receipt,
      retiredAt: new Date().toISOString(),
      retirementStatus: 'OWNER_CLEANED_RESOURCES'
    });
    this.retiredResources.set(resolved, {
      ...receipt,
      retiredAt: new Date().toISOString(),
      retirementStatus: 'OWNER_CLEANED_RESOURCES'
    });
    this.attestedResourceReceipts.delete(realpath);
    this.attestedResourceReceipts.delete(resolved);
    this.attestedResources.delete(realpath);
    this.attestedResources.delete(resolved);
    this.appendLog({
      action: 'ZCODE_RESOURCE_CLEANED_BY_OWNER_S4_5',
      resourceId: receipt.resourceId,
      realpath,
      status: result.status,
      attribution: result.attribution
    });
    return result;
  }

  /**
   * Verifies an active process against Broker in-memory attestation and OS process tree.
   *
   * @param {number} pid
   * @returns {Object}
   */
  verifyProcess(pid) {
    if (typeof pid !== 'number' || pid <= 0) {
      return { canTerminate: false, status: 'REJECTED_INVALID_PID', reason: 'Invalid PID' };
    }

    const inMemoryRecord = this.attestedProcesses.get(pid);
    if (!inMemoryRecord) {
      return {
        canTerminate: false,
        status: 'BLOCKED_NO_BROKER_ATTESTATION',
        reason: `PID ${pid} was not attested by the active Session Broker (Untrusted)`
      };
    }

    if (!checkProcessAlive(pid)) {
      return {
        canTerminate: false,
        status: 'ALREADY_TERMINATED',
        reason: `Process PID ${pid} is no longer alive`
      };
    }

    const live = getProcessSnapshot(pid);
    if (!live) {
      return {
        canTerminate: false,
        status: 'ALREADY_TERMINATED',
        reason: `Cannot capture process snapshot for PID ${pid}`
      };
    }

    // Never-Kill semantic check
    const nk = isNeverKill(live);
    if (nk.neverKill) {
      return {
        canTerminate: false,
        status: 'BLOCKED_BY_NEVER_KILL_POLICY',
        reason: `Never-Kill policy: ${nk.reason}`
      };
    }

    // PID reuse check
    const timeDiff = Math.abs(live.startTimeEpochMs - (inMemoryRecord.start_time_epoch_ms || 0));
    if (timeDiff > 1000 && live.lstart.trim() !== inMemoryRecord.lstart.trim()) {
      return {
        canTerminate: false,
        status: 'REJECTED_PID_REUSE_DETECTED',
        reason: `Process start time mismatch (recorded: "${inMemoryRecord.lstart}", live: "${live.lstart}")`
      };
    }

    // Executable integrity check
    if (live.canonicalExecutable !== inMemoryRecord.executable && live.comm !== inMemoryRecord.comm) {
      return {
        canTerminate: false,
        status: 'REJECTED_EXECUTABLE_MISMATCH',
        reason: `Executable mismatch: "${live.canonicalExecutable}" vs recorded "${inMemoryRecord.executable}"`
      };
    }

    // REAL ANCESTRY TRAVERSAL (Actively called, no dead code!)
    const ancestry = getProcessAncestry(pid);
    let ancestryLinked = false;

    // Direct parent matches launcher or session root
    if (live.ppid === inMemoryRecord.launcher_pid || live.ppid === this.rootPid) {
      ancestryLinked = true;
    } else if (ancestry.includes(inMemoryRecord.launcher_pid) || ancestry.includes(this.rootPid)) {
      ancestryLinked = true;
    } else if (live.ppid === 1 && inMemoryRecord.ownership === 'OWNED_CONFIRMED') {
      // Reparented to launchd: acceptable ONLY because creation-time ticket attestation is held in memory
      ancestryLinked = true;
    }

    if (!ancestryLinked) {
      return {
        canTerminate: false,
        status: 'REJECTED_ANCESTRY_UNLINKED',
        reason: `Process ancestry chain (${ancestry.join(' -> ')}) does not link to Launcher (${inMemoryRecord.launcher_pid}) or Root (${this.rootPid})`
      };
    }

    // In-memory cryptographic HMAC verification
    const expectedPayload = `${pid}:${inMemoryRecord.lstart}:${inMemoryRecord.executable}:${inMemoryRecord.registration_source}:${inMemoryRecord.launch_nonce}`;
    const expectedSig = computeAttestationSig(this.sessionSecret, expectedPayload);

    if (inMemoryRecord.attestation_sig !== expectedSig) {
      return {
        canTerminate: false,
        status: 'REJECTED_SIGNATURE_MISMATCH',
        reason: 'In-memory HMAC attestation signature invalid'
      };
    }

    return {
      success: true,
      canTerminate: inMemoryRecord.safe_to_kill === true,
      status: inMemoryRecord.safe_to_kill ? 'CONFIRMED_OWNED_TERMINABLE' : 'BLOCKED_SAFE_TO_KILL_FALSE',
      reason: 'All 8 ownership provenance factors verified by Broker in-memory attestation',
      ancestry
    };
  }

  /**
   * Verifies an attested resource for safe orphan deletion.
   *
   * @param {string} resPath
   * @returns {Object}
   */
  verifyResource(resPath) {
    const resolvedPath = path.resolve(resPath);
    const inMemoryRes = this.attestedResources.get(resolvedPath);

    if (!inMemoryRes) {
      return {
        success: true,
        canDelete: false,
        status: 'UNTRUSTED_EXTERNAL_RESOURCE',
        reason: `Path "${resolvedPath}" was not registered via Broker with session nonce (Untrusted)`
      };
    }

    if (!fs.existsSync(resolvedPath)) {
      return { success: true, canDelete: false, status: 'ALREADY_REMOVED', reason: 'File does not exist' };
    }

    let lstat;
    try {
      lstat = fs.lstatSync(resolvedPath);
      if (lstat.isSymbolicLink()) {
        return {
          success: true,
          canDelete: false,
          status: 'BLOCKED_SYMLINK_NOT_PERMITTED',
          reason: 'Symlinks are forbidden from deletion'
        };
      }
    } catch (err) {
      return { success: true, canDelete: false, status: 'STAT_ERROR', reason: err.message };
    }

    // Inode check if captured at registration
    if (inMemoryRes.ino !== null && lstat.ino !== inMemoryRes.ino) {
      return {
        success: true,
        canDelete: false,
        status: 'REJECTED_INODE_MISMATCH',
        reason: `File inode changed (recorded: ${inMemoryRes.ino}, live: ${lstat.ino}). File was substituted.`
      };
    }

    // Check open handles with lsof
    const handles = getOpenHandles(resolvedPath);
    if (handles.length > 0) {
      return {
        success: true,
        canDelete: false,
        status: 'BLOCKED_RESOURCE_IN_USE',
        reason: `Resource is open by active PID(s): ${handles.join(', ')}`,
        activeHandles: handles
      };
    }

    // Check owner if specified
    if (typeof inMemoryRes.owning_pid === 'number' && checkProcessAlive(inMemoryRes.owning_pid)) {
      return {
        success: true,
        canDelete: false,
        status: 'BLOCKED_OWNER_STILL_ALIVE',
        reason: `Owning process PID ${inMemoryRes.owning_pid} is still running`
      };
    }

    return {
      success: true,
      canDelete: true,
      status: 'CONFIRMED_ORPHANED_DELETABLE',
      reason: 'Resource verified by Broker, owner terminated, no open handles'
    };
  }

  /**
   * Generates status summary.
   */
  getStatus() {
    return {
      sessionId: this.sessionId,
      sessionNonce: this.sessionNonce,
      brokerPid: process.pid,
      rootPid: this.rootPid,
      attestedProcessesCount: this.attestedProcesses.size,
      attestedResourcesCount: this.attestedResources.size,
      activeTicketsCount: this.launchTickets.size,
      status: this.status
    };
  }

  writeProcessAuditRecord(record) {
    const procFile = path.join(this.sessionDir, 'processes.json');
    let list = [];
    if (fs.existsSync(procFile)) {
      try {
        list = JSON.parse(fs.readFileSync(procFile, 'utf8'));
      } catch (_) {}
    }
    const auditRecord = { ...record };
    delete auditRecord.attestation_sig; // Do not leak in-memory sig or secret
    list = list.filter(p => p.pid !== record.pid);
    list.push(auditRecord);
    fs.writeFileSync(procFile, JSON.stringify(list, null, 2), 'utf8');
  }

  writeResourceAuditRecord(record) {
    const resFile = path.join(this.sessionDir, 'resources.json');
    let list = [];
    if (fs.existsSync(resFile)) {
      try {
        list = JSON.parse(fs.readFileSync(resFile, 'utf8'));
      } catch (_) {}
    }
    list = list.filter(r => r.path !== record.path);
    list.push(record);
    fs.writeFileSync(resFile, JSON.stringify(list, null, 2), 'utf8');
  }

  /**
   * Safe retirement (tombstone) of a process record whose lifecycle has concluded.
   * Preserves historical auditability without leaking unbound memory.
   */
  retireProcess(pid, status = 'RETIRED', reason = 'Normal lifecycle completion') {
    const record = this.attestedProcesses.get(pid);
    if (record) {
      this.retiredProcesses.set(pid, {
        ...record,
        retiredAt: new Date().toISOString(),
        retirementStatus: status,
        retirementReason: reason
      });
      this.attestedProcesses.delete(pid);
    }
  }

  /**
   * Safe retirement (tombstone) of a resource receipt whose lifecycle has concluded.
   */
  retireResource(targetPath, status = 'RETIRED', reason = 'Normal lifecycle completion') {
    const receipt = this.attestedResourceReceipts.get(targetPath);
    if (receipt) {
      this.retiredResources.set(targetPath, {
        ...receipt,
        retiredAt: new Date().toISOString(),
        retirementStatus: status,
        retirementReason: reason
      });
      this.attestedResourceReceipts.delete(targetPath);
    }
  }

  /**
   * Reports comprehensive lifecycle state metrics (peak, live, retired).
   */
  getLifecycleStateMetrics() {
    const liveCount = this.attestedProcesses.size + this.attestedResourceReceipts.size + this.launchTickets.size + this.trustedLaunchers.size;
    const retiredCount = this.retiredProcesses.size + this.retiredResources.size;
    const total = liveCount + retiredCount;
    if (total > this.peakEntries) {
      this.peakEntries = total;
    }
    return {
      liveProcesses: this.attestedProcesses.size,
      liveResources: this.attestedResourceReceipts.size,
      liveLaunchTickets: this.launchTickets.size,
      liveTrustedLaunchers: this.trustedLaunchers.size,
      retiredProcesses: this.retiredProcesses.size,
      retiredResources: this.retiredResources.size,
      finalLiveEntries: liveCount,
      retiredEntries: retiredCount,
      peakEntries: this.peakEntries
    };
  }

  appendLog(entry) {
    const logFile = path.join(this.sessionDir, 'cleanup.log');
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      session_id: this.sessionId,
      operation_id: entry.operation_id || `op-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`,
      chain_id: entry.chain_id || entry.chainId || null,
      resource_id: entry.resource_id || entry.resourceId || null,
      ...entry
    }) + '\n';
    fs.appendFileSync(logFile, line, 'utf8');
  }
}
