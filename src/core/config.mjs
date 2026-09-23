import path from 'node:path';
import os from 'node:os';

export const RUNTIME_ROOT = process.env.SUPERVISOR_RUNTIME_ROOT ||
  (process.env.AGY_RUNTIME_ROOT || path.join(os.homedir(), '.open-computer-use-supervisor', 'runtime'));
export const SESSIONS_ROOT = path.join(RUNTIME_ROOT, 'sessions');

export const APPROVED_TEMP_DIRS = [
  '/tmp',
  '/private/tmp',
  '/var/folders',
  '/private/var/folders',
  RUNTIME_ROOT,
  path.join(os.homedir(), '.gemini', 'antigravity', 'runtime')
];

/**
 * System root PIDs. Kernel and Launchd.
 * Any attempt to use these as trust root must fail immediately.
 */
export const SYSTEM_ROOT_PIDS = new Set([0, 1]);

/**
 * Strong Registration Source Taxonomy.
 * Only SPAWN_ATTESTED, BRIDGE_ATTESTED, and PLAYWRIGHT_ATTESTED can ever qualify for OWNED_CONFIRMED.
 */
export const REGISTRATION_SOURCES = {
  SPAWN_ATTESTED: 'SPAWN_ATTESTED',
  BRIDGE_ATTESTED: 'BRIDGE_ATTESTED',
  PLAYWRIGHT_ATTESTED: 'PLAYWRIGHT_ATTESTED',
  MANUAL_TEST: 'MANUAL_TEST',
  DISCOVERED_EXISTING: 'DISCOVERED_EXISTING',
  RECOVERED_STALE: 'RECOVERED_STALE',
  UNKNOWN: 'UNKNOWN'
};

/**
 * Only attested sources can be considered for termination.
 */
export const TERMINABLE_SOURCES = new Set([
  REGISTRATION_SOURCES.SPAWN_ATTESTED,
  REGISTRATION_SOURCES.BRIDGE_ATTESTED,
  REGISTRATION_SOURCES.PLAYWRIGHT_ATTESTED
]);

/**
 * Semantic classifications for protected processes (replacing hardcoded live PIDs).
 */
export const NEVER_KILL_CATEGORIES = {
  USER_BROWSER: 'USER_BROWSER',
  SHARED_EXTERNAL_SERVICE: 'SHARED_EXTERNAL_SERVICE',
  STANDALONE_USER_ZCODE: 'STANDALONE_USER_ZCODE',
  SYSTEM_CRITICAL: 'SYSTEM_CRITICAL'
};

/**
 * Protected executable patterns.
 */
export const HARD_PROTECTED_EXECUTABLE_PATTERNS = [
  /Google Chrome\.app/i,
  /Google Chrome Helper/i,
  /Finder\.app/i,
  /Dock\.app/i,
  /WindowServer/i,
  /SystemUIServer/i,
  /Terminal\.app/i,
  /iTerm\.app/i,
  /\/sbin\/launchd/i,
  /kernel_task/i,
  /\/Applications\/Antigravity\.app\/Contents\/MacOS\/Antigravity/i,
  /\/Contents\/Resources\/bin\/language_server/i
];

/**
 * Broker & IPC configuration.
 */
export const BROKER_CONFIG = {
  socketName: 'broker.sock',
  ticketTtlMs: 10000, // 10-second window for single-use launch ticket
  ipcTimeoutMs: 3000
};

/**
 * Canonical Process Roles in Supervisor.
 */
export const ROLES = {
  DISPOSABLE_TEST_CHILD: 'supervisor-disposable-test-child',
  PLAYWRIGHT_WORKER: 'playwright-worker',
  PLAYWRIGHT_BROWSER_MAIN: 'playwright-browser-main',
  PLAYWRIGHT_HELPER: 'playwright-helper',
  BRIDGE_WORKER: 'bridge-worker',
  USER_BROWSER: 'user-browser',
  ZCODE_BRIDGE: 'zcode-bridge',
  ZCODE_RUNNER: 'zcode-runner',
  ZCODE_HELPER: 'zcode-helper',
  ZCODE_MCP_SERVER: 'zcode-mcp-server'
};

/**
 * Phase S2 Controlled Destructive Testing Invariants.
 * Strictly limited to newly created disposable test children.
 */
export const S2_CONTROLLED_CONFIG = {
  phase: 'S2-v0.5.0',
  disposableRole: ROLES.DISPOSABLE_TEST_CHILD,
  allowedRegistrationSource: REGISTRATION_SOURCES.SPAWN_ATTESTED,
  defaultGraceTimeoutMs: 1000,
  pollIntervalMs: 50,
  escalateToSigkill: true,
  allowGroupKill: false, // HARD RULE: 0 group kills
  allowResourceDeletion: false // HARD RULE: S2 does not delete resources
};

/**
 * Phase S2.5 Playwright Controlled Lifecycle Configuration.
 * Strictly limited to newly created test Playwright / Chromium instances.
 */
export const S2_5_PLAYWRIGHT_CONFIG = {
  phase: 'S2.5-v0.6.0',
  testExecutionMode: 'S2_5_PLAYWRIGHT_TEST_ONLY',
  allowedRoles: new Set([
    ROLES.PLAYWRIGHT_BROWSER_MAIN,
    ROLES.PLAYWRIGHT_HELPER,
    ROLES.DISPOSABLE_TEST_CHILD
  ]),
  allowedRegistrationSources: new Set([
    REGISTRATION_SOURCES.SPAWN_ATTESTED,
    REGISTRATION_SOURCES.PLAYWRIGHT_ATTESTED
  ]),
  defaultGraceTimeoutMs: 2000,
  pollIntervalMs: 50,
  escalateToSigkill: true,
  allowGroupKill: false, // HARD RULE: 0 group kills
  allowResourceDeletion: false // HARD RULE: S2.5 does not delete files/directories
};

/**
 * Canonical Resource Roles in Supervisor.
 */
export const RESOURCE_ROLES = {
  DISPOSABLE_TEST_RESOURCE: 'disposable-test-resource',
  PLAYWRIGHT_TEST_PROFILE: 'playwright-test-profile',
  PLAYWRIGHT_ARTIFACTS: 'playwright-artifacts',
  TEST_SOCKET: 'test-socket',
  TEST_TOKEN: 'test-token',
  ZCODE_TEST_SOCKET: 'zcode-test-socket',
  ZCODE_TEST_TOKEN: 'zcode-test-token'
};

/**
 * Hard Path Denylist: Absolute paths that can never, under any circumstances,
 * be deleted, unlinked, or traversed into for deletion.
 */
export const HARD_PATH_DENYLIST = [
  '/',
  os.homedir(),
  '/Users',
  '/Applications',
  '/System',
  '/Library',
  '/usr',
  '/bin',
  '/sbin',
  '/private',
  '/tmp',
  '/var',
  '/private/tmp',
  '/private/var',
  path.join(os.homedir(), 'Documents'),
  path.join(os.homedir(), 'Desktop'),
  path.join(os.homedir(), 'Downloads'),
  path.join(os.homedir(), '.zcode'),
  path.join(os.homedir(), '.gemini'),
  path.join(os.homedir(), '.gemini', 'antigravity'),
  path.join(os.homedir(), 'Library'),
  path.join(os.homedir(), 'Library', 'Application Support', 'Google'),
  path.join(os.homedir(), 'Library', 'Caches', 'ms-playwright')
];

/**
 * Phase S3 Controlled Temporary Resource Cleanup Configuration.
 * Strictly limited to newly created test resources in active session.
 */
export const S3_RESOURCE_CONFIG = {
  phase: 'S3-v0.7.0',
  testExecutionMode: 'S3_TEST_RESOURCE_DELETE_MODE',
  allowedRoles: new Set([
    RESOURCE_ROLES.DISPOSABLE_TEST_RESOURCE,
    RESOURCE_ROLES.PLAYWRIGHT_TEST_PROFILE,
    RESOURCE_ROLES.PLAYWRIGHT_ARTIFACTS,
    RESOURCE_ROLES.TEST_SOCKET,
    RESOURCE_ROLES.TEST_TOKEN
  ]),
  allowedCreationSources: new Set([
    'SUPERVISOR_CREATED',
    'PLAYWRIGHT_TEST_CREATED'
  ]),
  allowGeneralResourceDeletion: false, // General production cleanup remains false
  allowGroupKill: false
};

/**
 * Phase S4 ZCode CUA Controlled Lifecycle Configuration.
 * Strictly limited to newly created test ZCode CUA chains.
 */
export const S4_ZCODE_CONFIG = {
  phase: 'S4-v0.8.0',
  testExecutionMode: 'S4_ZCODE_TEST_ONLY',
  allowedRoles: new Set([
    ROLES.ZCODE_BRIDGE,
    ROLES.ZCODE_RUNNER,
    ROLES.ZCODE_HELPER,
    ROLES.ZCODE_MCP_SERVER
  ]),
  allowedRegistrationSources: new Set([
    REGISTRATION_SOURCES.BRIDGE_ATTESTED,
    REGISTRATION_SOURCES.SPAWN_ATTESTED
  ]),
  defaultGraceTimeoutMs: 2000,
  pollIntervalMs: 50,
  escalateToSigkill: false, // HARD RULE in S4: No automatic SIGKILL escalation for ZCode Helper!
  allowGroupKill: false,   // HARD RULE: 0 group kills
  allowResourceDeletion: false // S4 does not delete sockets/tokens (marked WOULD_DELETE_IN_S4_5)
};

/**
 * Phase S4.5 ZCode Ephemeral Resource Cleanup Configuration.
 * Strictly limited to newly created ephemeral Unix sockets and token files
 * belonging exclusively to attested test ZCode CUA chains.
 */
export const S4_5_RESOURCE_CONFIG = {
  phase: 'S4.5-v0.9.0',
  testExecutionMode: 'S4_5_ZCODE_RESOURCE_TEST_ONLY',
  allowedRoles: new Set([
    RESOURCE_ROLES.ZCODE_TEST_SOCKET,
    RESOURCE_ROLES.ZCODE_TEST_TOKEN
  ]),
  allowedRegistrationSources: new Set([
    REGISTRATION_SOURCES.BRIDGE_ATTESTED,
    REGISTRATION_SOURCES.SPAWN_ATTESTED
  ]),
  approvedTempRoots: [
    '/tmp',
    '/private/tmp',
    '/var/folders',
    '/private/var/folders'
  ],
  maxTokenBytes: 4096,
  allowGeneralResourceDeletion: false, // General production cleanup remains locked
  allowZCodeResourceDeletion: true,   // Only in S4_5_ZCODE_RESOURCE_TEST_ONLY for attested leaf resources
  allowGroupKill: false
};

/**
 * Production Global Execution Gate.
 * MUST REMAIN STRICTLY LOCKED (executeAllowed = false) in Release Candidate.
 */
export const PHASE_V0_1_CONFIG = {
  version: '1.0.0-rc.1',
  phase: '1.0.0-rc.1',
  dryRunDefault: true,
  executeAllowed: false, // Strict Fail-Closed Lock for general production execute
  lockReason: 'PRODUCTION_EXECUTE_LOCKED_RELEASE_CANDIDATE'
};
