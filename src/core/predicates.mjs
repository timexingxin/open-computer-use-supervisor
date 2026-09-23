import path from 'node:path';
import {
  SYSTEM_ROOT_PIDS,
  HARD_PROTECTED_EXECUTABLE_PATTERNS,
  APPROVED_TEMP_DIRS,
  NEVER_KILL_CATEGORIES
} from './config.mjs';

/**
 * Evaluates whether a process is protected by the Never-Kill policy.
 * Based on identity and semantics, NOT temporary transient PIDs.
 *
 * @param {Object} proc - Process snapshot { pid, ppid, comm, command, canonicalExecutable }
 * @returns {{ neverKill: boolean, reason: string | null, category: string | null }}
 */
export function isNeverKill(proc) {
  if (!proc || typeof proc.pid !== 'number') {
    return {
      neverKill: true,
      reason: 'INVALID_PROCESS_RECORD',
      category: NEVER_KILL_CATEGORIES.SYSTEM_CRITICAL
    };
  }

  const pid = proc.pid;
  const ppid = typeof proc.ppid === 'number' ? proc.ppid : -1;
  const comm = String(proc.comm || '');
  const command = String(proc.command || '');
  const canonical = String(proc.canonicalExecutable || comm || '');

  // 1. Root and Kernel tasks
  if (SYSTEM_ROOT_PIDS.has(pid) || pid <= 1 || ppid === 0) {
    return {
      neverKill: true,
      reason: 'SYSTEM_ROOT_PID_OR_INIT',
      category: NEVER_KILL_CATEGORIES.SYSTEM_CRITICAL
    };
  }

  // 2. User Chrome Browser (Dynamic Semantic Check)
  // ABSOLUTE RULE: Any binary located in /Applications/Google Chrome.app is ALWAYS User Chrome.
  const isAppBundleUserChrome = (
    canonical.includes('/Applications/Google Chrome.app') ||
    command.includes('/Applications/Google Chrome.app') ||
    comm === 'Google Chrome'
  );
  if (isAppBundleUserChrome) {
    return {
      neverKill: true,
      reason: 'USER_GOOGLE_CHROME_BROWSER',
      category: NEVER_KILL_CATEGORIES.USER_BROWSER
    };
  }

  // Protect any generic Chrome binary that is not an Antigravity-managed Playwright worker
  const isChromeBinary = (
    /Google Chrome(\.app|\sHelper)?/i.test(canonical) ||
    /Google Chrome/i.test(comm) ||
    /Google Chrome(\.app|\sHelper)?/i.test(command)
  );
  if (isChromeBinary) {
    const isManagedPlaywright = (
      command.includes('BrowserProfiles/agent-default') ||
      command.includes('ms-playwright') ||
      command.includes('playwright') ||
      command.includes('--headless')
    );
    if (!isManagedPlaywright) {
      return {
        neverKill: true,
        reason: 'UNMANAGED_CHROME_INSTANCE',
        category: NEVER_KILL_CATEGORIES.USER_BROWSER
      };
    }
  }

  // 3. Shared External Services (cdp-proxy, agentmemory)
  const isCdpProxy = /cdp-proxy(\.mjs)?/i.test(command) || /cdp-proxy/i.test(canonical);
  if (isCdpProxy) {
    return {
      neverKill: true,
      reason: 'SHARED_EXTERNAL_CDP_PROXY',
      category: NEVER_KILL_CATEGORIES.SHARED_EXTERNAL_SERVICE
    };
  }

  const isAgentMemoryDaemon = /\.agentmemory\/bin\/iii/i.test(command) || /agentmemory/i.test(canonical);
  if (isAgentMemoryDaemon) {
    return {
      neverKill: true,
      reason: 'SHARED_EXTERNAL_AGENTMEMORY',
      category: NEVER_KILL_CATEGORIES.SHARED_EXTERNAL_SERVICE
    };
  }

  // 4. Standalone ZCode editor protection (Distinguish from bridge-spawned CUA helper/runner)
  const isZCodeBinary = (
    /ZCode\.app\/Contents\/MacOS\/ZCode/i.test(canonical) ||
    comm === 'ZCode' ||
    /ZCode\.app\/Contents\/MacOS\/ZCode/i.test(command)
  );
  if (isZCodeBinary) {
    const isBridgeSpawned = (
      command.includes('zcode-cua-bridge.mjs') ||
      command.includes('zcode-cua-visible-bridge.mjs') ||
      command.includes('--permission-broker-socket') ||
      command.includes('--launcher-pid')
    );
    if (!isBridgeSpawned || ppid === 1) {
      return {
        neverKill: true,
        reason: 'STANDALONE_USER_ZCODE_APP',
        category: NEVER_KILL_CATEGORIES.STANDALONE_USER_ZCODE
      };
    }
  }

  const isZCodeComputerUseBinary = (
    /ZCode Computer Use/i.test(canonical) ||
    comm.includes('ZCode Computer') ||
    /ZCode Computer Use/i.test(command)
  );
  if (isZCodeComputerUseBinary) {
    const isAttestedHelper = command.includes('--launcher-pid') && command.includes('--socket');
    if (!isAttestedHelper || ppid === 1) {
      return {
        neverKill: true,
        reason: 'STANDALONE_USER_ZCODE_HELPER',
        category: NEVER_KILL_CATEGORIES.STANDALONE_USER_ZCODE
      };
    }
  }

  // 5. System UI Applications (Finder, Dock, WindowServer, Terminal, language_server)
  for (const pattern of HARD_PROTECTED_EXECUTABLE_PATTERNS) {
    if (/Google Chrome/i.test(pattern.source)) continue;

    if (pattern.test(canonical) || pattern.test(comm) || pattern.test(command)) {
      return {
        neverKill: true,
        reason: `PROTECTED_SYSTEM_APPLICATION_${pattern.source}`,
        category: NEVER_KILL_CATEGORIES.SYSTEM_CRITICAL
      };
    }
  }

  return { neverKill: false, reason: null, category: null };
}

/**
 * Validates whether a file path falls strictly within an approved safe temporary directory.
 *
 * @param {string} targetPath - Path to file or socket
 * @returns {boolean}
 */
export function isApprovedTempPath(targetPath) {
  if (!targetPath || typeof targetPath !== 'string') return false;
  const resolved = path.resolve(targetPath);
  return APPROVED_TEMP_DIRS.some(prefix => {
    const resolvedPrefix = path.resolve(prefix);
    return resolved.startsWith(resolvedPrefix + path.sep) || resolved === resolvedPrefix;
  });
}
