import { spawn, execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { tmpdir } from 'node:os';
import readline from 'node:readline';
import crypto from 'node:crypto';
import {
  getProcessSnapshot,
  checkProcessAlive,
  extractCanonicalExecutable
} from '../../core/identity.mjs';
import { ROLES, REGISTRATION_SOURCES } from '../../core/config.mjs';

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Captures all currently running ZCode-related processes, sockets, and tokens
 * as an immutable baseline snapshot.
 *
 * @returns {Object} Baseline snapshot
 */
export function captureZCodeBaseline() {
  const stdout = execFileSync('ps', ['-eo', 'pid=,ppid=,lstart=,comm=,command='], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore']
  });

  const lines = stdout.split('\n');
  const baselineList = [];
  const baselinePids = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/ZCode|zcode/i.test(trimmed)) {
      const parts = trimmed.split(/\s+/);
      const pid = parseInt(parts[0], 10);
      const ppid = parseInt(parts[1], 10);
      const lstart = `${parts[2]} ${parts[3]} ${parts[4]} ${parts[5]} ${parts[6]}`;
      const comm = parts[7] || '';
      const command = parts.slice(7).join(' ');
      baselineList.push({
        pid,
        ppid,
        lstart,
        comm,
        command,
        canonicalExecutable: extractCanonicalExecutable(command, comm),
        classification: 'BASELINE_PRE_EXISTING'
      });
      baselinePids.push(pid);
    }
  }

  // Also discover sockets & tokens in temporary directories
  const baselineSockets = [];
  const baselineTokens = [];
  const tmpDirs = [tmpdir(), '/tmp', '/private/tmp'];
  for (const dir of tmpDirs) {
    try {
      if (fs.existsSync(dir)) {
        const files = fs.readdirSync(dir);
        for (const file of files) {
          if (file.startsWith('zcode-cua-') && file.endsWith('.sock')) {
            baselineSockets.push(path.join(dir, file));
          } else if (file.startsWith('zcode-cua-token-') && file.endsWith('.txt')) {
            baselineTokens.push(path.join(dir, file));
          }
        }
      }
    } catch (_) {}
  }

  return {
    baselineList,
    baselinePids,
    baselineSockets: Array.from(new Set(baselineSockets)),
    baselineTokens: Array.from(new Set(baselineTokens)),
    capturedAt: new Date().toISOString()
  };
}

/**
 * Discovers the children of a bridge process: runner, helper, mcp server.
 *
 * @param {number} bridgePid
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<Object>}
 */
export async function discoverZCodeChainProcesses(bridgePid, timeoutMs = 5000) {
  const start = Date.now();
  let runnerPid = null;
  let helperPid = null;
  let mcpPid = null;
  let socketPath = null;
  let tokenPath = null;

  while (Date.now() - start < timeoutMs) {
    try {
      const stdout = execFileSync('ps', ['-eo', 'pid=,ppid=,command='], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
      });

      const lines = stdout.split('\n');
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const match = trimmed.match(/^(\d+)\s+(\d+)\s+(.*)$/);
        if (!match) continue;

        const pid = parseInt(match[1], 10);
        const ppid = parseInt(match[2], 10);
        const cmd = match[3];

        if (ppid === bridgePid) {
          if (cmd.includes('ZCode') && !runnerPid) {
            runnerPid = pid;
          }
        }

        if (runnerPid && ppid === runnerPid) {
          if ((cmd.includes('ZCode Computer Use') || cmd.includes('--launcher-pid')) && !helperPid) {
            helperPid = pid;
            const sockMatch = cmd.match(/--socket\s+(\S+)/);
            if (sockMatch) socketPath = sockMatch[1];
            const tokMatch = cmd.match(/--token-file\s+(\S+)/);
            if (tokMatch) tokenPath = tokMatch[1];
          } else if (cmd.includes('server.js') || cmd.includes('--permission-broker-socket')) {
            mcpPid = pid;
          }
        }
      }

      if (runnerPid && helperPid) {
        break;
      }
    } catch (_) {}
    await sleep(100);
  }

  return {
    runnerPid,
    helperPid,
    mcpPid,
    socketPath,
    tokenPath
  };
}

function getDefaultBridgePath() {
  if (process.env.ZCODE_BRIDGE_SCRIPT_PATH) {
    return process.env.ZCODE_BRIDGE_SCRIPT_PATH;
  }
  if (!process.env.HOME) return '';
  const candidates = [
    path.join(process.env.HOME, '.local/share/open-computer-use-supervisor/mcp-bridges/zcode-cua-bridge.mjs'),
    path.join(process.env.HOME, '.local/share/antigravity/mcp-bridges/zcode-cua-bridge.mjs')
  ];
  return candidates.find(p => fs.existsSync(p)) || candidates[0];
}

/**
 * Launches an official ZCode CUA MCP bridge process chain.
 *
 * @param {Object} options
 * @returns {Promise<Object>}
 */
export async function launchOfficialZCodeChain(options = {}) {
  const defaultBridge = getDefaultBridgePath();
  const bridgeScript = options.bridgeScriptPath || defaultBridge;
  const baselinePids = options.baselinePids || [];

  const bridgeProc = spawn(process.execPath, [bridgeScript], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      ...(options.env || {})
    }
  });

  const nextReqId = { val: 1 };
  const pendingRequests = new Map();

  const rl = readline.createInterface({ input: bridgeProc.stdout });
  rl.on('line', (line) => {
    try {
      const msg = JSON.parse(line.trim());
      if (msg.id && pendingRequests.has(msg.id)) {
        const { resolve, timer } = pendingRequests.get(msg.id);
        clearTimeout(timer);
        pendingRequests.delete(msg.id);
        resolve(msg);
      }
    } catch (_) {}
  });

  function sendMcpRequest(method, params = {}, timeout = 6000) {
    return new Promise((resolve, reject) => {
      const id = nextReqId.val++;
      const timer = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`MCP request ${id} (${method}) timed out after ${timeout}ms`));
      }, timeout);
      pendingRequests.set(id, { resolve, timer });
      try {
        bridgeProc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      } catch (err) {
        clearTimeout(timer);
        pendingRequests.delete(id);
        reject(err);
      }
    });
  }

  // Discover child processes
  const discovered = await discoverZCodeChainProcesses(bridgeProc.pid, options.discoveryTimeoutMs || 5000);

  // Attest with Broker if broker provided
  let attestResult = null;
  if (options.broker && options.launcherCapabilityToken) {
    attestResult = options.broker.attestZCodeChain({
      launcherCapabilityToken: options.launcherCapabilityToken,
      bridgePid: bridgeProc.pid,
      runnerPid: discovered.runnerPid,
      helperPid: discovered.helperPid,
      mcpPid: discovered.mcpPid,
      socketPath: discovered.socketPath,
      tokenPath: discovered.tokenPath,
      baselinePids
    });
  }

  async function closeGracefully(timeoutMs = 3000) {
    if (!checkProcessAlive(bridgeProc.pid)) {
      return { closedGracefully: true, exitCode: bridgeProc.exitCode };
    }

    try {
      bridgeProc.stdin.end();
    } catch (_) {}
    try {
      bridgeProc.kill('SIGTERM');
    } catch (_) {}

    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      if (!checkProcessAlive(bridgeProc.pid)) {
        break;
      }
      await sleep(50);
    }

    // Wait a brief moment for helper/runner cleanup propagation
    await sleep(200);

    return {
      closedGracefully: !checkProcessAlive(bridgeProc.pid),
      bridgeAlive: checkProcessAlive(bridgeProc.pid),
      runnerAlive: discovered.runnerPid ? checkProcessAlive(discovered.runnerPid) : false,
      helperAlive: discovered.helperPid ? checkProcessAlive(discovered.helperPid) : false,
      mcpAlive: discovered.mcpPid ? checkProcessAlive(discovered.mcpPid) : false
    };
  }

  return {
    bridgeProc,
    bridgePid: bridgeProc.pid,
    runnerPid: discovered.runnerPid,
    helperPid: discovered.helperPid,
    mcpPid: discovered.mcpPid,
    socketPath: discovered.socketPath,
    tokenPath: discovered.tokenPath,
    attestResult,
    sendMcpRequest,
    closeGracefully
  };
}

import { fileURLToPath } from 'node:url';
const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Spawns a controllable simulated ZCode CUA process chain fixture.
 * Allows deterministic testing of orphan scenarios, failure propagation,
 * and adversarial conditions without requiring full Electron UI.
 *
 * @param {Object} options
 * @returns {Promise<Object>}
 */
export async function launchMockZCodeChain(options = {}) {
  const sessionId = options.sessionId || crypto.randomBytes(4).toString('hex');
  const tempDir = tmpdir();
  const socketPath = path.join(tempDir, `zcode-cua-mock-${sessionId}.sock`);
  const tokenPath = path.join(tempDir, `zcode-cua-token-mock-${sessionId}.txt`);
  fs.writeFileSync(tokenPath, crypto.randomBytes(32).toString('hex'), { mode: 0o600 });

  const bridgeScriptPath = options.bridgeScriptPath || path.resolve(__dirname, '../../../tests/fixtures/mock-zcode-bridge.mjs');
  const bridgeArgs = [
    bridgeScriptPath,
    '--socket', socketPath,
    '--token-file', tokenPath
  ];
  if (options.leaveResources) {
    bridgeArgs.push('--leave-resources');
  }
  if (options.helperResistSigterm) {
    bridgeArgs.push('--resist-sigterm');
  }

  const bridgeProc = spawn(process.execPath, bridgeArgs, {
    stdio: ['pipe', 'pipe', 'pipe']
  });

  const nextReqId = { val: 1 };
  const pendingRequests = new Map();

  const rl = readline.createInterface({ input: bridgeProc.stdout });
  rl.on('line', (line) => {
    try {
      const msg = JSON.parse(line.trim());
      if (msg.id && pendingRequests.has(msg.id)) {
        const { resolve, timer } = pendingRequests.get(msg.id);
        clearTimeout(timer);
        pendingRequests.delete(msg.id);
        resolve(msg);
      }
    } catch (_) {}
  });

  function sendMcpRequest(method, params = {}, timeout = 5000) {
    return new Promise((resolve, reject) => {
      const id = nextReqId.val++;
      const timer = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`MCP request ${id} timed out`));
      }, timeout);
      pendingRequests.set(id, { resolve, timer });
      try {
        bridgeProc.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      } catch (err) {
        clearTimeout(timer);
        pendingRequests.delete(id);
        reject(err);
      }
    });
  }

  // Poll children
  let runnerPid = null;
  let helperPid = null;
  let mcpPid = null;
  const start = Date.now();
  while (Date.now() - start < 4000) {
    try {
      const stdout = execFileSync('ps', ['-eo', 'pid=,ppid=,command='], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'ignore']
      });
      for (const line of stdout.split('\n')) {
        const m = line.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
        if (!m) continue;
        const pid = parseInt(m[1], 10);
        const ppid = parseInt(m[2], 10);
        const cmd = m[3];
        if (ppid === bridgeProc.pid && !runnerPid) {
          runnerPid = pid;
        }
        if (runnerPid && ppid === runnerPid) {
          if (cmd.includes('--launcher-pid') && !helperPid) {
            helperPid = pid;
          } else if (cmd.includes('--permission-broker-socket') && !mcpPid) {
            mcpPid = pid;
          }
        }
      }
      if (runnerPid && helperPid && mcpPid) break;
    } catch (_) {}
    await sleep(50);
  }

  // Attest with Broker if requested
  let attestResult = null;
  if (options.broker && options.launcherCapabilityToken) {
    attestResult = options.broker.attestZCodeChain({
      launcherCapabilityToken: options.launcherCapabilityToken,
      bridgePid: bridgeProc.pid,
      runnerPid,
      helperPid,
      mcpPid,
      socketPath,
      tokenPath,
      baselinePids: options.baselinePids || []
    });
  }

  async function closeGracefully(timeoutMs = 2000) {
    try { bridgeProc.stdin.end(); } catch (_) {}
    try { bridgeProc.kill('SIGTERM'); } catch (_) {}

    const waitStart = Date.now();
    while (Date.now() - waitStart < timeoutMs) {
      if (!checkProcessAlive(bridgeProc.pid)) break;
      await sleep(50);
    }
    await sleep(150);

    return {
      closedGracefully: !checkProcessAlive(bridgeProc.pid),
      bridgeAlive: checkProcessAlive(bridgeProc.pid),
      runnerAlive: runnerPid ? checkProcessAlive(runnerPid) : false,
      helperAlive: helperPid ? checkProcessAlive(helperPid) : false,
      mcpAlive: mcpPid ? checkProcessAlive(mcpPid) : false
    };
  }

  /**
   * TEST-ONLY / RED-TEAM SIMULATION TEARDOWN:
   * Forcefully terminates mock chain processes for adversarial/orphan testing.
   * Strictly restricted to mock fixtures (launchMockZCodeChain).
   * Not present on or callable by production chains (launchOfficialZCodeChain).
   */
  async function terminateAbruptly() {
    if (!runnerPid || !helperPid || !mcpPid) {
      try {
        const stdout = execFileSync('ps', ['-eo', 'pid=,ppid=,command='], {
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'ignore']
        });
        for (const line of stdout.split('\n')) {
          const m = line.trim().match(/^(\d+)\s+(\d+)\s+(.*)$/);
          if (!m) continue;
          const pid = parseInt(m[1], 10);
          const ppid = parseInt(m[2], 10);
          const cmd = m[3];
          if (ppid === bridgeProc.pid && !runnerPid) runnerPid = pid;
          if (runnerPid && ppid === runnerPid) {
            if (cmd.includes('--launcher-pid') && !helperPid) helperPid = pid;
            if (cmd.includes('--permission-broker-socket') && !mcpPid) mcpPid = pid;
          }
        }
      } catch (_) {}
    }

    try { bridgeProc.kill('SIGKILL'); } catch (_) {}
    if (runnerPid) { try { process.kill(runnerPid, 'SIGKILL'); } catch (_) {} }
    if (helperPid) { try { process.kill(helperPid, 'SIGKILL'); } catch (_) {} }
    if (mcpPid) { try { process.kill(mcpPid, 'SIGKILL'); } catch (_) {} }

    const waitStart = Date.now();
    while (Date.now() - waitStart < 2000) {
      const helperAlive = helperPid ? checkProcessAlive(helperPid) : false;
      const runnerAlive = runnerPid ? checkProcessAlive(runnerPid) : false;
      const mcpAlive = mcpPid ? checkProcessAlive(mcpPid) : false;
      const bridgeAlive = checkProcessAlive(bridgeProc.pid);
      if (!helperAlive && !runnerAlive && !mcpAlive && !bridgeAlive) break;
      await sleep(50);
    }
  }

  return {
    bridgeProc,
    bridgePid: bridgeProc.pid,
    runnerPid,
    helperPid,
    mcpPid,
    socketPath,
    tokenPath,
    attestResult,
    sendMcpRequest,
    closeGracefully,
    terminateAbruptly
  };
}

/**
 * Universal launcher that selects official or mock chain.
 */
export async function launchTestZCodeChain(options = {}) {
  if (options.useOfficial) {
    return launchOfficialZCodeChain(options);
  }
  return launchMockZCodeChain(options);
}

/**
 * Detects whether the official ZCode runtime and bridge are installed and reachable.
 *
 * @param {Object} [options]
 * @returns {boolean}
 */
export function isOfficialZCodeInstalled(options = {}) {
  const defaultBridge = getDefaultBridgePath();
  const bridgeScript = options.bridgeScriptPath || defaultBridge;
  return Boolean(bridgeScript && fs.existsSync(bridgeScript) && fs.existsSync('/Applications/ZCode.app'));
}
