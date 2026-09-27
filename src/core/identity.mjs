import fs from 'node:fs';
import { execSync, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';

/**
 * Parses lstart string (e.g. "Sun Sep 20 22:05:23 2026") into epoch milliseconds.
 * Note: Standard BSD ps on macOS outputs time with 1-second resolution (1000ms precision).
 *
 * @param {string} lstartStr
 * @returns {number}
 */
export function parseLstartToEpochMs(lstartStr) {
  if (!lstartStr) return 0;
  const parsed = Date.parse(lstartStr.trim());
  return isNaN(parsed) ? 0 : parsed;
}

/**
 * Computes a SHA-256 fingerprint of the command line.
 *
 * @param {string} command
 * @returns {string}
 */
export function computeCommandFingerprint(command) {
  if (!command) return '';
  return crypto.createHash('sha256').update(command.trim()).digest('hex');
}

/**
 * Computes an HMAC-SHA256 signature for spawn/provenance attestation.
 *
 * @param {string} secret - Session secret
 * @param {string} data - Payload string
 * @returns {string}
 */
export function computeAttestationSig(secret, data) {
  if (!secret || !data) return '';
  return crypto.createHmac('sha256', secret).update(data).digest('hex');
}

/**
 * Extracts canonical executable path from command and comm fields.
 * Handles macOS application bundles with spaces (e.g. /Applications/Google Chrome.app/Contents/MacOS/Google Chrome).
 *
 * @param {string} command
 * @param {string} comm
 * @returns {string}
 */
export function extractCanonicalExecutable(command, comm) {
  if (!command) return comm || '';
  if (command.startsWith('/')) {
    if (command.includes('.app/Contents/MacOS/')) {
      const beforeFlags = command.split(/\s+-/)[0].trim();
      return beforeFlags;
    }
    return command.split(/\s+/)[0];
  }
  return comm || '';
}

/**
 * Checks if a process exists as a zombie/defunct in the OS.
 * On Linux, reads /proc/<pid>/status looking for State: Z or X.
 * On macOS / BSD, executes ps -p <pid> -o state= looking for leading 'Z'.
 *
 * @param {number} pid
 * @returns {boolean}
 */
export function isProcessZombie(pid) {
  if (typeof pid !== 'number' || pid <= 0) return false;
  if (process.platform === 'linux') {
    try {
      const status = fs.readFileSync(`/proc/${pid}/status`, 'utf8');
      return /^State:\s+[ZX]/m.test(status);
    } catch (err) {
      if (err.code === 'ENOENT') return false;
    }
  }
  try {
    const stdout = execFileSync('ps', ['-p', String(pid), '-o', 'state='], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
    return stdout.startsWith('Z');
  } catch (_) {
    return false;
  }
}

/**
 * Retrieves a live OS process snapshot for a given PID.
 *
 * @param {number} pid
 * @returns {Object | null}
 */
export function getProcessSnapshot(pid) {
  if (typeof pid !== 'number' || pid <= 0) return null;
  if (isProcessZombie(pid)) return null;
  try {
    const stdout = execFileSync('ps', ['-p', String(pid), '-o', 'pid=,ppid=,pgid=,lstart=,comm=,command='], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();

    if (!stdout) return null;

    const regex = /^\s*(\d+)\s+(\d+)\s+(\d+)\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+(\S+)\s+(.*)$/;
    const match = stdout.match(regex);

    if (match) {
      const parsedPid = parseInt(match[1], 10);
      const ppid = parseInt(match[2], 10);
      const pgid = parseInt(match[3], 10);
      const lstart = match[4].trim();
      const comm = match[5].trim();
      const command = match[6].trim();
      const startTimeEpochMs = parseLstartToEpochMs(lstart);
      const canonicalExecutable = extractCanonicalExecutable(command, comm);

      return {
        pid: parsedPid,
        ppid,
        pgid,
        lstart,
        startTimeEpochMs,
        comm,
        command,
        canonicalExecutable,
        commandFingerprint: computeCommandFingerprint(command)
      };
    }

    const tokens = stdout.trim().split(/\s+/);
    if (tokens.length >= 7) {
      const parsedPid = parseInt(tokens[0], 10);
      const ppid = parseInt(tokens[1], 10);
      const pgid = parseInt(tokens[2], 10);
      const lstart = `${tokens[3]} ${tokens[4]} ${tokens[5]} ${tokens[6]} ${tokens[7]}`;
      const comm = tokens[8] || '';
      const command = tokens.slice(8).join(' ');
      const canonicalExecutable = extractCanonicalExecutable(command, comm);

      return {
        pid: parsedPid,
        ppid,
        pgid,
        lstart,
        startTimeEpochMs: parseLstartToEpochMs(lstart),
        comm,
        command,
        canonicalExecutable,
        commandFingerprint: computeCommandFingerprint(command)
      };
    }

    return null;
  } catch (err) {
    return null;
  }
}

/**
 * Checks if a process is alive using POSIX signal 0 and confirming it is not a zombie.
 *
 * @param {number} pid
 * @returns {boolean}
 */
export function checkProcessAlive(pid) {
  if (typeof pid !== 'number' || pid <= 0) return false;
  try {
    process.kill(pid, 0);
  } catch (err) {
    if (err.code === 'ESRCH') {
      return false;
    }
    if (err.code !== 'EPERM') {
      return false;
    }
  }
  // A zombie process still has an entry in the kernel table, but is effectively dead
  if (isProcessZombie(pid)) {
    return false;
  }
  return true;
}

/**
 * Returns the ancestor PID chain up to launchd (PID 1) or limit.
 *
 * @param {number} pid
 * @param {number} [maxDepth=10]
 * @returns {number[]} Array of ancestor PIDs [ppid, grandparent, ...]
 */
export function getProcessAncestry(pid, maxDepth = 10) {
  const ancestors = [];
  let currentPid = pid;
  let depth = 0;

  while (currentPid > 1 && depth < maxDepth) {
    const snapshot = getProcessSnapshot(currentPid);
    if (!snapshot || !snapshot.ppid || snapshot.ppid <= 0) break;
    ancestors.push(snapshot.ppid);
    if (snapshot.ppid === 1) break;
    currentPid = snapshot.ppid;
    depth++;
  }

  return ancestors;
}

/**
 * Returns all active processes sharing a given process group ID (PGID).
 *
 * @param {number} pgid
 * @returns {Array<Object>} List of process snapshots in that PGID
 */
export function getProcessesInPgid(pgid) {
  if (typeof pgid !== 'number' || pgid <= 0) return [];
  try {
    const stdout = execFileSync('ps', ['-eo', 'pid=,ppid=,pgid=,comm=,command='], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    });

    const lines = stdout.split('\n');
    const matched = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      if (parts.length >= 5) {
        const pPid = parseInt(parts[0], 10);
        const pPpid = parseInt(parts[1], 10);
        const pPgid = parseInt(parts[2], 10);
        const pComm = parts[3];
        const pCommand = parts.slice(4).join(' ');

        if (pPgid === pgid) {
          matched.push({
            pid: pPid,
            ppid: pPpid,
            pgid: pPgid,
            comm: pComm,
            command: pCommand
          });
        }
      }
    }

    return matched;
  } catch (err) {
    return [];
  }
}

/**
 * Inspects whether any active OS processes currently hold open handles to the given path.
 *
 * @param {string} filePath
 * @returns {number[]} Array of PIDs holding open handles
 */
export function getOpenHandles(filePath) {
  if (!filePath || typeof filePath !== 'string') return [];
  try {
    const stdout = execFileSync('lsof', ['-t', filePath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore']
    }).trim();
    if (!stdout) return [];
    return stdout
      .split('\n')
      .map(line => parseInt(line.trim(), 10))
      .filter(p => !isNaN(p) && p > 0);
  } catch (err) {
    return [];
  }
}
