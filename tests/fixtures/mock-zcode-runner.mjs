import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const sockIdx = args.indexOf('--socket');
const socketPath = sockIdx !== -1 ? args[sockIdx + 1] : null;
const tokIdx = args.indexOf('--token-file');
const tokenPath = tokIdx !== -1 ? args[tokIdx + 1] : null;
const resistSigterm = args.includes('--resist-sigterm');

const helperArgs = [
  path.join(__dirname, 'mock-zcode-helper.mjs'),
  '--socket', socketPath || '/tmp/dummy.sock',
  '--token-file', tokenPath || '/tmp/dummy.txt',
  '--launcher-pid', String(process.pid)
];
if (resistSigterm) {
  helperArgs.push('--resist-sigterm');
}

const helper = spawn(process.execPath, helperArgs, { stdio: 'ignore' });

const mcpArgs = [
  path.join(__dirname, 'mock-zcode-mcp.mjs'),
  '--permission-broker-socket', socketPath || '/tmp/dummy.sock',
  '--launcher-pid', String(process.pid)
];
const mcp = spawn(process.execPath, mcpArgs, { stdio: 'ignore' });

process.on('SIGTERM', () => {
  try { helper.kill('SIGTERM'); } catch (_) {}
  try { mcp.kill('SIGTERM'); } catch (_) {}
  process.exit(0);
});

setInterval(() => {}, 1000);
