import { spawn } from 'node:child_process';
import readline from 'node:readline';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const sockIdx = args.indexOf('--socket');
const socketPath = sockIdx !== -1 ? args[sockIdx + 1] : null;
const tokIdx = args.indexOf('--token-file');
const tokenPath = tokIdx !== -1 ? args[tokIdx + 1] : null;
const resistSigterm = args.includes('--resist-sigterm');
const leaveResources = args.includes('--leave-resources');

const runnerArgs = [
  path.join(__dirname, 'mock-zcode-runner.mjs'),
  '--socket', socketPath || '/tmp/dummy.sock',
  '--token-file', tokenPath || '/tmp/dummy.txt',
  '--launcher-pid', String(process.pid)
];
if (resistSigterm) {
  runnerArgs.push('--resist-sigterm');
}

const runner = spawn(process.execPath, runnerArgs, { stdio: 'ignore' });

function cleanup() {
  try { runner.kill('SIGTERM'); } catch (_) {}
  if (!leaveResources) {
    if (socketPath) { try { fs.unlinkSync(socketPath); } catch (_) {} }
    if (tokenPath) { try { fs.unlinkSync(tokenPath); } catch (_) {} }
  }
}

process.on('SIGTERM', () => {
  cleanup();
  process.exit(0);
});

process.on('exit', () => {
  cleanup();
});

const rl = readline.createInterface({ input: process.stdin });
rl.on('line', (line) => {
  try {
    const req = JSON.parse(line.trim());
    if (req.method === 'tools/list') {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: req.id,
        result: { tools: [{ name: 'list_apps' }, { name: 'get_app_state' }] }
      }));
    } else if (req.method === 'tools/call') {
      console.log(JSON.stringify({
        jsonrpc: '2.0',
        id: req.id,
        result: { content: [{ type: 'text', text: JSON.stringify({ success: true, app: 'Calculator' }) }] }
      }));
    }
  } catch (_) {}
});

setInterval(() => {}, 1000);
