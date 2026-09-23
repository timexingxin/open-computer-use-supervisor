import net from 'node:net';

const args = process.argv.slice(2);
const sockIdx = args.indexOf('--socket');
const socketPath = sockIdx !== -1 ? args[sockIdx + 1] : null;
const resistSigterm = args.includes('--resist-sigterm');

if (socketPath) {
  try {
    net.createServer().listen(socketPath);
  } catch (_) {}
}

if (resistSigterm) {
  process.on('SIGTERM', () => {
    // Intentionally ignore SIGTERM to test SIGKILL escalation rejection
  });
} else {
  process.on('SIGTERM', () => {
    process.exit(0);
  });
}

setInterval(() => {}, 1000);
