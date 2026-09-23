const args = process.argv.slice(2);
const lIdx = args.indexOf('--launcher-pid');
const launcherPid = lIdx !== -1 ? parseInt(args[lIdx + 1], 10) : null;

process.on('SIGTERM', () => {
  process.exit(0);
});

if (launcherPid) {
  const watchTimer = setInterval(() => {
    try {
      process.kill(launcherPid, 0);
    } catch (_) {
      clearInterval(watchTimer);
      process.exit(0);
    }
  }, 200);
  watchTimer.unref();
}

setInterval(() => {}, 1000);
