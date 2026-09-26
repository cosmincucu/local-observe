// Revalidate the image's bundled page on every start before declaring readiness.
const { spawn } = require('node:child_process');
const { rmSync, writeFileSync } = require('node:fs');
const { setTimeout: delay } = require('node:timers/promises');

rmSync('/tmp/portal-ready', { force: true });
const child = spawn(process.execPath, ['server.js'], {
  stdio: 'inherit', env: { ...process.env, HOMEPAGE_BUILDTIME: String(Date.now()) },
});
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
child.on('exit', (code) => process.exit(code ?? 1));
child.on('error', () => process.exit(1));

(async () => {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch('http://127.0.0.1:3000/api/revalidate', { signal: AbortSignal.timeout(5000) });
      if (response.ok && (await response.json()).revalidated === true) {
        writeFileSync('/tmp/portal-ready', 'ready');
        return;
      }
    } catch { /* The server may still be starting. */ }
    await delay(500);
  }
  console.error('Homepage configuration revalidation failed');
  child.kill('SIGTERM');
})();
