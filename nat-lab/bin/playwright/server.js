const { chromium } = require('playwright');

const HOST = process.env.PW_HOST || '0.0.0.0';
const PORT = parseInt(process.env.PW_PORT || '4444', 10);
const WS_PATH = process.env.PW_WS_PATH || 'playwright';

(async () => {
  const server = await chromium.launchServer({
    host: HOST,
    port: PORT,
    wsPath: WS_PATH,
  });
  console.log(`Playwright server listening at ${server.wsEndpoint()}`);
  process.stdin.resume();
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, async () => {
      try { await server.close(); } finally { process.exit(0); }
    });
  }
})().catch((err) => {
  console.error('Failed to start Playwright server:', err);
  process.exit(1);
});
