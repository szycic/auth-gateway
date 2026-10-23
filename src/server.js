const http = require('http');
const config = require('./config');
const app = require('./app');
const authService = require('./services/authService');
const sessionService = require('./services/sessionService');
const { initSocketIO, closeSocketIO } = require('./services/socketService');

const server = http.createServer(app);

initSocketIO(server);

const activeHashOnBoot = authService.getApproverPasswordHash();
if (activeHashOnBoot) {
  console.log('[auth-gateway] Approver password hash is active.');
} else {
  console.warn('\n*******************************************************************');
  console.warn('⚠️  NO APPROVER PASSWORD CONFIGURED!');
  console.warn('   Run: docker exec -it auth-gateway node set-password.js');
  console.warn('   (or: npm run set-password)');
  console.warn('*******************************************************************\n');
}

process.on('SIGHUP', () => {
  console.log('[auth-gateway] Received SIGHUP signal, reloading configuration...');
  config.reload();
});

// Graceful shutdown handling (SIGTERM, SIGINT)
let isShuttingDown = false;

function gracefulShutdown(signal) {
  if (isShuttingDown) return;
  isShuttingDown = true;
  console.log(`[auth-gateway] Received ${signal}, shutting down gracefully...`);

  try {
    sessionService.savePersistedSessions();
    console.log('[auth-gateway] Persisted active sessions to disk.');
  } catch (err) {
    console.error('[auth-gateway] Error persisting sessions on shutdown:', err.message);
  }

  try {
    closeSocketIO();
  } catch (err) {}

  server.close(() => {
    console.log('[auth-gateway] HTTP server closed cleanly.');
    process.exit(0);
  });

  setTimeout(() => {
    console.warn('[auth-gateway] Forced termination after shutdown timeout.');
    process.exit(0);
  }, 5000).unref();
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

if (require.main === module || require.main?.filename === require.resolve('../server.js')) {
  server.listen(config.PORT, config.HOST, () => {
    console.log(`[auth-gateway] Server running on http://${config.HOST}:${config.PORT}`);
    console.log(`[auth-gateway] Public URL: ${config.BASE_URL}`);
    console.log(`[auth-gateway] Data directory: ${config.DATA_DIR}`);
    console.log(`[auth-gateway] Session cookie: ${config.AUTH_COOKIE_NAME}`);
    console.log(`[auth-gateway] Approver cookie: ${config.APPROVER_COOKIE_NAME}`);
    if (config.services && config.services.length > 0) {
      console.log(`[auth-gateway] Configured services: ${config.services.length}`);
    }
  });
}

module.exports = server;
