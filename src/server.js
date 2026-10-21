const http = require('http');
const config = require('./config');
const app = require('./app');
const authService = require('./services/authService');
const { initSocketIO } = require('./services/socketService');

const server = http.createServer(app);

// Initialize Socket.io
initSocketIO(server);

// Password configured check on startup
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

// SIGHUP reload signal
process.on('SIGHUP', () => {
  console.log('[auth-gateway] Received SIGHUP signal, reloading configuration...');
  config.reload();
});

// Start Server
if (require.main === module || require.main?.filename === require.resolve('../server.js')) {
  server.listen(config.PORT, config.HOST, () => {
    console.log(`[auth-gateway] Server running on http://${config.HOST}:${config.PORT}`);
    console.log(`[auth-gateway] Public URL: ${config.BASE_URL}`);
    console.log(`[auth-gateway] Data directory: ${config.DATA_DIR}`);
    console.log(`[auth-gateway] Session cookie: ${config.AUTH_COOKIE_NAME}`);
    console.log(`[auth-gateway] Approver cookie: ${config.APPROVER_COOKIE_NAME}`);
    console.log(`[auth-gateway] Target downstream app: ${config.TARGET_APP_URL}`);
  });
}

module.exports = server;
