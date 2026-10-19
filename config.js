const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

const DEFAULT_CONFIG = {
  app: {
    name: 'Auth Gateway',
    subtitle: 'Scan the QR code with your authenticated mobile device to approve access for this desktop.',
    footerText: 'Protected Gateway',
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    baseUrl: 'https://share.szycic.com',
  },
  downstream: {
    targetUrl: 'http://share-app:3000',
  },
  session: {
    authCookieName: 'share_auth_token',
    approverCookieName: 'gateway_approver_session',
    sessionTtlHours: 72,
    qrSessionTtlMs: 120000,
    approverTtlDays: 30,
  },
  publicBypass: {
    enabled: true,
    paths: ['/s/*', '/share/*', '/upload/*'],
    pattern: '^\\/(s|share|upload)\\/[^\\/]+',
  },
};

function loadConfigFile() {
  const possiblePaths = [
    process.env.CONFIG_PATH,
    path.join(DATA_DIR, 'config.json'),
    path.join(__dirname, 'config.json'),
    path.join(DATA_DIR, 'config.json.sample'),
    path.join(__dirname, 'config.json.sample'),
  ].filter(Boolean);

  for (const configPath of possiblePaths) {
    if (fs.existsSync(configPath)) {
      try {
        const raw = fs.readFileSync(configPath, 'utf8');
        console.log(`[auth-gateway] Loaded configuration from ${configPath}`);
        return JSON.parse(raw);
      } catch (err) {
        console.error(`[auth-gateway] Error reading config file at ${configPath}:`, err.message);
      }
    }
  }

  return {};
}

const fileConfig = loadConfigFile();

// Deep merge with environment variable overrides
const config = {
  app: {
    ...DEFAULT_CONFIG.app,
    ...(fileConfig.app || {}),
    name: process.env.APP_NAME || (fileConfig.app && fileConfig.app.name) || DEFAULT_CONFIG.app.name,
    subtitle: process.env.APP_SUBTITLE || (fileConfig.app && fileConfig.app.subtitle) || DEFAULT_CONFIG.app.subtitle,
    footerText: process.env.APP_FOOTER_TEXT || (fileConfig.app && fileConfig.app.footerText) || DEFAULT_CONFIG.app.footerText,
  },
  server: {
    ...DEFAULT_CONFIG.server,
    ...(fileConfig.server || {}),
    port: parseInt(process.env.PORT || (fileConfig.server && fileConfig.server.port) || DEFAULT_CONFIG.server.port, 10),
    host: process.env.HOST || (fileConfig.server && fileConfig.server.host) || DEFAULT_CONFIG.server.host,
    baseUrl: (process.env.BASE_URL || (fileConfig.server && fileConfig.server.baseUrl) || DEFAULT_CONFIG.server.baseUrl).replace(/\/+$/, ''),
  },
  downstream: {
    ...DEFAULT_CONFIG.downstream,
    ...(fileConfig.downstream || {}),
    targetUrl: process.env.TARGET_APP_URL || (fileConfig.downstream && fileConfig.downstream.targetUrl) || DEFAULT_CONFIG.downstream.targetUrl,
  },
  session: {
    ...DEFAULT_CONFIG.session,
    ...(fileConfig.session || {}),
    authCookieName: process.env.AUTH_COOKIE_NAME || (fileConfig.session && fileConfig.session.authCookieName) || DEFAULT_CONFIG.session.authCookieName,
    approverCookieName: process.env.APPROVER_COOKIE_NAME || (fileConfig.session && fileConfig.session.approverCookieName) || DEFAULT_CONFIG.session.approverCookieName,
    sessionTtlHours: parseInt(process.env.SESSION_TTL_HOURS || (fileConfig.session && fileConfig.session.sessionTtlHours) || DEFAULT_CONFIG.session.sessionTtlHours, 10),
    qrSessionTtlMs: parseInt(process.env.QR_SESSION_TTL_MS || (fileConfig.session && fileConfig.session.qrSessionTtlMs) || DEFAULT_CONFIG.session.qrSessionTtlMs, 10),
    approverTtlDays: parseInt(process.env.APPROVER_TTL_DAYS || (fileConfig.session && fileConfig.session.approverTtlDays) || DEFAULT_CONFIG.session.approverTtlDays, 10),
  },
  publicBypass: {
    ...DEFAULT_CONFIG.publicBypass,
    ...(fileConfig.publicBypass || {}),
  },
  dataDir: DATA_DIR,
  DATA_DIR: DATA_DIR,
  PORT: parseInt(process.env.PORT || (fileConfig.server && fileConfig.server.port) || DEFAULT_CONFIG.server.port, 10),
  HOST: process.env.HOST || (fileConfig.server && fileConfig.server.host) || DEFAULT_CONFIG.server.host,
  BASE_URL: (process.env.BASE_URL || (fileConfig.server && fileConfig.server.baseUrl) || DEFAULT_CONFIG.server.baseUrl).replace(/\/+$/, ''),
  TARGET_APP_URL: process.env.TARGET_APP_URL || (fileConfig.downstream && fileConfig.downstream.targetUrl) || DEFAULT_CONFIG.downstream.targetUrl,
  AUTH_COOKIE_NAME: process.env.AUTH_COOKIE_NAME || (fileConfig.session && fileConfig.session.authCookieName) || DEFAULT_CONFIG.session.authCookieName,
  APPROVER_COOKIE_NAME: process.env.APPROVER_COOKIE_NAME || (fileConfig.session && fileConfig.session.approverCookieName) || DEFAULT_CONFIG.session.approverCookieName,
  SESSION_TTL_HOURS: parseInt(process.env.SESSION_TTL_HOURS || (fileConfig.session && fileConfig.session.sessionTtlHours) || DEFAULT_CONFIG.session.sessionTtlHours, 10),
  QR_SESSION_TTL_MS: parseInt(process.env.QR_SESSION_TTL_MS || (fileConfig.session && fileConfig.session.qrSessionTtlMs) || DEFAULT_CONFIG.session.qrSessionTtlMs, 10),
  APPROVER_TTL_DAYS: parseInt(process.env.APPROVER_TTL_DAYS || (fileConfig.session && fileConfig.session.approverTtlDays) || DEFAULT_CONFIG.session.approverTtlDays, 10),
};

module.exports = config;
