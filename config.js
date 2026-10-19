const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

const DEFAULT_CONFIG = {
  app: {
    name: 'Szycic Auth',
    subtitle: 'Scan the QR code with your authenticated mobile device to approve access.',
    footerText: 'auth.szycic.com',
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    baseUrl: 'https://auth.szycic.com',
  },
  session: {
    cookieDomain: '.szycic.com',
    authCookieName: 'szycic_auth_token',
    approverCookieName: 'szycic_approver_session',
    sessionTtlHours: 72,
    qrSessionTtlMs: 120000,
    approverTtlDays: 30,
  },
  services: [
    {
      id: 'share',
      name: 'Pingvin Share',
      subtitle: 'Secure file sharing & storage portal',
      url: 'https://share.szycic.com',
      allowedRedirects: ['https://share.szycic.com*'],
    },
  ],
  downstream: {
    targetUrl: process.env.TARGET_APP_URL || '',
  },
  publicBypass: {
    enabled: false,
    paths: [],
    pattern: '',
  },
};

function loadConfigFile() {
  const possiblePaths = [
    process.env.CONFIG_PATH,
    path.join(DATA_DIR, 'config.json'),
    path.join(__dirname, 'config.json'),
    path.join(DATA_DIR, 'config.sample.json'),
    path.join(__dirname, 'config.sample.json'),
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

const mergedServices = Array.isArray(fileConfig.services) && fileConfig.services.length > 0
  ? fileConfig.services
  : DEFAULT_CONFIG.services;

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
  session: {
    ...DEFAULT_CONFIG.session,
    ...(fileConfig.session || {}),
    cookieDomain: process.env.COOKIE_DOMAIN !== undefined
      ? process.env.COOKIE_DOMAIN
      : (fileConfig.session && fileConfig.session.cookieDomain !== undefined
        ? fileConfig.session.cookieDomain
        : DEFAULT_CONFIG.session.cookieDomain),
    authCookieName: process.env.AUTH_COOKIE_NAME || (fileConfig.session && fileConfig.session.authCookieName) || DEFAULT_CONFIG.session.authCookieName,
    approverCookieName: process.env.APPROVER_COOKIE_NAME || (fileConfig.session && fileConfig.session.approverCookieName) || DEFAULT_CONFIG.session.approverCookieName,
    sessionTtlHours: parseInt(process.env.SESSION_TTL_HOURS || (fileConfig.session && fileConfig.session.sessionTtlHours) || DEFAULT_CONFIG.session.sessionTtlHours, 10),
    qrSessionTtlMs: parseInt(process.env.QR_SESSION_TTL_MS || (fileConfig.session && fileConfig.session.qrSessionTtlMs) || DEFAULT_CONFIG.session.qrSessionTtlMs, 10),
    approverTtlDays: parseInt(process.env.APPROVER_TTL_DAYS || (fileConfig.session && fileConfig.session.approverTtlDays) || DEFAULT_CONFIG.session.approverTtlDays, 10),
  },
  services: mergedServices,
  downstream: {
    ...DEFAULT_CONFIG.downstream,
    ...(fileConfig.downstream || {}),
    targetUrl: process.env.TARGET_APP_URL || (fileConfig.downstream && fileConfig.downstream.targetUrl) || DEFAULT_CONFIG.downstream.targetUrl,
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

  getService(idOrUrl) {
    if (!idOrUrl || typeof idOrUrl !== 'string') return null;
    const term = idOrUrl.trim().toLowerCase();

    // Match by ID
    const byId = this.services.find(s => s.id && s.id.toLowerCase() === term);
    if (byId) return byId;

    // Match by URL or hostname
    try {
      const parsed = new URL(term.startsWith('http') ? term : `https://${term}`);
      return this.services.find(s => {
        try {
          const sUrl = new URL(s.url);
          return sUrl.hostname.toLowerCase() === parsed.hostname.toLowerCase();
        } catch {
          return false;
        }
      }) || null;
    } catch {
      return null;
    }
  },

  isAllowedRedirect(redirectUrl) {
    if (!redirectUrl || typeof redirectUrl !== 'string') return false;
    const trimmed = redirectUrl.trim();

    // Relative path starting with single slash (not protocol-relative //)
    if (trimmed.startsWith('/') && !trimmed.startsWith('//')) return true;

    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

      // Base URL match
      try {
        const baseParsed = new URL(this.server.baseUrl);
        if (parsed.origin === baseParsed.origin) return true;
      } catch {}

      // Allowed root domain match
      const rootDomain = (this.session.cookieDomain || '').replace(/^\./, '').toLowerCase();
      if (rootDomain && (parsed.hostname.toLowerCase() === rootDomain || parsed.hostname.toLowerCase().endsWith('.' + rootDomain))) {
        return true;
      }

      // Check configured service patterns
      for (const svc of this.services) {
        if (Array.isArray(svc.allowedRedirects)) {
          for (const pattern of svc.allowedRedirects) {
            if (pattern === '*' || trimmed === pattern) return true;
            if (pattern.endsWith('*') && trimmed.startsWith(pattern.slice(0, -1))) return true;
          }
        }
      }
    } catch {
      return false;
    }

    return false;
  },

  normalizeRedirect(redirectUrl, fallback = '/') {
    return this.isAllowedRedirect(redirectUrl) ? redirectUrl : fallback;
  },
};

module.exports = config;
