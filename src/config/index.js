const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '../../');
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT_DIR, 'data');

const DEFAULT_CONFIG = {
  app: {
    name: 'Auth Gateway',
    subtitle: 'Scan the QR code with your authenticated mobile device to approve access.',
    footerText: 'auth.example.com',
  },
  server: {
    port: 3000,
    host: '0.0.0.0',
    baseUrl: 'https://auth.example.com',
  },
  session: {
    cookieDomain: '.example.com',
    authCookieName: 'gateway_auth_token',
    approverCookieName: 'gateway_approver_session',
    sessionTtlHours: 72,
    qrSessionTtlMs: 120000,
    approverTtlDays: 30,
  },
  services: [],
  downstream: {
    targetUrl: process.env.TARGET_APP_URL || '',
  },
};

let loadedConfigPath = null;

function loadConfigFile(isReload = false) {
  const possiblePaths = [
    process.env.CONFIG_PATH,
    path.join(ROOT_DIR, 'config.json'),
  ].filter(Boolean);

  for (const configPath of possiblePaths) {
    if (fs.existsSync(configPath)) {
      try {
        const raw = fs.readFileSync(configPath, 'utf8');
        console.log(`[auth-gateway] Loaded configuration from ${configPath}`);
        loadedConfigPath = configPath;
        return JSON.parse(raw);
      } catch (err) {
        console.error(`[auth-gateway] Error reading config file at ${configPath}:`, err.message);
        if (!isReload) {
          console.error('[auth-gateway] CRITICAL: Failed to parse config.json! Shutting down...');
          process.exit(1);
        }
        return null;
      }
    }
  }

  console.error('[auth-gateway] CRITICAL: config.json was not found in any expected search path:');
  for (const p of possiblePaths) {
    console.error(`  - ${p}`);
  }
  console.error('[auth-gateway] A valid config.json file is required to start. Shutting down...');
  process.exit(1);
}

const fileConfig = loadConfigFile();

function normalizeService(svc) {
  return {
    ...svc,
    disableService: Boolean(svc.disableService),
    disableAuth: Boolean(svc.disableAuth),
  };
}

const mergedServices = (Array.isArray(fileConfig.services) ? fileConfig.services : []).map(normalizeService);

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
  dataDir: DATA_DIR,
  DATA_DIR: DATA_DIR,
  ROOT_DIR: ROOT_DIR,
  PORT: parseInt(process.env.PORT || (fileConfig.server && fileConfig.server.port) || DEFAULT_CONFIG.server.port, 10),
  HOST: process.env.HOST || (fileConfig.server && fileConfig.server.host) || DEFAULT_CONFIG.server.host,
  BASE_URL: (process.env.BASE_URL || (fileConfig.server && fileConfig.server.baseUrl) || DEFAULT_CONFIG.server.baseUrl).replace(/\/+$/, ''),
  TARGET_APP_URL: process.env.TARGET_APP_URL || (fileConfig.downstream && fileConfig.downstream.targetUrl) || DEFAULT_CONFIG.downstream.targetUrl,
  AUTH_COOKIE_NAME: process.env.AUTH_COOKIE_NAME || (fileConfig.session && fileConfig.session.authCookieName) || DEFAULT_CONFIG.session.authCookieName,
  APPROVER_COOKIE_NAME: process.env.APPROVER_COOKIE_NAME || (fileConfig.session && fileConfig.session.approverCookieName) || DEFAULT_CONFIG.session.approverCookieName,
  SESSION_TTL_HOURS: parseInt(process.env.SESSION_TTL_HOURS || (fileConfig.session && fileConfig.session.sessionTtlHours) || DEFAULT_CONFIG.session.sessionTtlHours, 10),
  QR_SESSION_TTL_MS: parseInt(process.env.QR_SESSION_TTL_MS || (fileConfig.session && fileConfig.session.qrSessionTtlMs) || DEFAULT_CONFIG.session.qrSessionTtlMs, 10),
  APPROVER_TTL_DAYS: parseInt(process.env.APPROVER_TTL_DAYS || (fileConfig.session && fileConfig.session.approverTtlDays) || DEFAULT_CONFIG.session.approverTtlDays, 10),

  getService(idOrUrl, onlyActive = false) {
    if (!idOrUrl || typeof idOrUrl !== 'string') return null;
    const term = idOrUrl.trim().toLowerCase();

    const matches = s => {
      if (onlyActive && s.disableService) return false;
      if (s.id && s.id.toLowerCase() === term) return true;
      if (s.name && s.name.toLowerCase() === term) return true;
      try {
        const parsed = new URL(term.startsWith('http') ? term : `https://${term}`);
        const sUrl = new URL(s.url);
        return sUrl.hostname.toLowerCase() === parsed.hostname.toLowerCase();
      } catch {
        return false;
      }
    };

    return this.services.find(matches) || null;
  },

  getActiveServices() {
    return this.services.filter(s => !s.disableService);
  },

  isServiceDisabled(idOrUrl) {
    const svc = this.getService(idOrUrl);
    return Boolean(svc && svc.disableService);
  },

  isAuthDisabled(idOrUrl) {
    const svc = this.getService(idOrUrl);
    if (!svc) return false;
    return svc.disableAuth === true;
  },

  isAllowedRedirect(redirectUrl) {
    if (!redirectUrl || typeof redirectUrl !== 'string') return false;
    const trimmed = redirectUrl.trim();

    // Relative path starting with single slash (reject protocol-relative // and backslash bypasses /\ or /\\)
    if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.startsWith('/\\')) return true;

    try {
      const parsed = new URL(trimmed);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

      // Base URL match
      try {
        const baseParsed = new URL(this.server.baseUrl);
        if (parsed.origin === baseParsed.origin) return true;
      } catch {}

      // Reject if the target matches an explicitly disabled service
      const matchedService = this.getService(parsed.hostname);
      if (matchedService && matchedService.disableService) {
        return false;
      }

      // Check configured active services and their allowedRedirects
      for (const svc of this.services) {
        if (!svc || svc.disableService) continue;

        if (Array.isArray(svc.allowedRedirects) && svc.allowedRedirects.length > 0) {
          for (const pattern of svc.allowedRedirects) {
            if (typeof pattern !== 'string') continue;
            const p = pattern.trim();
            if (p === '*') return true;
            if (p.includes('*')) {
              const escaped = p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
              if (new RegExp(`^${escaped}$`, 'i').test(trimmed)) {
                return true;
              }
            } else if (trimmed === p || trimmed === p + '/' || trimmed + '/' === p) {
              return true;
            }
          }
        } else if (svc.url) {
          try {
            const svcOrigin = new URL(svc.url).origin.toLowerCase();
            if (parsed.origin.toLowerCase() === svcOrigin) {
              return true;
            }
          } catch {}
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

  reload() {
    try {
      const fileConfig = loadConfigFile(true);
      if (!fileConfig) {
        console.error('[auth-gateway] Configuration reload aborted due to read/parse failure.');
        return false;
      }
      const newMergedServices = (Array.isArray(fileConfig.services) ? fileConfig.services : []).map(normalizeService);

      this.app = {
        ...DEFAULT_CONFIG.app,
        ...(fileConfig.app || {}),
        name: process.env.APP_NAME || (fileConfig.app && fileConfig.app.name) || DEFAULT_CONFIG.app.name,
        subtitle: process.env.APP_SUBTITLE || (fileConfig.app && fileConfig.app.subtitle) || DEFAULT_CONFIG.app.subtitle,
        footerText: process.env.APP_FOOTER_TEXT || (fileConfig.app && fileConfig.app.footerText) || DEFAULT_CONFIG.app.footerText,
      };
      this.services = newMergedServices;
      this.downstream = {
        ...DEFAULT_CONFIG.downstream,
        ...(fileConfig.downstream || {}),
        targetUrl: process.env.TARGET_APP_URL || (fileConfig.downstream && fileConfig.downstream.targetUrl) || DEFAULT_CONFIG.downstream.targetUrl,
      };
      console.log(`[auth-gateway] Configuration reloaded successfully (${this.services.length} services, ${this.getActiveServices().length} active, ${this.services.filter(s => !s.disableAuth).length} require auth).`);
      return true;
    } catch (err) {
      console.error('[auth-gateway] Error reloading configuration:', err.message);
      return false;
    }
  },
};

if (loadedConfigPath) {
  try {
    fs.watchFile(loadedConfigPath, { interval: 1500 }, (curr, prev) => {
      if (curr.mtimeMs !== prev.mtimeMs) {
        console.log(`[auth-gateway] Configuration file modified on disk (${loadedConfigPath}). Auto-reloading...`);
        config.reload();
      }
    });
  } catch (err) {
    console.error('[auth-gateway] Error initializing config file watcher:', err.message);
  }
}

module.exports = config;
