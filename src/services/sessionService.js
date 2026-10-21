const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('./authService');

const SESSIONS_FILE = path.join(config.DATA_DIR, 'sessions.json');

// In-Memory State Stores
const activeSessions = new Map();
const approverSessions = new Map();
const pendingLoginSessions = new Map();

function loadPersistedSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
      const data = JSON.parse(raw);
      const now = Date.now();

      if (Array.isArray(data.activeSessions)) {
        for (const s of data.activeSessions) {
          if (!s.expiresAt || s.expiresAt > now) {
            if (!s.id) {
              s.id = crypto.randomUUID();
            }
            activeSessions.set(s.token, s);
          }
        }
      }

      if (Array.isArray(data.approverSessions)) {
        for (const a of data.approverSessions) {
          if (!a.expiresAt || a.expiresAt > now) {
            approverSessions.set(a.token, a);
          }
        }
      }

      console.log(`[auth-gateway] Loaded ${activeSessions.size} active sessions and ${approverSessions.size} approver sessions from disk.`);
    }
  } catch (err) {
    console.error('[auth-gateway] Error reading persisted sessions:', err.message);
  }
}

function savePersistedSessions() {
  try {
    const data = {
      activeSessions: Array.from(activeSessions.values()),
      approverSessions: Array.from(approverSessions.values()),
      lastSaved: new Date().toISOString(),
    };
    const tmp = `${SESSIONS_FILE}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmp, SESSIONS_FILE);
  } catch (err) {
    console.error('[auth-gateway] Error persisting sessions to disk:', err.message);
  }
}

// Initial session load
loadPersistedSessions();

// Password change listener invalidates active approver sessions
authService.setOnPasswordChanged(() => {
  const count = approverSessions.size;
  if (count > 0) {
    approverSessions.clear();
    savePersistedSessions();
    console.log(`[auth-gateway] Invalidated all ${count} approver session(s) due to password change.`);
  }
});

function isValidSession(token) {
  if (!token || typeof token !== 'string') return false;
  const session = activeSessions.get(token);
  if (!session) return false;
  if (session.expiresAt && Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    savePersistedSessions();
    return false;
  }
  return true;
}

function isApprover(req) {
  const token = req.cookies[config.APPROVER_COOKIE_NAME];
  if (!token || typeof token !== 'string') return false;
  const session = approverSessions.get(token);
  if (!session) return false;
  if (session.expiresAt && Date.now() > session.expiresAt) {
    approverSessions.delete(token);
    savePersistedSessions();
    return false;
  }
  const currentHash = authService.getApproverPasswordHash();
  if (!currentHash || (session.passwordHash && session.passwordHash !== currentHash)) {
    console.log('[auth-gateway] Invalidating approver session due to password change/mismatch.');
    approverSessions.delete(token);
    savePersistedSessions();
    return false;
  }
  return true;
}

function isSessionAllowedForService(session, service) {
  if (service && service.disableService) return false;
  if (service && service.disableAuth) return true;
  if (!session) return false;
  const hasRestrictedServices = Array.isArray(session.allowedServices) && session.allowedServices.length > 0 && !session.allowedServices.includes('*');
  if (!hasRestrictedServices) {
    return true;
  }
  if (!service) return false;
  const serviceId = typeof service === 'string' ? service.toLowerCase() : (service.id || '').toLowerCase();
  return session.allowedServices.map(s => s.toLowerCase()).includes(serviceId);
}

function getTargetServiceForRequest(req) {
  if (req.query && req.query.service) {
    const svc = config.getService(req.query.service);
    if (svc) return svc;
  }

  let rawHost = req.headers['x-service-host'] || req.headers['x-forwarded-host'] || req.headers.host || '';
  if (typeof rawHost === 'string' && rawHost.includes(',')) {
    const parts = rawHost.split(',').map(s => s.trim()).filter(Boolean);
    rawHost = parts[parts.length - 1] || '';
  }
  const host = rawHost.toLowerCase().split(':')[0].trim();
  const matched = config.getService(host);
  if (matched) return matched;

  const origin = req.headers.origin;
  if (origin) {
    try {
      const originHost = new URL(origin).hostname.toLowerCase();
      const svc = config.getService(originHost);
      if (svc) return svc;
    } catch {}
  }

  const referer = req.headers.referer;
  if (referer) {
    try {
      const refererHost = new URL(referer).hostname.toLowerCase();
      const svc = config.getService(refererHost);
      if (svc) return svc;
    } catch {}
  }

  return null;
}

function mintApproverSession(req, res) {
  const sessionToken = crypto.randomBytes(48).toString('base64url');
  const sessionId = crypto.randomUUID();
  const maxAgeMs = 10 * 365 * 24 * 3600 * 1000; // 10 years permanent
  const clientIp = authService.getClientIp(req);
  const ua = req.headers['user-agent'] || 'Unknown';
  const friendlyDevice = `Approver Phone (${parseUserAgent(ua)})`;
  const approverToken = req.cookies[config.APPROVER_COOKIE_NAME] || null;

  const sessionObj = {
    id: sessionId,
    token: sessionToken,
    approverToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + maxAgeMs,
    isTrusted: true,
    ip: clientIp,
    userAgent: ua,
    friendlyDevice,
    service: null,
    type: 'trusted_device',
  };

  activeSessions.set(sessionToken, sessionObj);
  savePersistedSessions();

  if (res) {
    res.cookie(config.AUTH_COOKIE_NAME, sessionToken, getCookieOptions(req, maxAgeMs));
  }
  return sessionObj;
}

// Periodic cleanup of expired sessions every 60 seconds
setInterval(() => {
  const now = Date.now();
  let changed = false;

  for (const [id, session] of pendingLoginSessions.entries()) {
    if (now > session.expiresAt) {
      if (session.pairCode) {
        authService.pairingCodes.delete(session.pairCode);
      }
      pendingLoginSessions.delete(id);
    }
  }

  for (const [token, session] of activeSessions.entries()) {
    if (session.expiresAt && now > session.expiresAt) {
      activeSessions.delete(token);
      changed = true;
    }
  }

  for (const [token, session] of approverSessions.entries()) {
    if (session.expiresAt && now > session.expiresAt) {
      approverSessions.delete(token);
      changed = true;
    }
  }

  if (changed) {
    savePersistedSessions();
  }
}, 60 * 1000).unref();

module.exports = {
  activeSessions,
  approverSessions,
  pendingLoginSessions,
  loadPersistedSessions,
  savePersistedSessions,
  isValidSession,
  isApprover,
  isSessionAllowedForService,
  getTargetServiceForRequest,
  mintApproverSession,
};
