const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const { parseUserAgent } = require('../utils/deviceDetector');
const { isAuthDomain } = require('../utils/originHelper');
const authService = require('./authService');

const SESSIONS_FILE = path.join(config.DATA_DIR, 'sessions.json');

// In-Memory State Stores
const activeSessions = new Map();
const approverSessions = new Map();
const pendingLoginSessions = new Map();
const recentlyRevokedSessions = new Map();
const recentlyRevokedApproverSessions = new Map();

function trackRevokedSession(token, sessionObj) {
  if (!token || !sessionObj) return;
  recentlyRevokedSessions.set(token, {
    ...sessionObj,
    revokedAt: Date.now(),
  });
  setTimeout(() => {
    recentlyRevokedSessions.delete(token);
  }, 15 * 60 * 1000).unref();
}

function trackRevokedApproverSession(token, approverObj) {
  if (!token || !approverObj) return;
  recentlyRevokedApproverSessions.set(token, {
    ...approverObj,
    revokedAt: Date.now(),
  });
  setTimeout(() => {
    recentlyRevokedApproverSessions.delete(token);
  }, 15 * 60 * 1000).unref();
}

let lastSavedRaw = '';

function loadPersistedSessions() {
  try {
    if (fs.existsSync(SESSIONS_FILE)) {
      const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
      lastSavedRaw = raw;
      const data = JSON.parse(raw);
      const now = Date.now();

      const prevActiveCount = activeSessions.size;
      activeSessions.clear();
      approverSessions.clear();

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

      // Link approver sessions to active manage sessions (and heal missing links)
      let sessionsModified = false;

      // 1. Link active sessions with their matching approver session
      for (const s of activeSessions.values()) {
        if (s.approverToken && approverSessions.has(s.approverToken)) {
          s.isApprover = true;
          s.type = 'approver';
          if (s.friendlyDevice && s.friendlyDevice.startsWith('Approver (')) {
            s.friendlyDevice = parseUserAgent(s.userAgent);
            sessionsModified = true;
          }
          const a = approverSessions.get(s.approverToken);
          if (!a.sessionId) {
            a.sessionId = s.id;
            sessionsModified = true;
          }
          if (!a.activeSessionToken) {
            a.activeSessionToken = s.token;
            sessionsModified = true;
          }
          if (s.friendlyDevice && a.friendlyDevice !== s.friendlyDevice) {
            a.friendlyDevice = s.friendlyDevice;
            sessionsModified = true;
          }
        } else if (!s.approverToken) {
          const isApproverDevice = s.type === 'approver' || s.isApprover;
          if (isApproverDevice) {
            let bestMatch = null;
            let minDiff = Infinity;
            for (const a of approverSessions.values()) {
              if (a.activeSessionToken && a.activeSessionToken !== s.token) continue;
              if (a.sessionId && a.sessionId !== s.id) continue;
              if (a.ip && s.ip && a.ip === s.ip) {
                const diff = Math.abs((a.createdAt || 0) - (s.createdAt || 0));
                if (diff < minDiff) {
                  minDiff = diff;
                  bestMatch = a;
                }
              }
            }
            if (bestMatch) {
              s.approverToken = bestMatch.token;
              s.isApprover = true;
              s.type = 'approver';
              if (s.friendlyDevice && s.friendlyDevice.startsWith('Approver (')) {
                s.friendlyDevice = parseUserAgent(s.userAgent);
              }
              bestMatch.sessionId = s.id;
              bestMatch.activeSessionToken = s.token;
              if (s.friendlyDevice && bestMatch.friendlyDevice !== s.friendlyDevice) {
                bestMatch.friendlyDevice = s.friendlyDevice;
              }
              sessionsModified = true;
            }
          }
        }
      }

      // 2. Ensure every approver session is linked to an active session in manage sessions
      for (const a of approverSessions.values()) {
        let hasActiveSession = false;
        if (a.activeSessionToken && activeSessions.has(a.activeSessionToken)) {
          hasActiveSession = true;
          const s = activeSessions.get(a.activeSessionToken);
          if (s && s.friendlyDevice && a.friendlyDevice !== s.friendlyDevice) {
            a.friendlyDevice = s.friendlyDevice;
            sessionsModified = true;
          }
        } else {
          for (const s of activeSessions.values()) {
            if (s.approverToken === a.token || (a.sessionId && s.id === a.sessionId)) {
              hasActiveSession = true;
              a.activeSessionToken = s.token;
              a.sessionId = s.id;
              if (s.friendlyDevice && a.friendlyDevice !== s.friendlyDevice) {
                a.friendlyDevice = s.friendlyDevice;
                sessionsModified = true;
              }
              break;
            }
          }
        }

        if (!hasActiveSession) {
          const sessionId = a.sessionId || crypto.randomUUID();
          const sessionToken = a.activeSessionToken || crypto.randomBytes(48).toString('base64url');
          const ua = a.userAgent || '';
          const friendlyDevice = parseUserAgent(ua);
          const maxAgeMs = 10 * 365 * 24 * 3600 * 1000;
          const sessionObj = {
            id: sessionId,
            token: sessionToken,
            approverToken: a.token,
            createdAt: a.createdAt || Date.now(),
            expiresAt: a.expiresAt || (Date.now() + maxAgeMs),
            isTrusted: true,
            isApprover: true,
            ip: a.ip || 'Unknown',
            userAgent: ua,
            friendlyDevice,
            service: null,
            type: 'approver',
            allowedServices: null,
            sortOrder: typeof a.sortOrder === 'number' ? a.sortOrder : 0,
          };
          activeSessions.set(sessionToken, sessionObj);
          a.sessionId = sessionId;
          a.activeSessionToken = sessionToken;
          sessionsModified = true;
        }
      }

      console.log(`[auth-gateway] Loaded ${activeSessions.size} active sessions and ${approverSessions.size} approver sessions from disk.`);

      if (sessionsModified) {
        savePersistedSessions();
      }

      if (prevActiveCount > 0 && activeSessions.size === 0) {
        try {
          const socketService = require('./socketService');
          if (socketService && typeof socketService.notifyAllSessionsRevoked === 'function') {
            socketService.notifyAllSessionsRevoked();
          }
        } catch (_) {}
      }
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
    const content = JSON.stringify(data, null, 2);
    lastSavedRaw = content;
    const tmp = `${SESSIONS_FILE}.tmp`;
    fs.writeFileSync(tmp, content, 'utf8');
    fs.renameSync(tmp, SESSIONS_FILE);
  } catch (err) {
    console.error('[auth-gateway] Error persisting sessions to disk:', err.message);
  }
}

// Initial session load
loadPersistedSessions();

// Synchronize external sessions.json modifications into memory
function syncSessionsFromFile() {
  try {
    if (!fs.existsSync(SESSIONS_FILE)) return;
    const raw = fs.readFileSync(SESSIONS_FILE, 'utf8');
    if (raw === lastSavedRaw) return;
    console.log('[auth-gateway] External sessions.json update detected, synchronizing sessions...');
    loadPersistedSessions();
  } catch (err) {
    // Ignore transient read errors while file is being swapped
  }
}

try {
  if (fs.existsSync(SESSIONS_FILE)) {
    fs.watchFile(SESSIONS_FILE, { interval: 1000 }, syncSessionsFromFile);
  } else if (fs.existsSync(config.DATA_DIR)) {
    fs.watch(config.DATA_DIR, (eventType, filename) => {
      if (filename === 'sessions.json') {
        syncSessionsFromFile();
      }
    });
  }
} catch (e) {
  setInterval(syncSessionsFromFile, 3000).unref();
}

// Password change listener (does not auto-logout sessions; set-password / logout-sessions ask the operator)
authService.setOnPasswordChanged(() => {
  console.log('[auth-gateway] Approver password changed.');
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
  if (session.authMethod === 'fido') {
    const webauthnService = require('./webauthnService');
    if (!webauthnService.hasEnrolledKeys()) {
      return false;
    }
    return true;
  }
  const currentHash = authService.getApproverPasswordHash();
  if (!currentHash) {
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
  if (serviceId === 'auth' || serviceId === 'auth-gateway') return true;
  return session.allowedServices.map(s => s.toLowerCase()).includes(serviceId);
}

function getTargetServiceForRequest(req) {
  if (isAuthDomain(req) && req.query && req.query.service) {
    const svc = config.getService(req.query.service);
    if (svc) return svc;
  }

  let rawHost = req.headers['x-forwarded-host'] || req.headers.host || '';
  if (typeof rawHost === 'string' && rawHost.includes(',')) {
    const parts = rawHost.split(',').map(s => s.trim()).filter(Boolean);
    for (const part of parts) {
      const h = part.toLowerCase().split(':')[0].trim();
      const svc = config.getService(h);
      if (svc) return svc;
    }
    rawHost = parts[0] || '';
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

function mintApproverSession(req, res, approverTokenExplicit) {
  const sessionToken = crypto.randomBytes(48).toString('base64url');
  const sessionId = crypto.randomUUID();
  const maxAgeMs = 10 * 365 * 24 * 3600 * 1000; // 10 years permanent
  const clientIp = authService.getClientIp(req);
  const ua = (req && req.headers && req.headers['user-agent']) || 'Unknown';
  const friendlyDevice = parseUserAgent(ua);
  const approverToken = approverTokenExplicit || (req && req.cookies && req.cookies[config.APPROVER_COOKIE_NAME]) || null;

  // Clean up any old active session on this client to prevent duplicate cards
  const oldAuthToken = req && req.cookies && (req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token']);
  if (oldAuthToken && activeSessions.has(oldAuthToken)) {
    activeSessions.delete(oldAuthToken);
  }

  const sessionObj = {
    id: sessionId,
    token: sessionToken,
    approverToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + maxAgeMs,
    isTrusted: true,
    isApprover: true,
    ip: clientIp,
    userAgent: ua,
    friendlyDevice,
    service: null,
    type: 'approver',
    allowedServices: null,
    sortOrder: 0,
    lastActiveAt: Date.now(),
    lastActiveService: 'Szycic Auth',
  };

  if (approverToken && approverSessions.has(approverToken)) {
    const a = approverSessions.get(approverToken);
    a.sessionId = sessionId;
    a.activeSessionToken = sessionToken;
    a.friendlyDevice = friendlyDevice;
  }

  activeSessions.set(sessionToken, sessionObj);
  savePersistedSessions();

  if (res) {
    res.cookie(config.AUTH_COOKIE_NAME, sessionToken, getCookieOptions(req, maxAgeMs));
  }
  return sessionObj;
}

let persistDebounceTimer = null;

/**
 * Resolves the underlying active session for a session or approver session object.
 */
function getLinkedActiveSession(sessionOrApprover) {
  if (!sessionOrApprover) return null;
  if (sessionOrApprover.friendlyDevice && sessionOrApprover.id && activeSessions.has(sessionOrApprover.token)) {
    return sessionOrApprover;
  }
  if (sessionOrApprover.activeSessionToken && activeSessions.has(sessionOrApprover.activeSessionToken)) {
    return activeSessions.get(sessionOrApprover.activeSessionToken);
  }
  if (sessionOrApprover.sessionId) {
    for (const s of activeSessions.values()) {
      if (s.id === sessionOrApprover.sessionId) return s;
    }
  }
  if (sessionOrApprover.token) {
    for (const s of activeSessions.values()) {
      if (s.approverToken === sessionOrApprover.token) return s;
    }
  }
  return sessionOrApprover;
}

function touchSession(session, serviceName, fullUrl, ip) {
  if (!session) return;
  const now = Date.now();
  session.lastActiveAt = now;
  if (serviceName) session.lastActiveService = serviceName;
  if (fullUrl) session.lastActiveUrl = fullUrl;
  if (ip) session.lastActiveIp = ip;

  if (session.approverToken && approverSessions.has(session.approverToken)) {
    const a = approverSessions.get(session.approverToken);
    a.lastActiveAt = now;
    if (serviceName) a.lastActiveService = serviceName;
    if (fullUrl) a.lastActiveUrl = fullUrl;
    if (ip) a.lastActiveIp = ip;
  } else if (session.activeSessionToken && activeSessions.has(session.activeSessionToken)) {
    const act = activeSessions.get(session.activeSessionToken);
    act.lastActiveAt = now;
    if (serviceName) act.lastActiveService = serviceName;
    if (fullUrl) act.lastActiveUrl = fullUrl;
    if (ip) act.lastActiveIp = ip;
  } else if (session.sessionId) {
    for (const act of activeSessions.values()) {
      if (act.id === session.sessionId) {
        act.lastActiveAt = now;
        if (serviceName) act.lastActiveService = serviceName;
        if (fullUrl) act.lastActiveUrl = fullUrl;
        if (ip) act.lastActiveIp = ip;
        break;
      }
    }
  }

  // Debounced persistence to avoid constant disk writes during rapid page loads
  if (!persistDebounceTimer) {
    persistDebounceTimer = setTimeout(() => {
      persistDebounceTimer = null;
      savePersistedSessions();
    }, 5000);
    persistDebounceTimer.unref();
  }
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
  recentlyRevokedSessions,
  recentlyRevokedApproverSessions,
  trackRevokedSession,
  trackRevokedApproverSession,
  loadPersistedSessions,
  savePersistedSessions,
  isValidSession,
  isApprover,
  isSessionAllowedForService,
  getTargetServiceForRequest,
  mintApproverSession,
  getLinkedActiveSession,
  touchSession,
  parseUserAgent,
};
