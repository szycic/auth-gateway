const fs = require('fs');
const path = require('path');
const config = require('../config');
const { auditLog, updateLogAttempts } = require('../utils/auditLogger');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('./authService');

const JAIL_FILE = path.join(config.DATA_DIR, 'jail.json');

// Jailed IPs map: ip -> { reason, bannedUntil, count, hitCount, firstBannedAt, escalationLevel, isManual }
const jailedIps = new Map();

// Rate limiting map for unauthenticated requests: ip -> { count, resetAt }
const unauthRequests = new Map();

// Debounce map for audit log: ip:event -> lastLogTimestamp
const auditDebounceMap = new Map();

// Debounce map for SERVICE_AUTH_REQUIRED: ip:serviceId -> lastLogTimestamp
const authRequiredDebounceMap = new Map();

// Scanner path regexes based on observed real-world attack patterns
const SCANNER_PATH_PATTERNS = [
  // 1. Secrets, environment variables, credentials, git, svn, docker, ssh
  {
    regex: /^\/(\.env|\.git|\.svn|\.hg|\.bzr|\.docker|\.aws|\.ssh|\.config|\.well-known\/security\.txt|\.DS_Store)($|\/|\.)/i,
    category: 'Secrets & Environment file fuzzing'
  },
  {
    regex: /\.(env|git|svn|bak|backup|old|save|swp|sql|tar|gz|zip|rar|7z)($|\?)/i,
    category: 'Backup & sensitive archive probe'
  },

  // 2. PHP, WordPress, Joomla, Drupal, phpMyAdmin, Adminer, web shells
  {
    regex: /^\/(wp|wp-[\w.-]+|wordpress|xmlrpc\.php|phpmyadmin|pma|myadmin|adminer|setup\.php|install\.php|test\.php|info\.php|phpinfo|eval\.php|dbadmin|mysql|sqladmin)($|\/|\?)/i,
    category: 'WordPress & database admin scanner'
  },
  {
    regex: /\.php($|\?)/i,
    category: 'PHP file execution probe'
  },

  // 3. Common scanner probing paths: /backup, /old, /new, /bk, /bc, /main, /temp, /tmp
  {
    regex: /^\/(backup|backups|bk|bc|old|new|main|temp|tmp|dump|sql|db)($|\/|\.)/i,
    category: 'Common scanner path fuzzing'
  },

  // 4. Exposed framework, debug, and actuator endpoints
  {
    regex: /^\/(actuator|telescope|_ignition|solr|console|vendor|node_modules|cgi-bin|api\/v1\/auth|manager\/html)($|\/|\.)/i,
    category: 'Framework & debug endpoint probe'
  },
];

// Automated Scanner User-Agents
const SCANNER_UA_PATTERN = /(sqlmap|nikto|nuclei|masscan|zgrab|nmap|gobuster|dirbuster|ffuf|wpscan|censys|shodan|python-requests|aiohttp|httpx)/i;

const JAIL_DURATION_DEFAULT_MS = 30 * 60 * 1000; // 30 minutes initial jail
const JAIL_DURATION_REPEAT_MS = 2 * 60 * 60 * 1000; // 2 hours for repeat offenders (strike 2)
const JAIL_DURATION_AGGRESSIVE_MS = 6 * 60 * 60 * 1000; // 6 hours for aggressive burst scanners (15+ hits)
const JAIL_DURATION_MAX_MS = 24 * 60 * 60 * 1000; // 24 hours for extreme burst scanners (50+ hits) or strike 3+
const UNAUTH_RATE_LIMIT_PER_MINUTE = 20; // Max 20 unauthenticated requests per minute per IP

/**
 * Check if an IP address belongs to private/local/VPN network ranges.
 */
function isPrivateOrLocalIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.replace(/^::ffff:/, '').trim().toLowerCase();
  if (clean === '127.0.0.1' || clean === '::1' || clean === 'localhost') return true;
  if (/^10\./.test(clean)) return true;
  if (/^192\.168\./.test(clean)) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)) return true;
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(clean)) return true; // Tailscale CGNAT
  return false;
}

/**
 * Check if an IP address is exempt from being jailed:
 * - Local/private IP
 * - IP currently associated with an active authenticated user session or approver session
 */
function isIpExemptFromJail(ip) {
  if (!ip) return true;
  if (isPrivateOrLocalIp(ip)) return true;
  try {
    const sessionService = require('./sessionService');
    const now = Date.now();
    if (sessionService && sessionService.activeSessions) {
      for (const s of sessionService.activeSessions.values()) {
        if (s.expiresAt > now && (s.ip === ip || s.lastActiveIp === ip)) {
          return true;
        }
      }
    }
    if (sessionService && sessionService.approverSessions) {
      for (const a of sessionService.approverSessions.values()) {
        if (a.expiresAt > now && (a.ip === ip || a.lastActiveIp === ip)) {
          return true;
        }
      }
    }
  } catch (_) {}
  return false;
}

/**
 * Load persisted jail entries from disk on startup.
 */
function loadPersistedJail() {
  try {
    if (fs.existsSync(JAIL_FILE)) {
      const raw = fs.readFileSync(JAIL_FILE, 'utf8');
      const data = JSON.parse(raw);
      const now = Date.now();
      if (Array.isArray(data.jailed)) {
        for (const item of data.jailed) {
          if (item && item.ip && item.bannedUntil > now) {
            jailedIps.set(item.ip, {
              reason: item.reason || 'Malicious probe',
              bannedUntil: item.bannedUntil,
              count: item.count || 1,
              hitCount: item.hitCount || 0,
              firstBannedAt: item.firstBannedAt || now,
              escalationLevel: item.escalationLevel || '30m',
              isManual: Boolean(item.isManual),
              escalated15: Boolean(item.escalated15),
              escalated50: Boolean(item.escalated50),
            });
          }
        }
      }
    }
  } catch (err) {
    console.error('[auth-gateway] Error loading persisted jail:', err.message);
  }
}

/**
 * Persist active jail entries to disk atomically.
 */
function savePersistedJail() {
  try {
    if (!fs.existsSync(config.DATA_DIR)) {
      fs.mkdirSync(config.DATA_DIR, { recursive: true });
    }
    const now = Date.now();
    const list = [];
    for (const [ip, entry] of jailedIps.entries()) {
      if (entry.bannedUntil > now) {
        list.push({
          ip,
          reason: entry.reason,
          bannedUntil: entry.bannedUntil,
          count: entry.count,
          hitCount: entry.hitCount,
          firstBannedAt: entry.firstBannedAt,
          escalationLevel: entry.escalationLevel,
          isManual: Boolean(entry.isManual),
          escalated15: Boolean(entry.escalated15),
          escalated50: Boolean(entry.escalated50),
        });
      }
    }
    const data = {
      jailed: list,
      lastSaved: new Date().toISOString(),
    };
    const content = JSON.stringify(data, null, 2);
    const tmp = `${JAIL_FILE}.tmp`;
    fs.writeFileSync(tmp, content, 'utf8');
    fs.renameSync(tmp, JAIL_FILE);
  } catch (err) {
    console.error('[auth-gateway] Error saving persisted jail:', err.message);
  }
}

// Initial jail load
loadPersistedJail();

/**
 * Extract pathname from relative URI or absolute URL.
 */
function extractPathname(urlOrUri) {
  if (!urlOrUri || typeof urlOrUri !== 'string') return '';
  try {
    if (urlOrUri.startsWith('http://') || urlOrUri.startsWith('https://')) {
      return new URL(urlOrUri).pathname;
    }
  } catch {}
  return urlOrUri.split('?')[0].split('#')[0];
}

/**
 * Check if request URL, pathname, or User-Agent matches scanner/bot heuristics.
 */
function isScannerRequest(req, targetUrlOrUri) {
  const pathname = extractPathname(targetUrlOrUri);
  const ua = (req && req.headers && req.headers['user-agent']) || '';

  if (pathname) {
    for (const { regex, category } of SCANNER_PATH_PATTERNS) {
      if (regex.test(pathname)) {
        return { isScanner: true, reason: `${category}: ${pathname}` };
      }
    }
  }

  if (ua && SCANNER_UA_PATTERN.test(ua)) {
    return { isScanner: true, reason: `Known scanner User-Agent: ${ua.slice(0, 50)}` };
  }

  return { isScanner: false, reason: null };
}

/**
 * Check whether an IP is currently jailed.
 */
function isIpJailed(ip) {
  if (!ip) return { jailed: false };
  const entry = jailedIps.get(ip);
  if (!entry) return { jailed: false };

  const now = Date.now();
  if (now > entry.bannedUntil) {
    jailedIps.delete(ip);
    savePersistedJail();
    return { jailed: false };
  }

  const remainingSeconds = Math.max(1, Math.ceil((entry.bannedUntil - now) / 1000));
  return {
    jailed: true,
    remainingSeconds,
    reason: entry.reason,
    bannedUntil: entry.bannedUntil,
    count: entry.count,
    hitCount: entry.hitCount || 0,
    firstBannedAt: entry.firstBannedAt,
    escalationLevel: entry.escalationLevel,
    isManual: Boolean(entry.isManual),
  };
}

/**
 * Jail an IP address for a specified duration with strike-based escalation.
 */
function jailIp(ip, reason, durationMs = JAIL_DURATION_DEFAULT_MS) {
  if (!ip) return;
  if (isIpExemptFromJail(ip)) {
    console.warn(`[AUTH_JAIL_EXEMPT] Refused to jail ip=${ip} reason="${reason}" (authenticated session or private network)`);
    return;
  }

  const now = Date.now();
  const existing = jailedIps.get(ip);
  const count = (existing ? existing.count : 0) + 1;
  let finalDuration = durationMs;
  let escalationLevel = '30m';

  if (count === 2) {
    finalDuration = JAIL_DURATION_REPEAT_MS; // 2 hours
    escalationLevel = '2h (repeat strike 2)';
  } else if (count >= 3) {
    finalDuration = JAIL_DURATION_MAX_MS; // 24 hours
    escalationLevel = `24h (persistent strike ${count})`;
  }

  jailedIps.set(ip, {
    reason,
    bannedUntil: now + finalDuration,
    count,
    hitCount: existing ? (existing.hitCount || 0) : 0,
    firstBannedAt: existing ? existing.firstBannedAt : now,
    escalationLevel,
    escalated15: existing ? existing.escalated15 : false,
    escalated50: existing ? existing.escalated50 : false,
  });

  savePersistedJail();
  console.warn(`[AUTH_SCANNER_BLOCKED] ip=${ip} reason="${reason}" duration=${Math.round(finalDuration / 60000)}m strike=${count} (${escalationLevel})`);
}

/**
 * Block a scanner probe request: jails the IP, emits SCANNER_PROBE_BLOCKED audit event (debounced), and returns 403.
 */
function blockScannerProbe(req, res, targetUrlOrUri, reason) {
  const clientIp = authService.getClientIp(req);
  jailIp(clientIp, reason);

  // Debounced audit logging: log at most once per 10 minutes per IP to avoid log spam, tracking attempt counts
  const debounceKey = `scanner:${clientIp}`;
  const now = Date.now();
  const entry = auditDebounceMap.get(debounceKey);

  if (!entry || now - entry.lastLogged > 10 * 60 * 1000) {
    const ua = (req.headers && req.headers['user-agent']) || '';
    const jailEntry = jailedIps.get(clientIp);
    const initialJail = (jailEntry && jailEntry.escalationLevel) || '30m';
    const logRecord = auditLog('SCANNER_PROBE_BLOCKED', {
      ip: clientIp,
      url: targetUrlOrUri || req.originalUrl || req.url,
      path: extractPathname(targetUrlOrUri || req.originalUrl || req.url),
      reason,
      device: parseUserAgent(ua) || 'Automated Scanner',
      userAgent: ua.slice(0, 150),
      jailDuration: initialJail,
    });
    auditDebounceMap.set(debounceKey, { lastLogged: now, count: 1, logRecord });
  } else {
    entry.count += 1;
    entry.lastLogged = now;
    updateLogAttempts(entry.logRecord, entry.count);
  }

  return res.status(403).set({
    'X-Auth-Status': 'blocked',
    'X-Auth-Reason': 'scanner_probe_blocked',
    'Retry-After': '1800',
  }).send('Forbidden: Malicious scanner probe detected');
}

/**
 * Record repeated hit from an already jailed IP, adaptively escalating jail duration for aggressive bursts.
 */
function recordJailedHit(clientIp) {
  if (!clientIp) return;
  const now = Date.now();
  const jailEntry = jailedIps.get(clientIp);
  let escalatedLabel = null;

  if (jailEntry) {
    jailEntry.hitCount = (jailEntry.hitCount || 0) + 1;

    // Adaptive escalation based on concurrent burst hits during jail
    if (jailEntry.hitCount >= 50 && !jailEntry.escalated50) {
      jailEntry.escalated50 = true;
      jailEntry.bannedUntil = Math.max(jailEntry.bannedUntil, now + JAIL_DURATION_MAX_MS); // Escalate to 24 hours
      jailEntry.escalationLevel = '24h (adaptive: 50+ burst hits)';
      escalatedLabel = jailEntry.escalationLevel;
      console.warn(`[AUTH_JAIL_ESCALATED] ip=${clientIp} escalated to 24h due to ${jailEntry.hitCount} burst hits`);
    } else if (jailEntry.hitCount >= 15 && !jailEntry.escalated15 && !jailEntry.escalated50) {
      jailEntry.escalated15 = true;
      jailEntry.bannedUntil = Math.max(jailEntry.bannedUntil, now + JAIL_DURATION_AGGRESSIVE_MS); // Escalate to 6 hours
      jailEntry.escalationLevel = '6h (adaptive: 15+ burst hits)';
      escalatedLabel = jailEntry.escalationLevel;
      console.warn(`[AUTH_JAIL_ESCALATED] ip=${clientIp} escalated to 6h due to ${jailEntry.hitCount} burst hits`);
    }
    if (escalatedLabel) {
      savePersistedJail();
    }
  }

  const scannerEntry = auditDebounceMap.get(`scanner:${clientIp}`);
  if (scannerEntry) {
    scannerEntry.count += 1;
    scannerEntry.lastLogged = now;
    if (escalatedLabel && scannerEntry.logRecord && scannerEntry.logRecord.details) {
      scannerEntry.logRecord.details.jailDuration = escalatedLabel;
    }
    updateLogAttempts(scannerEntry.logRecord, scannerEntry.count);
    return;
  }
  const rateEntry = auditDebounceMap.get(`ratelimit:${clientIp}`);
  if (rateEntry) {
    rateEntry.count += 1;
    rateEntry.lastLogged = now;
    if (escalatedLabel && rateEntry.logRecord && rateEntry.logRecord.details) {
      rateEntry.logRecord.details.jailDuration = escalatedLabel;
    }
    updateLogAttempts(rateEntry.logRecord, rateEntry.count);
  }
}

/**
 * Retrieve the current list of jailed IPs. Prunes expired entries automatically.
 */
function getJailedIpsList() {
  const now = Date.now();
  const list = [];
  let pruned = false;

  for (const [ip, entry] of jailedIps.entries()) {
    if (now > entry.bannedUntil) {
      jailedIps.delete(ip);
      pruned = true;
      continue;
    }
    const remainingSeconds = Math.max(1, Math.ceil((entry.bannedUntil - now) / 1000));
    list.push({
      ip,
      reason: entry.reason || 'Malicious probe',
      bannedUntil: entry.bannedUntil,
      remainingSeconds,
      count: entry.count || 1,
      hitCount: entry.hitCount || 0,
      firstBannedAt: entry.firstBannedAt || now,
      escalationLevel: entry.escalationLevel || '30m',
      isManual: Boolean(entry.isManual),
    });
  }

  if (pruned) {
    savePersistedJail();
  }

  list.sort((a, b) => b.bannedUntil - a.bannedUntil);
  return list;
}

/**
 * Manually unjail an IP address.
 */
function unjailIp(ip, unjailedBy) {
  if (!ip) return false;
  const cleanIp = String(ip).trim();
  const existed = jailedIps.has(cleanIp);
  const entry = jailedIps.get(cleanIp);

  jailedIps.delete(cleanIp);
  auditDebounceMap.delete(`scanner:${cleanIp}`);
  auditDebounceMap.delete(`ratelimit:${cleanIp}`);
  unauthRequests.delete(cleanIp);
  savePersistedJail();

  if (existed) {
    auditLog('IP_UNJAILED', {
      ip: cleanIp,
      unjailedByIp: unjailedBy || 'Approver',
      previousReason: entry ? entry.reason : undefined,
    });
  }
  return true;
}

/**
 * Extend an existing jail or add ban time for an IP.
 */
function extendJail(ip, durationMinutes, reason, extendedBy) {
  if (!ip) throw new Error('IP is required');
  const cleanIp = String(ip).trim();
  const durationMs = Math.max(1, parseInt(durationMinutes, 10) || 30) * 60 * 1000;
  const now = Date.now();
  const existing = jailedIps.get(cleanIp);
  const currentEnd = (existing && existing.bannedUntil > now) ? existing.bannedUntil : now;
  const newBannedUntil = currentEnd + durationMs;
  const updatedReason = reason ? String(reason).trim() : (existing ? existing.reason : 'Manually extended ban');
  const minutes = Math.round(durationMs / 60000);
  const levelLabel = `+${minutes}m (extended)`;

  const entry = {
    reason: updatedReason,
    bannedUntil: newBannedUntil,
    count: (existing ? existing.count : 0) + 1,
    hitCount: existing ? (existing.hitCount || 0) : 0,
    firstBannedAt: existing ? existing.firstBannedAt : now,
    escalationLevel: levelLabel,
    isManual: true,
  };
  jailedIps.set(cleanIp, entry);
  savePersistedJail();

  auditLog('IP_JAIL_EXTENDED', {
    ip: cleanIp,
    extendedByIp: extendedBy || 'Approver',
    durationMinutes: minutes,
    bannedUntil: new Date(newBannedUntil).toISOString(),
    reason: updatedReason,
  });

  return {
    ip: cleanIp,
    ...entry,
    remainingSeconds: Math.ceil((newBannedUntil - now) / 1000),
  };
}

/**
 * Manually jail an IP address for administrative reasons.
 */
function manuallyJailIp(ip, durationMinutes, reason, jailedBy) {
  if (!ip) throw new Error('IP is required');
  const cleanIp = String(ip).trim();
  if (isIpExemptFromJail(cleanIp)) {
    throw new Error('This IP belongs to an authenticated session or private network and cannot be jailed');
  }
  const durationMs = Math.max(1, parseInt(durationMinutes, 10) || 30) * 60 * 1000;
  const now = Date.now();
  const bannedUntil = now + durationMs;
  const finalReason = reason ? String(reason).trim() : 'Manual administrative ban';
  const minutes = Math.round(durationMs / 60000);
  const escalationLevel = `${minutes}m (manual)`;

  const entry = {
    reason: finalReason,
    bannedUntil,
    count: 1,
    hitCount: 0,
    firstBannedAt: now,
    escalationLevel,
    isManual: true,
  };
  jailedIps.set(cleanIp, entry);
  savePersistedJail();

  auditLog('IP_MANUALLY_JAILED', {
    ip: cleanIp,
    jailedByIp: jailedBy || 'Approver',
    durationMinutes: minutes,
    bannedUntil: new Date(bannedUntil).toISOString(),
    reason: finalReason,
  });

  return {
    ip: cleanIp,
    ...entry,
    remainingSeconds: Math.ceil((bannedUntil - now) / 1000),
  };
}

/**
 * Record RATE_LIMIT_TRIGGERED with debounce and attempt tracking.
 */
function recordRateLimitHit(clientIp, endpoint, req) {
  if (!clientIp) return;
  const debounceKey = `ratelimit:${clientIp}`;
  const now = Date.now();
  const entry = auditDebounceMap.get(debounceKey);

  if (!entry || now - entry.lastLogged > 10 * 60 * 1000) {
    const logRecord = auditLog('RATE_LIMIT_TRIGGERED', {
      ip: clientIp,
      endpoint,
      count: UNAUTH_RATE_LIMIT_PER_MINUTE,
      device: parseUserAgent((req && req.headers && req.headers['user-agent']) || '') || 'Desktop Browser',
    });
    auditDebounceMap.set(debounceKey, { lastLogged: now, count: 1, logRecord });
  } else {
    entry.count += 1;
    entry.lastLogged = now;
    updateLogAttempts(entry.logRecord, entry.count);
  }
}

/**
 * Sliding-window rate limit for unauthenticated requests from a given IP.
 */
function checkUnauthRateLimit(ip) {
  if (!ip) return { allowed: true };
  const now = Date.now();
  const entry = unauthRequests.get(ip);

  if (!entry || now > entry.resetAt) {
    unauthRequests.set(ip, { count: 1, resetAt: now + 60000 });
    return { allowed: true };
  }

  entry.count += 1;
  if (entry.count > UNAUTH_RATE_LIMIT_PER_MINUTE) {
    const retryAfterSec = Math.max(1, Math.ceil((entry.resetAt - now) / 1000));
    // Auto-jail for 15 minutes on aggressive unauth rate limit breach
    jailIp(ip, 'Excessive unauthenticated requests rate limit exceeded', 15 * 60 * 1000);
    return { allowed: false, retryAfter: retryAfterSec };
  }

  return { allowed: true };
}

/**
 * Record SERVICE_AUTH_REQUIRED logging per IP and service with 60-second debounce and attempt counting.
 */
function recordAuthRequired(clientIp, targetService, redirectTarget, req) {
  if (!clientIp) return;
  const effectiveService = targetService || config.getAuthService();
  const serviceId = effectiveService ? effectiveService.id : null;
  const key = `${clientIp}:${serviceId || 'unknown'}`;
  const now = Date.now();
  const entry = authRequiredDebounceMap.get(key);

  if (!entry || now - entry.lastTime > 60000) {
    const logRecord = auditLog('SERVICE_AUTH_REQUIRED', {
      service: effectiveService ? effectiveService.name : 'Unknown Service',
      serviceId,
      url: redirectTarget || (effectiveService ? effectiveService.url : ''),
      ip: clientIp,
      device: parseUserAgent((req && req.headers && req.headers['user-agent']) || '') || 'Desktop Browser',
    });
    authRequiredDebounceMap.set(key, {
      firstTime: now,
      lastTime: now,
      count: 1,
      logRecord,
    });
    return;
  }

  // Repeat hit within 60-second debounce window
  entry.count += 1;
  entry.lastTime = now;
  updateLogAttempts(entry.logRecord, entry.count);

  // Prune map if large
  if (authRequiredDebounceMap.size > 2000) {
    for (const [k, e] of authRequiredDebounceMap) {
      if (now - e.lastTime > 120000) authRequiredDebounceMap.delete(k);
    }
  }
}

// Debounce map for SERVICE_ACCESS: sessionId:serviceId -> timestamp
const accessDebounceMap = new Map();

/**
 * Log SERVICE_ACCESS event for document requests with 15-second debounce per session per service.
 */
function logServiceAccess(req, session, targetService, isApprover = false) {
  if (!req) return;
  // If watchdog query param is present or request is on auth domain directly, it's not a service page navigation
  if (req.query && req.query.service) return;

  let authHost = '';
  try {
    authHost = new URL(config.BASE_URL).hostname.toLowerCase();
  } catch {}

  const forwardedHost = ((req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0]).toLowerCase().trim();
  if (!forwardedHost) return;

  const originalMethod = (req.headers['x-forwarded-method'] || req.method || 'GET').toUpperCase();
  if (originalMethod !== 'GET') return;

  const secFetchDest = req.headers['sec-fetch-dest'];
  const secFetchMode = req.headers['sec-fetch-mode'];
  const accept = req.headers['accept'] || '';
  const forwardedUri = req.headers['x-forwarded-uri'] || req.originalUrl || req.url || '';

  // Filter out static subresources
  if (/\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|otf|map|webmanifest|json|txt|xml)($|\?)/i.test(forwardedUri)) {
    return;
  }

  // Filter out internal/streaming APIs and WebSockets
  if (
    forwardedUri.startsWith('/api/') ||
    forwardedUri.startsWith('/ws') ||
    forwardedUri.startsWith('/socket.io/') ||
    forwardedUri.startsWith('/hubs/') ||
    forwardedUri.startsWith('/System/')
  ) {
    return;
  }

  // Must be a top-level page navigation (document request)
  const isDocument = (secFetchDest === 'document') ||
                     (secFetchMode === 'navigate') ||
                     (!secFetchDest && accept.includes('text/html'));
  if (!isDocument) return;

  const sessionService = require('./sessionService');
  const activeSession = sessionService.getLinkedActiveSession ? sessionService.getLinkedActiveSession(session) : session;
  const effectiveSession = activeSession || session;

  const service = targetService || (forwardedHost === authHost ? config.getAuthService() : null);
  const serviceId = service ? service.id : forwardedHost;
  const auditSessionId = (effectiveSession && effectiveSession.id) || (session && (session.id || session.sessionId)) || undefined;
  const debounceKey = `${auditSessionId || authService.getClientIp(req)}:${serviceId}`;
  const now = Date.now();
  const lastTime = accessDebounceMap.get(debounceKey) || 0;

  // Debounce window of 15 seconds per session per service to avoid duplicate logs on redirects/page loads
  if (now - lastTime < 15000) return;
  accessDebounceMap.set(debounceKey, now);

  // Prune map if large
  if (accessDebounceMap.size > 5000) {
    for (const [k, t] of accessDebounceMap) {
      if (now - t > 60000) accessDebounceMap.delete(k);
    }
  }

  const serviceName = service ? service.name : forwardedHost;
  const proto = req.headers['x-forwarded-proto'] || (req.protocol === 'http' || req.protocol === 'https' ? req.protocol : 'https');
  const fullUrl = `${proto}://${forwardedHost}${forwardedUri}`;

  const device = (effectiveSession && effectiveSession.friendlyDevice)
    || (session && session.friendlyDevice)
    || parseUserAgent(req.headers['user-agent'] || '')
    || (isApprover ? 'Approver Device' : 'Desktop Browser');

  const isTrusted = effectiveSession ? Boolean(effectiveSession.isTrusted) : (session ? Boolean(session.isTrusted) : false);

  auditLog('SERVICE_ACCESS', {
    service: serviceName,
    serviceId: service ? service.id : null,
    site: forwardedHost,
    url: fullUrl,
    ip: authService.getClientIp(req),
    device,
    sessionId: auditSessionId,
    trusted: isTrusted,
    ...(isApprover ? { isApprover: true } : {}),
  });

  if (session) {
    try {
      sessionService.touchSession(session, serviceName, fullUrl, authService.getClientIp(req));
    } catch (_) {}
  }
}

/**
 * Debounce SERVICE_AUTH_REQUIRED logging per IP and service to avoid log flooding.
 */
function shouldLogAuthRequired(clientIp, serviceId) {
  if (!clientIp) return true;
  const key = `${clientIp}:${serviceId || 'unknown'}`;
  const now = Date.now();
  const entry = authRequiredDebounceMap.get(key);
  const lastTime = (entry && entry.lastTime) || (typeof entry === 'number' ? entry : 0);

  // Debounce window of 60 seconds per IP per service
  if (now - lastTime < 60000) {
    return false;
  }
  return true;
}

// Periodic cleanup of expired memory records
setInterval(() => {
  const now = Date.now();
  let prunedJail = false;
  for (const [ip, entry] of jailedIps.entries()) {
    if (now > entry.bannedUntil) {
      jailedIps.delete(ip);
      prunedJail = true;
    }
  }
  if (prunedJail) {
    savePersistedJail();
  }
  for (const [ip, entry] of unauthRequests.entries()) {
    if (now > entry.resetAt) unauthRequests.delete(ip);
  }
  for (const [k, t] of auditDebounceMap.entries()) {
    if (now - t > 60 * 60 * 1000) auditDebounceMap.delete(k);
  }
}, 5 * 60 * 1000).unref();

module.exports = {
  extractPathname,
  isScannerRequest,
  isIpJailed,
  isIpExemptFromJail,
  jailIp,
  blockScannerProbe,
  recordJailedHit,
  recordRateLimitHit,
  checkUnauthRateLimit,
  recordAuthRequired,
  shouldLogAuthRequired,
  logServiceAccess,
  getJailedIpsList,
  unjailIp,
  extendJail,
  manuallyJailIp,
  loadPersistedJail,
  savePersistedJail,
  UNAUTH_RATE_LIMIT_PER_MINUTE,
};
