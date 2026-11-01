const config = require('../config');
const { auditLog, updateLogAttempts } = require('../utils/auditLogger');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('./authService');

// Jailed IPs map: ip -> { reason, bannedUntil, count, firstBannedAt }
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
const JAIL_DURATION_REPEAT_MS = 2 * 60 * 60 * 1000; // 2 hours for repeat offenders
const UNAUTH_RATE_LIMIT_PER_MINUTE = 20; // Max 20 unauthenticated requests per minute per IP

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
    return { jailed: false };
  }

  const remainingSeconds = Math.max(1, Math.ceil((entry.bannedUntil - now) / 1000));
  return {
    jailed: true,
    remainingSeconds,
    reason: entry.reason,
    bannedUntil: entry.bannedUntil,
  };
}

/**
 * Jail an IP address for a specified duration.
 */
function jailIp(ip, reason, durationMs = JAIL_DURATION_DEFAULT_MS) {
  if (!ip) return;
  const now = Date.now();
  const existing = jailedIps.get(ip);
  const count = (existing ? existing.count : 0) + 1;
  const finalDuration = count > 1 ? JAIL_DURATION_REPEAT_MS : durationMs;

  jailedIps.set(ip, {
    reason,
    bannedUntil: now + finalDuration,
    count,
    firstBannedAt: existing ? existing.firstBannedAt : now,
  });

  console.warn(`[AUTH_SCANNER_BLOCKED] ip=${ip} reason="${reason}" duration=${Math.round(finalDuration / 60000)}m strike=${count}`);
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
    const logRecord = auditLog('SCANNER_PROBE_BLOCKED', {
      ip: clientIp,
      url: targetUrlOrUri || req.originalUrl || req.url,
      path: extractPathname(targetUrlOrUri || req.originalUrl || req.url),
      reason,
      device: parseUserAgent(ua) || 'Automated Scanner',
      userAgent: ua.slice(0, 150),
      jailDuration: '30m',
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
 * Record repeated hit from an already jailed IP, updating attempt counts on the blocked event.
 */
function recordJailedHit(clientIp) {
  if (!clientIp) return;
  const scannerEntry = auditDebounceMap.get(`scanner:${clientIp}`);
  if (scannerEntry) {
    scannerEntry.count += 1;
    scannerEntry.lastLogged = Date.now();
    updateLogAttempts(scannerEntry.logRecord, scannerEntry.count);
    return;
  }
  const rateEntry = auditDebounceMap.get(`ratelimit:${clientIp}`);
  if (rateEntry) {
    rateEntry.count += 1;
    rateEntry.lastLogged = Date.now();
    updateLogAttempts(rateEntry.logRecord, rateEntry.count);
  }
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

  const service = targetService || (forwardedHost === authHost ? config.getAuthService() : null);
  const serviceId = service ? service.id : forwardedHost;
  const sessionId = (session && session.id) || (session && session.sessionId) || authService.getClientIp(req);
  const debounceKey = `${sessionId}:${serviceId}`;
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

  auditLog('SERVICE_ACCESS', {
    service: serviceName,
    serviceId: service ? service.id : null,
    site: forwardedHost,
    url: fullUrl,
    ip: authService.getClientIp(req),
    device: (session && session.friendlyDevice) || parseUserAgent(req.headers['user-agent'] || '') || (isApprover ? 'Approver Device' : 'Desktop Browser'),
    sessionId: (session && session.id) || undefined,
    trusted: session ? session.isTrusted : false,
    ...(isApprover ? { isApprover: true } : {}),
  });
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
  for (const [ip, entry] of jailedIps.entries()) {
    if (now > entry.bannedUntil) jailedIps.delete(ip);
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
  jailIp,
  blockScannerProbe,
  recordJailedHit,
  recordRateLimitHit,
  checkUnauthRateLimit,
  recordAuthRequired,
  shouldLogAuthRequired,
  logServiceAccess,
  UNAUTH_RATE_LIMIT_PER_MINUTE,
};
