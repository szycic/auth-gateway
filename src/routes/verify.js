const express = require('express');
const config = require('../config');
const { isAllowedOrigin } = require('../utils/originHelper');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');
const securityService = require('../services/securityService');
const { auditLog } = require('../utils/auditLogger');
const { parseUserAgent } = require('../utils/deviceDetector');

const router = express.Router();

// Debounce map: sessionId:serviceId -> timestamp
const accessDebounceMap = new Map();

function logServiceAccess(req, session, targetService, isApprover = false) {
  // If watchdog query param is present or request is on auth domain directly, it's not a service page navigation
  if (req.query && req.query.service) return;

  let authHost = '';
  try {
    authHost = new URL(config.BASE_URL).hostname.toLowerCase();
  } catch {}

  const forwardedHost = ((req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0]).toLowerCase().trim();
  if (!forwardedHost || forwardedHost === authHost) return;

  const originalMethod = (req.headers['x-forwarded-method'] || req.method || 'GET').toUpperCase();
  if (originalMethod !== 'GET') return;

  const secFetchDest = req.headers['sec-fetch-dest'];
  const secFetchMode = req.headers['sec-fetch-mode'];
  const accept = req.headers['accept'] || '';
  const forwardedUri = req.headers['x-forwarded-uri'] || req.url || '';

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

  const serviceId = targetService ? targetService.id : forwardedHost;
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

  const serviceName = targetService ? targetService.name : forwardedHost;
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const fullUrl = `${proto}://${forwardedHost}${forwardedUri}`;

  auditLog('SERVICE_ACCESS', {
    service: serviceName,
    serviceId: targetService ? targetService.id : null,
    site: forwardedHost,
    url: fullUrl,
    ip: authService.getClientIp(req),
    device: (session && session.friendlyDevice) || parseUserAgent(req.headers['user-agent'] || '') || (isApprover ? 'Approver Device' : 'Desktop Browser'),
    sessionId: (session && session.id) || undefined,
    trusted: session ? session.isTrusted : false,
    ...(isApprover ? { isApprover: true } : {}),
  });
}

// CORS Preflight handler - strictly for authentic OPTIONS requests
router.options('/verify', (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    if (isAllowedOrigin(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
      const reqHeaders = req.headers['access-control-request-headers'];
      res.setHeader('Access-Control-Allow-Headers', reqHeaders || 'Content-Type, Authorization, X-Requested-With, X-Gateway-Token, X-Auth-Token');
      res.setHeader('Access-Control-Max-Age', '86400');
      return res.status(204).end();
    }
    return res.status(403).send('Forbidden: CORS origin not allowed');
  }
  return res.status(204).end();
});

router.all('/verify', (req, res) => {
  const clientIp = authService.getClientIp(req);
  const jailStatus = securityService.isIpJailed(clientIp);
  if (jailStatus.jailed) {
    securityService.recordJailedHit(clientIp);
    return res.status(403).set({
      'X-Auth-Status': 'blocked',
      'X-Auth-Reason': 'ip_jailed',
      'Retry-After': String(jailStatus.remainingSeconds),
    }).send(`Forbidden: IP temporarily banned (${jailStatus.remainingSeconds}s remaining)`);
  }

  const origin = req.headers.origin;

  if (origin) {
    if (isAllowedOrigin(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
      const reqHeaders = req.headers['access-control-request-headers'];
      res.setHeader('Access-Control-Allow-Headers', reqHeaders || 'Content-Type, Authorization, X-Requested-With, X-Gateway-Token, X-Auth-Token');
      res.setHeader('Access-Control-Max-Age', '86400');
    } else {
      return res.status(403).send('Forbidden: CORS origin not allowed');
    }
  }

  const targetService = sessionService.getTargetServiceForRequest(req);
  if (targetService && targetService.disableService) {
    return res.status(503).set({
      'X-Auth-Status': 'service_disabled',
      'X-Auth-Reason': 'service_disabled',
    }).send('Service Disabled');
  }

  // Public service bypass: If authentication is disabled for this service, allow all traffic
  if (targetService && targetService.disableAuth) {
    return res.status(200).set({
      'X-Auth-Status': 'public',
      'X-Auth-Role': 'public',
      'X-Auth-User': 'anonymous',
    }).send('OK: Service is public');
  }

  // Gateway Secret Token check (via custom headers: X-Gateway-Token, X-Auth-Token, or Bearer token)
  if (authService.isGatewayTokenValid(req)) {
    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': 'api_token',
      'X-Auth-User': 'api_user',
    }).send('OK: Authenticated via Gateway Token');
  }

  // Cross-Subdomain XSS & Request Isolation:
  // Prevent malicious scripts executing on one subdomain (e.g. stash.szycic.com) from
  // making cross-subdomain fetch/XHR API requests or state-mutating requests (POST, PUT, DELETE)
  // to another protected service (e.g. docs.szycic.com, tools.szycic.com).
  let baseAuthHost = '';
  try {
    baseAuthHost = new URL(config.BASE_URL).hostname.toLowerCase();
  } catch {}

  const forwardedHost = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0].toLowerCase().trim();
  const targetHost = (targetService && targetService.url)
    ? new URL(targetService.url).hostname.toLowerCase()
    : forwardedHost;

  const originalMethod = (req.headers['x-forwarded-method'] || req.method || 'GET').toUpperCase();
  const secFetchMode = req.headers['sec-fetch-mode'];
  const secFetchSite = req.headers['sec-fetch-site'];

  if (targetHost && targetHost !== baseAuthHost) {
    if (origin) {
      try {
        const originHost = new URL(origin).hostname.toLowerCase();
        if (originHost !== targetHost && originHost !== baseAuthHost) {
          if (
            ['POST', 'PUT', 'PATCH', 'DELETE'].includes(originalMethod) ||
            secFetchMode === 'cors' ||
            secFetchSite === 'same-site' ||
            secFetchSite === 'cross-site'
          ) {
            auditLog('CROSS_SUBDOMAIN_BLOCKED', {
              origin,
              targetHost,
              method: originalMethod,
              secFetchMode,
              ip: authService.getClientIp(req),
            });
            return res.status(403).set({
              'X-Auth-Status': 'cross_subdomain_blocked',
              'X-Auth-Reason': 'cross_subdomain_forbidden',
            }).send('Forbidden: Cross-subdomain request blocked');
          }
        }
      } catch (_) {}
    }

    const referer = req.headers['referer'];
    if (referer && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(originalMethod)) {
      try {
        const refHost = new URL(referer).hostname.toLowerCase();
        if (refHost !== targetHost && refHost !== baseAuthHost) {
          auditLog('CROSS_SUBDOMAIN_BLOCKED', {
            referer,
            targetHost,
            method: originalMethod,
            ip: authService.getClientIp(req),
          });
          return res.status(403).set({
            'X-Auth-Status': 'cross_subdomain_blocked',
            'X-Auth-Reason': 'cross_subdomain_forbidden',
          }).send('Forbidden: Cross-subdomain request blocked');
        }
      } catch (_) {}
    }
  }

  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  if (sessionService.isValidSession(token)) {
    const session = sessionService.activeSessions.get(token);

    // Check service access restrictions (fail-closed if restricted session)
    let authHost = '';
    try {
      authHost = new URL(config.BASE_URL).hostname.toLowerCase();
    } catch {}
    const reqHost = ((req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0]).toLowerCase().trim();

    if (targetService) {
      if (!sessionService.isSessionAllowedForService(session, targetService)) {
        return res.status(401).set({
          'X-Auth-Status': 'unauthorized',
          'X-Auth-Reason': 'service_not_allowed',
        }).send('Unauthorized: Service access not granted');
      }
    } else if (reqHost !== authHost) {
      if (!sessionService.isSessionAllowedForService(session, null)) {
        return res.status(401).set({
          'X-Auth-Status': 'unauthorized',
          'X-Auth-Reason': 'service_not_allowed',
        }).send('Unauthorized: Service access not granted');
      }
    }

    logServiceAccess(req, session, targetService, false);

    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': session && session.isTrusted ? 'trusted_device' : 'guest',
      'X-Auth-User': 'authenticated_user',
    }).send('OK');
  }

  // Authorize approver without redirect
  if (sessionService.isApprover(req)) {
    const approverToken = req.cookies[config.APPROVER_COOKIE_NAME];
    const approverSession = approverToken ? sessionService.approverSessions.get(approverToken) : null;
    logServiceAccess(req, approverSession, targetService, true);

    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': 'trusted_device',
      'X-Auth-User': 'approver',
    }).send('OK');
  }

  // Scanner Probe Detection for Unauthenticated Requests:
  const forwardedUri = req.headers['x-forwarded-uri'] || req.url || '';
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const fullUrl = `${proto}://${forwardedHost}${forwardedUri}`;

  const scannerCheck = securityService.isScannerRequest(req, fullUrl);
  if (scannerCheck.isScanner) {
    return securityService.blockScannerProbe(req, res, fullUrl, scannerCheck.reason);
  }

  // Rate Limiter for Unauthenticated Traffic:
  const rateCheck = securityService.checkUnauthRateLimit(clientIp);
  if (!rateCheck.allowed) {
    securityService.recordRateLimitHit(clientIp, fullUrl, req);
    return res.status(429).set({
      'X-Auth-Status': 'rate_limited',
      'Retry-After': String(rateCheck.retryAfter),
    }).send('Too Many Requests');
  }

  return res.status(401).send('Unauthorized');
});

module.exports = router;
