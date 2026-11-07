const express = require('express');
const config = require('../config');
const { isAllowedOrigin, isExtensionOrigin } = require('../utils/originHelper');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');
const securityService = require('../services/securityService');
const { auditLog } = require('../utils/auditLogger');
const { parseUserAgent } = require('../utils/deviceDetector');

const router = express.Router();

// CORS Preflight handler - strictly for authentic OPTIONS requests
router.options('/verify', (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    if (isAllowedOrigin(origin)) {
      if (isExtensionOrigin(origin)) {
        const reqHeaders = (req.headers['access-control-request-headers'] || '').toLowerCase();
        const hasTokenHeader = reqHeaders.includes('x-gateway-token') || reqHeaders.includes('x-auth-token');
        if (!hasTokenHeader) {
          return res.status(403).send('Forbidden: Extension CORS preflight requires X-Gateway-Token');
        }
      }
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
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
  const isApprover = sessionService.isApprover(req);
  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  const hasValidSession = Boolean(token && sessionService.isValidSession(token));
  const hasGatewayToken = authService.isGatewayTokenValid(req);

  // Authenticated sessions, approvers, and valid gateway tokens are exempt from jail blocks
  const isAuthenticated = isApprover || hasValidSession || hasGatewayToken;

  // Jail Enforcement (strictly unauthenticated requests; authenticated users, devices, and approvers are never locked out):
  const jailStatus = securityService.isIpJailed(clientIp);
  if (jailStatus.jailed && !isAuthenticated) {
    securityService.recordJailedHit(clientIp);
    return res.status(403).set({
      'X-Auth-Status': 'blocked',
      'X-Auth-Reason': 'ip_jailed',
      'Retry-After': String(jailStatus.remainingSeconds),
    }).send(`Forbidden: IP temporarily banned (${jailStatus.remainingSeconds}s remaining)`);
  }

  // If this IP was previously jailed but now carries an active authenticated session or approver, clear jail
  if (jailStatus.jailed && isAuthenticated) {
    securityService.unjailIp(clientIp, 'Auto-unjailed: Authenticated activity detected');
  }

  const targetService = sessionService.getTargetServiceForRequest(req);
  if (targetService && targetService.disableService) {
    return res.status(503).set({
      'X-Auth-Status': 'service_disabled',
      'X-Auth-Reason': 'service_disabled',
    }).send('Service Disabled');
  }

  const forwardedHost = (req.headers['x-forwarded-host'] || req.headers.host || '').split(':')[0].toLowerCase().trim();
  const forwardedUri = req.headers['x-forwarded-uri'] || req.url || '';
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const fullUrl = `${proto}://${forwardedHost}${forwardedUri}`;

  const origin = req.headers.origin;
  const isExtension = isExtensionOrigin(origin);
  const originalMethod = (req.headers['x-forwarded-method'] || req.method || 'GET').toUpperCase();
  const acrm = req.headers['access-control-request-method'];
  const isCorsPreflight = originalMethod === 'OPTIONS' && Boolean(origin && acrm);

  if (origin) {
    if (isAllowedOrigin(origin)) {
      if (isCorsPreflight) {
        if (isExtension) {
          const reqHeaders = (req.headers['access-control-request-headers'] || '').toLowerCase();
          const hasTokenHeader = reqHeaders.includes('x-gateway-token') || reqHeaders.includes('x-auth-token');
          if (!hasTokenHeader) {
            return res.status(403).send('Forbidden: Extension CORS preflight requires X-Gateway-Token');
          }
        }
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
        const reqHeaders = req.headers['access-control-request-headers'];
        res.setHeader('Access-Control-Allow-Headers', reqHeaders || 'Content-Type, Authorization, X-Requested-With, X-Gateway-Token, X-Auth-Token');
        res.setHeader('Access-Control-Max-Age', '86400');
        return res.status(200).set({
          'X-Auth-Status': 'public',
          'X-Auth-Role': 'preflight',
          'X-Auth-User': 'anonymous',
        }).send('OK: CORS Preflight');
      }

      // Non-preflight requests: set CORS headers for non-extension origins immediately
      if (!isExtension) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Credentials', 'true');
      }
    } else {
      return res.status(403).send('Forbidden: CORS origin not allowed');
    }
  }

  // If this is a standalone OPTIONS request without origin/acrm, approve it
  if (originalMethod === 'OPTIONS') {
    return res.status(200).set({
      'X-Auth-Status': 'public',
      'X-Auth-Role': 'preflight',
      'X-Auth-User': 'anonymous',
    }).send('OK: CORS Preflight');
  }

  // Gateway Secret Token check (via custom headers: X-Gateway-Token, X-Auth-Token, or Bearer token)
  if (authService.isGatewayTokenValid(req)) {
    if (isExtension && origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
    }
    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': 'api_token',
      'X-Auth-User': 'api_user',
    }).send('OK: Authenticated via Gateway Token');
  }

  // Browser extensions MUST authenticate via Gateway Token; they cannot hijack ambient user session cookies
  if (isExtension) {
    return res.status(401).set({
      'X-Auth-Status': 'unauthorized',
      'X-Auth-Reason': 'extension_gateway_token_required',
    }).send('Unauthorized: Extensions must provide a valid X-Gateway-Token');
  }

  // Cross-Subdomain XSS & Request Isolation:
  // Prevent malicious scripts executing on one subdomain (e.g. stash.szycic.com) from
  // making cross-subdomain fetch/XHR API requests or state-mutating requests (POST, PUT, DELETE)
  // to another protected service (e.g. docs.szycic.com, tools.szycic.com).
  let baseAuthHost = '';
  try {
    baseAuthHost = new URL(config.BASE_URL).hostname.toLowerCase();
  } catch {}
  const authHost = baseAuthHost;

  const targetHost = (targetService && targetService.url)
    ? new URL(targetService.url).hostname.toLowerCase()
    : forwardedHost;

  const secFetchMode = req.headers['sec-fetch-mode'];
  const secFetchSite = req.headers['sec-fetch-site'];

  if (targetHost && targetHost !== baseAuthHost) {
    if (origin) {
      try {
        const originHost = new URL(origin).hostname.toLowerCase();
        if (!isExtension && originHost !== targetHost && originHost !== baseAuthHost) {
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

  if (hasValidSession) {
    const session = sessionService.activeSessions.get(token);

    // Check service access restrictions (fail-closed if restricted session)
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

    securityService.logServiceAccess(req, session, targetService, false);

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
    const effectiveSession = approverSession ? sessionService.getLinkedActiveSession(approverSession) : null;
    securityService.logServiceAccess(req, effectiveSession || approverSession, targetService, true);

    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': 'trusted_device',
      'X-Auth-User': 'approver',
    }).send('OK');
  }

  // =========================================================================
  // UNAUTHENTICATED TRAFFIC ONLY BEYOND THIS POINT:
  // Legitimate authenticated devices never reach here.
  // =========================================================================

  // Scanner Probe Detection (strictly unauthenticated requests):
  const scannerCheck = securityService.isScannerRequest(req, fullUrl);
  if (scannerCheck.isScanner) {
    return securityService.blockScannerProbe(req, res, fullUrl, scannerCheck.reason);
  }

  // Public service bypass: If authentication is disabled for this service, allow clean unauthenticated traffic
  if (targetService && targetService.disableAuth) {
    return res.status(200).set({
      'X-Auth-Status': 'public',
      'X-Auth-Role': 'public',
      'X-Auth-User': 'anonymous',
    }).send('OK: Service is public');
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

  if (forwardedHost === authHost) {
    securityService.recordAuthRequired(clientIp, config.getAuthService(), fullUrl, req);
  }

  return res.status(401).send('Unauthorized');
});

module.exports = router;
