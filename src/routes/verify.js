const express = require('express');
const config = require('../config');
const { isAllowedOrigin } = require('../utils/originHelper');
const sessionService = require('../services/sessionService');

const router = express.Router();

router.all('/verify', (req, res) => {
  const origin = req.headers.origin;
  if (origin) {
    if (isAllowedOrigin(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
    } else {
      return res.status(403).send('Forbidden: CORS origin not allowed');
    }
  }
  if (req.method === 'OPTIONS') {
    return res.status(204).end();
  }

  const targetService = sessionService.getTargetServiceForRequest(req);
  if (targetService && targetService.disableService) {
    res.status(503).set({
      'X-Auth-Status': 'service_disabled',
      'X-Auth-Reason': 'service_disabled',
    });
    if (req.accepts('html') && !req.xhr) {
      return res.render('statusNotice', {
        title: `${targetService.name} is Temporarily Disabled`,
        message: 'This service is currently disabled on demand or undergoing maintenance.',
        actionUrl: config.BASE_URL,
        actionLabel: 'Return to Dashboard',
        type: 'error',
      });
    }
    return res.send('Service Disabled');
  }

  // Public service bypass: If authentication is disabled for this service, allow all traffic
  if (targetService && targetService.disableAuth) {
    return res.status(200).set({
      'X-Auth-Status': 'public',
      'X-Auth-Role': 'public',
      'X-Auth-User': 'anonymous',
    }).send('OK: Service is public');
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

    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': session && session.isTrusted ? 'trusted_device' : 'guest',
      'X-Auth-User': 'authenticated_user',
    }).send('OK');
  }

  // Authorize approver without redirect
  if (sessionService.isApprover(req)) {
    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': 'trusted_device',
      'X-Auth-User': 'approver',
    }).send('OK');
  }

  return res.status(401).send('Unauthorized');
});

module.exports = router;
