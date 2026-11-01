const express = require('express');
const config = require('../config');
const versionHelper = require('../utils/versionHelper');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');
const { parseUserAgent } = require('../utils/deviceDetector');
const { auditLog } = require('../utils/auditLogger');

const router = express.Router();

router.get('/version', (req, res) => {
  return res.json(versionHelper.getMetadata());
});

router.get('/launch/:serviceId', (req, res) => {
  let token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  let session = sessionService.activeSessions.get(token);
  const isApprover = sessionService.isApprover(req);

  if (!session || !sessionService.isValidSession(token)) {
    if (isApprover) {
      session = sessionService.mintApproverSession(req, res);
      token = session.token;
    } else {
      const returnUrl = `/launch/${encodeURIComponent(req.params.serviceId)}`;
      return res.redirect(`/login?redirect=${encodeURIComponent(returnUrl)}`);
    }
  }

  const service = (config.services || []).find(s => s.id && s.id.toLowerCase() === req.params.serviceId.toLowerCase());
  if (!service) {
    return res.redirect('/');
  }

  if (service.disableService) {
    return res.status(503).render('statusNotice', {
      title: `${service.name} is Temporarily Disabled`,
      message: 'This service is currently disabled on demand or undergoing maintenance.',
      actionUrl: '/',
      actionLabel: 'Return to Dashboard',
      type: 'error',
    });
  }

  if (!sessionService.isSessionAllowedForService(session, service)) {
    return res.status(403).render('statusNotice', {
      title: 'Access Restricted',
      message: `Your active session is not authorized to access ${service.name}.`,
      actionUrl: '/',
      actionLabel: 'Return to Dashboard',
      type: 'error',
    });
  }

  auditLog('SERVICE_REDIRECT', {
    service: service.name,
    serviceId: service.id,
    url: service.url,
    ip: authService.getClientIp(req),
    device: (session && session.friendlyDevice) || parseUserAgent(req.headers['user-agent'] || '') || (isApprover ? 'Approver Device' : 'Desktop Browser'),
    sessionId: session ? session.id : undefined,
    trusted: session ? session.isTrusted : false,
    source: 'portal',
  });

  return res.redirect(service.url || '/');
});

router.get(['/', '/portal'], (req, res) => {
  let token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  let session = sessionService.activeSessions.get(token);

  if (!session || !sessionService.isValidSession(token)) {
    if (sessionService.isApprover(req)) {
      session = sessionService.mintApproverSession(req, res);
      token = session.token;
    } else {
      return res.redirect('/login');
    }
  }

  return res.render('portalDashboard', {
    session,
    isApproverUser: sessionService.isApprover(req),
    services: config.services,
    showRestricted: config.showRestricted !== undefined ? config.showRestricted : (config.app && config.app.showRestricted),
    isSessionAllowedForService: sessionService.isSessionAllowedForService,
    notice: req.query.notice,
  });
});

module.exports = router;
