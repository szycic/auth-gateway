const express = require('express');
const crypto = require('crypto');
const config = require('../config');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const socketService = require('../services/socketService');
const { auditLog } = require('../utils/auditLogger');

const router = express.Router();

router.get('/approve', (req, res) => {
  const { id, key } = req.query;

  if (!id || !key || typeof id !== 'string' || typeof key !== 'string') {
    return res.status(400).render('statusNotice', {
      title: 'Invalid Request',
      message: 'Missing or malformed authorization parameters.',
      type: 'error',
    });
  }

  // If mobile is NOT authenticated as Approver, require login first!
  if (!sessionService.isApprover(req)) {
    const returnUrl = `/auth/approve?id=${encodeURIComponent(id)}&key=${encodeURIComponent(key)}`;
    return res.redirect(`/auth/approver/login?returnTo=${encodeURIComponent(returnUrl)}`);
  }

  const session = sessionService.pendingLoginSessions.get(id);
  if (!session) {
    return res.status(404).render('statusNotice', {
      title: 'Session Not Found',
      message: 'This authorization session does not exist or has already been used.',
      type: 'error',
      actionUrl: '/auth/sessions',
      actionLabel: 'View Active Sessions',
    });
  }

  if (Date.now() > session.expiresAt || session.status !== 'pending') {
    if (session.pairCode) authService.pairingCodes.delete(session.pairCode);
    sessionService.pendingLoginSessions.delete(id);
    return res.status(410).render('statusNotice', {
      title: 'Session Expired',
      message: 'This authorization request has expired. Please refresh the session on the desktop screen.',
      type: 'warning',
      actionUrl: '/auth/sessions',
      actionLabel: 'Active Sessions',
      secondaryUrl: '/auth/sessions?action=scan',
      secondaryLabel: 'Scan QR Again',
    });
  }

  // Validate secret key
  const keyBuf = Buffer.from(key);
  const sessionKeyBuf = Buffer.from(session.key);
  if (keyBuf.length !== sessionKeyBuf.length || !crypto.timingSafeEqual(keyBuf, sessionKeyBuf)) {
    return res.status(403).render('statusNotice', {
      title: 'Access Denied',
      message: 'The authorization key provided does not match.',
      type: 'error',
    });
  }

  // Resolve target platform if the user initiated login from a specific service
  const targetService = session.serviceId
    ? config.getService(session.serviceId)
    : (session.redirect ? config.getService(session.redirect) : (session.serviceName ? config.getService(session.serviceName) : null));

  // Set cache prevention headers
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');

  return res.render('approvalDecision', {
    id,
    key,
    desktopIp: session.desktopIp,
    friendlyDevice: session.friendlyDevice,
    serviceName: session.serviceName,
    targetService,
    expiresAt: session.expiresAt,
    activeSessionsList: Array.from(sessionService.activeSessions.values()),
    services: config.services,
  });
});

router.post('/approve/action', (req, res) => {
  if (!sessionService.isApprover(req)) {
    return res.status(401).send('Unauthorized approver.');
  }

  const { id, key, action, trusted, customName } = req.body;
  if (!id || !key || typeof id !== 'string' || typeof key !== 'string') {
    return res.status(400).send('Invalid request parameters.');
  }

  const session = sessionService.pendingLoginSessions.get(id);
  if (!session) {
    return res.status(404).render('statusNotice', {
      title: 'Session Expired',
      message: 'This authorization session is no longer active.',
      type: 'warning',
      actionUrl: '/auth/sessions',
      actionLabel: 'Active Sessions',
      secondaryUrl: '/auth/sessions?action=scan',
      secondaryLabel: 'Scan QR Again',
    });
  }

  // Timing safe key check
  const keyBuf = Buffer.from(key);
  const sessionKeyBuf = Buffer.from(session.key);
  if (keyBuf.length !== sessionKeyBuf.length || !crypto.timingSafeEqual(keyBuf, sessionKeyBuf)) {
    return res.status(403).send('Invalid authorization key.');
  }

  if (session.pairCode) {
    authService.pairingCodes.delete(session.pairCode);
  }
  sessionService.pendingLoginSessions.delete(id);

  if (action === 'reject') {
    auditLog('SESSION_REJECTED', {
      id,
      desktopIp: session.desktopIp,
      device: session.friendlyDevice,
      approverIp: authService.getClientIp(req),
    });
    socketService.notifySessionRejected(id, { message: 'Authorization was rejected by the approver.' });

    return res.render('statusNotice', {
      title: 'Request Rejected',
      message: `Access denied for desktop (${session.friendlyDevice || 'Device'}).`,
      type: 'error',
      actionUrl: '/auth/sessions',
      actionLabel: 'Back to Sessions',
      secondaryUrl: '/',
      secondaryLabel: 'Return to Portal',
    });
  }

  // Action is APPROVE -> Grant desktop session
  const isTrusted = trusted === 'true';
  const sessionToken = crypto.randomBytes(48).toString('base64url');
  const sessionId = crypto.randomUUID();

  const finalDeviceName = (typeof customName === 'string' && customName.trim())
    ? customName.trim().slice(0, 50)
    : (session.friendlyDevice || 'Desktop Browser');

  // Parse custom expiration time
  let ttlHours = config.SESSION_TTL_HOURS;
  const rawTtl = req.body.sessionTtl;
  const rawCustomTtl = req.body.customTtlHours;

  if (rawTtl === 'custom' && rawCustomTtl) {
    const parsed = parseFloat(rawCustomTtl);
    if (!isNaN(parsed) && parsed > 0) {
      ttlHours = parsed;
    }
  } else if (rawTtl && rawTtl !== 'default' && rawTtl !== '72') {
    const parsed = parseFloat(rawTtl);
    if (!isNaN(parsed) && parsed > 0) {
      ttlHours = parsed;
    }
  }

  let tokenExpiresAt;
  if (isTrusted) {
    tokenExpiresAt = Date.now() + 10 * 365 * 24 * 3600 * 1000;
  } else {
    tokenExpiresAt = Date.now() + Math.round(ttlHours * 3600 * 1000);
  }

  // Parse allowed services
  let allowedServices = null;
  if (req.body.services) {
    let rawServices = [];
    if (Array.isArray(req.body.services)) {
      rawServices = req.body.services.map(s => String(s).trim()).filter(Boolean);
    } else if (typeof req.body.services === 'string' && req.body.services.trim()) {
      rawServices = [req.body.services.trim()];
    }

    const allConfiguredServices = (config.services || []).filter(s => !s.disableService && !s.disableAuth);
    if (rawServices.length > 0 && rawServices.length < allConfiguredServices.length) {
      allowedServices = rawServices;
    }
  }

  sessionService.activeSessions.set(sessionToken, {
    id: sessionId,
    token: sessionToken,
    createdAt: Date.now(),
    expiresAt: tokenExpiresAt,
    isTrusted,
    ip: session.desktopIp,
    userAgent: session.desktopUserAgent,
    friendlyDevice: finalDeviceName,
    service: session.serviceName || null,
    type: isTrusted ? 'trusted_device' : 'desktop_guest',
    allowedServices,
  });

  sessionService.savePersistedSessions();

  auditLog('SESSION_APPROVED', {
    sessionId,
    loginSessionId: id,
    device: finalDeviceName,
    desktopIp: session.desktopIp,
    trusted: isTrusted,
    ttlHours: isTrusted ? 'permanent' : ttlHours,
    services: allowedServices ? allowedServices.join(',') : 'all',
    approverIp: authService.getClientIp(req),
  });

  // Create single-use exchange code
  const exchangeCode = authService.createExchangeCode(sessionToken, 60 * 1000);

  // Emit real-time approved event to desktop room
  socketService.notifySessionApproved(id, {
    code: exchangeCode,
    redirect: session.redirect,
  });

  let servicesMsg = '';
  if (Array.isArray(allowedServices) && allowedServices.length > 0) {
    const svcNames = allowedServices.map(id => {
      const found = (config.services || []).find(svc => svc.id.toLowerCase() === id.toLowerCase());
      return found ? found.name : id;
    });
    servicesMsg = ` (Allowed services: ${svcNames.join(', ')})`;
  }

  return res.render('statusNotice', {
    title: isTrusted ? 'Trusted Device Authorized!' : 'Device Approved!',
    message: isTrusted
      ? `Permanently authorized ${finalDeviceName} (${session.desktopIp}) as a Trusted Device.${servicesMsg}`
      : `Granted access to ${finalDeviceName} (${session.desktopIp}).${servicesMsg}`,
    type: 'success',
    actionUrl: '/auth/sessions',
    actionLabel: 'Manage Active Sessions',
    secondaryUrl: '/',
    secondaryLabel: 'Open Portal',
  });
});

module.exports = router;
