const express = require('express');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const socketService = require('../services/socketService');
const { auditLog } = require('../utils/auditLogger');
const { verifySameOrigin } = require('../utils/csrfHelper');

const router = express.Router();
router.use(verifySameOrigin);

// Session management dashboard
router.get('/sessions', (req, res) => {
  if (!sessionService.isApprover(req)) {
    return res.redirect('/auth/approver/login?returnTo=/auth/sessions');
  }

  const currentApproverToken = req.cookies[config.APPROVER_COOKIE_NAME] || null;
  const currentAuthToken = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'] || null;
  let currentSession = null;
  if (currentAuthToken) {
    currentSession = sessionService.activeSessions.get(currentAuthToken);
  }
  if (!currentSession && currentApproverToken) {
    for (const s of sessionService.activeSessions.values()) {
      if (s.approverToken === currentApproverToken) {
        currentSession = s;
        break;
      }
    }
  }

  const currentSessionId = currentSession ? currentSession.id : null;
  const currentSessionToken = currentSession ? currentSession.token : currentAuthToken;

  const activeSessionsList = Array.from(sessionService.activeSessions.values()).sort((a, b) => {
    const orderA = typeof a.sortOrder === 'number' ? a.sortOrder : 999999;
    const orderB = typeof b.sortOrder === 'number' ? b.sortOrder : 999999;
    if (orderA !== orderB) return orderA - orderB;
    return (b.createdAt || 0) - (a.createdAt || 0);
  });

  return res.render('sessionsDashboard', {
    activeSessionsList,
    notice: req.query.notice,
    currentSessionId,
    currentSessionToken,
    currentApproverToken,
  });
});

// Revoke session(s)
router.post('/sessions/revoke', (req, res) => {
  if (!sessionService.isApprover(req)) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }
    return res.status(401).send('Unauthorized.');
  }

  const { sessionId, all } = req.body;
  const isAll = all === 'true' || all === true;

  if (isAll) {
    const currentApproverToken = req.cookies[config.APPROVER_COOKIE_NAME];
    const currentAuthToken = req.cookies[config.AUTH_COOKIE_NAME];
    for (const [appTok] of sessionService.approverSessions.entries()) {
      if (appTok !== currentApproverToken) {
        sessionService.approverSessions.delete(appTok);
      }
    }
    let count = 0;
    for (const [tok, session] of sessionService.activeSessions.entries()) {
      if (tok !== currentAuthToken && session.approverToken !== currentApproverToken) {
        sessionService.activeSessions.delete(tok);
        count++;
      }
    }
    sessionService.savePersistedSessions();
    socketService.notifyAllSessionsRevoked();
    auditLog('ALL_SESSIONS_REVOKED', {
      count,
      revokedByIp: authService.getClientIp(req),
    });

    if (req.accepts('json') && !req.accepts('html')) {
      return res.json({ success: true, all: true, count, message: `Revoked ${count} active sessions.` });
    }
    return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Revoked ${count} active sessions.`));
  }

  if (sessionId) {
    let targetSession = null;
    let targetToken = null;

    for (const [token, session] of sessionService.activeSessions.entries()) {
      if (session.id === sessionId || session.token === sessionId || token === sessionId) {
        targetSession = session;
        targetToken = token;
        break;
      }
    }

    if (targetSession) {
      const sid = targetSession.id || sessionId;
      const appToken = targetSession.approverToken;

      // Revoke the approver session completely if this device is an approver!
      if (appToken) {
        sessionService.approverSessions.delete(appToken);
      }
      for (const [aTok, aSess] of sessionService.approverSessions.entries()) {
        if (aSess.sessionId === sid || aSess.activeSessionToken === targetToken || (appToken && aTok === appToken)) {
          sessionService.approverSessions.delete(aTok);
        }
      }

      sessionService.activeSessions.delete(targetToken);
      sessionService.savePersistedSessions();
      socketService.notifySessionRevoked(sid, targetToken, appToken);

      const isApproverDevice = !!(targetSession.isApprover || targetSession.type === 'approver' || appToken);

      auditLog('SESSION_REVOKED', {
        sessionId: sid,
        device: targetSession.friendlyDevice,
        deviceIp: targetSession.ip,
        isApprover: isApproverDevice,
        revokedByIp: authService.getClientIp(req),
      });

      // If the current caller revoked their own session or approver token, clear cookies immediately
      const currentAppTok = req.cookies[config.APPROVER_COOKIE_NAME];
      const currentAuthTok = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
      const isCurrentSession = !!(
        (currentAppTok && (currentAppTok === appToken || !sessionService.approverSessions.has(currentAppTok))) ||
        (currentAuthTok && currentAuthTok === targetToken)
      );

      if (isCurrentSession) {
        const cookieOpts = getCookieOptions(req);
        delete cookieOpts.maxAge;
        res.clearCookie(config.APPROVER_COOKIE_NAME, cookieOpts);
        res.clearCookie(config.AUTH_COOKIE_NAME, cookieOpts);
        if (cookieOpts.domain) {
          const hostOnly = { ...cookieOpts };
          delete hostOnly.domain;
          res.clearCookie(config.APPROVER_COOKIE_NAME, hostOnly);
          res.clearCookie(config.AUTH_COOKIE_NAME, hostOnly);
        }
      }

      const msg = isApproverDevice
        ? `Approver session for ${targetSession.friendlyDevice} was completely revoked.`
        : `Session for ${targetSession.friendlyDevice} was revoked.`;

      if (req.accepts('json') && !req.accepts('html')) {
        return res.json({ success: true, sessionId: sid, isCurrentSession, message: msg });
      }
      return res.redirect('/auth/sessions?notice=' + encodeURIComponent(msg));
    }

    // Direct check in approverSessions (fallback if not in activeSessions)
    for (const [aTok, aSess] of sessionService.approverSessions.entries()) {
      if (aTok === sessionId || aSess.sessionId === sessionId) {
        sessionService.approverSessions.delete(aTok);
        if (aSess.activeSessionToken) {
          sessionService.activeSessions.delete(aSess.activeSessionToken);
        }
        sessionService.savePersistedSessions();
        socketService.notifySessionRevoked(aSess.sessionId || sessionId, aSess.activeSessionToken, aTok);
        auditLog('APPROVER_SESSION_REVOKED', {
          token: aTok,
          revokedByIp: authService.getClientIp(req),
        });

        const currentAppTok = req.cookies[config.APPROVER_COOKIE_NAME];
        const isCurrentSession = (currentAppTok && currentAppTok === aTok);
        if (isCurrentSession) {
          const cookieOpts = getCookieOptions(req);
          delete cookieOpts.maxAge;
          res.clearCookie(config.APPROVER_COOKIE_NAME, cookieOpts);
        }

        if (req.accepts('json') && !req.accepts('html')) {
          return res.json({ success: true, sessionId, isCurrentSession, message: 'Approver session was revoked.' });
        }
        return res.redirect('/auth/sessions?notice=' + encodeURIComponent('Approver session was revoked.'));
      }
    }
  }

  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ error: 'Session not found' });
  }
  return res.redirect('/auth/sessions');
});

// Rename session
router.post('/sessions/rename', (req, res) => {
  if (!sessionService.isApprover(req)) {
    return res.status(401).send('Unauthorized.');
  }

  const { sessionId, name } = req.body;
  if (!sessionId || typeof sessionId !== 'string') {
    return res.status(400).send('Invalid session ID.');
  }

  const trimmed = typeof name === 'string' ? name.trim().slice(0, 50) : '';
  let updatedDevice = null;

  for (const [, session] of sessionService.activeSessions.entries()) {
    if (session.id === sessionId) {
      session.friendlyDevice = trimmed || parseUserAgent(session.userAgent) || 'Desktop Browser';
      updatedDevice = session.friendlyDevice;
      break;
    }
  }

  if (updatedDevice) {
    sessionService.savePersistedSessions();
    return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Renamed device to "${updatedDevice}".`));
  }

  return res.redirect('/auth/sessions');
});

// Reorder active sessions
router.post('/sessions/reorder', (req, res) => {
  if (!sessionService.isApprover(req)) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }
    return res.status(401).send('Unauthorized.');
  }

  const { order } = req.body;
  if (!Array.isArray(order)) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(400).json({ error: 'Invalid order list.' });
    }
    return res.status(400).send('Invalid order list.');
  }

  const sessionsById = new Map();
  for (const session of sessionService.activeSessions.values()) {
    if (session.id) {
      sessionsById.set(session.id, session);
    }
  }

  order.forEach((item, index) => {
    const sessionId = typeof item === 'string' ? item : (item && item.id);
    const session = sessionsById.get(sessionId);
    if (session) {
      session.sortOrder = typeof (item && item.sortOrder) === 'number' ? item.sortOrder : index;
      if (item && typeof item.group !== 'undefined') {
        const trimmed = typeof item.group === 'string' ? item.group.trim().slice(0, 40) : '';
        session.group = trimmed || null;
      }
    }
  });

  sessionService.savePersistedSessions();

  if (req.accepts('json') && !req.accepts('html')) {
    return res.json({ success: true, count: order.length });
  }
  return res.redirect('/auth/sessions');
});

// Update session group
router.post('/sessions/group', (req, res) => {
  if (!sessionService.isApprover(req)) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }
    return res.status(401).send('Unauthorized.');
  }

  const { sessionId, group } = req.body;
  if (!sessionId || typeof sessionId !== 'string') {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(400).json({ error: 'Invalid session ID.' });
    }
    return res.status(400).send('Invalid session ID.');
  }

  let targetSession = null;
  for (const session of sessionService.activeSessions.values()) {
    if (session.id === sessionId) {
      targetSession = session;
      break;
    }
  }

  if (!targetSession) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(404).json({ error: 'Session not found.' });
    }
    return res.redirect('/auth/sessions');
  }

  const trimmed = typeof group === 'string' ? group.trim().slice(0, 40) : '';
  targetSession.group = trimmed || null;
  sessionService.savePersistedSessions();

  if (req.accepts('json') && !req.accepts('html')) {
    return res.json({ success: true, sessionId, group: targetSession.group });
  }
  return res.redirect('/auth/sessions?notice=' + encodeURIComponent(trimmed ? `Moved to group "${trimmed}".` : 'Removed from group.'));
});

// Update session service permissions
router.post('/sessions/permissions', (req, res) => {
  if (!sessionService.isApprover(req)) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(401).json({ error: 'Unauthorized.' });
    }
    return res.status(401).send('Unauthorized.');
  }

  const { sessionId, services } = req.body;
  if (!sessionId || typeof sessionId !== 'string') {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(400).json({ error: 'Invalid session ID.' });
    }
    return res.status(400).send('Invalid session ID.');
  }

  let targetSession = null;
  for (const session of sessionService.activeSessions.values()) {
    if (session.id === sessionId) {
      targetSession = session;
      break;
    }
  }

  if (!targetSession) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(404).json({ error: 'Session not found or expired.' });
    }
    return res.redirect('/auth/sessions?notice=' + encodeURIComponent('Session not found or expired.'));
  }

  const allActiveServices = (config.getActiveServices ? config.getActiveServices() : config.services)
    .map(s => (s.id || '').toLowerCase());
  const selectedList = (Array.isArray(services) ? services : (services ? [services] : []))
    .map(s => String(s).trim().toLowerCase())
    .filter(Boolean);

  if (selectedList.length === 0) {
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(400).json({ error: 'At least one service must be selected.' });
    }
    return res.redirect('/auth/sessions?notice=' + encodeURIComponent('At least one service must be selected.'));
  }

  // If all active services are selected or '*' is included, null means unrestricted full access
  const isAll = selectedList.includes('*') || (allActiveServices.length > 0 && allActiveServices.every(id => selectedList.includes(id)));
  targetSession.allowedServices = isAll ? null : selectedList;
  sessionService.savePersistedSessions();

  if (socketService.notifySessionPermissionsUpdated) {
    socketService.notifySessionPermissionsUpdated(targetSession.id, targetSession.allowedServices);
  }

  auditLog('SESSION_PERMISSIONS_UPDATED', {
    ip: authService.getClientIp(req),
    sessionId: targetSession.id,
    device: targetSession.friendlyDevice,
    allowedServices: targetSession.allowedServices ? targetSession.allowedServices.join(',') : 'all',
  });

  const svcNames = targetSession.allowedServices
    ? targetSession.allowedServices.map(id => {
        const found = (config.services || []).find(s => (s.id || '').toLowerCase() === id);
        return found ? found.name : id;
      }).join(', ')
    : 'All Services';

  if (req.accepts('json') && !req.accepts('html')) {
    return res.json({
      success: true,
      sessionId: targetSession.id,
      allowedServices: targetSession.allowedServices,
      accessLabel: svcNames,
      message: `Permissions updated for "${targetSession.friendlyDevice}": ${svcNames}`,
    });
  }

  return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Permissions updated for "${targetSession.friendlyDevice}".`));
});

// Desktop token exchange
router.get('/exchange', (req, res) => {
  const { code, redirect } = req.query;
  let sessionToken = null;

  if (code && typeof code === 'string') {
    sessionToken = authService.consumeExchangeCode(code);
  }

  if (sessionToken && sessionService.isValidSession(sessionToken)) {
    const session = sessionService.activeSessions.get(sessionToken);
    const maxAgeMs = session && session.isTrusted
      ? 10 * 365 * 24 * 3600 * 1000 // 10 years permanent
      : config.SESSION_TTL_HOURS * 3600 * 1000;

    res.cookie(config.AUTH_COOKIE_NAME, sessionToken, getCookieOptions(req, maxAgeMs));
    const target = config.normalizeRedirect(redirect, '/');
    return res.redirect(target);
  }

  return res.redirect('/login');
});

// Logout
router.get('/logout', (req, res) => {
  auditLog('USER_LOGOUT', { ip: authService.getClientIp(req) });
  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  if (token) {
    sessionService.activeSessions.delete(token);
  }
  const approverToken = req.cookies[config.APPROVER_COOKIE_NAME];
  if (approverToken) {
    sessionService.approverSessions.delete(approverToken);
  }
  sessionService.savePersistedSessions();

  const cookieOptions = getCookieOptions(req);
  delete cookieOptions.maxAge;
  res.clearCookie(config.AUTH_COOKIE_NAME, cookieOptions);
  res.clearCookie('share_auth_token', cookieOptions);
  res.clearCookie(config.APPROVER_COOKIE_NAME, cookieOptions);
  if (cookieOptions.domain) {
    const hostOnly = { ...cookieOptions };
    delete hostOnly.domain;
    res.clearCookie(config.AUTH_COOKIE_NAME, hostOnly);
    res.clearCookie('share_auth_token', hostOnly);
    res.clearCookie(config.APPROVER_COOKIE_NAME, hostOnly);
  }

  const noticeParam = req.query.notice ? ('?notice=' + encodeURIComponent(req.query.notice)) : '';
  const redirectTarget = config.normalizeRedirect(req.query.redirect || req.query.returnTo, '/login' + noticeParam);
  return res.redirect(redirectTarget);
});

// Rename current device
router.post('/device/rename', (req, res) => {
  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  if (!sessionService.isValidSession(token)) {
    return res.redirect('/login');
  }

  const session = sessionService.activeSessions.get(token);
  if (!session) return res.redirect('/login');

  const { name } = req.body;
  const trimmed = typeof name === 'string' ? name.trim().slice(0, 50) : '';
  if (trimmed) {
    session.friendlyDevice = trimmed;
    sessionService.savePersistedSessions();
  }

  return res.redirect('/?notice=' + encodeURIComponent(`Device renamed to "${session.friendlyDevice}".`));
});

module.exports = router;
