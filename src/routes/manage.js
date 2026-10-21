const express = require('express');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const socketService = require('../services/socketService');
const { renderSessionsDashboardHtml } = require('../views/sessionsDashboardView');

const router = express.Router();

// 1. Session Management Dashboard
router.get('/sessions', (req, res) => {
  if (!sessionService.isApprover(req)) {
    return res.redirect('/auth/approver/login?returnTo=/auth/sessions');
  }

  return res.send(renderSessionsDashboardHtml({
    activeSessionsList: Array.from(sessionService.activeSessions.values()),
    notice: req.query.notice,
  }));
});

// 2. Revoke a specific session or all sessions
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
    for (const [appTok] of sessionService.approverSessions.entries()) {
      if (appTok !== currentApproverToken) {
        sessionService.approverSessions.delete(appTok);
      }
    }
    const count = sessionService.activeSessions.size;
    sessionService.activeSessions.clear();
    sessionService.savePersistedSessions();
    socketService.notifyAllSessionsRevoked();

    if (req.accepts('json') && !req.accepts('html')) {
      return res.json({ success: true, all: true, count, message: `Revoked all ${count} active sessions.` });
    }
    return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Revoked all ${count} active sessions.`));
  }

  if (sessionId) {
    for (const [token, session] of sessionService.activeSessions.entries()) {
      if (session.id === sessionId || session.token === sessionId || token === sessionId) {
        const sid = session.id || sessionId;
        if (session.approverToken) {
          sessionService.approverSessions.delete(session.approverToken);
        }
        sessionService.activeSessions.delete(token);
        sessionService.savePersistedSessions();
        socketService.notifySessionRevoked(sid, token);

        if (req.accepts('json') && !req.accepts('html')) {
          return res.json({ success: true, sessionId: sid, message: `Session for ${session.friendlyDevice} was revoked.` });
        }
        return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Session for ${session.friendlyDevice} was revoked.`));
      }
    }
  }

  if (req.accepts('json') && !req.accepts('html')) {
    return res.status(404).json({ error: 'Session not found' });
  }
  return res.redirect('/auth/sessions');
});

// 3. Rename a specific session in dashboard
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

// 4. Desktop Token Exchange Endpoint
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

// 5. Logout Endpoint
router.get('/logout', (req, res) => {
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

// 6. Current Session Device Rename
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
