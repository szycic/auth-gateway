const express = require('express');
const crypto = require('crypto');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const { auditLog } = require('../utils/auditLogger');

const router = express.Router();

router.get('/login', (req, res) => {
  const rawRedirect = req.query.redirect || req.query.returnTo || '';
  const matchedService = config.getService(req.query.service || rawRedirect);
  const redirectTarget = config.isAllowedRedirect(rawRedirect) ? rawRedirect : '';

  if (matchedService && matchedService.disableService) {
    return res.status(503).render('statusNotice', {
      title: `${matchedService.name} is Temporarily Disabled`,
      message: 'This service is currently disabled on demand or undergoing maintenance.',
      actionUrl: '/',
      actionLabel: 'Return to Dashboard',
      type: 'error',
    });
  }

  if (matchedService && matchedService.disableAuth) {
    return res.redirect(redirectTarget || matchedService.url || '/');
  }

  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  if (sessionService.isValidSession(token)) {
    const session = sessionService.activeSessions.get(token);
    if (redirectTarget) {
      const targetService = config.getService(redirectTarget);
      if (targetService && !sessionService.isSessionAllowedForService(session, targetService)) {
        return res.status(403).render('statusNotice', {
          title: 'Access Restricted',
          message: `Your active session is not authorized to access ${targetService.name}.`,
          actionUrl: '/',
          actionLabel: 'Return to Dashboard',
          type: 'error',
        });
      }
    }
    return res.redirect(redirectTarget || '/');
  }

  // Approver auto-authorization
  if (sessionService.isApprover(req)) {
    if (req.query.notice) {
      return res.render('approverSelfAuth', {
        redirect: redirectTarget,
        notice: req.query.notice,
      });
    }

    sessionService.mintApproverSession(req, res);
    return res.redirect(redirectTarget || '/');
  }

  return res.render('desktopLogin', {
    matchedService,
    redirectTarget,
    error: req.query.error || '',
    notice: req.query.notice || '',
  });
});

router.post('/login', (req, res) => {
  const { password, redirect } = req.body;
  const rawRedirect = redirect || req.query.redirect || req.query.returnTo || '';
  const redirectTarget = config.isAllowedRedirect(rawRedirect) ? rawRedirect : '/';

  const currentHash = authService.getApproverPasswordHash();
  if (!currentHash) {
    return res.status(503).render('approverSetup', {});
  }

  const clientIp = authService.getClientIp(req);
  const lockoutStatus = authService.checkLoginLockout(clientIp);
  if (lockoutStatus.locked) {
    const err = `Too many failed attempts. Locked out for ${lockoutStatus.remainingMins} min.`;
    return res.redirect(`/login?redirect=${encodeURIComponent(redirectTarget)}&error=${encodeURIComponent(err)}`);
  }

  if (!password || typeof password !== 'string') {
    return res.redirect(`/login?redirect=${encodeURIComponent(redirectTarget)}&error=${encodeURIComponent('Please enter your password.')}`);
  }

  const isValid = authService.verifyPassword(password, currentHash);
  if (!isValid) {
    const attempt = authService.recordFailedLogin(clientIp);
    auditLog('LOGIN_FAILED', {
      ip: clientIp,
      locked: attempt.locked,
      remainingAttempts: attempt.remainingAttempts,
    });
    if (attempt.locked) {
      return res.redirect(`/login?redirect=${encodeURIComponent(redirectTarget)}&error=${encodeURIComponent('Account locked for 15 minutes due to failed attempts.')}`);
    } else {
      const remaining = attempt.remainingAttempts;
      return res.redirect(`/login?redirect=${encodeURIComponent(redirectTarget)}&error=${encodeURIComponent(`Incorrect password. (${remaining} attempt${remaining === 1 ? '' : 's'} remaining)`)}`);
    }
  }

  authService.clearFailedLogins(clientIp);
  auditLog('LOGIN_SUCCESS', {
    ip: clientIp,
    userAgent: req.headers['user-agent'] || 'Unknown',
  });

  const approverToken = crypto.randomBytes(48).toString('base64url');
  const maxAgeMs = config.APPROVER_TTL_DAYS * 24 * 3600 * 1000;
  sessionService.approverSessions.set(approverToken, {
    token: approverToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + maxAgeMs,
    passwordHash: currentHash,
    ip: req.ip || req.headers['x-forwarded-for'],
    userAgent: req.headers['user-agent'],
  });
  sessionService.savePersistedSessions();

  res.cookie(config.APPROVER_COOKIE_NAME, approverToken, getCookieOptions(req, maxAgeMs));
  sessionService.mintApproverSession(req, res);

  return res.redirect(redirectTarget);
});

module.exports = router;
