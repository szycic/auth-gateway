const express = require('express');
const crypto = require('crypto');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const { auditLog } = require('../utils/auditLogger');

const router = express.Router();

router.get(['/approver', '/approver/'], (req, res) => {
  const returnTo = req.query.returnTo || req.query.redirect || '/';
  if (sessionService.isApprover(req)) {
    return res.redirect(config.normalizeRedirect(returnTo, '/'));
  }
  const target = '/auth/approver/login' + (returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : '');
  return res.redirect(target);
});

router.get('/approver/login', (req, res) => {
  const returnTo = req.query.returnTo || req.query.redirect || '/';
  if (sessionService.isApprover(req)) {
    return res.redirect(config.normalizeRedirect(returnTo, '/'));
  }
  const currentHash = authService.getApproverPasswordHash();
  if (!currentHash) {
    return res.status(503).render('approverSetup', {});
  }
  return res.render('approverLogin', { returnTo, error: '' });
});

router.post('/approver/login', (req, res) => {
  const { password, returnTo } = req.body;
  const rawTarget = returnTo || req.query.returnTo || req.query.redirect || '';
  const redirectTarget = config.normalizeRedirect(rawTarget, '/');

  const currentHash = authService.getApproverPasswordHash();
  if (!currentHash) {
    return res.status(503).render('approverSetup', {});
  }

  const clientIp = authService.getClientIp(req);
  const lockoutStatus = authService.checkLoginLockout(clientIp);
  if (lockoutStatus.locked) {
    return res.status(429).render('approverLogin', {
      returnTo: redirectTarget,
      error: `Too many failed login attempts. Locked out for ${lockoutStatus.remainingMins} more minute(s).`,
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).render('approverLogin', {
      returnTo: redirectTarget,
      error: 'Please enter the approver password.',
    });
  }

  const isValid = authService.verifyPassword(password, currentHash);
  if (!isValid) {
    const attempt = authService.recordFailedLogin(clientIp);
    auditLog('APPROVER_LOGIN_FAILED', {
      ip: clientIp,
      locked: attempt.locked,
      remainingAttempts: attempt.remainingAttempts,
    });
    if (attempt.locked) {
      return res.status(429).render('approverLogin', {
        returnTo: redirectTarget,
        error: 'Too many failed attempts. Account locked for 15 minutes.',
      });
    } else {
      const remainingAttempts = attempt.remainingAttempts;
      return res.status(401).render('approverLogin', {
        returnTo: redirectTarget,
        error: `Incorrect approver password. (${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} remaining)`,
      });
    }
  }

  authService.clearFailedLogins(clientIp);
  auditLog('APPROVER_LOGIN_SUCCESS', {
    ip: clientIp,
    userAgent: req.headers['user-agent'] || 'Unknown',
  });

  // Issue Approver session token (30 days)
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

router.get('/approver/logout', (req, res) => {
  const clientIp = authService.getClientIp(req);
  auditLog('APPROVER_LOGOUT', { ip: clientIp });
  const token = req.cookies[config.APPROVER_COOKIE_NAME];
  if (token) {
    sessionService.approverSessions.delete(token);
  }
  const sessionToken = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  if (sessionToken) {
    sessionService.activeSessions.delete(sessionToken);
  }
  sessionService.savePersistedSessions();

  const opts = getCookieOptions(req);
  delete opts.maxAge;
  res.clearCookie(config.APPROVER_COOKIE_NAME, opts);
  res.clearCookie(config.AUTH_COOKIE_NAME, opts);
  res.clearCookie('share_auth_token', opts);
  if (opts.domain) {
    const hostOnly = { ...opts };
    delete hostOnly.domain;
    res.clearCookie(config.APPROVER_COOKIE_NAME, hostOnly);
    res.clearCookie(config.AUTH_COOKIE_NAME, hostOnly);
    res.clearCookie('share_auth_token', hostOnly);
  }
  return res.redirect('/login');
});

router.post('/approver/self-authorize', (req, res) => {
  if (!sessionService.isApprover(req)) {
    return res.redirect('/auth/approver/login');
  }
  const rawRedirect = req.body.redirect || '';
  const redirectTarget = config.isAllowedRedirect(rawRedirect) ? rawRedirect : '/';
  sessionService.mintApproverSession(req, res);
  return res.redirect(redirectTarget);
});

module.exports = router;
