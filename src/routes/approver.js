const express = require('express');
const crypto = require('crypto');
const config = require('../config');
const { getCookieOptions } = require('../utils/cookieHelper');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const webauthnService = require('../services/webauthnService');
const { auditLog } = require('../utils/auditLogger');
const { verifySameOrigin } = require('../utils/csrfHelper');

const router = express.Router();
router.use(verifySameOrigin);

router.get(['/approver', '/approver/'], (req, res) => {
  const returnTo = req.query.returnTo || req.query.redirect || '/';
  if (sessionService.isApprover(req)) {
    return res.redirect(config.normalizeRedirect(returnTo, '/'));
  }
  const target = '/auth/approver/login' + (returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : '');
  return res.redirect(target);
});

// Single-use FIDO Enrollment view
router.get('/enroll-fido', (req, res) => {
  const token = req.query.token;
  const tokenRecord = webauthnService.getEnrollmentToken(token);
  if (!tokenRecord) {
    return res.render('enrollFido', {
      token: '',
      expired: true,
    });
  }
  return res.render('enrollFido', {
    token,
    expired: false,
  });
});

// Single-use FIDO Enrollment registration options
router.get('/enroll-fido/options', async (req, res) => {
  try {
    const token = req.query.token;
    const options = await webauthnService.generateRegistrationOptionsForToken(token, req);
    res.json(options);
  } catch (err) {
    console.error('[auth-gateway] FIDO enrollment options error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// Single-use FIDO Enrollment verification
router.post('/enroll-fido/verify', async (req, res) => {
  try {
    const { token, keyName, response } = req.body;
    if (!token || !response) {
      return res.status(400).json({ error: 'Missing enrollment parameters.' });
    }
    const credRecord = await webauthnService.verifyRegistrationForToken(token, response, keyName, req);
    res.json({
      success: true,
      credential: {
        id: credRecord.id,
        name: credRecord.name,
      },
    });
  } catch (err) {
    console.error('[auth-gateway] FIDO enrollment verify error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// WebAuthn Approver Login challenge options
router.get('/approver/webauthn/login-options', async (req, res) => {
  try {
    const activeMethod = webauthnService.getActiveAuthMethod();
    if (activeMethod !== 'fido') {
      return res.status(400).json({ error: 'FIDO login is not currently the active login method.' });
    }
    const { challengeId, options } = await webauthnService.generateLoginOptions(req);
    res.json({ challengeId, options });
  } catch (err) {
    console.error('[auth-gateway] WebAuthn login options error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// WebAuthn Approver Login verification
router.post('/approver/webauthn/login-verify', async (req, res) => {
  const clientIp = authService.getClientIp(req);
  const lockoutStatus = authService.checkLoginLockout(clientIp);
  if (lockoutStatus.locked) {
    return res.status(429).json({
      error: `Too many failed login attempts. Locked out for ${lockoutStatus.remainingMins} more minute(s).`,
    });
  }

  const activeMethod = webauthnService.getActiveAuthMethod();
  if (activeMethod !== 'fido') {
    return res.status(400).json({ error: 'FIDO login is not currently the active login method.' });
  }

  const { challengeId, response, returnTo } = req.body;
  const rawTarget = returnTo || req.query.returnTo || req.query.redirect || '';
  const redirectTarget = config.normalizeRedirect(rawTarget, '/');

  try {
    if (!challengeId || !response) {
      return res.status(400).json({ error: 'Invalid authentication parameters.' });
    }

    const cred = await webauthnService.verifyLoginResponse(challengeId, response, req);

    authService.clearFailedLogins(clientIp);
    auditLog('APPROVER_LOGIN_SUCCESS', {
      ip: clientIp,
      method: 'fido',
      keyName: cred.name,
      keyId: cred.id,
      userAgent: req.headers['user-agent'] || 'Unknown',
    });

    // Issue Approver session token (30 days)
    const approverToken = crypto.randomBytes(48).toString('base64url');
    const maxAgeMs = config.APPROVER_TTL_DAYS * 24 * 3600 * 1000;
    const currentHash = authService.getApproverPasswordHash() || 'fido-auth';

    const appObj = {
      token: approverToken,
      createdAt: Date.now(),
      expiresAt: Date.now() + maxAgeMs,
      passwordHash: currentHash,
      authMethod: 'fido',
      keyId: cred.id,
      ip: req.ip || req.headers['x-forwarded-for'],
      userAgent: req.headers['user-agent'],
    };
    sessionService.approverSessions.set(approverToken, appObj);

    res.cookie(config.APPROVER_COOKIE_NAME, approverToken, getCookieOptions(req, maxAgeMs));
    const activeSess = sessionService.mintApproverSession(req, res, approverToken);
    if (activeSess) {
      appObj.sessionId = activeSess.id;
      appObj.activeSessionToken = activeSess.token;
    }
    sessionService.savePersistedSessions();

    return res.json({ success: true, redirect: redirectTarget });
  } catch (err) {
    const attempt = authService.recordFailedLogin(clientIp);
    auditLog('APPROVER_LOGIN_FAILED', {
      ip: clientIp,
      method: 'fido',
      locked: attempt.locked,
      remainingAttempts: attempt.remainingAttempts,
      error: err.message,
    });

    console.error('[auth-gateway] FIDO login verification failed:', err.message);
    if (attempt.locked) {
      return res.status(429).json({ error: 'Too many failed attempts. Account locked for 15 minutes.' });
    }
    return res.status(401).json({
      error: `Security key authentication failed. (${attempt.remainingAttempts} attempt${attempt.remainingAttempts === 1 ? '' : 's'} remaining)`,
    });
  }
});

// Approver Login page (exclusive: either FIDO or Password)
router.get('/approver/login', (req, res) => {
  const returnTo = req.query.returnTo || req.query.redirect || '/';
  if (sessionService.isApprover(req)) {
    return res.redirect(config.normalizeRedirect(returnTo, '/'));
  }

  const activeMethod = webauthnService.getActiveAuthMethod();
  const currentHash = authService.getApproverPasswordHash();

  if (activeMethod === 'password' && !currentHash) {
    return res.status(503).render('approverSetup', {});
  }

  return res.render('approverLogin', {
    returnTo,
    error: '',
    mode: activeMethod,
  });
});

// Approver Password submission
router.post('/approver/login', (req, res) => {
  const activeMethod = webauthnService.getActiveAuthMethod();
  const { password, returnTo } = req.body;
  const rawTarget = returnTo || req.query.returnTo || req.query.redirect || '';
  const redirectTarget = config.normalizeRedirect(rawTarget, '/');

  if (activeMethod !== 'password') {
    return res.status(400).render('approverLogin', {
      returnTo: redirectTarget,
      error: 'Password authentication is disabled. Active login method is FIDO Security Key.',
      mode: activeMethod,
    });
  }

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
      mode: activeMethod,
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).render('approverLogin', {
      returnTo: redirectTarget,
      error: 'Please enter the approver password.',
      mode: activeMethod,
    });
  }

  const isValid = authService.verifyPassword(password, currentHash);
  if (!isValid) {
    const attempt = authService.recordFailedLogin(clientIp);
    auditLog('APPROVER_LOGIN_FAILED', {
      ip: clientIp,
      method: 'password',
      locked: attempt.locked,
      remainingAttempts: attempt.remainingAttempts,
    });
    if (attempt.locked) {
      return res.status(429).render('approverLogin', {
        returnTo: redirectTarget,
        error: 'Too many failed attempts. Account locked for 15 minutes.',
        mode: activeMethod,
      });
    } else {
      const remainingAttempts = attempt.remainingAttempts;
      return res.status(401).render('approverLogin', {
        returnTo: redirectTarget,
        error: `Incorrect approver password. (${remainingAttempts} attempt${remainingAttempts === 1 ? '' : 's'} remaining)`,
        mode: activeMethod,
      });
    }
  }

  authService.clearFailedLogins(clientIp);
  auditLog('APPROVER_LOGIN_SUCCESS', {
    ip: clientIp,
    method: 'password',
    userAgent: req.headers['user-agent'] || 'Unknown',
  });

  // Issue Approver session token (30 days)
  const approverToken = crypto.randomBytes(48).toString('base64url');
  const maxAgeMs = config.APPROVER_TTL_DAYS * 24 * 3600 * 1000;
  const appObj = {
    token: approverToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + maxAgeMs,
    passwordHash: currentHash,
    authMethod: 'password',
    ip: req.ip || req.headers['x-forwarded-for'],
    userAgent: req.headers['user-agent'],
  };
  sessionService.approverSessions.set(approverToken, appObj);

  res.cookie(config.APPROVER_COOKIE_NAME, approverToken, getCookieOptions(req, maxAgeMs));
  const activeSess = sessionService.mintApproverSession(req, res, approverToken);
  if (activeSess) {
    appObj.sessionId = activeSess.id;
    appObj.activeSessionToken = activeSess.token;
  }
  sessionService.savePersistedSessions();
  return res.redirect(redirectTarget);
});

router.get('/approver/logout', (req, res) => {
  const clientIp = authService.getClientIp(req);
  auditLog('APPROVER_LOGOUT', { ip: clientIp });
  const token = req.cookies[config.APPROVER_COOKIE_NAME];
  if (token) {
    sessionService.approverSessions.delete(token);
    for (const [sTok, s] of sessionService.activeSessions.entries()) {
      if (s.approverToken === token) {
        sessionService.activeSessions.delete(sTok);
      }
    }
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
