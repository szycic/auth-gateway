const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');
const config = require('../config');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');

const router = express.Router();

const initRequests = new Map(); // ip -> { count, resetAt }
const MAX_INIT_PER_MINUTE = 20;

function checkInitRateLimit(ip) {
  const now = Date.now();
  const entry = initRequests.get(ip);
  if (!entry || now > entry.resetAt) {
    initRequests.set(ip, { count: 1, resetAt: now + 60000 });
    return true;
  }
  if (entry.count >= MAX_INIT_PER_MINUTE) {
    return false;
  }
  entry.count += 1;
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of initRequests.entries()) {
    if (now > entry.resetAt) {
      initRequests.delete(ip);
    }
  }
}, 5 * 60 * 1000).unref();

router.get('/init', async (req, res) => {
  const clientIp = authService.getClientIp(req);
  if (!checkInitRateLimit(clientIp)) {
    return res.status(429).json({ error: 'Too many requests. Please wait before refreshing.' });
  }

  try {
    const loginSessionId = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + config.QR_SESSION_TTL_MS;
    const desktopIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
    const desktopUserAgent = req.headers['user-agent'] || 'Unknown';

    const rawRedirect = req.query.redirect || req.query.returnTo || '';
    const redirectTarget = config.isAllowedRedirect(rawRedirect) ? rawRedirect : '';
    const matchedService = config.getService(req.query.service || redirectTarget);

    const pairCode = authService.generatePairCode();
    authService.pairingCodes.set(pairCode, loginSessionId);

    sessionService.pendingLoginSessions.set(loginSessionId, {
      key,
      pairCode,
      desktopIp,
      desktopUserAgent,
      friendlyDevice: parseUserAgent(desktopUserAgent),
      serviceName: matchedService ? matchedService.name : null,
      serviceId: matchedService ? matchedService.id : null,
      redirect: redirectTarget,
      createdAt: Date.now(),
      expiresAt,
      status: 'pending',
    });

    const approveUrl = `${config.BASE_URL}/auth/approve?id=${encodeURIComponent(loginSessionId)}&key=${encodeURIComponent(key)}`;

    const qrCode = await QRCode.toDataURL(approveUrl, {
      width: 320,
      margin: 1,
      errorCorrectionLevel: 'M',
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    });

    const pairCodeFormatted = `${pairCode.slice(0, 4)} - ${pairCode.slice(4)}`;

    res.json({
      success: true,
      loginSessionId,
      qrCode,
      pairCode,
      pairCodeFormatted,
      expiresAt,
      ttlMs: config.QR_SESSION_TTL_MS,
      service: matchedService ? { id: matchedService.id, name: matchedService.name } : null,
    });
  } catch (err) {
    console.error('Error generating QR code:', err);
    res.status(500).json({ error: 'Failed to initialize QR session' });
  }
});

module.exports = router;
