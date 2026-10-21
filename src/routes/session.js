const express = require('express');
const crypto = require('crypto');
const QRCode = require('qrcode');
const config = require('../config');
const { parseUserAgent } = require('../utils/deviceDetector');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');

const router = express.Router();

router.get('/init', async (req, res) => {
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
