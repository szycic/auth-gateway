const express = require('express');
const authService = require('../services/authService');
const sessionService = require('../services/sessionService');
const { auditLog } = require('../utils/auditLogger');
const { verifySameOrigin } = require('../utils/csrfHelper');

const router = express.Router();
router.use(verifySameOrigin);

router.post('/code/verify', (req, res) => {
  if (!sessionService.isApprover(req)) {
    return res.status(401).json({ error: 'Unauthorized approver.' });
  }

  const rawCode = req.body && req.body.code;
  const cleanCode = typeof rawCode === 'string' ? rawCode.replace(/\D/g, '') : '';

  if (cleanCode.length !== 8) {
    return res.status(400).json({ error: 'Please enter a valid 8-digit code.' });
  }

  const loginSessionId = authService.pairingCodes.get(cleanCode);
  if (!loginSessionId) {
    return res.status(404).json({ error: 'Code not found or expired. Please check the screen.' });
  }

  const session = sessionService.pendingLoginSessions.get(loginSessionId);
  if (!session || Date.now() > session.expiresAt || session.status !== 'pending') {
    authService.pairingCodes.delete(cleanCode);
    if (session) sessionService.pendingLoginSessions.delete(loginSessionId);
    return res.status(410).json({ error: 'This authorization code has expired.' });
  }

  auditLog('PAIR_CODE_VERIFIED', {
    sessionId: loginSessionId,
    device: session.friendlyDevice,
    desktopIp: session.desktopIp,
    approverIp: authService.getClientIp(req),
  });

  const redirectUrl = `/auth/approve?id=${encodeURIComponent(loginSessionId)}&key=${encodeURIComponent(session.key)}`;
  return res.json({
    success: true,
    redirectUrl,
    sessionId: loginSessionId,
  });
});

module.exports = router;
