const express = require('express');
const config = require('../config');
const versionHelper = require('../utils/versionHelper');
const sessionService = require('../services/sessionService');
const authService = require('../services/authService');

const router = express.Router();

router.get('/health', (req, res) => {
  const isPrivileged =
    authService.isGatewayTokenValid(req) ||
    sessionService.isApprover(req);

  const baseResponse = {
    status: 'ok',
    version: versionHelper.version,
    assetVersion: versionHelper.assetVersion,
    commit: versionHelper.commit,
    timestamp: new Date().toISOString(),
  };

  if (!isPrivileged) {
    return res.json(baseResponse);
  }

  const mem = process.memoryUsage();
  return res.json({
    ...baseResponse,
    uptime: process.uptime(),
    metrics: {
      activeSessions: sessionService.activeSessions.size,
      approverSessions: sessionService.approverSessions.size,
      pendingLogins: sessionService.pendingLoginSessions.size,
      memoryRssMb: Math.round((mem.rss / 1024 / 1024) * 10) / 10,
    },
    services: config.services.map((s) => ({
      id: s.id,
      name: s.name,
      url: s.url,
      disableService: Boolean(s.disableService),
      disableAuth: Boolean(s.disableAuth),
    })),
  });
});

router.get('/version', (req, res) => {
  return res.json(versionHelper.getMetadata());
});

module.exports = router;
