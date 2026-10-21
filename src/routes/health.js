const express = require('express');
const config = require('../config');
const sessionService = require('../services/sessionService');

const router = express.Router();

router.get('/health', (req, res) => {
  const mem = process.memoryUsage();
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
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

module.exports = router;
