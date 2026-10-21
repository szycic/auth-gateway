const express = require('express');
const config = require('../config');

const router = express.Router();

router.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    services: config.services.map((s) => ({
      id: s.id,
      name: s.name,
      url: s.url,
      disableService: Boolean(s.disableService),
      disableAuth: Boolean(s.disableAuth),
    })),
    uptime: process.uptime(),
  });
});

module.exports = router;
