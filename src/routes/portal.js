const express = require('express');
const config = require('../config');
const sessionService = require('../services/sessionService');

const router = express.Router();

router.get('/', (req, res) => {
  let token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  let session = sessionService.activeSessions.get(token);

  if (!session || !sessionService.isValidSession(token)) {
    if (sessionService.isApprover(req)) {
      session = sessionService.mintApproverSession(req, res);
      token = session.token;
    } else {
      return res.redirect('/login');
    }
  }

  return res.render('portalDashboard', {
    session,
    isApproverUser: sessionService.isApprover(req),
    services: config.services,
    notice: req.query.notice,
  });
});

module.exports = router;
