const express = require('express');
const config = require('../config');
const proxyService = require('../services/proxyService');
const { isAuthDomain } = require('../utils/originHelper');

const assetsRoutes = require('./assets');
const healthRoutes = require('./health');
const verifyRoutes = require('./verify');
const sessionRoutes = require('./session');
const pairRoutes = require('./pair');
const approverRoutes = require('./approver');
const approveRoutes = require('./approve');
const manageRoutes = require('./manage');
const loginRoutes = require('./login');
const portalRoutes = require('./portal');

const router = express.Router();

router.use(assetsRoutes);

router.use('/auth', healthRoutes);
router.use('/auth', verifyRoutes);
router.use('/auth', sessionRoutes);
router.use('/auth', pairRoutes);
router.use('/auth', approverRoutes);
router.use('/auth', approveRoutes);
router.use('/auth', manageRoutes);

// Downstream reverse proxy (handles non-auth domains)
router.use((req, res, next) => {
  if (req.path.startsWith('/auth/')) {
    return next();
  }

  if (!isAuthDomain(req)) {
    return proxyService.proxyToTargetApp(req, res);
  }
  next();
});

router.use(loginRoutes);
router.use(portalRoutes);

module.exports = router;
