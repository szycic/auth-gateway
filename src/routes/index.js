const express = require('express');
const config = require('../config');
const proxyService = require('../services/proxyService');

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

// 1. Static Assets & PWA manifests / workers
router.use(assetsRoutes);

// 2. Auth API & Core Endpoints
router.use('/auth', healthRoutes);
router.use('/auth', verifyRoutes);
router.use('/auth', sessionRoutes);
router.use('/auth', pairRoutes);
router.use('/auth', approverRoutes);
router.use('/auth', approveRoutes);
router.use('/auth', manageRoutes);

// 3. Downstream Reverse Proxy Middleware (handles non-auth domains)
router.use((req, res, next) => {
  const host = (req.headers.host || '').split(':')[0].toLowerCase();
  let authHost = '';
  try {
    authHost = new URL(config.BASE_URL).hostname.toLowerCase();
  } catch (e) {}

  if (req.path.startsWith('/auth/') || req.path === '/login') {
    return next();
  }

  if (host && host !== authHost && host !== 'localhost') {
    return proxyService.proxyToTargetApp(req, res);
  }
  next();
});

// 4. Central Portal & Login Routes
router.use(loginRoutes);
router.use(portalRoutes);

module.exports = router;
