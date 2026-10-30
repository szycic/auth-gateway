const config = require('../config');
const authService = require('../services/authService');
const { auditLog } = require('./auditLogger');

/**
 * Validate that state-changing requests originate strictly from the configured BASE_URL.
 * Blocks cross-site and cross-subdomain CSRF requests.
 */
function verifySameOrigin(req, res, next) {
  // Safe HTTP methods do not alter state
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  // Allow machine-to-machine API calls authenticated via valid Gateway Token
  if (authService.isGatewayTokenValid(req)) {
    return next();
  }

  let expectedOrigin = '';
  try {
    expectedOrigin = new URL(config.server.baseUrl || config.BASE_URL).origin.toLowerCase();
  } catch {}

  const origin = req.headers.origin;
  if (origin) {
    if (origin.toLowerCase() !== expectedOrigin) {
      auditLog('CSRF_BLOCKED', {
        path: req.originalUrl || req.path,
        origin,
        expectedOrigin,
        ip: authService.getClientIp(req),
      });
      if (req.accepts('json') && !req.accepts('html')) {
        return res.status(403).json({ error: 'Forbidden: Invalid request origin' });
      }
      return res.status(403).render('statusNotice', {
        title: '403 - Forbidden',
        message: 'Cross-site request blocked: Invalid origin.',
        type: 'error',
      });
    }
    return next();
  }

  const secFetchSite = req.headers['sec-fetch-site'];
  if (secFetchSite && secFetchSite !== 'same-origin' && secFetchSite !== 'none') {
    auditLog('CSRF_BLOCKED', {
      path: req.originalUrl || req.path,
      secFetchSite,
      ip: authService.getClientIp(req),
    });
    if (req.accepts('json') && !req.accepts('html')) {
      return res.status(403).json({ error: 'Forbidden: Cross-site request blocked' });
    }
    return res.status(403).render('statusNotice', {
      title: '403 - Forbidden',
      message: 'Cross-site request blocked.',
      type: 'error',
    });
  }

  const referer = req.headers.referer;
  if (referer) {
    try {
      const refOrigin = new URL(referer).origin.toLowerCase();
      if (refOrigin !== expectedOrigin) {
        auditLog('CSRF_BLOCKED', {
          path: req.originalUrl || req.path,
          referer,
          expectedOrigin,
          ip: authService.getClientIp(req),
        });
        if (req.accepts('json') && !req.accepts('html')) {
          return res.status(403).json({ error: 'Forbidden: Invalid referer origin' });
        }
        return res.status(403).render('statusNotice', {
          title: '403 - Forbidden',
          message: 'Cross-site request blocked: Invalid referer.',
          type: 'error',
        });
      }
    } catch {
      return res.status(403).send('Forbidden: Malformed referer');
    }
  }

  next();
}

module.exports = {
  verifySameOrigin,
};

