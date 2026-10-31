const config = require('../config');

/**
 * Generate secure Express cookie configuration options.
 * @param {import('express').Request} req
 * @param {number} [maxAgeMs]
 * @param {boolean} [isHostOnly=false]
 * @returns {import('express').CookieOptions}
 */
function getCookieOptions(req, maxAgeMs, isHostOnly = false) {
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    config.BASE_URL.startsWith('https:');

  const opts = {
    httpOnly: true,
    secure: isHttps,
    sameSite: 'lax',
    path: '/',
    maxAge: maxAgeMs || config.SESSION_TTL_HOURS * 3600 * 1000,
  };

  if (!isHostOnly && config.session && config.session.cookieDomain) {
    opts.domain = config.session.cookieDomain;
  }

  return opts;
}

/**
 * Generate host-only cookie options strictly for Approver sessions.
 * Never sets wildcard domain (.szycic.com) so approver credentials are not leaked to downstream apps.
 * @param {import('express').Request} req
 * @param {number} [maxAgeMs]
 * @returns {import('express').CookieOptions}
 */
function getApproverCookieOptions(req, maxAgeMs) {
  return getCookieOptions(
    req,
    maxAgeMs || config.APPROVER_TTL_DAYS * 24 * 3600 * 1000,
    true
  );
}

module.exports = {
  getCookieOptions,
  getApproverCookieOptions,
};
