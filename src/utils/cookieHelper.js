const config = require('../config');

/**
 * Generate secure Express cookie configuration options.
 * @param {import('express').Request} req
 * @param {number} [maxAgeMs]
 * @returns {import('express').CookieOptions}
 */
function getCookieOptions(req, maxAgeMs) {
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

  if (config.session && config.session.cookieDomain) {
    opts.domain = config.session.cookieDomain;
  }

  return opts;
}

module.exports = {
  getCookieOptions,
};
