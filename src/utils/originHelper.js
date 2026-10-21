const config = require('../config');

/**
 * Validate CORS origins against BASE_URL and configured cookieDomain.
 * @param {string} origin
 * @returns {boolean}
 */
function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    const u = new URL(origin);
    const host = u.hostname.toLowerCase();
    let baseHost = '';
    try {
      baseHost = new URL(config.BASE_URL).hostname.toLowerCase();
    } catch (e) {}

    const cookieDomain = (config.session.cookieDomain || '').replace(/^\./, '').toLowerCase();

    if (
      origin === config.BASE_URL ||
      (baseHost && host === baseHost) ||
      host === 'localhost' ||
      host === '127.0.0.1' ||
      (cookieDomain && (host === cookieDomain || host.endsWith('.' + cookieDomain)))
    ) {
      return true;
    }
  } catch (e) {}
  return false;
}

/**
 * Check if the request is targeting the central Auth Gateway host.
 * @param {import('express').Request} req
 * @returns {boolean}
 */
function isAuthDomain(req) {
  const host = (req.headers.host || '').split(':')[0].toLowerCase();
  let authHost = '';
  try {
    authHost = new URL(config.BASE_URL).hostname.toLowerCase();
  } catch (e) {}
  return !host || (authHost && host === authHost) || host === 'localhost' || host === '127.0.0.1';
}

module.exports = {
  isAllowedOrigin,
  isAuthDomain,
};
