const http = require('http');
const config = require('../config');
const sessionService = require('./sessionService');
const authService = require('./authService');
const { isAllowedOrigin } = require('../utils/originHelper');

/**
 * Resolve target upstream URL for a given Host header.
 * @param {string} hostHeader
 * @returns {string}
 */
function getUpstreamUrlForHost(hostHeader = '') {
  const host = (hostHeader || '').split(':')[0].toLowerCase();
  if (!host) {
    return (config.services && config.services[0] ? config.services[0].upstream : '') || '';
  }

  // 1. Direct match by configured service URL hostname
  const matchedService = (config.services || []).find((s) => {
    try {
      if (!s.url) return false;
      return new URL(s.url).hostname.toLowerCase() === host;
    } catch (e) {
      return false;
    }
  });

  if (matchedService && matchedService.upstream) {
    if (matchedService.disableService) return '';
    return matchedService.upstream;
  }

  // 2. Match by service ID prefix (e.g. "<id>.<domain>" or "<id>")
  const byId = (config.services || []).find((s) => {
    if (!s.id) return false;
    const id = s.id.toLowerCase();
    return host === id || host.startsWith(id + '.');
  });

  if (byId && byId.upstream) {
    if (byId.disableService) return '';
    return byId.upstream;
  }

  // 3. Fallback to first configured active service
  const firstActive = (config.getActiveServices ? config.getActiveServices() : config.services)[0];
  return (firstActive && firstActive.upstream) || '';
}

/**
 * Relax Content-Security-Policy header so watchdog script can run and communicate.
 * @param {string} csp
 * @param {string} authBaseUrl
 * @returns {string}
 */
function relaxCspForWatchdog(csp, authBaseUrl = config.BASE_URL) {
  if (!csp || typeof csp !== 'string') return csp;
  let authOrigin = config.BASE_URL;
  try {
    authOrigin = new URL(authBaseUrl || config.BASE_URL).origin;
  } catch (e) {}
  const wsOrigin = authOrigin.replace(/^http/, 'ws');

  let updated = csp;

  // 1. Allow script execution from authOrigin
  if (/script-src-elem\s+/i.test(updated)) {
    updated = updated.replace(/(script-src-elem\s+[^;]+)/i, `$1 ${authOrigin}`);
  }
  if (/script-src\s+/i.test(updated)) {
    updated = updated.replace(/(script-src\s+[^;]+)/i, `$1 ${authOrigin}`);
  } else if (/default-src\s+/i.test(updated)) {
    updated = updated.replace(/(default-src\s+[^;]+)/i, `$1 ${authOrigin}`);
  }

  // 2. Allow API fetch and WebSocket connections to authOrigin and wsOrigin
  if (/connect-src\s+/i.test(updated)) {
    updated = updated.replace(/(connect-src\s+[^;]+)/i, `$1 ${authOrigin} ${wsOrigin}`);
  } else {
    updated = updated.trim();
    if (updated.length > 0 && !updated.endsWith(';')) updated += ';';
    updated += ` connect-src 'self' ${authOrigin} ${wsOrigin};`;
  }

  return updated;
}

function relaxCspHeader(val, authBaseUrl) {
  if (Array.isArray(val)) {
    return val.map((item) => relaxCspForWatchdog(item, authBaseUrl));
  }
  return relaxCspForWatchdog(val, authBaseUrl);
}

/**
 * Proxy request to downstream target app with session enforcement and watchdog injection.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 */
function proxyToTargetApp(req, res) {
  if (req.method === 'OPTIONS') {
    const origin = req.headers.origin;
    if (origin && isAllowedOrigin(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS');
      const reqHeaders = req.headers['access-control-request-headers'];
      res.setHeader('Access-Control-Allow-Headers', reqHeaders || 'Content-Type, Authorization, X-Requested-With, X-Gateway-Token, X-Auth-Token');
      res.setHeader('Access-Control-Max-Age', '86400');
    }
    return res.status(204).end();
  }

  const matchedService = sessionService.getTargetServiceForRequest(req) || config.getService(req.headers.host);
  if (matchedService && matchedService.disableService) {
    return res.status(503).render('statusNotice', {
      title: `${matchedService.name} is Temporarily Disabled`,
      message: 'This service is currently disabled on demand or undergoing maintenance.',
      actionUrl: config.BASE_URL,
      actionLabel: 'Return to Dashboard',
      type: 'error',
    });
  }

  const isPublicRequest = req.headers['x-auth-status'] === 'public';
  const isAuthRequired = matchedService ? !matchedService.disableAuth : true;
  const isGatewayTokenAuth = authService.isGatewayTokenValid(req);
  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  const session = sessionService.activeSessions.get(token);
  const isSessionValid = sessionService.isApprover(req) || (matchedService && sessionService.isSessionAllowedForService(session, matchedService));

  if (!isPublicRequest && isAuthRequired && !isGatewayTokenAuth && !isSessionValid) {
    return res.status(403).render('statusNotice', {
      title: 'Access Restricted',
      message: matchedService
        ? `Your active session is not authorized to access ${matchedService.name}.`
        : 'Your active session is not authorized to access this service.',
      actionUrl: config.BASE_URL,
      actionLabel: 'Return to Dashboard',
      type: 'error',
    });
  }

  const upstreamHost = (matchedService && matchedService.url)
    ? new URL(matchedService.url).hostname
    : (req.headers['x-forwarded-host'] || req.headers.host || '');
  const upstreamBase = getUpstreamUrlForHost(upstreamHost);
  if (!upstreamBase || !upstreamBase.trim()) {
    return res.status(502).render('statusNotice', {
      title: 'Service Unavailable',
      message: 'Downstream application is not configured.',
      actionUrl: config.BASE_URL,
      actionLabel: 'Return Home',
      type: 'error',
    });
  }

  let targetUrl;
  try {
    targetUrl = new URL(req.originalUrl || req.url, upstreamBase);
  } catch (err) {
    return res.status(400).render('statusNotice', {
      title: 'Invalid Request',
      message: 'The requested URL is invalid.',
      actionUrl: config.BASE_URL,
      actionLabel: 'Return Home',
      type: 'error',
    });
  }

  const downstreamHost = req.headers.host || (matchedService && matchedService.url ? new URL(matchedService.url).host : 'localhost');
  const proxyHeaders = {
    ...req.headers,
    host: downstreamHost,
    'x-forwarded-for': req.ip || req.headers['x-forwarded-for'],
    'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https',
  };

  const isHtmlExpected = (req.headers.accept || '').includes('text/html');
  if (!isGatewayTokenAuth && isHtmlExpected && req.method === 'GET') {
    delete proxyHeaders['accept-encoding'];
  }

  const proxyReq = http.request(
    targetUrl,
    {
      method: req.method,
      headers: proxyHeaders,
    },
    (proxyRes) => {
      const contentType = (proxyRes.headers['content-type'] || '').toLowerCase();
      const rawContentLength = proxyRes.headers['content-length'];
      const contentLength = rawContentLength ? parseInt(rawContentLength, 10) : null;
      const MAX_INJECT_BYTES = 2 * 1024 * 1024; // 2MB max for HTML injection
      const isHtml = contentType.includes('text/html') && proxyRes.statusCode < 300 && (!contentLength || contentLength <= MAX_INJECT_BYTES);

      if (!isGatewayTokenAuth && isHtml && req.method === 'GET') {
        let body = '';
        let exceeded = false;
        proxyRes.setEncoding('utf8');
        proxyRes.on('data', (chunk) => {
          if (exceeded) return;
          body += chunk;
          if (body.length > MAX_INJECT_BYTES) {
            exceeded = true;
          }
        });
        proxyRes.on('end', () => {
          if (exceeded) {
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            return res.end(body);
          }
          const scriptName = isSessionValid ? 'auth-watchdog.js' : 'auth-public-guard.js';
          const injectionScript = `<script src="${config.BASE_URL}/auth/assets/${scriptName}" crossorigin="anonymous"></script>`;

          if (body.includes('</body>')) {
            body = body.replace('</body>', `${injectionScript}</body>`);
          } else {
            body += injectionScript;
          }
          const headers = { ...proxyRes.headers };
          delete headers['transfer-encoding'];
          delete headers['content-length'];
          headers['content-length'] = Buffer.byteLength(body);
          if (headers['content-security-policy']) {
            headers['content-security-policy'] = relaxCspHeader(headers['content-security-policy'], config.BASE_URL);
          }
          if (headers['content-security-policy-report-only']) {
            headers['content-security-policy-report-only'] = relaxCspHeader(headers['content-security-policy-report-only'], config.BASE_URL);
          }
          res.writeHead(proxyRes.statusCode, headers);
          res.end(body);
        });
      } else {
        const headers = { ...proxyRes.headers };
        const origin = req.headers.origin;
        if (origin && isAllowedOrigin(origin)) {
          headers['access-control-allow-origin'] = origin;
          headers['access-control-allow-credentials'] = 'true';
        }
        res.writeHead(proxyRes.statusCode, headers);
        proxyRes.pipe(res);
      }
    }
  );

  proxyReq.on('error', (err) => {
    console.error('[target-app proxy error]', err.message);
    res.status(502).render('statusNotice', {
      title: 'Service Unavailable',
      message: 'The downstream service is currently unreachable.',
      actionUrl: config.BASE_URL,
      actionLabel: 'Return Home',
      type: 'error',
    });
  });

  if (req.body !== undefined && req.body !== null && req.method !== 'GET' && req.method !== 'HEAD') {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    let bodyData = null;
    if (ct.includes('application/json')) {
      bodyData = JSON.stringify(req.body);
    } else if (ct.includes('application/x-www-form-urlencoded')) {
      bodyData = new URLSearchParams(req.body).toString();
    }
    if (bodyData !== null) {
      proxyReq.write(bodyData);
      proxyReq.end();
      return;
    }
  }
  req.pipe(proxyReq);
}

module.exports = {
  getUpstreamUrlForHost,
  relaxCspForWatchdog,
  relaxCspHeader,
  proxyToTargetApp,
};
