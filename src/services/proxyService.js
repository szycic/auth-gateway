const http = require('http');
const config = require('../config');
const sessionService = require('./sessionService');

/**
 * Resolve target upstream URL for a given Host header.
 * @param {string} hostHeader
 * @returns {string}
 */
function getUpstreamUrlForHost(hostHeader = '') {
  const host = (hostHeader || '').split(':')[0].toLowerCase();
  if (!host) {
    return config.TARGET_APP_URL || (config.downstream && config.downstream.targetUrl) || '';
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

  // 3. Fallback to generic downstream target URL from config or environment
  return config.TARGET_APP_URL || (config.downstream && config.downstream.targetUrl) || (config.services && config.services[0] ? config.services[0].upstream : '') || '';
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

  const isAuthRequired = matchedService ? !matchedService.disableAuth : true;
  const token = req.cookies[config.AUTH_COOKIE_NAME] || req.cookies['share_auth_token'];
  const session = sessionService.activeSessions.get(token);

  if (isAuthRequired && !sessionService.isApprover(req) && (!matchedService || !sessionService.isSessionAllowedForService(session, matchedService))) {
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
  if (isAuthRequired && isHtmlExpected && req.method === 'GET') {
    delete proxyHeaders['accept-encoding'];
  }

  const proxyReq = http.request(
    targetUrl,
    {
      method: req.method,
      headers: proxyHeaders,
    },
    (proxyRes) => {
      const contentType = proxyRes.headers['content-type'] || '';
      const isHtml = contentType.includes('text/html') && proxyRes.statusCode < 300;

      if (isAuthRequired && isHtml && req.method === 'GET') {
        let body = '';
        proxyRes.setEncoding('utf8');
        proxyRes.on('data', (chunk) => { body += chunk; });
        proxyRes.on('end', () => {
          const injectionScript = `<script src="${config.BASE_URL}/auth/assets/auth-watchdog.js"></script>`;

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
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
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

  if (req.body && Object.keys(req.body).length > 0) {
    const ct = (req.headers['content-type'] || '').toLowerCase();
    let bodyData;
    if (ct.includes('application/json')) {
      bodyData = JSON.stringify(req.body);
    } else if (ct.includes('application/x-www-form-urlencoded')) {
      bodyData = new URLSearchParams(req.body).toString();
    }
    if (bodyData) {
      proxyReq.write(bodyData);
    }
    proxyReq.end();
  } else {
    req.pipe(proxyReq);
  }
}

module.exports = {
  getUpstreamUrlForHost,
  relaxCspForWatchdog,
  relaxCspHeader,
  proxyToTargetApp,
};
