/**
 * Pingvin Share Auth Gateway
 * High-performance Forward Auth server with Approver-gated QR code authentication & Session Management
 */

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const QRCode = require('qrcode');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

// Configuration
const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const BASE_URL = (process.env.BASE_URL || 'https://share.szycic.com').replace(/\/+$/, '');
const AUTH_COOKIE_NAME = process.env.AUTH_COOKIE_NAME || 'share_auth_token';
const APPROVER_COOKIE_NAME = process.env.APPROVER_COOKIE_NAME || 'gateway_approver_session';
const APPROVER_PASSWORD = process.env.APPROVER_PASSWORD || 'szycic-share-admin';
const SESSION_TTL_HOURS = parseInt(process.env.SESSION_TTL_HOURS || '72', 10);
const QR_SESSION_TTL_MS = parseInt(process.env.QR_SESSION_TTL_MS || '120000', 10); // 2 minutes
const APPROVER_TTL_DAYS = 30;
const TARGET_APP_URL = process.env.TARGET_APP_URL || 'http://share-app:3000';

// In-Memory State Stores
// activeSessions: token -> { id, token, createdAt, expiresAt, ip, userAgent, friendlyDevice, type }
const activeSessions = new Map();

// approverSessions: token -> { token, createdAt, expiresAt, ip, userAgent }
const approverSessions = new Map();

// pendingQrSessions: qrSessionId -> { key, desktopIp, desktopUserAgent, friendlyDevice, createdAt, expiresAt, status }
const pendingQrSessions = new Map();

// Helper: Friendly Device Parser from User-Agent
function parseUserAgent(ua = '') {
  if (!ua || ua === 'Unknown') return 'Unknown Device';
  let os = 'Unknown OS';
  if (/windows/i.test(ua)) os = 'Windows';
  else if (/macintosh|mac os x/i.test(ua)) os = 'macOS';
  else if (/android/i.test(ua)) os = 'Android';
  else if (/iphone|ipad|ipod/i.test(ua)) os = 'iOS';
  else if (/linux/i.test(ua)) os = 'Linux';

  let browser = 'Browser';
  if (/edg/i.test(ua)) browser = 'Edge';
  else if (/chrome|crios/i.test(ua)) browser = 'Chrome';
  else if (/firefox|fxios/i.test(ua)) browser = 'Firefox';
  else if (/safari/i.test(ua)) browser = 'Safari';

  return `${browser} on ${os}`;
}

// Session Validation Helper (Desktop / Guest access)
function isValidSession(token) {
  if (!token || typeof token !== 'string') return false;
  const session = activeSessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return false;
  }
  return true;
}

// Approver Session Helper (Mobile Approver)
function isApprover(req) {
  const token = req.cookies[APPROVER_COOKIE_NAME];
  if (!token || typeof token !== 'string') return false;
  const session = approverSessions.get(token);
  if (!session) return false;
  if (Date.now() > session.expiresAt) {
    approverSessions.delete(token);
    return false;
  }
  return true;
}

// Periodic cleanup of expired sessions every 60 seconds
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of pendingQrSessions.entries()) {
    if (now > session.expiresAt) {
      pendingQrSessions.delete(id);
    }
  }
  for (const [token, session] of activeSessions.entries()) {
    if (now > session.expiresAt) {
      activeSessions.delete(token);
    }
  }
  for (const [token, session] of approverSessions.entries()) {
    if (now > session.expiresAt) {
      approverSessions.delete(token);
    }
  }
}, 60 * 1000);

// Initialize Express App & HTTP Server
const app = express();
const server = http.createServer(app);

app.set('trust proxy', 1);

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize Socket.io
const io = new Server(server, {
  cors: {
    origin: BASE_URL,
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

io.on('connection', (socket) => {
  socket.on('join-session', (qrSessionId) => {
    if (typeof qrSessionId === 'string' && qrSessionId.trim().length > 0) {
      socket.join(qrSessionId.trim());
    }
  });
});

// Helper for Secure Cookie Options
function getCookieOptions(req, maxAgeMs) {
  const isHttps =
    req.secure ||
    req.headers['x-forwarded-proto'] === 'https' ||
    BASE_URL.startsWith('https:');

  return {
    httpOnly: true,
    secure: isHttps,
    sameSite: 'lax',
    path: '/',
    maxAge: maxAgeMs || SESSION_TTL_HOURS * 3600 * 1000,
  };
}

// ----------------------------------------------------
// 1. Healthcheck Endpoint
// ----------------------------------------------------
app.get('/auth/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    activeSessions: activeSessions.size,
    approverSessions: approverSessions.size,
    pendingQrSessions: pendingQrSessions.size,
    uptime: process.uptime(),
  });
});

// ----------------------------------------------------
// 2. Forward Auth Verification Endpoint
// Caddy queries this endpoint for every protected request
// ----------------------------------------------------
app.get('/auth/verify', (req, res) => {
  const token = req.cookies[AUTH_COOKIE_NAME];
  if (isValidSession(token)) {
    return res.status(200).set({
      'X-Auth-Status': 'authenticated',
      'X-Auth-Role': 'guest',
    }).send('OK');
  }
  return res.status(401).send('Unauthorized');
});

// ----------------------------------------------------
// 3. QR Code Initialization Endpoint (Desktop)
// ----------------------------------------------------
app.get('/auth/qr-init', async (req, res) => {
  try {
    const qrSessionId = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + QR_SESSION_TTL_MS;
    const desktopIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
    const desktopUserAgent = req.headers['user-agent'] || 'Unknown';

    pendingQrSessions.set(qrSessionId, {
      key,
      desktopIp,
      desktopUserAgent,
      friendlyDevice: parseUserAgent(desktopUserAgent),
      createdAt: Date.now(),
      expiresAt,
      status: 'pending',
    });

    const approveUrl = `${BASE_URL}/auth/qr-approve?id=${encodeURIComponent(qrSessionId)}&key=${encodeURIComponent(key)}`;

    const qrCode = await QRCode.toDataURL(approveUrl, {
      width: 320,
      margin: 1,
      errorCorrectionLevel: 'M',
      color: {
        dark: '#0f172a',
        light: '#ffffff',
      },
    });

    res.json({
      success: true,
      qrSessionId,
      qrCode,
      expiresAt,
      ttlMs: QR_SESSION_TTL_MS,
    });
  } catch (err) {
    console.error('Error generating QR code:', err);
    res.status(500).json({ error: 'Failed to initialize QR session' });
  }
});

// ----------------------------------------------------
// 4. Approver Login Routes
// ----------------------------------------------------
app.get('/auth/approver/login', (req, res) => {
  const returnTo = req.query.returnTo || '/auth/sessions';
  if (isApprover(req)) {
    return res.redirect(returnTo);
  }
  res.send(renderApproverLoginHtml({ returnTo }));
});

app.post('/auth/approver/login', (req, res) => {
  const { password, returnTo } = req.body;
  const redirectTarget = returnTo && typeof returnTo === 'string' && returnTo.startsWith('/auth/')
    ? returnTo
    : '/auth/sessions';

  if (!password || typeof password !== 'string') {
    return res.status(400).send(renderApproverLoginHtml({
      returnTo: redirectTarget,
      error: 'Please enter the approver password.',
    }));
  }

  // Timing-safe password comparison
  const passBuf = Buffer.from(password);
  const expectedBuf = Buffer.from(APPROVER_PASSWORD);
  const isValid =
    passBuf.length === expectedBuf.length &&
    crypto.timingSafeEqual(passBuf, expectedBuf);

  if (!isValid) {
    return res.status(401).send(renderApproverLoginHtml({
      returnTo: redirectTarget,
      error: 'Incorrect approver password.',
    }));
  }

  // Issue Approver session token (30 days)
  const approverToken = crypto.randomBytes(48).toString('base64url');
  const maxAgeMs = APPROVER_TTL_DAYS * 24 * 3600 * 1000;
  approverSessions.set(approverToken, {
    token: approverToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + maxAgeMs,
    ip: req.ip || req.headers['x-forwarded-for'],
    userAgent: req.headers['user-agent'],
  });

  res.cookie(APPROVER_COOKIE_NAME, approverToken, getCookieOptions(req, maxAgeMs));
  return res.redirect(redirectTarget);
});

// Approver Logout
app.get('/auth/approver/logout', (req, res) => {
  const token = req.cookies[APPROVER_COOKIE_NAME];
  if (token) {
    approverSessions.delete(token);
  }
  const opts = getCookieOptions(req);
  delete opts.maxAge;
  res.clearCookie(APPROVER_COOKIE_NAME, opts);
  return res.redirect('/auth/approver/login');
});

// ----------------------------------------------------
// 5. QR Approval Screen (Mobile Scanner Target)
// ----------------------------------------------------
app.get('/auth/qr-approve', (req, res) => {
  const { id, key } = req.query;

  if (!id || !key || typeof id !== 'string' || typeof key !== 'string') {
    return res.status(400).send(renderStatusNoticeHtml({
      title: 'Invalid Request',
      message: 'Missing or malformed authorization parameters.',
      type: 'error',
    }));
  }

  // If mobile is NOT authenticated as Approver, require login first!
  if (!isApprover(req)) {
    const returnUrl = `/auth/qr-approve?id=${encodeURIComponent(id)}&key=${encodeURIComponent(key)}`;
    return res.redirect(`/auth/approver/login?returnTo=${encodeURIComponent(returnUrl)}`);
  }

  const session = pendingQrSessions.get(id);
  if (!session) {
    return res.status(404).send(renderStatusNoticeHtml({
      title: 'Session Not Found',
      message: 'This QR code session does not exist or has already been used.',
      type: 'error',
      actionUrl: '/auth/sessions',
      actionLabel: 'View Active Sessions',
    }));
  }

  if (Date.now() > session.expiresAt || session.status !== 'pending') {
    pendingQrSessions.delete(id);
    return res.status(410).send(renderStatusNoticeHtml({
      title: 'QR Code Expired',
      message: 'This authorization request has expired. Please refresh the QR code on the desktop screen.',
      type: 'error',
      actionUrl: '/auth/sessions',
      actionLabel: 'View Active Sessions',
    }));
  }

  // Validate secret key
  const keyBuf = Buffer.from(key);
  const sessionKeyBuf = Buffer.from(session.key);
  if (keyBuf.length !== sessionKeyBuf.length || !crypto.timingSafeEqual(keyBuf, sessionKeyBuf)) {
    return res.status(403).send(renderStatusNoticeHtml({
      title: 'Access Denied',
      message: 'The authorization key provided does not match.',
      type: 'error',
    }));
  }

  // Render the Approval Decision Screen on Mobile
  res.send(renderApprovalDecisionHtml({
    id,
    key,
    desktopIp: session.desktopIp,
    friendlyDevice: session.friendlyDevice,
    expiresAt: session.expiresAt,
    activeSessionsList: Array.from(activeSessions.values()),
  }));
});

// ----------------------------------------------------
// 6. QR Action Handler (Approve / Reject)
// ----------------------------------------------------
app.post('/auth/qr-action', (req, res) => {
  if (!isApprover(req)) {
    return res.status(401).send('Unauthorized approver.');
  }

  const { id, key, action } = req.body;
  if (!id || !key || typeof id !== 'string' || typeof key !== 'string') {
    return res.status(400).send('Invalid request parameters.');
  }

  const session = pendingQrSessions.get(id);
  if (!session) {
    return res.status(404).send(renderStatusNoticeHtml({
      title: 'Session Expired',
      message: 'This authorization session is no longer active.',
      type: 'error',
      actionUrl: '/auth/sessions',
      actionLabel: 'Active Sessions',
    }));
  }

  // Timing safe key check
  const keyBuf = Buffer.from(key);
  const sessionKeyBuf = Buffer.from(session.key);
  if (keyBuf.length !== sessionKeyBuf.length || !crypto.timingSafeEqual(keyBuf, sessionKeyBuf)) {
    return res.status(403).send('Invalid authorization key.');
  }

  pendingQrSessions.delete(id);

  if (action === 'reject') {
    // Notify desktop of rejection
    io.to(id).emit('rejected', { message: 'Authorization was rejected by the approver.' });

    return res.send(renderStatusNoticeHtml({
      title: 'Request Rejected',
      message: `Access denied for desktop (${session.friendlyDevice}).`,
      type: 'error',
      actionUrl: '/auth/sessions',
      actionLabel: 'Back to Sessions',
    }));
  }

  // Action is APPROVE -> Grant desktop guest session
  const sessionToken = crypto.randomBytes(48).toString('base64url');
  const sessionId = crypto.randomUUID();
  const tokenExpiresAt = Date.now() + SESSION_TTL_HOURS * 3600 * 1000;

  activeSessions.set(sessionToken, {
    id: sessionId,
    token: sessionToken,
    createdAt: Date.now(),
    expiresAt: tokenExpiresAt,
    ip: session.desktopIp,
    userAgent: session.desktopUserAgent,
    friendlyDevice: session.friendlyDevice,
    type: 'desktop_guest',
  });

  // Emit real-time approved event to desktop room
  io.to(id).emit('approved', {
    token: sessionToken,
  });

  return res.send(renderStatusNoticeHtml({
    title: 'Desktop Approved!',
    message: `Granted guest upload access to ${session.friendlyDevice} (${session.desktopIp}). You can revoke this session at any time below.`,
    type: 'success',
    actionUrl: '/auth/sessions',
    actionLabel: 'Manage Active Sessions',
  }));
});

// ----------------------------------------------------
// 7. Session Management Dashboard (`/auth/sessions`)
// Allows logged-in approvers to view & revoke active sessions
// ----------------------------------------------------
app.get('/auth/sessions', (req, res) => {
  if (!isApprover(req)) {
    return res.redirect('/auth/approver/login?returnTo=/auth/sessions');
  }

  res.send(renderSessionsDashboardHtml({
    activeSessionsList: Array.from(activeSessions.values()),
  }));
});

// Revoke a specific session or all sessions
app.post('/auth/sessions/revoke', (req, res) => {
  if (!isApprover(req)) {
    return res.status(401).send('Unauthorized.');
  }

  const { sessionId, all } = req.body;

  if (all === 'true') {
    const count = activeSessions.size;
    activeSessions.clear();
    io.emit('session-revoked', { all: true });
    return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Revoked all ${count} active sessions.`));
  }

  if (sessionId) {
    for (const [token, session] of activeSessions.entries()) {
      if (session.id === sessionId) {
        activeSessions.delete(token);
        io.emit('session-revoked', { sessionId });
        return res.redirect('/auth/sessions?notice=' + encodeURIComponent(`Session for ${session.friendlyDevice} was revoked.`));
      }
    }
  }

  return res.redirect('/auth/sessions');
});

// ----------------------------------------------------
// 8. Desktop Token Exchange Endpoint
// Redirect target when desktop receives Socket.io 'approved'
// ----------------------------------------------------
app.get('/auth/exchange', (req, res) => {
  const { token } = req.query;

  if (token && typeof token === 'string' && isValidSession(token)) {
    res.cookie(AUTH_COOKIE_NAME, token, getCookieOptions(req));
    return res.redirect('/');
  }

  return res.redirect('/login');
});

// ----------------------------------------------------
// 9. Logout Endpoint (Desktop)
// ----------------------------------------------------
app.get('/auth/logout', (req, res) => {
  const token = req.cookies[AUTH_COOKIE_NAME];
  if (token) {
    activeSessions.delete(token);
  }

  const cookieOptions = getCookieOptions(req);
  delete cookieOptions.maxAge;
  res.clearCookie(AUTH_COOKIE_NAME, cookieOptions);

  return res.redirect('/login');
});

// ----------------------------------------------------
// 10. Fallback Reverse Proxy for Downstream App (/auth/*)
// Passes Pingvin Share internal routes (e.g. /auth/signIn) to share-app
// ----------------------------------------------------
app.all('/auth/*', (req, res) => {
  const targetUrl = new URL(req.originalUrl, TARGET_APP_URL);

  const proxyReq = http.request(
    targetUrl,
    {
      method: req.method,
      headers: {
        ...req.headers,
        host: req.headers.host || 'share.szycic.com',
        'x-forwarded-for': req.ip || req.headers['x-forwarded-for'],
        'x-forwarded-proto': req.headers['x-forwarded-proto'] || 'https',
      },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxyReq.on('error', (err) => {
    console.error('[proxy error]', err.message);
    res.status(502).send('Bad Gateway');
  });

  req.pipe(proxyReq);
});

// ----------------------------------------------------
// 11. Desktop Login View (`/login`)
// Dynamic QR Code, Real-Time Socket.io, Sleek Dark UI
// ----------------------------------------------------
app.get('/login', (req, res) => {
  if (isValidSession(req.cookies[AUTH_COOKIE_NAME])) {
    return res.redirect('/');
  }

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to Pingvin Share</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="/socket.io/socket.io.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: radial-gradient(circle at 50% -20%, #1e293b 0%, #090d16 100%);
      color: #f1f5f9;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.5rem;
      overflow-x: hidden;
    }
    .ambient-glow {
      position: fixed;
      width: 600px;
      height: 600px;
      background: radial-gradient(circle, rgba(14, 165, 233, 0.12) 0%, rgba(99, 102, 241, 0.05) 50%, transparent 70%);
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      pointer-events: none;
      z-index: 0;
    }
    .card {
      position: relative;
      z-index: 1;
      width: 100%;
      max-width: 440px;
      background: rgba(15, 23, 42, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      border-radius: 28px;
      padding: 2.5rem 2.25rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
      text-align: center;
    }
    .logo-container {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 68px;
      height: 68px;
      border-radius: 20px;
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      box-shadow: 0 10px 25px -5px rgba(2, 132, 199, 0.4);
      margin-bottom: 1.5rem;
    }
    .logo-container svg { width: 36px; height: 36px; color: #ffffff; }
    h1 { font-size: 1.55rem; font-weight: 700; color: #ffffff; margin-bottom: 0.5rem; }
    p.subtitle { font-size: 0.925rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.75rem; }
    .qr-frame {
      position: relative;
      width: 280px;
      height: 280px;
      margin: 0 auto 1.5rem;
      background: #ffffff;
      border-radius: 22px;
      padding: 14px;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 15px 35px -5px rgba(0, 0, 0, 0.4);
      overflow: hidden;
    }
    .qr-frame img { width: 100%; height: 100%; display: block; border-radius: 12px; }
    .scan-line {
      position: absolute;
      top: 0; left: 0; width: 100%; height: 3px;
      background: linear-gradient(90deg, transparent, #0284c7, #38bdf8, transparent);
      box-shadow: 0 0 12px #38bdf8;
      animation: scan 2.6s cubic-bezier(0.4, 0, 0.2, 1) infinite;
      opacity: 0.85;
      pointer-events: none;
    }
    @keyframes scan { 0% { top: 4%; } 50% { top: 96%; } 100% { top: 4%; } }
    .overlay {
      position: absolute;
      inset: 0;
      background: rgba(15, 23, 42, 0.94);
      border-radius: 22px;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      padding: 1.25rem;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.3s ease;
      z-index: 10;
    }
    .overlay.active { opacity: 1; pointer-events: auto; }
    .spinner {
      width: 38px; height: 38px;
      border: 3px solid rgba(2, 132, 199, 0.2);
      border-top-color: #38bdf8;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin-bottom: 0.75rem;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    .status-bar {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.6rem;
      font-size: 0.85rem;
      color: #94a3b8;
      font-weight: 500;
    }
    .status-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #10b981; box-shadow: 0 0 8px #10b981;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    .btn-refresh {
      background: #0284c7; color: #ffffff; border: none;
      padding: 0.65rem 1.25rem; font-size: 0.875rem; font-weight: 600;
      border-radius: 12px; cursor: pointer; display: inline-flex;
      align-items: center; gap: 0.5rem; transition: background 0.2s;
      margin-top: 0.5rem;
    }
    .btn-refresh:hover { background: #0369a1; }
    .approved-state {
      display: flex; flex-direction: column; align-items: center;
      justify-content: center; padding: 1rem 0;
    }
    .approved-icon {
      width: 64px; height: 64px; border-radius: 50%;
      background: rgba(16, 185, 129, 0.15); border: 2px solid #10b981;
      color: #10b981; display: flex; align-items: center; justify-content: center;
      margin-bottom: 1rem;
    }
    .footer { margin-top: 1.75rem; font-size: 0.775rem; color: #64748b; }
    .approver-link {
      display: inline-block; margin-top: 1rem; color: #38bdf8;
      font-size: 0.8rem; text-decoration: none; transition: opacity 0.2s;
    }
    .approver-link:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="ambient-glow"></div>

  <div class="card" id="mainCard">
    <div class="logo-container">
      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
      </svg>
    </div>

    <h1>Pingvin Share</h1>
    <p class="subtitle">Scan the QR code with your authenticated mobile device to approve guest upload access for this desktop.</p>

    <div class="qr-frame" id="qrContainer">
      <div class="scan-line" id="scanLine"></div>
      <img id="qrImage" src="" alt="QR Authorization Code" style="display: none;">

      <div class="overlay active" id="loadingOverlay">
        <div class="spinner"></div>
        <p style="font-size: 0.875rem; color: #cbd5e1;">Generating secure QR...</p>
      </div>

      <div class="overlay" id="expiredOverlay">
        <svg style="width: 36px; height: 36px; color: #f59e0b; margin-bottom: 0.5rem;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p style="font-size: 0.875rem; color: #e2e8f0; margin-bottom: 0.75rem;">QR Code Expired</p>
        <button class="btn-refresh" onclick="initQrSession()">Refresh QR</button>
      </div>
    </div>

    <div class="status-bar" id="statusBar">
      <div class="status-dot"></div>
      <span id="statusText">Awaiting approver scan (<span id="timerCount">120</span>s)</span>
    </div>

    <div>
      <a href="/auth/approver/login" class="approver-link">Approver Portal &bull; Manage Sessions</a>
    </div>

    <div class="footer">
      Protected Gateway &bull; szycic.com
    </div>
  </div>

  <script>
    const socket = io();
    let currentSessionId = null;
    let timerInterval = null;
    let secondsLeft = 120;

    const qrImage = document.getElementById('qrImage');
    const scanLine = document.getElementById('scanLine');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const expiredOverlay = document.getElementById('expiredOverlay');
    const statusText = document.getElementById('statusText');
    const timerCount = document.getElementById('timerCount');
    const mainCard = document.getElementById('mainCard');

    function startTimer(durationMs) {
      clearInterval(timerInterval);
      secondsLeft = Math.floor(durationMs / 1000);
      timerCount.textContent = secondsLeft;

      timerInterval = setInterval(() => {
        secondsLeft--;
        if (secondsLeft <= 0) {
          clearInterval(timerInterval);
          onSessionExpired();
        } else {
          timerCount.textContent = secondsLeft;
        }
      }, 1000);
    }

    function onSessionExpired() {
      scanLine.style.display = 'none';
      expiredOverlay.classList.add('active');
      statusText.textContent = 'Session timed out';
    }

    async function initQrSession() {
      try {
        loadingOverlay.classList.add('active');
        expiredOverlay.classList.remove('active');
        scanLine.style.display = 'none';

        const res = await fetch('/auth/qr-init', { cache: 'no-store' });
        if (!res.ok) throw new Error('Failed to fetch QR');
        const data = await res.json();

        currentSessionId = data.qrSessionId;
        qrImage.src = data.qrCode;
        qrImage.style.display = 'block';

        socket.emit('join-session', currentSessionId);

        loadingOverlay.classList.remove('active');
        scanLine.style.display = 'block';

        startTimer(data.ttlMs || 120000);
        statusText.innerHTML = 'Awaiting approver scan (<span id="timerCount">' + secondsLeft + '</span>s)';
      } catch (err) {
        console.error(err);
        statusText.textContent = 'Failed to load QR code';
      }
    }

    socket.on('approved', (data) => {
      clearInterval(timerInterval);
      scanLine.style.display = 'none';

      mainCard.innerHTML = \`
        <div class="approved-state">
          <div class="approved-icon">
            <svg style="width: 36px; height: 36px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 style="color: #ffffff; font-size: 1.45rem; font-weight: 700; margin-bottom: 0.5rem;">Access Approved</h2>
          <p style="color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem;">Opening Pingvin Share guest upload...</p>
          <div class="spinner"></div>
        </div>
      \`;

      setTimeout(() => {
        if (data && data.token) {
          window.location.href = '/auth/exchange?token=' + encodeURIComponent(data.token);
        } else {
          window.location.href = '/';
        }
      }, 700);
    });

    socket.on('rejected', (data) => {
      clearInterval(timerInterval);
      scanLine.style.display = 'none';
      statusText.innerHTML = '<span style="color: #ef4444; font-weight: 600;">Request Rejected by Approver</span>';
      setTimeout(() => {
        initQrSession();
      }, 2500);
    });

    socket.on('connect', () => {
      if (currentSessionId) {
        socket.emit('join-session', currentSessionId);
      }
    });

    initQrSession();
  </script>
</body>
</html>`);
});

// ----------------------------------------------------
// UI Templates: Approver Login, Decision & Sessions
// ----------------------------------------------------

// 1. Approver Login HTML
function renderApproverLoginHtml({ returnTo = '/auth/sessions', error = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Approver Authentication - Pingvin Share</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%);
      color: #f1f5f9; min-height: 100vh; display: flex; align-items: center;
      justify-content: center; padding: 1.5rem;
    }
    .card {
      width: 100%; max-width: 400px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      border-radius: 24px; padding: 2.25rem 2rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
      text-align: center;
    }
    .icon {
      width: 64px; height: 64px; border-radius: 20px;
      background: rgba(2, 132, 199, 0.15); border: 1.5px solid #0284c7;
      color: #38bdf8; display: inline-flex; align-items: center; justify-content: center;
      margin-bottom: 1.25rem;
    }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff; }
    p.desc { font-size: 0.875rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem; }
    .form-group { margin-bottom: 1.25rem; text-align: left; }
    label { display: block; font-size: 0.825rem; color: #cbd5e1; font-weight: 600; margin-bottom: 0.5rem; }
    input[type="password"] {
      width: 100%; padding: 0.85rem 1rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 12px; color: #ffffff; font-size: 1rem;
      outline: none; transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="password"]:focus {
      border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }
    .btn {
      width: 100%; padding: 0.85rem 1.25rem;
      background: #0284c7; color: #ffffff; font-weight: 600;
      font-size: 0.95rem; border-radius: 12px; border: none;
      cursor: pointer; transition: background 0.2s, transform 0.1s;
    }
    .btn:hover { background: #0369a1; transform: translateY(-1px); }
    .error-box {
      background: rgba(239, 68, 68, 0.15); border: 1px solid #ef4444;
      color: #fca5a5; font-size: 0.85rem; padding: 0.75rem 1rem;
      border-radius: 10px; margin-bottom: 1.25rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg style="width: 32px; height: 32px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    </div>
    <h1>Approver Sign In</h1>
    <p class="desc">Sign in on this device to authorize desktop sessions and manage guest access.</p>

    ${error ? `<div class="error-box">${error}</div>` : ''}

    <form method="POST" action="/auth/approver/login">
      <input type="hidden" name="returnTo" value="${returnTo}">
      <div class="form-group">
        <label for="password">Approver Password</label>
        <input type="password" id="password" name="password" required autofocus placeholder="Enter password...">
      </div>
      <button type="submit" class="btn">Sign In as Approver</button>
    </form>
  </div>
</body>
</html>`;
}

// 2. Approval Decision HTML (Mobile Scanned Screen)
function renderApprovalDecisionHtml({ id, key, desktopIp, friendlyDevice, expiresAt, activeSessionsList }) {
  const activeCount = activeSessionsList.length;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize Desktop - Pingvin Share</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%);
      color: #f1f5f9; min-height: 100vh; padding: 1.5rem 1rem;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
    }
    .card {
      width: 100%; max-width: 440px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      border-radius: 24px; padding: 2rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
      margin-bottom: 1.5rem;
    }
    .header { text-align: center; margin-bottom: 1.75rem; }
    .badge-wrap {
      display: inline-flex; align-items: center; gap: 0.4rem;
      background: rgba(56, 189, 248, 0.12); color: #38bdf8;
      border: 1px solid rgba(56, 189, 248, 0.3); border-radius: 100px;
      padding: 0.35rem 0.85rem; font-size: 0.775rem; font-weight: 600;
      margin-bottom: 0.75rem;
    }
    h1 { font-size: 1.35rem; font-weight: 700; color: #ffffff; }
    .device-info {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px; padding: 1.25rem; margin-bottom: 1.75rem;
    }
    .info-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 0.5rem 0; font-size: 0.875rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #94a3b8; }
    .info-val { color: #f8fafc; font-weight: 600; }
    .btn-group { display: flex; gap: 0.75rem; }
    .btn {
      flex: 1; padding: 0.85rem 1rem; border-radius: 12px; font-weight: 600;
      font-size: 0.95rem; border: none; cursor: pointer; text-align: center;
      transition: background 0.2s, transform 0.1s;
    }
    .btn-approve { background: #10b981; color: #ffffff; }
    .btn-approve:hover { background: #059669; }
    .btn-reject { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .btn-reject:hover { background: rgba(239, 68, 68, 0.3); }
    .bottom-link { text-align: center; font-size: 0.85rem; color: #94a3b8; }
    .bottom-link a { color: #38bdf8; text-decoration: none; font-weight: 600; }
  </style>
</head>
<body>
  <div class="card">
    <div class="header">
      <div class="badge-wrap">
        <svg style="width: 14px; height: 14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        Approver Verified
      </div>
      <h1>Authorize Desktop Access?</h1>
    </div>

    <div class="device-info">
      <div class="info-row">
        <span class="info-label">Device</span>
        <span class="info-val">${friendlyDevice}</span>
      </div>
      <div class="info-row">
        <span class="info-label">IP Address</span>
        <span class="info-val">${desktopIp}</span>
      </div>
      <div class="info-row">
        <span class="info-label">Access Level</span>
        <span class="info-val" style="color: #38bdf8;">Guest Uploader</span>
      </div>
    </div>

    <form method="POST" action="/auth/qr-action">
      <input type="hidden" name="id" value="${id}">
      <input type="hidden" name="key" value="${key}">
      <div class="btn-group">
        <button type="submit" name="action" value="reject" class="btn btn-reject">Reject</button>
        <button type="submit" name="action" value="approve" class="btn btn-approve">Approve Desktop</button>
      </div>
    </form>
  </div>

  <div class="bottom-link">
    Currently active sessions: <b>${activeCount}</b> &bull; <a href="/auth/sessions">Manage Sessions</a>
  </div>
</body>
</html>`;
}

// 3. Sessions Dashboard HTML (View & Revoke Active Sessions)
function renderSessionsDashboardHtml({ activeSessionsList = [] }) {
  const sessionsRows = activeSessionsList.map((s) => {
    const elapsedMinutes = Math.floor((Date.now() - s.createdAt) / 60000);
    const timeLabel = elapsedMinutes < 1 ? 'Just now' : `${elapsedMinutes}m ago`;

    return `
      <div class="session-card">
        <div class="session-info">
          <div class="session-name">${s.friendlyDevice || 'Desktop Browser'}</div>
          <div class="session-sub">${s.ip} &bull; Started ${timeLabel}</div>
        </div>
        <form method="POST" action="/auth/sessions/revoke">
          <input type="hidden" name="sessionId" value="${s.id}">
          <button type="submit" class="btn-revoke">Log Out</button>
        </form>
      </div>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Active Sessions - Pingvin Share Gateway</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%);
      color: #f1f5f9; min-height: 100vh; padding: 2rem 1rem;
      display: flex; flex-direction: column; align-items: center;
    }
    .container { width: 100%; max-width: 540px; }
    .top-bar {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 1.5rem;
    }
    h1 { font-size: 1.45rem; font-weight: 700; color: #ffffff; }
    .btn-logout {
      font-size: 0.85rem; color: #94a3b8; text-decoration: none;
      padding: 0.4rem 0.8rem; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .btn-logout:hover { color: #f87171; border-color: rgba(248, 113, 113, 0.4); }
    .session-list { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.5rem; }
    .session-card {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px; padding: 1.15rem 1.25rem;
      display: flex; justify-content: space-between; align-items: center;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    .session-name { font-weight: 600; font-size: 0.95rem; color: #ffffff; margin-bottom: 0.2rem; }
    .session-sub { font-size: 0.8rem; color: #94a3b8; }
    .btn-revoke {
      background: rgba(239, 68, 68, 0.15); color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 10px;
      padding: 0.45rem 0.85rem; font-size: 0.825rem; font-weight: 600;
      cursor: pointer; transition: background 0.2s;
    }
    .btn-revoke:hover { background: rgba(239, 68, 68, 0.3); }
    .empty-state {
      background: rgba(15, 23, 42, 0.6); border: 1px dashed rgba(255, 255, 255, 0.15);
      border-radius: 16px; padding: 2.5rem 1rem; text-align: center; color: #94a3b8;
    }
    .revoke-all-form { text-align: center; margin-top: 1rem; }
    .btn-revoke-all {
      background: none; border: none; color: #f87171; font-size: 0.85rem;
      cursor: pointer; text-decoration: underline;
    }
    .btn-revoke-all:hover { color: #ef4444; }
    .notice {
      background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981;
      color: #a7f3d0; padding: 0.75rem 1rem; border-radius: 12px;
      font-size: 0.875rem; margin-bottom: 1.25rem;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="top-bar">
      <h1>Active Sessions</h1>
      <a href="/auth/approver/logout" class="btn-logout">Approver Sign Out</a>
    </div>

    ${activeSessionsList.length > 0 ? `
      <div class="session-list">
        ${sessionsRows}
      </div>
      <form method="POST" action="/auth/sessions/revoke" class="revoke-all-form">
        <input type="hidden" name="all" value="true">
        <button type="submit" class="btn-revoke-all" onclick="return confirm('Revoke all authenticated desktop sessions?');">
          Log Out All Active Sessions
        </button>
      </form>
    ` : `
      <div class="empty-state">
        <p>No active desktop sessions.</p>
        <p style="font-size: 0.8rem; margin-top: 0.4rem;">Scan the QR code on a desktop to authorize a session.</p>
      </div>
    `}
  </div>
</body>
</html>`;
}

// 4. Status Notice HTML (Generic result view)
function renderStatusNoticeHtml({ title, message, type = 'success', actionUrl, actionLabel }) {
  const isSuccess = type === 'success';
  const color = isSuccess ? '#10b981' : '#ef4444';
  const bg = isSuccess ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - Pingvin Share</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%);
      color: #f1f5f9; min-height: 100vh; display: flex; align-items: center;
      justify-content: center; padding: 1.5rem;
    }
    .card {
      width: 100%; max-width: 400px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      border-radius: 24px; padding: 2.25rem 2rem;
      text-align: center;
    }
    .icon {
      width: 64px; height: 64px; border-radius: 50%;
      background: ${bg}; border: 2px solid ${color}; color: ${color};
      display: inline-flex; align-items: center; justify-content: center;
      margin-bottom: 1.25rem;
    }
    h1 { font-size: 1.35rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff; }
    p { font-size: 0.9rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem; }
    .btn {
      display: block; width: 100%; padding: 0.85rem 1rem;
      background: #0284c7; color: #ffffff; font-weight: 600;
      border-radius: 12px; text-decoration: none;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg style="width: 32px; height: 32px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        ${isSuccess
          ? '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M5 13l4 4L19 7" />'
          : '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />'
        }
      </svg>
    </div>
    <h1>${title}</h1>
    <p>${message}</p>
    ${actionUrl ? `<a href="${actionUrl}" class="btn">${actionLabel || 'Continue'}</a>` : ''}
  </div>
</body>
</html>`;
}

// Start Server
server.listen(PORT, HOST, () => {
  console.log(`[auth-gateway] Server running on http://${HOST}:${PORT}`);
  console.log(`[auth-gateway] Public URL: ${BASE_URL}`);
  console.log(`[auth-gateway] Session cookie: ${AUTH_COOKIE_NAME}`);
  console.log(`[auth-gateway] Approver cookie: ${APPROVER_COOKIE_NAME}`);
  console.log(`[auth-gateway] Target downstream app: ${TARGET_APP_URL}`);
});
