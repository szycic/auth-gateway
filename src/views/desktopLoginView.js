const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderDesktopLoginHtml({ matchedService, redirectTarget = '', error = '', notice = '' }) {
  const appDisplayName = matchedService ? matchedService.name : config.app.name;
  const appDisplaySubtitle = matchedService
    ? (matchedService.subtitle || `Scan the QR code with your mobile device to sign in to ${matchedService.name}.`)
    : config.app.subtitle;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in to ${escapeHtml(appDisplayName)}</title>
  ${getPwaHeadTags()}
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
    .pair-code-card {
      margin: 1.85rem 0 1.5rem;
      text-align: center;
      transition: opacity 0.2s;
    }
    .pair-code-label {
      font-size: 0.725rem;
      font-weight: 700;
      color: #94a3b8;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin-bottom: 0.45rem;
    }
    .pair-code-digits {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 1.55rem;
      font-weight: 800;
      letter-spacing: 0.14em;
      color: #38bdf8;
      user-select: all;
    }
    .footer { margin-top: 1.75rem; font-size: 0.775rem; color: #64748b; }
  </style>
</head>
<body>
  <div class="ambient-glow"></div>

  <div class="card" id="mainCard">
    <div class="logo-container">
      <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    </div>

    <h1>${escapeHtml(appDisplayName)}</h1>
    <p class="subtitle">${escapeHtml(appDisplaySubtitle)}</p>

    <div class="qr-frame" id="qrContainer">
      <img id="qrImage" src="" alt="QR Authorization Code" style="display: none;">

      <div class="overlay active" id="loadingOverlay">
        <div class="spinner"></div>
        <p style="font-size: 0.875rem; color: #cbd5e1;">Generating secure QR...</p>
      </div>

      <div class="overlay" id="expiredOverlay">
        <svg style="width: 36px; height: 36px; color: #f59e0b; margin-bottom: 0.5rem;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p style="font-size: 0.875rem; color: #e2e8f0; margin-bottom: 0.75rem;">Session Expired</p>
        <button class="btn-refresh" onclick="initQrSession()">Refresh Session</button>
      </div>
    </div>

    <div class="pair-code-card" id="pairCodeCard">
      <div class="pair-code-label">Or enter the code below</div>
      <div class="pair-code-digits" id="pairCodeDigits">•••• - ••••</div>
    </div>

    <div class="status-bar" id="statusBar">
      <div class="status-dot"></div>
      <span id="statusText">Awaiting approval (<span id="timerCount">120</span>s)</span>
    </div>

    <div class="footer">
      ${config.app.footerText}
    </div>
  </div>

  <script>
    const socket = io();
    let currentSessionId = null;
    let timerInterval = null;
    let secondsLeft = 120;

    const redirectTarget = ${JSON.stringify(redirectTarget)};
    const serviceId = ${JSON.stringify(matchedService ? matchedService.id : '')};

    const qrImage = document.getElementById('qrImage');
    const loadingOverlay = document.getElementById('loadingOverlay');
    const expiredOverlay = document.getElementById('expiredOverlay');
    const statusText = document.getElementById('statusText');
    const mainCard = document.getElementById('mainCard');

    function startTimer(durationMs) {
      clearInterval(timerInterval);
      secondsLeft = Math.floor(durationMs / 1000);
      statusText.innerHTML = 'Awaiting approval (<span id="timerCount">' + secondsLeft + '</span>s)';

      timerInterval = setInterval(() => {
        secondsLeft--;
        const countSpan = document.getElementById('timerCount');
        if (countSpan) {
          countSpan.textContent = secondsLeft;
        }

        if (secondsLeft <= 0) {
          clearInterval(timerInterval);
          onSessionExpired();
        }
      }, 1000);
    }

    function onSessionExpired() {
      expiredOverlay.classList.add('active');
      statusText.textContent = 'Session timed out';
      const pairCodeCard = document.getElementById('pairCodeCard');
      if (pairCodeCard) pairCodeCard.style.opacity = '0.35';
    }

    async function initQrSession() {
      try {
        loadingOverlay.classList.add('active');
        expiredOverlay.classList.remove('active');

        const params = new URLSearchParams();
        if (redirectTarget) params.append('redirect', redirectTarget);
        if (serviceId) params.append('service', serviceId);

        const url = '/auth/init' + (params.toString() ? '?' + params.toString() : '');
        const res = await fetch(url, { cache: 'no-store' });
        if (!res.ok) throw new Error('Failed to fetch session init');
        const data = await res.json();

        currentSessionId = data.loginSessionId;
        qrImage.src = data.qrCode;
        qrImage.style.display = 'block';

        const pairCodeDigits = document.getElementById('pairCodeDigits');
        if (pairCodeDigits && data.pairCodeFormatted) {
          pairCodeDigits.textContent = data.pairCodeFormatted;
        }
        const pairCodeCard = document.getElementById('pairCodeCard');
        if (pairCodeCard) pairCodeCard.style.opacity = '1';

        socket.emit('join-session', currentSessionId);

        loadingOverlay.classList.remove('active');

        startTimer(data.ttlMs || 120000);
      } catch (err) {
        console.error(err);
        statusText.textContent = 'Failed to load QR code';
      }
    }

    socket.on('approved', (data) => {
      clearInterval(timerInterval);

      mainCard.innerHTML = \`
        <div class="approved-state">
          <div class="approved-icon">
            <svg style="width: 36px; height: 36px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
              <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          </div>
          <h2 style="color: #ffffff; font-size: 1.45rem; font-weight: 700; margin-bottom: 0.5rem;">Access Approved</h2>
          <p style="color: #94a3b8; font-size: 0.95rem; margin-bottom: 1.5rem;">Starting session...</p>
          <div class="spinner"></div>
        </div>
      \`;

      setTimeout(() => {
        const dest = (data && data.redirect) ? data.redirect : redirectTarget;
        if (data && data.code) {
          window.location.href = '/auth/exchange?code=' + encodeURIComponent(data.code) + (dest ? '&redirect=' + encodeURIComponent(dest) : '');
        } else if (data && data.token) {
          window.location.href = '/auth/exchange?token=' + encodeURIComponent(data.token) + (dest ? '&redirect=' + encodeURIComponent(dest) : '');
        } else {
          window.location.href = dest || '/';
        }
      }, 700);
    });

    socket.on('rejected', (data) => {
      clearInterval(timerInterval);
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
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderDesktopLoginHtml,
};
