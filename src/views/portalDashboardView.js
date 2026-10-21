const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderPortalDashboardHtml({ session, isApproverUser, services = [], notice = '' }) {
  const isTrusted = session && session.isTrusted;
  const friendlyDevice = (session && session.friendlyDevice) || 'Current Device';
  const ip = (session && session.ip) || 'Connected';
  const sessionId = (session && session.id) || '';
  const sessionToken = (session && session.token) || '';

  const servicesHtml = services.filter(svc => !svc.disableService).map(svc => {
    const isPublic = Boolean(svc.disableAuth);
    const isAllowed = isPublic || isApproverUser || isSessionAllowedForService(session, svc);
    return `
    <div class="service-card" style="${isAllowed ? '' : 'opacity: 0.55;'}">
      <div class="service-info">
        <div class="service-name">${escapeHtml(svc.name)}${isPublic ? ' <span style="font-size: 0.7rem; font-weight: 600; color: #38bdf8; background: rgba(56, 189, 248, 0.12); padding: 0.15rem 0.45rem; border-radius: 6px; margin-left: 0.35rem; border: 1px solid rgba(56, 189, 248, 0.2);">Public</span>' : ''}</div>
        <div class="service-desc">${escapeHtml(svc.subtitle || svc.url)}</div>
      </div>
      ${isAllowed ? `
      <a href="${escapeHtml(svc.url)}" class="btn-launch" target="_blank" rel="noopener">
        <span>Launch</span>
        <svg style="width: 14px; height: 14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
        </svg>
      </a>
      ` : `
      <span class="badge-no-access" style="font-size: 0.75rem; font-weight: 600; color: #94a3b8; background: rgba(255, 255, 255, 0.05); padding: 0.4rem 0.7rem; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.08);">
        Restricted
      </span>
      `}
    </div>
  `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(config.app.name || 'Auth Gateway')} - Portal</title>
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
      color: #f1f5f9; min-height: 100vh;
      display: flex; flex-direction: column; align-items: center; justify-content: center;
      padding: 2rem 1.25rem;
    }
    .ambient-glow {
      position: fixed; width: 600px; height: 600px;
      background: radial-gradient(circle, rgba(14, 165, 233, 0.12) 0%, rgba(99, 102, 241, 0.05) 50%, transparent 70%);
      top: 50%; left: 50%; transform: translate(-50%, -50%); pointer-events: none; z-index: 0;
    }
    .card {
      position: relative; z-index: 1; width: 100%; max-width: 520px;
      background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px); border-radius: 28px; padding: 2.25rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
    }
    .header { text-align: center; margin-bottom: 2rem; }
    .logo-container {
      width: 56px; height: 56px; border-radius: 16px;
      background: linear-gradient(135deg, rgba(56, 189, 248, 0.15), rgba(99, 102, 241, 0.15));
      border: 1px solid rgba(56, 189, 248, 0.3); display: inline-flex;
      align-items: center; justify-content: center; margin-bottom: 1rem;
      color: #38bdf8; box-shadow: 0 0 20px rgba(56, 189, 248, 0.2);
    }
    .logo-container svg { width: 28px; height: 28px; }
    h1 { font-size: 1.6rem; font-weight: 800; color: #ffffff; margin-bottom: 0.3rem; letter-spacing: -0.025em; }
    .subtitle { font-size: 0.875rem; color: #94a3b8; }
    
    .session-badge {
      display: flex; align-items: center; justify-content: space-between;
      background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px; padding: 0.85rem 1rem; margin-bottom: 1.75rem;
    }
    .device-title { font-weight: 600; font-size: 0.9rem; color: #f8fafc; }
    .device-sub { font-size: 0.775rem; color: #94a3b8; }
    .status-tag {
      font-size: 0.725rem; font-weight: 700; padding: 0.25rem 0.6rem; border-radius: 6px;
    }
    .status-trusted {
      background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3);
    }
    .status-guest {
      background: rgba(56, 189, 248, 0.12); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.25);
    }


    .section-title {
      font-size: 0.8rem; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.05em; color: #64748b; margin-bottom: 0.85rem;
    }
    .services-grid { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.75rem; }
    .service-card {
      background: rgba(255, 255, 255, 0.03); border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px; padding: 1rem 1.15rem; display: flex;
      justify-content: space-between; align-items: center;
      transition: border-color 0.2s, background 0.2s;
    }
    .service-card:hover {
      background: rgba(255, 255, 255, 0.05); border-color: rgba(56, 189, 248, 0.3);
    }
    .service-name { font-weight: 700; font-size: 0.95rem; color: #ffffff; }
    .service-desc { font-size: 0.8rem; color: #94a3b8; margin-top: 0.15rem; }
    .btn-launch {
      display: inline-flex; align-items: center; gap: 0.4rem;
      background: #0284c7; color: #ffffff; padding: 0.55rem 0.9rem;
      border-radius: 10px; font-size: 0.825rem; font-weight: 600;
      text-decoration: none; transition: background 0.2s;
    }
    .btn-launch:hover { background: #0369a1; }

    .actions-row {
      display: flex; justify-content: space-between; align-items: center;
      padding-top: 1.25rem; border-top: 1px solid rgba(255, 255, 255, 0.08);
    }
    .btn-action {
      font-size: 0.825rem; color: #94a3b8; text-decoration: none; font-weight: 600;
      padding: 0.5rem 0.85rem; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.1);
      transition: color 0.2s, border-color 0.2s;
    }
    .btn-action:hover { color: #f1f5f9; border-color: rgba(255, 255, 255, 0.25); }
    .btn-logout { color: #f87171; border-color: rgba(248, 113, 113, 0.25); }
    .btn-logout:hover { color: #fca5a5; border-color: rgba(248, 113, 113, 0.5); }
  </style>
</head>
<body>
  <div class="ambient-glow"></div>
  <div class="card">
    <div class="header">
      <div class="logo-container">
        <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
        </svg>
      </div>
      <h1>${escapeHtml(config.app.name)}</h1>
      <p class="subtitle">Central Authentication &amp; Services Portal</p>
    </div>

    ${notice ? `<div style="background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; color: #a7f3d0; padding: 0.65rem 0.9rem; border-radius: 12px; font-size: 0.85rem; margin-bottom: 1.25rem;">${escapeHtml(notice)}</div>` : ''}

    <div class="session-badge">
      <div>
        <div class="device-title">${escapeHtml(friendlyDevice)}</div>
        <div class="device-sub">${escapeHtml(ip)}</div>
      </div>
      <span class="status-tag ${isTrusted ? 'status-trusted' : 'status-guest'}">
        ${isTrusted ? 'Trusted Device' : 'Active Session'}
      </span>
    </div>

    <div class="section-title">Authorized Services</div>
    <div class="services-grid">
      ${servicesHtml || '<p style="color: #94a3b8; font-size: 0.85rem;">No services configured.</p>'}
    </div>

    <div class="actions-row" style="justify-content: ${isApproverUser ? 'space-between' : 'flex-end'};">
      ${isApproverUser ? `<a href="/auth/sessions" class="btn-action" style="color: #38bdf8; border-color: rgba(56, 189, 248, 0.3);">Manage Sessions</a>` : ''}
      <a href="/auth/logout" class="btn-action btn-logout">Sign Out</a>
    </div>
  </div>



  <script>
    const socket = typeof io !== 'undefined' ? io() : null;
    if (socket) {
      function registerDesktop() {
        socket.emit('register-desktop', '${escapeHtml(sessionId)}');
      }
      socket.on('connect', registerDesktop);
      registerDesktop();

      socket.on('session-revoked', function(data) {
        if (data && (data.all || data.sessionId === '${escapeHtml(sessionId)}' || (data.token && data.token === '${escapeHtml(sessionToken)}'))) {
          lockCurrentSession();
        } else {
          fetch('/auth/verify', { cache: 'no-store' }).then(function(r) {
            if (r.status === 401) lockCurrentSession();
          }).catch(function() {});
        }
      });
    }

    function lockCurrentSession() {
      document.body.innerHTML = '<div style="min-height: 100vh; display: flex; align-items: center; justify-content: center; background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%); color: #f1f5f9; font-family: inherit; padding: 1.5rem;">' +
        '<div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 24px; padding: 2.25rem 2rem; max-width: 400px; text-align: center; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);">' +
          '<div style="width: 64px; height: 64px; border-radius: 50%; background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; color: #ef4444; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 1.25rem;">' +
            '<svg style="width: 32px; height: 32px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">' +
              '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />' +
            '</svg>' +
          '</div>' +
          '<h1 style="font-size: 1.35rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff;">Session Revoked</h1>' +
          '<p style="font-size: 0.9rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem;">Access for this device was terminated by an approver. Redirecting to login...</p>' +
        '</div>' +
      '</div>';
      setTimeout(function() {
        window.location.href = '/auth/logout?notice=' + encodeURIComponent('Your session has been revoked.');
      }, 1000);
    }

    // Fast heartbeat check against /auth/verify every 2 seconds as safety net
    setInterval(function() {
      fetch('/auth/verify', { cache: 'no-store' }).then(function(r) {
        if (r.status === 401) {
          lockCurrentSession();
        }
      }).catch(function() {});
    }, 2000);

    document.addEventListener('visibilitychange', function() {
      if (document.visibilityState === 'visible') {
        fetch('/auth/verify', { cache: 'no-store' }).then(function(r) {
          if (r.status === 401) lockCurrentSession();
        }).catch(function() {});
      }
    });
  </script>
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderPortalDashboardHtml,
};
