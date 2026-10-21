const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderApproverSetupRequiredHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Setup Required - ${escapeHtml(config.app.name || 'Auth Gateway')}</title>
  ${getPwaHeadTags()}
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
      width: 100%; max-width: 480px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      border-radius: 24px; padding: 2.25rem 2rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
      text-align: center;
    }
    .icon-warn {
      width: 64px; height: 64px; border-radius: 20px;
      background: rgba(245, 158, 11, 0.15); border: 1.5px solid #f59e0b;
      color: #fbbf24; display: inline-flex; align-items: center; justify-content: center;
      margin: 0 auto 1.25rem auto;
    }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff; }
    p.desc { font-size: 0.9rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem; }
    .cmd-box {
      background: #030712; border: 1px solid #1f2937; border-radius: 12px;
      padding: 0.85rem 1rem; text-align: left; margin-bottom: 1.25rem;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.825rem; color: #38bdf8; overflow-x: auto;
    }
    .cmd-label {
      font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;
      color: #94a3b8; font-weight: 700; margin-bottom: 0.4rem; text-align: left;
    }
    .note {
      font-size: 0.8rem; color: #64748b; line-height: 1.4; margin-top: 1rem;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon-warn">
      <svg style="width: 32px; height: 32px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    </div>
    <h1>No Password Configured</h1>
    <p class="desc">For maximum security, there is no default password. Please configure your master approver password from your server terminal:</p>

    <div class="cmd-label">Run on server (inside docker):</div>
    <div class="cmd-box">docker exec -it auth-gateway node set-password.js</div>

    <div class="cmd-label">Or run with npm (in auth-gateway dir):</div>
    <div class="cmd-box">npm run set-password</div>

    <p class="note">Once run, refresh this page to sign in. The new password takes effect immediately without needing to restart the container.</p>
  </div>
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderApproverSetupRequiredHtml,
};
