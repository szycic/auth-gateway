const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderApproverSelfAuthHtml({ redirect = '', notice = '' }) {
  const noticeText = notice === 'revoked'
    ? 'Your device session was revoked from the management dashboard.'
    : (notice === 'logged_out'
      ? 'You have signed out of this device session.'
      : (notice ? String(notice) : 'Your device session is no longer active.'));

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Master Approver - Self Authorization</title>
  ${getPwaHeadTags()}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
      background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%);
      color: #f1f5f9; min-height: 100vh; display: flex; align-items: center;
      justify-content: center; padding: 1.5rem;
    }
    .card {
      width: 100%; max-width: 440px;
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(20px);
      border-radius: 28px; padding: 2.25rem 2rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
      text-align: center;
    }
    .icon {
      width: 64px; height: 64px; border-radius: 20px;
      background: rgba(14, 165, 233, 0.15); border: 1.5px solid #0ea5e9;
      color: #38bdf8; display: inline-flex; align-items: center; justify-content: center;
      margin: 0 auto 1.25rem auto;
    }
    h1 { font-size: 1.4rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff; }
    p.desc { font-size: 0.875rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem; }
    .notice-box {
      background: rgba(245, 158, 11, 0.12); border: 1px solid rgba(245, 158, 11, 0.3);
      color: #fbbf24; border-radius: 12px; padding: 0.75rem 1rem; font-size: 0.85rem;
      margin-bottom: 1.5rem; line-height: 1.4;
    }
    .btn-auth {
      display: block; width: 100%; padding: 0.95rem 1rem;
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: #ffffff; font-weight: 700; font-size: 0.95rem;
      border: none; border-radius: 14px; cursor: pointer;
      box-shadow: 0 10px 20px -5px rgba(2, 132, 199, 0.4);
      transition: transform 0.15s, box-shadow 0.15s;
      margin-bottom: 0.85rem;
    }
    .btn-auth:hover {
      transform: translateY(-2px);
      box-shadow: 0 15px 25px -5px rgba(2, 132, 199, 0.5);
    }
    .btn-link {
      display: inline-block; font-size: 0.85rem; color: #94a3b8;
      text-decoration: none; padding: 0.4rem 0.8rem;
    }
    .btn-link:hover { color: #ffffff; }
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">
      <svg style="width: 32px; height: 32px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v6a2 2 0 002 2z" />
      </svg>
    </div>
    <h1>Master Approver Device</h1>
    <div class="notice-box">${escapeHtml(noticeText)}</div>
    <p class="desc">As the Master Approver, you can instantly authorize access to all protected services on this phone.</p>
    <form method="POST" action="/auth/approver/self-authorize">
      <input type="hidden" name="redirect" value="${escapeHtml(redirect)}">
      <button type="submit" class="btn-auth">Authorize This Phone</button>
    </form>
    <a href="/auth/sessions" class="btn-link">Open Sessions &amp; QR Scanner</a>
  </div>
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderApproverSelfAuthHtml,
};
