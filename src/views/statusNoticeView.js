const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderStatusNoticeHtml({ title, message, type = 'success', actionUrl, actionLabel }) {
  const isSuccess = type === 'success';
  const color = isSuccess ? '#10b981' : '#ef4444';
  const bg = isSuccess ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)';

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - ${escapeHtml(config.app.name || 'Auth Gateway')}</title>
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
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
    ${actionUrl ? `<a href="${actionUrl}" class="btn">${escapeHtml(actionLabel || 'Continue')}</a>` : ''}
  </div>
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderStatusNoticeHtml,
};
