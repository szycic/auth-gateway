const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderApproverLoginHtml({ returnTo = '/auth/sessions', error = '' }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Approver Authentication - ${escapeHtml(config.app.name || 'Auth Gateway')}</title>
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
    .password-wrapper {
      position: relative;
      display: flex;
      align-items: center;
    }
    .password-wrapper input {
      width: 100%; padding: 0.85rem 2.75rem 0.85rem 1rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.15);
      border-radius: 12px; color: #ffffff; font-size: 1rem;
      outline: none; transition: border-color 0.2s, box-shadow 0.2s;
    }
    .password-wrapper input:focus {
      border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }
    .btn-toggle-pw {
      position: absolute; right: 0.75rem; top: 50%; transform: translateY(-50%);
      background: none; border: none; color: #94a3b8; cursor: pointer;
      display: inline-flex; align-items: center; justify-content: center;
      padding: 0.25rem; border-radius: 6px; transition: color 0.2s;
    }
    .btn-toggle-pw:hover { color: #38bdf8; }
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
    <p class="desc">Sign in on this device to authorize desktop sessions and manage access.</p>

    ${error ? `<div class="error-box">${error}</div>` : ''}

    <form method="POST" action="/auth/approver/login">
      <input type="hidden" name="returnTo" value="${escapeHtml(returnTo)}">
      <div class="form-group">
        <label for="password">Approver Password</label>
        <div class="password-wrapper">
          <input type="password" id="password" name="password" required autofocus placeholder="Enter password...">
          <button type="button" class="btn-toggle-pw" id="togglePwBtn" aria-label="Show password" title="Show password" onclick="togglePasswordVisibility()">
            <svg id="eyeIcon" style="width: 20px; height: 20px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              <path stroke-linecap="round" stroke-linejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
            </svg>
            <svg id="eyeOffIcon" style="width: 20px; height: 20px; display: none;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l18 18" />
            </svg>
          </button>
        </div>
      </div>

      <button type="submit" class="btn">Sign In as Approver</button>
    </form>
  </div>

  <script>
    function togglePasswordVisibility() {
      const input = document.getElementById('password');
      const eyeIcon = document.getElementById('eyeIcon');
      const eyeOffIcon = document.getElementById('eyeOffIcon');
      const btn = document.getElementById('togglePwBtn');
      const isVisible = input.type === 'password';

      input.type = isVisible ? 'text' : 'password';
      eyeIcon.style.display = isVisible ? 'none' : 'block';
      eyeOffIcon.style.display = isVisible ? 'block' : 'none';
      btn.setAttribute('aria-label', isVisible ? 'Hide password' : 'Show password');
      btn.setAttribute('title', isVisible ? 'Hide password' : 'Show password');
    }
  </script>
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderApproverLoginHtml,
};
