const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderSessionsDashboardHtml({ activeSessionsList = [], notice = '' }) {
  const sessionsRows = activeSessionsList.map((s) => {
    const elapsedMinutes = Math.floor(Math.max(0, Date.now() - (s.createdAt || Date.now())) / 60000);
    let timeLabel = 'just now';
    if (elapsedMinutes >= 60 * 24) {
      timeLabel = `${Math.floor(elapsedMinutes / (60 * 24))}d ago`;
    } else if (elapsedMinutes >= 60) {
      timeLabel = `${Math.floor(elapsedMinutes / 60)}h ago`;
    } else if (elapsedMinutes >= 1) {
      timeLabel = `${elapsedMinutes}m ago`;
    }

    const pad = (n) => String(n).padStart(2, '0');
    let expiresLabel = 'Never';
    if (s.expiresAt) {
      const expDate = new Date(s.expiresAt);
      if (!isNaN(expDate.getTime())) {
        expiresLabel = `${pad(expDate.getDate())}.${pad(expDate.getMonth() + 1)}.${expDate.getFullYear()} ${pad(expDate.getHours())}:${pad(expDate.getMinutes())}`;
      }
    }
    const deviceName = s.friendlyDevice || 'Desktop Browser';

    return `
      <div class="session-card" id="session-card-${s.id}">
        <div class="session-info">
          <div class="session-header" id="header-${s.id}">
            <span class="session-name" id="name-${s.id}">${escapeHtml(deviceName)}</span>
            <button type="button" class="btn-rename-trigger" onclick="openRename('${s.id}')" title="Rename device" aria-label="Rename device">
              <svg style="width: 13px; height: 13px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z" />
              </svg>
            </button>
            ${s.isTrusted
              ? `<span class="badge-trusted">
                   <svg style="width: 12px; height: 12px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                     <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                   </svg>
                   Trusted
                 </span>`
              : `<span class="badge-temp">Temporary</span>`
            }
          </div>
          <form method="POST" action="/auth/sessions/rename" class="rename-form" id="rename-form-${s.id}" style="display: none;">
            <input type="hidden" name="sessionId" value="${s.id}">
            <input type="text" name="name" class="rename-input" id="rename-input-${s.id}" value="${escapeHtml(deviceName)}" maxlength="40" required placeholder="Device name">
            <button type="submit" class="btn-rename-save">Save</button>
            <button type="button" class="btn-rename-cancel" onclick="closeRename('${s.id}')">Cancel</button>
          </form>
          <div class="session-sub">
            <div>${escapeHtml(s.ip)} &bull; <span class="session-started" data-created="${s.createdAt || ''}">Started ${timeLabel}</span></div>
            <div class="session-expiry" data-expires="${s.expiresAt || ''}">Expires ${expiresLabel}</div>
            ${Array.isArray(s.allowedServices) && s.allowedServices.length > 0 ? `<div class="session-services" style="font-size: 0.75rem; color: #38bdf8; margin-top: 0.15rem;">Access: ${escapeHtml(s.allowedServices.map(id => { const found = (config.services || []).find(svc => svc.id.toLowerCase() === id.toLowerCase()); return found ? found.name : id; }).join(', '))}</div>` : ''}
          </div>
        </div>
        <form method="POST" action="/auth/sessions/revoke" onsubmit="handleRevoke(event, '${s.id}')">
          <input type="hidden" name="sessionId" value="${s.id}">
          <button type="submit" class="btn-revoke" id="btn-revoke-${s.id}" title="Revoke access">Revoke</button>
        </form>
      </div>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Active Sessions - ${config.app.name}</title>
  ${getPwaHeadTags()}
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <script src="/socket.io/socket.io.js"></script>
  <script src="/auth/assets/jsqr.js"></script>
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

    /* Dual Action Buttons Header */
    .action-buttons-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 0.75rem;
      margin-bottom: 1.75rem;
    }
    .btn-action-hero {
      width: 100%;
      padding: 0.95rem 1rem;
      border: none;
      border-radius: 16px;
      font-size: 0.925rem;
      font-weight: 700;
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      transition: transform 0.15s, box-shadow 0.15s, background 0.15s;
    }
    .btn-scan-qr {
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: #ffffff;
      box-shadow: 0 10px 25px -5px rgba(2, 132, 199, 0.4);
    }
    .btn-scan-qr:hover {
      transform: translateY(-2px);
      box-shadow: 0 15px 30px -5px rgba(2, 132, 199, 0.5);
    }
    .btn-enter-code {
      background: rgba(255, 255, 255, 0.07);
      border: 1px solid rgba(56, 189, 248, 0.35);
      color: #38bdf8;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
    }
    .btn-enter-code:hover {
      transform: translateY(-2px);
      background: rgba(56, 189, 248, 0.12);
      border-color: #38bdf8;
    }

    .notice {
      background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981;
      color: #a7f3d0; padding: 0.75rem 1rem; border-radius: 12px;
      font-size: 0.875rem; margin-bottom: 1.25rem;
    }
    .session-list { display: flex; flex-direction: column; gap: 0.75rem; margin-bottom: 1.5rem; }
    .session-card {
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px; padding: 1.15rem 1.25rem;
      display: flex; justify-content: space-between; align-items: center;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    .session-header { display: flex; align-items: center; gap: 0.45rem; margin-bottom: 0.25rem; flex-wrap: wrap; }
    .session-name { font-weight: 600; font-size: 0.95rem; color: #ffffff; }
    .session-sub { font-size: 0.8rem; color: #94a3b8; line-height: 1.45; }
    .session-expiry { color: #cbd5e1; margin-top: 0.15rem; }

    .btn-rename-trigger {
      background: none; border: none; color: #94a3b8;
      display: inline-flex; align-items: center; justify-content: center;
      cursor: pointer; padding: 2px 4px; border-radius: 6px;
      transition: color 0.15s, background 0.15s;
    }
    .btn-rename-trigger:hover {
      color: #38bdf8; background: rgba(56, 189, 248, 0.1);
    }
    .rename-form {
      display: flex; align-items: center; gap: 0.4rem;
      margin-bottom: 0.35rem; flex-wrap: wrap;
    }
    .rename-input {
      background: rgba(255, 255, 255, 0.08);
      border: 1px solid rgba(56, 189, 248, 0.4);
      border-radius: 8px; color: #ffffff;
      padding: 0.35rem 0.65rem; font-size: 0.85rem; font-family: inherit;
      outline: none; max-width: 200px; width: 100%;
    }
    .rename-input:focus {
      border-color: #38bdf8; box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.25);
    }
    .btn-rename-save {
      background: #0284c7; color: #ffffff; border: none;
      border-radius: 8px; padding: 0.35rem 0.75rem; font-size: 0.8rem;
      font-weight: 600; cursor: pointer; transition: background 0.15s;
    }
    .btn-rename-save:hover { background: #0369a1; }
    .btn-rename-cancel {
      background: rgba(255, 255, 255, 0.1); color: #94a3b8; border: none;
      border-radius: 8px; padding: 0.35rem 0.65rem; font-size: 0.8rem;
      cursor: pointer; transition: background 0.15s, color 0.15s;
    }
    .btn-rename-cancel:hover { background: rgba(255, 255, 255, 0.18); color: #ffffff; }

    .badge-trusted {
      display: inline-flex; align-items: center; gap: 0.3rem;
      background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3);
      color: #34d399; font-size: 0.725rem; font-weight: 700;
      padding: 0.15rem 0.5rem; border-radius: 6px;
    }
    .badge-temp {
      background: rgba(148, 163, 184, 0.12); color: #94a3b8;
      font-size: 0.725rem; font-weight: 600; padding: 0.15rem 0.5rem; border-radius: 6px;
    }

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

    /* In-App Camera QR Scanner Modal Overlay */
    .scanner-overlay {
      position: fixed; inset: 0; background: rgba(0, 0, 0, 0.95);
      z-index: 9999; display: none; flex-direction: column;
      align-items: center; justify-content: center; padding: 1.5rem;
    }
    .scanner-overlay.active { display: flex; }
    .scanner-header {
      width: 100%; max-width: 420px; display: flex;
      justify-content: space-between; align-items: center; margin-bottom: 1.5rem;
    }
    .scanner-title { font-size: 1.25rem; font-weight: 700; color: #ffffff; }
    .btn-close-scanner {
      background: rgba(255, 255, 255, 0.1); border: none; color: #ffffff;
      width: 40px; height: 40px; border-radius: 50%; display: flex;
      align-items: center; justify-content: center; cursor: pointer;
    }
    .btn-close-scanner:hover { background: rgba(255, 255, 255, 0.2); }

    .scanner-viewfinder {
      position: relative; width: 300px; height: 300px;
      border-radius: 24px; overflow: hidden; background: #000000;
      box-shadow: 0 0 30px rgba(2, 132, 199, 0.3);
    }
    .scanner-video { width: 100%; height: 100%; object-fit: cover; }

    .scanner-corners {
      position: absolute; inset: 16px; pointer-events: none;
      border: 2px dashed rgba(56, 189, 248, 0.6); border-radius: 16px;
    }
    .scanner-tip {
      margin-top: 1.5rem; font-size: 0.9rem; color: #cbd5e1; text-align: center;
      max-width: 320px; line-height: 1.4;
    }
    .scanner-status {
      margin-top: 0.75rem; font-size: 0.85rem; color: #38bdf8; font-weight: 600;
    }

    /* 8-Digit Pairing Code Modal */
    .pair-modal-overlay {
      position: fixed; inset: 0; background: rgba(0, 0, 0, 0.85);
      backdrop-filter: blur(8px);
      z-index: 9999; display: none; align-items: center; justify-content: center;
      padding: 1.5rem;
    }
    .pair-modal-overlay.active { display: flex; }
    .pair-modal-card {
      width: 100%; max-width: 400px;
      background: rgba(15, 23, 42, 0.95);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 24px; padding: 1.75rem;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7);
    }
    .pair-modal-header {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 0.75rem;
    }
    .pair-modal-title { font-size: 1.2rem; font-weight: 700; color: #ffffff; }
    .pair-modal-desc {
      font-size: 0.85rem; color: #94a3b8; line-height: 1.45;
      margin-bottom: 1.25rem;
    }
    .pair-boxes-wrap {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.65rem;
      margin-bottom: 1.25rem;
    }
    .pair-box {
      width: 135px;
      height: 56px;
      background: rgba(255, 255, 255, 0.05);
      border: 2px solid rgba(56, 189, 248, 0.35);
      border-radius: 14px;
      color: #38bdf8;
      font-size: 1.55rem;
      font-weight: 800;
      letter-spacing: 0.18em;
      text-align: center;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      outline: none;
      box-sizing: border-box;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    .pair-box:focus {
      border-color: #38bdf8;
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.25);
    }
    .pair-box-sep {
      font-size: 1.4rem;
      font-weight: 700;
      color: #64748b;
      user-select: none;
    }
    .pair-modal-error {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.35);
      color: #fca5a5;
      padding: 0.6rem 0.85rem;
      border-radius: 10px;
      font-size: 0.825rem;
      margin-bottom: 1rem;
      text-align: center;
    }
    .btn-pair-submit {
      width: 100%;
      padding: 0.85rem 1.25rem;
      background: linear-gradient(135deg, #0284c7 0%, #0369a1 100%);
      color: #ffffff;
      border: none;
      border-radius: 14px;
      font-size: 0.95rem;
      font-weight: 700;
      cursor: pointer;
      transition: transform 0.15s, background 0.15s;
    }
    .btn-pair-submit:hover {
      transform: translateY(-1px);
      box-shadow: 0 10px 20px -5px rgba(2, 132, 199, 0.4);
    }
    .btn-pair-submit:disabled {
      opacity: 0.6;
      cursor: not-allowed;
      transform: none;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="top-bar">
      <h1>Session Gateway</h1>
      <div style="display: flex; gap: 0.5rem; align-items: center;">
        <a href="/" class="btn-logout" style="color: #38bdf8; border-color: rgba(56, 189, 248, 0.3);">Portal</a>
        <a href="/auth/approver/logout" class="btn-logout">Sign Out</a>
      </div>
    </div>

    ${notice ? `<div class="notice" id="dashboard-notice">${escapeHtml(notice)}</div>` : `<div class="notice" id="dashboard-notice" style="display: none;"></div>`}

    <!-- Dual Action Header: Scan QR & Enter Code -->
    <div class="action-buttons-grid">
      <button type="button" class="btn-action-hero btn-scan-qr" onclick="openScanner()">
        <svg style="width: 20px; height: 20px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z" />
        </svg>
        <span>Scan QR Code</span>
      </button>
      <button type="button" class="btn-action-hero btn-enter-code" onclick="openPairCodeModal()">
        <svg style="width: 20px; height: 20px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />
        </svg>
        <span>Enter Code</span>
      </button>
    </div>

    <h2 style="font-size: 1.15rem; font-weight: 700; margin-bottom: 0.85rem; color: #ffffff;">Active Authorized Sessions</h2>

    <div id="sessions-container">
      ${activeSessionsList.length > 0 ? `
        <div class="session-list">
          ${sessionsRows}
        </div>
        <form method="POST" action="/auth/sessions/revoke" class="revoke-all-form" onsubmit="handleRevokeAll(event)">
          <input type="hidden" name="all" value="true">
          <button type="submit" class="btn-revoke-all" id="btn-revoke-all">
            Revoke All Active Sessions
          </button>
        </form>
      ` : `
        <div class="empty-state">
          <p>No active desktop sessions.</p>
          <p style="font-size: 0.8rem; margin-top: 0.4rem;">Tap "Scan Desktop QR Code" above to authorize a new computer.</p>
        </div>
      `}
    </div>
  </div>

  <!-- In-App Scanner Modal -->
  <div class="scanner-overlay" id="scannerModal">
    <div class="scanner-header">
      <div class="scanner-title">Scan QR Code</div>
      <button class="btn-close-scanner" onclick="closeScanner()" aria-label="Close">
        <svg style="width: 20px; height: 20px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      </button>
    </div>

    <div class="scanner-viewfinder">
      <video id="scannerVideo" class="scanner-video" playsinline muted autoplay></video>
      <div class="scanner-corners"></div>
      <canvas id="scannerCanvas" style="display: none;"></canvas>
    </div>

    <p class="scanner-tip">Point your phone camera directly at the QR code on the computer screen.</p>
    <div class="scanner-status" id="scannerStatus">Starting camera...</div>
  </div>

  <!-- In-App 8-Digit Pairing Code Modal -->
  <div class="pair-modal-overlay" id="pairCodeModal" onclick="if(event.target===this)closePairCodeModal()">
    <div class="pair-modal-card">
      <div class="pair-modal-header">
        <div class="pair-modal-title">Enter 8-Digit Code</div>
        <button type="button" class="btn-close-scanner" onclick="closePairCodeModal()" aria-label="Close">
          <svg style="width: 20px; height: 20px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      </div>

      <p class="pair-modal-desc">Type the 8 digits shown on the computer screen to authorize access.</p>

      <form id="pairCodeForm" onsubmit="handlePairCodeSubmit(event)">
        <div class="pair-boxes-wrap">
          <input
            type="text"
            id="pairBox1"
            class="pair-box"
            inputmode="numeric"
            pattern="[0-9]*"
            maxlength="4"
            placeholder="••••"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            oninput="handleBoxInput(this, 'pairBox2')"
            onkeydown="handleBoxKeydown(this, event, null, 'pairBox2')"
            onpaste="handleBoxPaste(event)"
          />
          <span class="pair-box-sep">—</span>
          <input
            type="text"
            id="pairBox2"
            class="pair-box"
            inputmode="numeric"
            pattern="[0-9]*"
            maxlength="4"
            placeholder="••••"
            autocomplete="off"
            autocorrect="off"
            autocapitalize="off"
            spellcheck="false"
            oninput="handleBoxInput(this, null)"
            onkeydown="handleBoxKeydown(this, event, 'pairBox1', null)"
            onpaste="handleBoxPaste(event)"
          />
        </div>
        <div class="pair-modal-error" id="pairCodeError" style="display: none;"></div>

        <button type="submit" class="btn-pair-submit" id="btnPairSubmit">
          Authorize Device
        </button>
      </form>
    </div>
  </div>

  <script>
    function openRename(id) {
      const form = document.getElementById('rename-form-' + id);
      const header = document.getElementById('header-' + id);
      if (!form) return;
      form.style.display = 'flex';
      if (header) header.style.display = 'none';
      const input = document.getElementById('rename-input-' + id);
      if (input) {
        input.focus();
        input.select();
      }
    }

    function closeRename(id) {
      const form = document.getElementById('rename-form-' + id);
      const header = document.getElementById('header-' + id);
      if (!form) return;
      form.style.display = 'none';
      if (header) header.style.display = 'flex';
    }

    function padZero(n) {
      return String(n).padStart(2, '0');
    }

    function updateSessionTimestamps() {
      // 1. Format expiration dates in approver's local browser timezone (DD.MM.YYYY HH:mm)
      document.querySelectorAll('.session-expiry[data-expires]').forEach(function(el) {
        const raw = el.getAttribute('data-expires');
        if (!raw) return;
        const ts = Number(raw);
        if (!ts || isNaN(ts)) return;
        const d = new Date(ts);
        if (isNaN(d.getTime())) return;
        const formatted = padZero(d.getDate()) + '.' +
          padZero(d.getMonth() + 1) + '.' +
          d.getFullYear() + ' ' +
          padZero(d.getHours()) + ':' +
          padZero(d.getMinutes());
        el.textContent = 'Expires ' + formatted;
      });

      // 2. Format elapsed start time (from 60m into h, from 24h into d)
      document.querySelectorAll('.session-started[data-created]').forEach(function(el) {
        const raw = el.getAttribute('data-created');
        if (!raw) return;
        const ts = Number(raw);
        if (!ts || isNaN(ts)) return;
        const elapsedMinutes = Math.floor(Math.max(0, Date.now() - ts) / 60000);
        let label = 'just now';
        if (elapsedMinutes >= 60 * 24) {
          label = Math.floor(elapsedMinutes / (60 * 24)) + 'd ago';
        } else if (elapsedMinutes >= 60) {
          label = Math.floor(elapsedMinutes / 60) + 'h ago';
        } else if (elapsedMinutes >= 1) {
          label = elapsedMinutes + 'm ago';
        }
        el.textContent = 'Started ' + label;
      });
    }

    updateSessionTimestamps();
    setInterval(updateSessionTimestamps, 60000);

    const socket = typeof io !== 'undefined' ? io() : null;
    if (socket) {
      socket.on('session-revoked', function(data) {
        if (data && data.all) {
          removeAllSessionCards('All sessions revoked.');
        } else if (data && data.sessionId) {
          removeSessionCard(data.sessionId, 'Session revoked.');
        }
      });
    }

    function showNotice(msg) {
      let noticeEl = document.getElementById('dashboard-notice');
      if (noticeEl) {
        noticeEl.textContent = msg;
        noticeEl.style.display = 'block';
      }
    }

    function removeSessionCard(sessionId, noticeMsg) {
      const card = document.getElementById('session-card-' + sessionId);
      if (card) {
        card.style.transition = 'opacity 0.25s ease, transform 0.25s ease';
        card.style.opacity = '0';
        card.style.transform = 'scale(0.95)';
        setTimeout(() => {
          card.remove();
          const list = document.querySelector('.session-list');
          if (list && list.children.length === 0) {
            showEmptyState();
          }
        }, 250);
      }
      if (noticeMsg) showNotice(noticeMsg);
    }

    function removeAllSessionCards(noticeMsg) {
      const list = document.querySelector('.session-list');
      if (list) {
        list.style.transition = 'opacity 0.25s ease';
        list.style.opacity = '0';
        setTimeout(() => {
          showEmptyState();
        }, 250);
      }
      if (noticeMsg) showNotice(noticeMsg);
    }

    function showEmptyState() {
      const container = document.getElementById('sessions-container');
      if (container) {
        container.innerHTML = '<div class="empty-state">' +
          '<p>No active desktop sessions.</p>' +
          '<p style="font-size: 0.8rem; margin-top: 0.4rem;">Tap "Scan Desktop QR Code" above to authorize a new computer.</p>' +
          '</div>';
      }
    }

    async function handleRevoke(e, sessionId) {
      if (e) e.preventDefault();
      const btn = document.getElementById('btn-revoke-' + sessionId);
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Revoking...';
      }
      try {
        const res = await fetch('/auth/sessions/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ sessionId })
        });
        if (!res.ok) {
          const errData = await res.json().catch(function() { return {}; });
          throw new Error(errData.error || ('Revocation failed (' + res.status + ')'));
        }
        const data = await res.json();
        removeSessionCard(sessionId, data.message || 'Session revoked.');
      } catch (err) {
        console.error(err);
        alert('Could not revoke session: ' + err.message);
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Revoke';
        }
      }
    }

    async function handleRevokeAll(e) {
      if (e) e.preventDefault();
      if (!confirm('Revoke all authenticated desktop sessions?')) return;
      const btn = document.getElementById('btn-revoke-all');
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Revoking All...';
      }
      try {
        const res = await fetch('/auth/sessions/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ all: true })
        });
        if (!res.ok) {
          const errData = await res.json().catch(function() { return {}; });
          throw new Error(errData.error || ('Revocation failed (' + res.status + ')'));
        }
        const data = await res.json();
        removeAllSessionCards(data.message || 'All sessions revoked.');
      } catch (err) {
        console.error(err);
        alert('Could not revoke all sessions: ' + err.message);
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Revoke All Active Sessions';
        }
      }
    }

    let scannerStream = null;
    let scanAnimFrame = null;
    const scannerModal = document.getElementById('scannerModal');
    const scannerVideo = document.getElementById('scannerVideo');
    const scannerCanvas = document.getElementById('scannerCanvas');
    const scannerStatus = document.getElementById('scannerStatus');
    const canvasCtx = scannerCanvas.getContext('2d');

    async function openScanner() {
      scannerModal.classList.add('active');
      scannerStatus.textContent = 'Initializing camera...';

      try {
        scannerStream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: { ideal: 'environment' } }
        });
        scannerVideo.srcObject = scannerStream;
        await scannerVideo.play();
        scannerStatus.textContent = 'Scanning for QR code...';
        scanFrame();
      } catch (err) {
        console.error('Camera error:', err);
        scannerStatus.innerHTML = '<span style="color: #ef4444;">Camera permission denied or camera unavailable.</span>';
      }
    }

    function closeScanner() {
      if (scannerStream) {
        scannerStream.getTracks().forEach(t => t.stop());
        scannerStream = null;
      }
      if (scanAnimFrame) {
        cancelAnimationFrame(scanAnimFrame);
        scanAnimFrame = null;
      }
      scannerModal.classList.remove('active');
    }

    function scanFrame() {
      if (!scannerModal.classList.contains('active')) return;

      if (scannerVideo.readyState === scannerVideo.HAVE_ENOUGH_DATA) {
        scannerCanvas.width = scannerVideo.videoWidth;
        scannerCanvas.height = scannerVideo.videoHeight;
        canvasCtx.drawImage(scannerVideo, 0, 0, scannerCanvas.width, scannerCanvas.height);

        const imgData = canvasCtx.getImageData(0, 0, scannerCanvas.width, scannerCanvas.height);

        // Scan via jsQR
        if (typeof jsQR !== 'undefined') {
          const code = jsQR(imgData.data, imgData.width, imgData.height, {
            inversionAttempts: 'dontInvert',
          });

          if (code && code.data) {
            handleDecodedQr(code.data);
            return;
          }
        }
      }

      scanAnimFrame = requestAnimationFrame(scanFrame);
    }

    function handleDecodedQr(url) {
      if (url.includes('/auth/approve')) {
        scannerStatus.innerHTML = '<span style="color: #10b981; font-weight: 700;">QR Detected! Redirecting to authorization...</span>';
        if (navigator.vibrate) navigator.vibrate([50, 50, 50]);
        setTimeout(() => {
          window.location.href = url;
        }, 300);
      } else {
        scannerStatus.textContent = 'Non-authorization QR code detected.';
        scanAnimFrame = requestAnimationFrame(scanFrame);
      }
    }

    // Auto-open scanner or PIN modal if launched via shortcut
    const actionParam = new URLSearchParams(window.location.search).get('action');
    if (actionParam === 'scan') {
      window.addEventListener('DOMContentLoaded', () => {
        setTimeout(openScanner, 250);
      });
    } else if (actionParam === 'pin' || actionParam === 'code') {
      window.addEventListener('DOMContentLoaded', () => {
        setTimeout(openPairCodeModal, 250);
      });
    }

    function openPairCodeModal() {
      const modal = document.getElementById('pairCodeModal');
      const b1 = document.getElementById('pairBox1');
      const b2 = document.getElementById('pairBox2');
      const errEl = document.getElementById('pairCodeError');
      const btn = document.getElementById('btnPairSubmit');
      if (errEl) errEl.style.display = 'none';
      if (btn) {
        btn.disabled = false;
        btn.textContent = 'Authorize Device';
      }
      if (b1) { b1.value = ''; b1.disabled = false; }
      if (b2) { b2.value = ''; b2.disabled = false; }
      if (modal) modal.classList.add('active');
      setTimeout(() => {
        if (b1) b1.focus();
      }, 100);
    }

    function closePairCodeModal() {
      const modal = document.getElementById('pairCodeModal');
      if (modal) modal.classList.remove('active');
    }

    function handleBoxInput(el, nextBoxId) {
      el.value = el.value.replace(/\D/g, '').slice(0, 4);
      const errEl = document.getElementById('pairCodeError');
      if (errEl) errEl.style.display = 'none';

      if (el.value.length === 4 && nextBoxId) {
        const next = document.getElementById(nextBoxId);
        if (next) {
          next.focus();
          next.select();
        }
      }

      checkAndSubmitCode();
    }

    function handleBoxKeydown(el, e, prevBoxId, nextBoxId) {
      if (e.key === 'Escape') {
        closePairCodeModal();
        return;
      }
      if (e.key === 'Backspace' && el.value.length === 0 && prevBoxId) {
        const prev = document.getElementById(prevBoxId);
        if (prev) {
          prev.focus();
          prev.value = prev.value.slice(0, -1);
          e.preventDefault();
        }
      } else if ((e.key === '-' || e.key === ' ') && nextBoxId) {
        e.preventDefault();
        const next = document.getElementById(nextBoxId);
        if (next) next.focus();
      } else if (e.key === 'ArrowRight' && el.selectionStart === el.value.length && nextBoxId) {
        const next = document.getElementById(nextBoxId);
        if (next) next.focus();
      } else if (e.key === 'ArrowLeft' && el.selectionStart === 0 && prevBoxId) {
        const prev = document.getElementById(prevBoxId);
        if (prev) prev.focus();
      }
    }

    function handleBoxPaste(e) {
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData('text') || '';
      const digits = text.replace(/\D/g, '').slice(0, 8);
      const b1 = document.getElementById('pairBox1');
      const b2 = document.getElementById('pairBox2');
      if (!b1 || !b2) return;

      b1.value = digits.slice(0, 4);
      b2.value = digits.slice(4, 8);

      if (b1.value.length === 4 && b2.value.length < 4) {
        b2.focus();
      } else if (b2.value.length === 4) {
        b2.focus();
      }
      checkAndSubmitCode();
    }

    function checkAndSubmitCode() {
      const b1 = document.getElementById('pairBox1');
      const b2 = document.getElementById('pairBox2');
      if (!b1 || !b2) return;
      const code = (b1.value + b2.value).replace(/\D/g, '');
      if (code.length === 8) {
        verifyPairCode(code);
      }
    }

    async function handlePairCodeSubmit(e) {
      if (e) e.preventDefault();
      const b1 = document.getElementById('pairBox1');
      const b2 = document.getElementById('pairBox2');
      if (!b1 || !b2) return;
      const code = (b1.value + b2.value).replace(/\D/g, '');
      if (code.length !== 8) {
        const errEl = document.getElementById('pairCodeError');
        if (errEl) {
          errEl.textContent = 'Please enter all 8 digits.';
          errEl.style.display = 'block';
        }
        if (b1.value.length < 4) b1.focus();
        else b2.focus();
        return;
      }
      verifyPairCode(code);
    }

    async function verifyPairCode(cleanCode) {
      const btn = document.getElementById('btnPairSubmit');
      const b1 = document.getElementById('pairBox1');
      const b2 = document.getElementById('pairBox2');
      const errEl = document.getElementById('pairCodeError');
      if (errEl) errEl.style.display = 'none';
      if (btn) {
        btn.disabled = true;
        btn.textContent = 'Verifying...';
      }
      if (b1) b1.disabled = true;
      if (b2) b2.disabled = true;

      try {
        const res = await fetch('/auth/code/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ code: cleanCode })
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok || !data.success) {
          throw new Error(data.error || 'Code verification failed.');
        }
        if (data.redirectUrl) {
          window.location.href = data.redirectUrl;
        }
      } catch (err) {
        if (errEl) {
          errEl.textContent = err.message || 'Invalid or expired code.';
          errEl.style.display = 'block';
        }
        if (btn) {
          btn.disabled = false;
          btn.textContent = 'Authorize Device';
        }
        if (b1) {
          b1.disabled = false;
          b1.focus();
          b1.select();
        }
        if (b2) {
          b2.disabled = false;
        }
      }
    }
  </script>
  ${PWA_SW_SCRIPT}
</body>
</html>`;
}

module.exports = {
  renderSessionsDashboardHtml,
};
