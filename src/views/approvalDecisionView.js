const config = require('../config');
const { escapeHtml } = require('../utils/htmlEscape');
const { getPwaHeadTags, PWA_SW_SCRIPT } = require('./components/pwa');

function renderApprovalDecisionHtml({ id, key, desktopIp, friendlyDevice, targetService, expiresAt, activeSessionsList, services }) {
  const activeCount = activeSessionsList.length;
  const servicesList = (services || config.services || []).filter(svc => !svc.disableService && !svc.disableAuth);
  const targetServiceId = targetService && !targetService.disableAuth ? targetService.id : null;

  const servicesChecklistHtml = servicesList.map(svc => {
    const isTarget = targetServiceId && svc.id.toLowerCase() === targetServiceId.toLowerCase();
    return `
    <label class="service-check-item ${isTarget ? 'service-check-target' : ''}">
      <input type="checkbox" name="services" value="${escapeHtml(svc.id)}" checked class="service-checkbox" data-service-id="${escapeHtml(svc.id)}" onchange="handleServiceCheckboxChange()">
      <div class="service-check-info">
        <div class="service-check-name-row">
          <span class="service-check-name">${escapeHtml(svc.name)}</span>
          ${isTarget ? `<span class="badge-target-svc">Current</span>` : ''}
        </div>
        <span class="service-check-sub">${escapeHtml(svc.subtitle || svc.url)}</span>
      </div>
    </label>
  `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize Desktop - ${config.app.name}</title>
  ${getPwaHeadTags()}
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
    .header { text-align: center; margin-bottom: 1.5rem; }
    h1 { font-size: 1.35rem; font-weight: 700; color: #ffffff; }
    .device-info {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px; padding: 1.15rem; margin-bottom: 1.25rem;
    }
    .info-row {
      display: flex; justify-content: space-between; align-items: center;
      padding: 0.45rem 0; font-size: 0.875rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    }
    .info-row:last-child { border-bottom: none; }
    .info-label { color: #94a3b8; }
    .info-val { color: #f8fafc; font-weight: 600; }

    .name-box {
      margin-bottom: 1.25rem; text-align: left;
    }
    .name-box label {
      display: block; font-size: 0.85rem; font-weight: 600;
      color: #94a3b8; margin-bottom: 0.45rem;
    }
    .name-input-wrapper input {
      width: 100%; padding: 0.8rem 1rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 12px; color: #ffffff;
      font-size: 0.95rem; font-family: inherit;
      outline: none; transition: border-color 0.2s, box-shadow 0.2s;
    }
    .name-input-wrapper input:focus {
      border-color: #38bdf8;
      box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
    }

    /* Toggle Containers (Trust Device & Restrict Platform) */
    .trust-box {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px; padding: 1rem 1.15rem; margin-bottom: 1rem;
      display: flex; align-items: center; gap: 0.85rem; cursor: pointer;
      user-select: none;
      transition: background 0.15s ease, border-color 0.15s ease;
    }
    .trust-box:hover {
      background: rgba(255, 255, 255, 0.06);
      border-color: rgba(255, 255, 255, 0.16);
    }
    .trust-box:has(input[type="checkbox"]:checked),
    .trust-box.is-checked {
      background: rgba(2, 132, 199, 0.12);
      border-color: rgba(56, 189, 248, 0.4);
    }
    .trust-box:has(input[type="checkbox"]:checked):hover,
    .trust-box.is-checked:hover {
      background: rgba(2, 132, 199, 0.18);
      border-color: rgba(56, 189, 248, 0.55);
    }
    .trust-box input[type="checkbox"] {
      width: 20px; height: 20px; accent-color: #0284c7; cursor: pointer; flex-shrink: 0;
    }
    .trust-text { text-align: left; }
    .trust-title { display: block; font-size: 0.925rem; font-weight: 600; color: #ffffff; margin-bottom: 0.15rem; }
    .trust-desc { display: block; font-size: 0.775rem; color: #94a3b8; line-height: 1.3; }

    /* Advanced Collapsible Section */
    .advanced-box {
      background: rgba(255, 255, 255, 0.02);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px;
      margin-bottom: 1.5rem;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .advanced-box[open] {
      border-color: rgba(56, 189, 248, 0.35);
      background: rgba(15, 23, 42, 0.6);
    }
    .advanced-summary {
      padding: 0.85rem 1.15rem;
      font-size: 0.875rem;
      font-weight: 600;
      color: #94a3b8;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      user-select: none;
      list-style: none;
    }
    .advanced-summary::-webkit-details-marker {
      display: none;
    }
    .advanced-summary:hover {
      color: #f8fafc;
    }
    .advanced-title {
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }
    .chevron-icon {
      transition: transform 0.2s ease;
    }
    .advanced-box[open] .chevron-icon {
      transform: rotate(180deg);
    }
    .advanced-content {
      padding: 0 1.15rem 1.15rem 1.15rem;
      border-top: 1px solid rgba(255, 255, 255, 0.06);
      margin-top: 0.25rem;
      padding-top: 0.85rem;
    }
    .adv-group { text-align: left; transition: opacity 0.2s; }
    .adv-group-disabled { opacity: 0.6; }
    .adv-group-disabled .adv-select,
    .adv-group-disabled .adv-input {
      cursor: not-allowed;
      background: rgba(255, 255, 255, 0.02);
      border-color: rgba(255, 255, 255, 0.06);
      color: #94a3b8;
    }
    .adv-label {
      display: block; font-size: 0.825rem; font-weight: 600;
      color: #cbd5e1; margin-bottom: 0.35rem;
    }
    .adv-label-row {
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 0.25rem;
    }
    .adv-desc {
      font-size: 0.75rem; color: #94a3b8; margin-bottom: 0.5rem;
    }
    .adv-select, .adv-input {
      width: 100%; padding: 0.65rem 0.85rem;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.12);
      border-radius: 10px; color: #ffffff;
      font-size: 0.875rem; font-family: inherit;
      outline: none; transition: border-color 0.2s, background 0.2s;
    }
    .adv-select:focus, .adv-input:focus {
      border-color: #38bdf8;
    }
    .adv-select option {
      background: #0f172a; color: #ffffff;
    }
    .ttl-trust-badge {
      font-size: 0.725rem; font-weight: 700; color: #38bdf8;
      background: rgba(56, 189, 248, 0.12); padding: 0.15rem 0.5rem;
      border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.25);
    }
    .ttl-trust-notice {
      margin-top: 0.45rem; font-size: 0.75rem; color: #94a3b8; line-height: 1.4;
    }


    .services-header-actions {
      display: flex; align-items: center; gap: 0.75rem;
    }
    .btn-toggle-service {
      background: none; border: none; color: #38bdf8;
      font-size: 0.75rem; font-weight: 600; cursor: pointer;
    }
    .btn-toggle-service:hover {
      text-decoration: underline;
    }
    .service-check-name-row {
      display: flex; align-items: center; gap: 0.45rem; flex-wrap: wrap;
    }
    .badge-target-svc {
      font-size: 0.65rem; font-weight: 700; color: #38bdf8;
      background: rgba(56, 189, 248, 0.15); border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 0.1rem 0.4rem; border-radius: 4px; line-height: 1.2;
    }
    .service-check-target {
      border-color: rgba(56, 189, 248, 0.3);
      background: rgba(56, 189, 248, 0.04);
    }

    .services-checklist {
      display: flex; flex-direction: column; gap: 0.45rem;
      max-height: 220px; overflow-y: auto; padding-right: 0.25rem;
    }
    .service-check-item {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid rgba(255, 255, 255, 0.06);
      border-radius: 10px; padding: 0.55rem 0.75rem;
      display: flex; align-items: center; gap: 0.65rem;
      cursor: pointer; transition: background 0.15s, border-color 0.15s;
    }
    .service-check-item:hover {
      background: rgba(255, 255, 255, 0.06);
      border-color: rgba(56, 189, 248, 0.25);
    }
    .service-checkbox {
      width: 17px; height: 17px; accent-color: #0284c7; cursor: pointer; flex-shrink: 0;
    }
    .service-check-info {
      display: flex; flex-direction: column; min-width: 0;
    }
    .service-check-name {
      font-size: 0.85rem; font-weight: 600; color: #ffffff;
    }
    .service-check-sub {
      font-size: 0.725rem; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .btn-toggle-all {
      background: none; border: none; color: #38bdf8;
      font-size: 0.75rem; font-weight: 600; cursor: pointer;
    }
    .btn-toggle-all:hover {
      text-decoration: underline;
    }

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
      <h1>Authorize Desktop Access?</h1>
    </div>

    <form method="POST" action="/auth/approve/action" onsubmit="return validateApprovalForm(event)">
      <input type="hidden" name="id" value="${id}">
      <input type="hidden" name="key" value="${key}">

      <div class="device-info">
        <div class="info-row">
          <span class="info-label">Detected Device</span>
          <span class="info-val">${escapeHtml(friendlyDevice)}</span>
        </div>
        <div class="info-row">
          <span class="info-label">IP Address</span>
          <span class="info-val">${escapeHtml(desktopIp)}</span>
        </div>
        ${targetService ? `
        <div class="info-row">
          <span class="info-label">Target Platform</span>
          <span class="info-val" style="color: #38bdf8; font-weight: 700;">${escapeHtml(targetService.name)}</span>
        </div>
        ` : ''}
        <div class="info-row">
          <span class="info-label">Access Level</span>
          <span class="info-val" style="color: #38bdf8;">Standard Access</span>
        </div>
      </div>

      <div class="name-box">
        <label for="customName">Device Name</label>
        <div class="name-input-wrapper">
          <input
            type="text"
            id="customName"
            name="customName"
            value="${escapeHtml(friendlyDevice)}"
            placeholder="e.g. Work Laptop, Living Room PC"
            maxlength="40"
            autocomplete="off"
            spellcheck="false"
          >
        </div>
      </div>

      <!-- Service Access Restriction Toggle (Prominent on Main Screen) -->
      ${targetService ? `
      <label class="trust-box">
        <input type="checkbox" id="onlyPlatformToggle" data-target-id="${escapeHtml(targetService.id)}" onchange="handleOnlyPlatformToggle(this, '${escapeHtml(targetService.id)}')">
        <div class="trust-text">
          <span class="trust-title">Grant access only to ${escapeHtml(targetService.name)}</span>
          <span class="trust-desc">Lock this session exclusively to ${escapeHtml(targetService.name)} (uncheck other services).</span>
        </div>
      </label>
      ` : `
      <label class="trust-box">
        <input type="checkbox" id="onlyPlatformToggle" onchange="handleGenericPlatformToggle(this)">
        <div class="trust-text">
          <span class="trust-title">Restrict to single platform</span>
          <span class="trust-desc">Limit this device to one service instead of full access.</span>
        </div>
      </label>
      <div id="platformPickerWrap" style="display: none; margin-top: -0.5rem; margin-bottom: 1rem; width: 100%;">
        <label style="display: block; font-size: 0.75rem; font-weight: 600; color: #94a3b8; margin-bottom: 0.35rem;">Select allowed platform:</label>
        <select id="platformPickerSelect" class="adv-select" onchange="handlePlatformPickerChange(this)">
          ${servicesList.map(s => `<option value="${escapeHtml(s.id)}">${escapeHtml(s.name)}</option>`).join('')}
        </select>
      </div>
      `}

      <label class="trust-box">
        <input type="checkbox" name="trusted" id="trustedCheckbox" value="true" onchange="handleTrustChange(this)">
        <div class="trust-text">
          <span class="trust-title">Trust this device</span>
          <span class="trust-desc">Keep signed in permanently until manually revoked.</span>
        </div>
      </label>

      <!-- Advanced Settings: Custom Expiration & Service Permissions -->
      <details class="advanced-box">
        <summary class="advanced-summary">
          <span class="advanced-title">
            <svg style="width: 15px; height: 15px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
            Advanced
          </span>
          <svg class="chevron-icon" style="width: 14px; height: 14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M19 9l-7 7-7-7" />
          </svg>
        </summary>

        <div class="advanced-content">
          <!-- 1. Expiration Time -->
          <div class="adv-group" id="expirationGroup">
            <div class="adv-label-row">
              <label class="adv-label" for="sessionTtl">Expiration Time</label>
              <span id="ttlTrustBadge" class="ttl-trust-badge" style="display: none;">Permanent (Trusted)</span>
            </div>
            <select name="sessionTtl" id="sessionTtl" class="adv-select" onchange="handleTtlChange(this)">
              <option value="1">1 hour</option>
              <option value="8">8 hours</option>
              <option value="24">24 hours (1 day)</option>
              <option value="72" selected>72 hours (3 days - default)</option>
              <option value="168">7 days (1 week)</option>
              <option value="720">30 days (1 month)</option>
              <option value="custom">Custom hours...</option>
            </select>
            <div id="customTtlWrap" style="display: none; margin-top: 0.5rem;">
              <input type="number" name="customTtlHours" id="customTtlHours" class="adv-input" min="1" max="87600" placeholder="Enter hours (e.g. 12)">
            </div>
            <div id="ttlTrustNotice" class="ttl-trust-notice" style="display: none;">
              Trusted devices never expire automatically. Expiration time cannot be changed while trusted.
            </div>
          </div>

          <!-- 2. Services Access Checklist -->
          <div class="adv-group" style="margin-top: 1rem;">
            <div class="adv-label-row">
              <label class="adv-label">Service Access</label>
              <div class="services-header-actions">
                ${targetService ? `<button type="button" class="btn-toggle-service" onclick="selectOnlyTargetService('${escapeHtml(targetService.id)}')">Only ${escapeHtml(targetService.name)}</button>` : ''}
                <button type="button" class="btn-toggle-all" onclick="toggleAllServices()">Toggle All</button>
              </div>
            </div>
            <div class="adv-desc">Customize individual service permissions:</div>
            <div class="services-checklist">
              ${servicesChecklistHtml}
            </div>
          </div>
        </div>
      </details>

      <div class="btn-group">
        <button type="submit" name="action" value="reject" class="btn btn-reject">Reject</button>
        <button type="submit" name="action" value="approve" class="btn btn-approve">Approve Desktop</button>
      </div>
    </form>
  </div>

  <div class="bottom-link">
    Currently active sessions: <b>${activeCount}</b> &bull; <a href="/auth/sessions">Manage Sessions</a>
  </div>
  ${PWA_SW_SCRIPT}

  <script>
    function syncToggleBoxStyle(checkbox) {
      if (!checkbox) return;
      var box = checkbox.closest('.trust-box');
      if (box) {
        if (checkbox.checked) {
          box.classList.add('is-checked');
        } else {
          box.classList.remove('is-checked');
        }
      }
    }

    function handleTrustChange(checkbox) {
      syncToggleBoxStyle(checkbox);
      var isTrusted = checkbox.checked;
      var sel = document.getElementById('sessionTtl');
      var customInp = document.getElementById('customTtlHours');
      var badge = document.getElementById('ttlTrustBadge');
      var notice = document.getElementById('ttlTrustNotice');
      var expGroup = document.getElementById('expirationGroup');

      if (sel) {
        sel.disabled = isTrusted;
      }
      if (customInp) {
        customInp.disabled = isTrusted;
      }
      if (badge) {
        badge.style.display = isTrusted ? 'inline-block' : 'none';
      }
      if (notice) {
        notice.style.display = isTrusted ? 'block' : 'none';
      }
      if (expGroup) {
        if (isTrusted) {
          expGroup.classList.add('adv-group-disabled');
        } else {
          expGroup.classList.remove('adv-group-disabled');
        }
      }
    }

    function handleTtlChange(sel) {
      var wrap = document.getElementById('customTtlWrap');
      if (!wrap) return;
      if (sel.value === 'custom') {
        wrap.style.display = 'block';
        var inp = document.getElementById('customTtlHours');
        if (inp) inp.focus();
      } else {
        wrap.style.display = 'none';
      }
    }

    function handleOnlyPlatformToggle(toggle, targetId) {
      syncToggleBoxStyle(toggle);
      var boxes = document.querySelectorAll('.service-checkbox');
      if (toggle.checked) {
        boxes.forEach(function(b) {
          b.checked = (b.value.toLowerCase() === targetId.toLowerCase());
        });
      } else {
        boxes.forEach(function(b) {
          b.checked = true;
        });
      }
    }

    function handleGenericPlatformToggle(toggle) {
      syncToggleBoxStyle(toggle);
      var wrap = document.getElementById('platformPickerWrap');
      var sel = document.getElementById('platformPickerSelect');
      var boxes = document.querySelectorAll('.service-checkbox');

      if (toggle.checked) {
        if (wrap) wrap.style.display = 'block';
        var selectedId = sel ? sel.value : (boxes[0] ? boxes[0].value : '');
        boxes.forEach(function(b) {
          b.checked = (b.value.toLowerCase() === selectedId.toLowerCase());
        });
      } else {
        if (wrap) wrap.style.display = 'none';
        boxes.forEach(function(b) {
          b.checked = true;
        });
      }
    }

    function handlePlatformPickerChange(sel) {
      var toggle = document.getElementById('onlyPlatformToggle');
      if (!toggle || !toggle.checked) return;
      var selectedId = sel.value;
      var boxes = document.querySelectorAll('.service-checkbox');
      boxes.forEach(function(b) {
        b.checked = (b.value.toLowerCase() === selectedId.toLowerCase());
      });
    }

    function selectOnlyTargetService(targetId) {
      var toggle = document.getElementById('onlyPlatformToggle');
      if (toggle) {
        toggle.checked = true;
        syncToggleBoxStyle(toggle);
        handleOnlyPlatformToggle(toggle, targetId);
      } else {
        var boxes = document.querySelectorAll('.service-checkbox');
        boxes.forEach(function(b) {
          b.checked = (b.value.toLowerCase() === targetId.toLowerCase());
        });
      }
    }

    function handleServiceCheckboxChange() {
      updatePlatformToggleState();
    }

    function updatePlatformToggleState() {
      var toggle = document.getElementById('onlyPlatformToggle');
      if (!toggle) return;
      var targetId = toggle.getAttribute('data-target-id');
      var boxes = document.querySelectorAll('.service-checkbox');

      if (targetId) {
        var targetFound = false;
        var anyOtherChecked = false;

        boxes.forEach(function(b) {
          if (b.value.toLowerCase() === targetId.toLowerCase()) {
            if (b.checked) targetFound = true;
          } else {
            if (b.checked) anyOtherChecked = true;
          }
        });

        toggle.checked = targetFound && !anyOtherChecked;
      } else {
        var wrap = document.getElementById('platformPickerWrap');
        var sel = document.getElementById('platformPickerSelect');
        var checkedBoxes = Array.from(boxes).filter(function(b) { return b.checked; });

        if (checkedBoxes.length === 1) {
          toggle.checked = true;
          if (wrap) wrap.style.display = 'block';
          if (sel) sel.value = checkedBoxes[0].value;
        } else {
          toggle.checked = false;
          if (wrap) wrap.style.display = 'none';
        }
      }
      syncToggleBoxStyle(toggle);
    }

    function toggleAllServices() {
      var boxes = document.querySelectorAll('.service-checkbox');
      var allChecked = Array.from(boxes).every(function(b) { return b.checked; });
      boxes.forEach(function(b) { b.checked = !allChecked; });
      updatePlatformToggleState();
    }

    function validateApprovalForm(event) {
      var submitter = event.submitter || document.activeElement;
      if (submitter && submitter.value === 'reject') {
        return true;
      }
      var checkedBoxes = document.querySelectorAll('.service-checkbox:checked');
      if (checkedBoxes.length === 0) {
        alert('Please select at least one service to grant access.');
        event.preventDefault();
        return false;
      }
      return true;
    }

    // Initialize toggle box states on load
    document.querySelectorAll('.trust-box input[type="checkbox"]').forEach(function(inp) {
      syncToggleBoxStyle(inp);
    });
  </script>
</body>
</html>`;
}

module.exports = {
  renderApprovalDecisionHtml,
};
