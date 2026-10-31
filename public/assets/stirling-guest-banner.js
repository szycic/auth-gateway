(function() {
  var BANNER_ID = 'stirling-guest-banner';
  var STYLE_ID = 'stirling-guest-banner-styles';
  var GUEST_USER = 'guest';
  var GUEST_PASS = 'guestguest';

  function injectStyles() {
    if (document.getElementById(STYLE_ID)) return;
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = [
      '#stirling-guest-banner {',
      '  box-sizing: border-box;',
      '  width: 100%;',
      '  margin: 0 0 1.25rem 0;',
      '  padding: 0.9rem 1rem;',
      '  background: var(--c-surface-sunken, #f8fafc);',
      '  border: 1px solid var(--c-border, #e2e8f0);',
      '  border-left: 4px solid var(--c-brand, #3b82f6);',
      '  border-radius: 0.75rem;',
      '  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);',
      '  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;',
      '  color: var(--auth-text-primary, #1e293b);',
      '  animation: guestBannerFade 0.25s cubic-bezier(0.16, 1, 0.3, 1);',
      '  position: relative;',
      '  z-index: 10;',
      '}',
      '[data-mantine-color-scheme="dark"] #stirling-guest-banner,',
      '[data-theme="dark"] #stirling-guest-banner,',
      '.dark #stirling-guest-banner {',
      '  background: var(--c-surface-sunken, #1e2430);',
      '  border-color: var(--c-border, #334155);',
      '  border-left-color: var(--c-brand, #38bdf8);',
      '  color: var(--auth-text-primary, #f1f5f9);',
      '  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.25);',
      '}',
      '@keyframes guestBannerFade {',
      '  from { opacity: 0; transform: translateY(-6px); }',
      '  to { opacity: 1; transform: translateY(0); }',
      '}',
      '.guest-banner-header {',
      '  display: flex;',
      '  align-items: center;',
      '  justify-content: space-between;',
      '  gap: 0.5rem;',
      '  margin-bottom: 0.4rem;',
      '}',
      '.guest-banner-title {',
      '  display: flex;',
      '  align-items: center;',
      '  gap: 0.45rem;',
      '  font-weight: 700;',
      '  font-size: 0.88rem;',
      '  letter-spacing: -0.01em;',
      '}',
      '.guest-banner-icon {',
      '  color: var(--c-brand, #3b82f6);',
      '  flex-shrink: 0;',
      '}',
      '[data-mantine-color-scheme="dark"] .guest-banner-icon {',
      '  color: var(--c-brand, #38bdf8);',
      '}',
      '.guest-autofill-btn {',
      '  display: inline-flex;',
      '  align-items: center;',
      '  gap: 0.35rem;',
      '  background: var(--c-brand, #3b82f6);',
      '  color: #ffffff;',
      '  border: none;',
      '  border-radius: 0.375rem;',
      '  padding: 0.25rem 0.65rem;',
      '  font-size: 0.75rem;',
      '  font-weight: 600;',
      '  cursor: pointer;',
      '  transition: opacity 0.15s, transform 0.1s;',
      '}',
      '.guest-autofill-btn:hover {',
      '  opacity: 0.9;',
      '}',
      '.guest-autofill-btn:active {',
      '  transform: scale(0.97);',
      '}',
      '.guest-banner-msg {',
      '  font-size: 0.8rem;',
      '  line-height: 1.4;',
      '  color: var(--auth-text-secondary, #64748b);',
      '  margin: 0.25rem 0 0.55rem;',
      '}',
      '[data-mantine-color-scheme="dark"] .guest-banner-msg {',
      '  color: var(--auth-text-secondary, #94a3b8);',
      '}',
      '.guest-creds-row {',
      '  display: flex;',
      '  flex-wrap: wrap;',
      '  gap: 0.5rem;',
      '}',
      '.guest-cred-chip {',
      '  display: inline-flex;',
      '  align-items: center;',
      '  gap: 0.35rem;',
      '  background: var(--c-surface, #ffffff);',
      '  border: 1px solid var(--c-border, #e2e8f0);',
      '  border-radius: 0.5rem;',
      '  padding: 0.25rem 0.55rem;',
      '  font-size: 0.78rem;',
      '  cursor: pointer;',
      '  user-select: none;',
      '  transition: border-color 0.15s, background-color 0.15s;',
      '}',
      '[data-mantine-color-scheme="dark"] .guest-cred-chip {',
      '  background: var(--c-surface, #151921);',
      '  border-color: var(--c-border, #334155);',
      '}',
      '.guest-cred-chip:hover {',
      '  border-color: var(--c-brand, #3b82f6);',
      '}',
      '.guest-cred-label {',
      '  color: var(--auth-text-secondary, #64748b);',
      '  font-size: 0.72rem;',
      '}',
      '.guest-cred-val {',
      '  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;',
      '  font-weight: 600;',
      '}',
      '.guest-copy-icon {',
      '  opacity: 0.55;',
      '  display: flex;',
      '  align-items: center;',
      '}',
      '.guest-cred-chip:hover .guest-copy-icon {',
      '  opacity: 1;',
      '  color: var(--c-brand, #3b82f6);',
      '}',
      '.guest-banner-note {',
      '  font-size: 0.72rem;',
      '  font-style: italic;',
      '  color: var(--auth-text-secondary, #94a3b8);',
      '  margin-top: 0.45rem;',
      '}'
    ].join('\n');
    document.head.appendChild(style);
  }

  function isLoginRoute() {
    var p = (window.location && window.location.pathname) ? window.location.pathname : '';
    return p === '/login' || p === '/login/' || p.endsWith('/login') || p.endsWith('/login/');
  }

  function isInsideModalOrDialog(el) {
    if (!el || !el.closest) return false;
    return !!el.closest('.sui-modal, [role="dialog"], .modal, .dialog, dialog, [aria-modal="true"]');
  }

  function getAuthContainer() {
    if (!isLoginRoute()) return null;
    var container = document.querySelector('div[class*="_authContent"], div[class*="authContent"], div[class*="_authCard"], div[class*="authCard"]');
    if (container && isInsideModalOrDialog(container)) {
      return null;
    }
    return container;
  }

  function setNativeValue(el, val) {
    if (!el) return;
    try {
      var proto = Object.getPrototypeOf(el);
      var desc = Object.getOwnPropertyDescriptor(proto, 'value');
      if (desc && desc.set) {
        desc.set.call(el, val);
      } else {
        el.value = val;
      }
      el.dispatchEvent(new Event('input', { bubbles: true }));
      el.dispatchEvent(new Event('change', { bubbles: true }));
    } catch(e) {
      try {
        el.value = val;
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      } catch(err) {}
    }
  }

  function findInputs() {
    var container = getAuthContainer();
    if (!container) return { user: null, pass: null, container: null, form: null };

    var pass = container.querySelector('input[type="password"], input[name="current-password"], #password');
    if (!pass || isInsideModalOrDialog(pass)) {
      return { user: null, pass: null, container: null, form: null };
    }

    var form = pass.closest('form');
    if (form) {
      var formText = (form.textContent || '').toLowerCase();
      if (form.querySelector('input[autocomplete="new-password"]') ||
          formText.indexOf('create account') !== -1 ||
          formText.indexOf('create a self-hosted account') !== -1 ||
          formText.indexOf('sign up') !== -1 ||
          formText.indexOf('register') !== -1) {
        return { user: null, pass: null, container: null, form: null };
      }
    }

    var user = container.querySelector('#email, input[name="username"], input[name="login"], input[name="email"], input[autocomplete="username"], input[type="text"]');
    return { user: user, pass: pass, container: container, form: form };
  }

  function fillCredentials(btn) {
    var inputs = findInputs();
    if (inputs.user) setNativeValue(inputs.user, GUEST_USER);
    if (inputs.pass) setNativeValue(inputs.pass, GUEST_PASS);

    if (btn) {
      var oldHtml = btn.innerHTML;
      btn.innerHTML = 'Filled \u2713';
      btn.style.filter = 'brightness(1.15)';
      setTimeout(function() {
        btn.innerHTML = oldHtml;
        btn.style.filter = '';
      }, 1500);
    }
  }

  function copyText(text, chipEl) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text);
    } else {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); } catch(e) {}
      document.body.removeChild(ta);
    }
    if (chipEl) {
      var old = chipEl.innerHTML;
      chipEl.innerHTML = '<span style="color:#22c55e;font-weight:600;">Copied!</span>';
      setTimeout(function() {
        chipEl.innerHTML = old;
      }, 1400);
    }
  }

  function createBanner() {
    injectStyles();
    var div = document.createElement('div');
    div.id = BANNER_ID;
    div.innerHTML = [
      '<div class="guest-banner-header">',
      '  <div class="guest-banner-title">',
      '    <svg class="guest-banner-icon" viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" stroke-width="2.2" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
      '    <span>Guest Login</span>',
      '  </div>',
      '  <button type="button" class="guest-autofill-btn" id="guest-autofill-trigger" title="Fill credentials">',
      '    <svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2.5" fill="none" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
      '    <span>Auto-fill</span>',
      '  </button>',
      '</div>',
      '<div class="guest-banner-msg">You can log in with the guest credentials below:</div>',
      '<div class="guest-creds-row">',
      '  <div class="guest-cred-chip" id="guest-chip-user" title="Click to copy username">',
      '    <span class="guest-cred-label">User:</span>',
      '    <code class="guest-cred-val">' + GUEST_USER + '</code>',
      '    <span class="guest-copy-icon"><svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></span>',
      '  </div>',
      '  <div class="guest-cred-chip" id="guest-chip-pass" title="Click to copy password">',
      '    <span class="guest-cred-label">Password:</span>',
      '    <code class="guest-cred-val">' + GUEST_PASS + '</code>',
      '    <span class="guest-copy-icon"><svg viewBox="0 0 24 24" width="12" height="12" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></span>',
      '  </div>',
      '</div>',
      '<div class="guest-banner-note">Click credentials to copy, or click Auto-fill to enter them directly.</div>'
    ].join('\n');

    div.querySelector('#guest-autofill-trigger').addEventListener('click', function(e) {
      e.preventDefault();
      fillCredentials(this);
    });

    div.querySelector('#guest-chip-user').addEventListener('click', function(e) {
      e.preventDefault();
      copyText(GUEST_USER, this);
    });

    div.querySelector('#guest-chip-pass').addEventListener('click', function(e) {
      e.preventDefault();
      copyText(GUEST_PASS, this);
    });

    return div;
  }

  function check() {
    var existing = document.getElementById(BANNER_ID);

    if (!isLoginRoute()) {
      if (existing) existing.remove();
      return;
    }

    var inputs = findInputs();
    if (!inputs.pass || !inputs.container) {
      if (existing) existing.remove();
      return;
    }

    if (existing) {
      return;
    }

    var authContent = document.querySelector('div[class*="_authContent"], div[class*="authContent"]');
    var banner = createBanner();

    if (authContent && inputs.form) {
      authContent.insertBefore(banner, inputs.form);
    } else if (inputs.form) {
      inputs.form.insertBefore(banner, inputs.form.firstChild);
    } else if (inputs.container) {
      inputs.container.insertBefore(banner, inputs.container.firstChild);
    }
  }

  var observer = new MutationObserver(check);
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
    check();
  } else {
    document.addEventListener('DOMContentLoaded', function() {
      observer.observe(document.body, { childList: true, subtree: true });
      check();
    });
  }
})();
