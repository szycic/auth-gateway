const express = require('express');
const path = require('path');
const fs = require('fs');
const config = require('../config');
const { isAuthDomain } = require('../utils/originHelper');
const { generatePwaManifest } = require('../utils/pwaHelper');

const router = express.Router();

// Dynamic PWA manifest route (only on Auth Gateway domain)
router.get('/manifest.webmanifest', (req, res, next) => {
  if (!isAuthDomain(req)) return next();
  res.setHeader('Content-Type', 'application/manifest+json');
  res.setHeader('Cache-Control', 'public, max-age=86400');
  return res.json(generatePwaManifest());
});

// Serve static PWA assets (sw.js, icons) ONLY for Auth Gateway host or /auth/ paths
const servePwaStatic = express.static(path.join(config.ROOT_DIR, 'public'), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('sw.js')) {
      res.setHeader('Service-Worker-Allowed', '/');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    } else if (filePath.endsWith('.css')) {
      res.setHeader('Content-Type', 'text/css');
      res.setHeader('Cache-Control', 'public, max-age=604800');
    } else if (filePath.endsWith('.png') || filePath.endsWith('.svg')) {
      res.setHeader('Cache-Control', 'public, max-age=604800');
    }
  },
});

router.use('/auth/assets', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  next();
});

router.use('/auth/assets/css', express.static(path.join(config.ROOT_DIR, 'public/css'), {
  maxAge: '7d',
}));

router.use('/auth/assets', express.static(path.join(config.ROOT_DIR, 'public/assets'), {
  maxAge: '7d',
}));

// Root icon fallbacks for standard browser probes
router.get(['/favicon.ico', '/icon.svg'], (req, res, next) => {
  if (!isAuthDomain(req)) return next();
  res.setHeader('Cache-Control', 'public, max-age=604800');
  return res.sendFile(path.join(config.ROOT_DIR, 'public/assets/icon.svg'));
});

router.get('/apple-touch-icon.png', (req, res, next) => {
  if (!isAuthDomain(req)) return next();
  res.setHeader('Cache-Control', 'public, max-age=604800');
  return res.sendFile(path.join(config.ROOT_DIR, 'public/assets/apple-touch-icon.png'));
});

router.use((req, res, next) => {
  if (isAuthDomain(req) || req.path.startsWith('/auth/')) {
    return servePwaStatic(req, res, next);
  }
  next();
});

router.get('/sw.js', (req, res, next) => {
  if (!isAuthDomain(req)) return next();
  res.sendFile(path.join(config.ROOT_DIR, 'public/sw.js'), {
    headers: {
      'Content-Type': 'application/javascript',
      'Service-Worker-Allowed': '/',
      'Cache-Control': 'no-cache, no-store, must-revalidate',
    },
  });
});

// Serve jsQR for in-app scanner
router.get('/auth/assets/jsqr.js', (req, res) => {
  const localFile = path.join(config.ROOT_DIR, 'node_modules/jsqr/dist/jsQR.js');
  if (fs.existsSync(localFile)) {
    res.setHeader('Content-Type', 'application/javascript');
    res.setHeader('Cache-Control', 'public, max-age=604800');
    return res.sendFile(localFile);
  }
  return res.redirect('https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.min.js');
});

// Watchdog script content
function getAuthWatchdogScript() {
  return `(function() {
  if (window.__szycicWatchdogLoaded) return;
  window.__szycicWatchdogLoaded = true;

  var AUTH_URL = '${config.BASE_URL}';
  var isLocked = false;

  function lockdown() {
    if (isLocked) return;
    isLocked = true;

    var existing = document.getElementById('szycic-lockout-overlay');
    if (existing) return;

    var overlay = document.createElement('div');
    overlay.id = 'szycic-lockout-overlay';
    overlay.style.cssText = [
      'position: fixed',
      'top: 0',
      'left: 0',
      'width: 100vw',
      'height: 100vh',
      'background: radial-gradient(circle at 50% 0%, #1e293b 0%, #090d16 100%)',
      'color: #f1f5f9',
      'font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
      'z-index: 2147483647',
      'display: flex',
      'align-items: center',
      'justify-content: center',
      'padding: 1.5rem',
      'box-sizing: border-box',
      'animation: szycicFadeIn 0.25s ease-out'
    ].join(' !important;') + ' !important;';

    overlay.innerHTML = [
      '<style>',
      '@keyframes szycicFadeIn { from { opacity: 0; transform: scale(0.98); } to { opacity: 1; transform: scale(1); } }',
      '@keyframes szycicSpin { to { transform: rotate(360deg); } }',
      '</style>',
      '<div style="background: rgba(15, 23, 42, 0.94); border: 1px solid rgba(239, 68, 68, 0.4); border-radius: 24px; padding: 2.25rem 2rem; max-width: 420px; width: 100%; text-align: center; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.7); backdrop-filter: blur(16px); box-sizing: border-box;">',
        '<div style="width: 64px; height: 64px; border-radius: 50%; background: rgba(239, 68, 68, 0.15); border: 2px solid #ef4444; color: #ef4444; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 1.25rem;">',
          '<svg style="width: 32px; height: 32px;" fill="none" viewBox="0 0 24 24" stroke="currentColor">',
            '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />',
          '</svg>',
        '</div>',
        '<h2 style="font-size: 1.35rem; font-weight: 700; margin-bottom: 0.5rem; color: #ffffff;">Session Revoked</h2>',
        '<p style="font-size: 0.9rem; color: #94a3b8; line-height: 1.5; margin-bottom: 1.5rem;">Access for this device was terminated by an approver. Redirecting to login...</p>',
        '<div style="width: 24px; height: 24px; border: 2.5px solid rgba(239, 68, 68, 0.2); border-top-color: #ef4444; border-radius: 50%; animation: szycicSpin 0.7s linear infinite; margin: 0 auto;"></div>',
      '</div>'
    ].join('');

    document.documentElement.appendChild(overlay);

    setTimeout(function() {
      var redirectTarget = window.location.href;
      window.location.href = AUTH_URL + '/login?redirect=' + encodeURIComponent(redirectTarget);
    }, 1000);
  }

  function verifySession() {
    if (isLocked) return;
    var verifyUrl = AUTH_URL + '/auth/verify?service=' + encodeURIComponent(window.location.hostname);
    fetch(verifyUrl, {
      method: 'GET',
      credentials: 'include',
      cache: 'no-store'
    }).then(function(res) {
      if (res.status === 401) {
        lockdown();
      }
    }).catch(function() {});
  }

  setInterval(verifySession, 2000);

  function initSocket() {
    if (typeof io === 'undefined') {
      var script = document.createElement('script');
      script.src = AUTH_URL + '/socket.io/socket.io.js';
      script.onload = function() {
        connectSocket();
      };
      document.head.appendChild(script);
    } else {
      connectSocket();
    }
  }

  function connectSocket() {
    try {
      var socket = io(AUTH_URL, {
        withCredentials: true,
        transports: ['websocket', 'polling']
      });
      socket.emit('register-desktop', '');
      socket.on('session-revoked', function() {
        verifySession();
      });
    } catch (e) {}
  }

  if (window.fetch) {
    var origFetch = window.fetch;
    window.fetch = function() {
      var args = Array.prototype.slice.call(arguments);
      if (typeof args[0] === 'string' && args[0].indexOf('/fonts//') !== -1) {
        args[0] = args[0].split('/fonts//').join('/fonts/');
      } else if (args[0] && typeof args[0].url === 'string' && args[0].url.indexOf('/fonts//') !== -1) {
        try {
          args[0] = new Request(args[0].url.split('/fonts//').join('/fonts/'), args[0]);
        } catch (e) {}
      }
      return origFetch.apply(this, args).then(function(res) {
        if (res.status === 401) {
          verifySession();
        }
        return res;
      });
    };
  }

  if (window.XMLHttpRequest) {
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
      if (typeof url === 'string' && url.indexOf('/fonts//') !== -1) {
        url = url.split('/fonts//').join('/fonts/');
      }
      this._url = url;
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
      this.addEventListener('load', function() {
        if (this.status === 401) {
          verifySession();
        }
      });
      return origSend.apply(this, arguments);
    };
  }

  document.addEventListener('visibilitychange', function() {
    if (document.visibilityState === 'visible') {
      verifySession();
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initSocket);
  } else {
    initSocket();
  }
})();`;
}

router.get('/auth/assets/auth-watchdog.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  return res.send(getAuthWatchdogScript());
});

function getAuthPublicGuardScript() {
  const authBaseUrl = config.server.baseUrl;
  return `(function() {
  var AUTH_URL = window.__AUTH_BASE_URL__ || '${authBaseUrl}';
  var currentOrigin = window.location.origin;
  var lastPublicUrl = window.location.href;
  var cache = {};

  function redirectToAuth(targetHref) {
    try {
      var target = new URL(targetHref, window.location.href).href;
      var fromUrl = lastPublicUrl || window.location.href;
      window.location.href = AUTH_URL + '/login?redirect=' + encodeURIComponent(target) + '&from=' + encodeURIComponent(fromUrl);
    } catch (e) {
      window.location.href = targetHref;
    }
  }

  function checkWithCaddy(targetUrl, onAuthRequired) {
    var url;
    try {
      url = new URL(targetUrl, window.location.href);
    } catch (e) {
      return;
    }
    if (url.origin !== currentOrigin) return;

    var pathname = url.pathname;
    if (pathname === window.location.pathname) return;

    if (cache[pathname] === true) return;
    if (cache[pathname] === false) {
      if (onAuthRequired) onAuthRequired(url.href);
      return;
    }

    fetch(pathname, {
      method: 'HEAD',
      redirect: 'manual',
      credentials: 'include'
    }).then(function(res) {
      if (res.type === 'opaqueredirect' || res.status === 302 || res.status === 401 || res.redirected) {
        cache[pathname] = false;
        if (onAuthRequired) onAuthRequired(url.href);
      } else if (res.status === 200) {
        cache[pathname] = true;
        lastPublicUrl = url.href;
      } else {
        cache[pathname] = false;
        if (onAuthRequired) onAuthRequired(url.href);
      }
    }).catch(function() {
      cache[pathname] = false;
      if (onAuthRequired) onAuthRequired(url.href);
    });
  }

  var origPushState = history.pushState;
  history.pushState = function(state, title, url) {
    if (url) {
      checkWithCaddy(url, function(redirectHref) {
        redirectToAuth(redirectHref);
      });
    }
    return origPushState.apply(this, arguments);
  };

  var origReplaceState = history.replaceState;
  history.replaceState = function(state, title, url) {
    if (url) {
      checkWithCaddy(url, function(redirectHref) {
        redirectToAuth(redirectHref);
      });
    }
    return origReplaceState.apply(this, arguments);
  };

  document.addEventListener('mouseover', function(e) {
    var a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (a && a.href) {
      checkWithCaddy(a.href);
    }
  }, { passive: true });

  document.addEventListener('focusin', function(e) {
    var a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (a && a.href) {
      checkWithCaddy(a.href);
    }
  }, { passive: true });

  document.addEventListener('click', function(e) {
    var a = e.target && e.target.closest ? e.target.closest('a') : null;
    if (a && a.href) {
      checkWithCaddy(a.href, function(redirectHref) {
        e.preventDefault();
        e.stopPropagation();
        redirectToAuth(redirectHref);
      });
    }
  }, true);
})();`;
}

router.get('/auth/assets/auth-public-guard.js', (req, res) => {
  res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  return res.send(getAuthPublicGuardScript());
});

module.exports = router;

