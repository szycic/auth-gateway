const config = require('../../config');
const { escapeHtml } = require('../../utils/htmlEscape');

function getPwaHeadTags() {
  return `
  <link rel="manifest" href="/manifest.webmanifest">
  <meta name="theme-color" content="#090d16">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="${escapeHtml(config.app.name || 'Auth Gateway')}">
  <link rel="apple-touch-icon" href="/apple-touch-icon.png">
  <link rel="icon" type="image/svg+xml" href="/icon.svg">
  <link rel="icon" type="image/png" sizes="192x192" href="/icon-192.png">
  <link rel="icon" type="image/png" sizes="512x512" href="/icon-512.png">`;
}

const PWA_SW_SCRIPT = `
  <script>
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js', { scope: '/' })
          .catch(err => console.warn('[PWA] ServiceWorker registration failed:', err));
      });
    }
  </script>
`;

function generatePwaManifest() {
  return {
    id: '/',
    name: config.app.name || 'Auth Gateway',
    short_name: config.app.name || 'Auth Gateway',
    description: config.app.subtitle || 'Mobile Authenticator and Device Approval Gateway',
    start_url: '/auth/sessions?source=pwa',
    scope: '/',
    display: 'standalone',
    orientation: 'portrait-primary',
    background_color: '#090d16',
    theme_color: '#090d16',
    categories: ['utilities', 'security'],
    icons: [
      { src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
      { src: '/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/icon-maskable.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
    shortcuts: [
      {
        name: 'Scan Desktop QR',
        short_name: 'Scan QR',
        description: 'Quickly scan a desktop login QR code',
        url: '/auth/sessions?action=scan&source=pwa',
        icons: [{ src: '/icon-192.png', sizes: '192x192' }],
      },
    ],
  };
}

module.exports = {
  getPwaHeadTags,
  PWA_SW_SCRIPT,
  generatePwaManifest,
};
