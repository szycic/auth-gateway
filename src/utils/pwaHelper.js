const config = require('../config');

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
      { src: '/assets/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' },
      { src: '/assets/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any' },
      { src: '/assets/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any' },
      { src: '/assets/icon-maskable.png', sizes: '512x512', type: 'image/png', purpose: 'maskable' },
    ],
    shortcuts: [
      {
        name: 'Scan Desktop QR',
        short_name: 'Scan QR',
        description: 'Quickly scan a desktop login QR code',
        url: '/auth/sessions?action=scan&source=pwa',
        icons: [{ src: '/assets/icon-192.png', sizes: '192x192' }],
      },
    ],
  };
}

module.exports = {
  generatePwaManifest,
};
