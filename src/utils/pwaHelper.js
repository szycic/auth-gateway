const config = require('../config');

function generatePwaManifest() {
  const appConfig = (config && config.app) || {};
  const baseName = appConfig.name || 'Auth Gateway';
  const fullName = appConfig.fullName || (baseName.endsWith('Gateway') ? baseName : `${baseName} Gateway`);
  const shortName = appConfig.shortName || baseName;
  const description = appConfig.description || 'Mobile Authenticator and Device Approval Gateway';

  return {
    id: '/',
    name: fullName,
    short_name: shortName,
    description,
    start_url: '/auth/sessions?source=pwa',
    scope: '/',
    display: 'standalone',
    orientation: 'portrait-primary',
    background_color: '#1e293b',
    theme_color: '#1e293b',
    categories: ['utilities', 'security'],
    icons: [
      {
        src: '/assets/icon.svg',
        sizes: 'any',
        type: 'image/svg+xml',
        purpose: 'any',
      },
      {
        src: '/assets/icon-192.png',
        sizes: '192x192',
        type: 'image/png',
        purpose: 'any',
      },
      {
        src: '/assets/icon-512.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'any',
      },
      {
        src: '/assets/icon-maskable.png',
        sizes: '512x512',
        type: 'image/png',
        purpose: 'maskable',
      },
    ],
    shortcuts: [
      {
        name: 'Scan Desktop QR',
        short_name: 'Scan QR',
        description: 'Quickly scan a desktop login QR code',
        url: '/auth/sessions?action=scan&source=pwa',
        icons: [
          {
            src: '/assets/icon-192.png',
            sizes: '192x192',
          },
        ],
      },
      {
        name: 'Enter Authorization PIN',
        short_name: 'Enter PIN',
        description: 'Quickly enter an 8-digit desktop pairing code',
        url: '/auth/sessions?action=pin&source=pwa',
        icons: [
          {
            src: '/assets/icon-192.png',
            sizes: '192x192',
          },
        ],
      },
    ],
  };
}

module.exports = {
  generatePwaManifest,
};

