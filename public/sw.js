const CACHE_NAME = 'auth-gateway-v4';
const STATIC_ASSETS = [
  '/manifest.webmanifest',
  '/icon.svg',
  '/icon-192.png',
  '/icon-512.png',
  '/icon-maskable.png',
  '/apple-touch-icon.png',
  '/auth/assets/jsqr.js',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(STATIC_ASSETS).catch((err) => {
        console.warn('[SW] Cache addAll warning:', err.message);
      });
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.filter((key) => key !== CACHE_NAME).map((key) => caches.delete(key))
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // Never cache POST or WebSocket requests
  if (event.request.method !== 'GET') return;
  if (url.pathname.startsWith('/socket.io/')) return;

  // Dynamic auth check and session action routes: always fetch fresh from network
  const isDynamicRoute =
    url.pathname.startsWith('/auth/verify') ||
    url.pathname.startsWith('/auth/init') ||
    url.pathname.startsWith('/auth/sessions') ||
    url.pathname.startsWith('/auth/code') ||
    url.pathname.startsWith('/auth/approve') ||
    url.pathname.startsWith('/auth/exchange') ||
    url.pathname.startsWith('/auth/logout');

  if (isDynamicRoute) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Static assets: Cache-first
  const isStaticAsset =
    STATIC_ASSETS.some((path) => url.pathname === path) ||
    url.pathname.startsWith('/auth/assets/') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.webmanifest');

  if (isStaticAsset) {
    event.respondWith(
      caches.match(event.request).then((cachedResponse) => {
        if (cachedResponse) {
          // Revalidate in background
          fetch(event.request).then((networkResponse) => {
            if (networkResponse && networkResponse.status === 200) {
              caches.open(CACHE_NAME).then((cache) => cache.put(event.request, networkResponse));
            }
          }).catch(() => {});
          return cachedResponse;
        }
        return fetch(event.request).then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200) {
            const clone = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(event.request, clone));
          }
          return networkResponse;
        });
      })
    );
    return;
  }

  // Navigation and pages (e.g. /auth/sessions, /auth/approver/login): Network-first
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
