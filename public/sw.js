/**
 * App-shell service worker. Only the static, non-secret UI is cached - the
 * share pages (/f/<id>) and every /api/* call always go straight to the
 * network, since caching anything keyed by a file id or bearing a link
 * fragment would be a place for ciphertext-adjacent metadata to linger.
 */
const CACHE = 'ephemeral-shell-v3';
const SHELL = [
  '/',
  '/style.css',
  '/app.js',
  '/crypto.js',
  '/manifest.webmanifest',
  '/favicon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
  '/icons/apple-touch-icon.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/f/')) return; // never cache

  if (!SHELL.includes(url.pathname)) return; // unknown path: let the network 404 it

  event.respondWith(
    caches.match(request).then((cached) => cached || fetch(request).then((response) => {
      const copy = response.clone();
      caches.open(CACHE).then((cache) => cache.put(request, copy));
      return response;
    }).catch(() => cached)),
  );
});
