/**
 * App-shell service worker. Only the static, non-secret UI is cached - the
 * share pages (/f/<id>) and every /api/* call always go straight to the
 * network, since caching anything keyed by a file id or bearing a link
 * fragment would be a place for ciphertext-adjacent metadata to linger.
 *
 * Shell files are network-first: online, every load gets the deployed
 * app.js/crypto.js together (share pages always get fresh HTML, so a stale
 * script beside it is a version skew); the cache is only the offline and
 * slow-network fallback.
 */
const CACHE = 'ephemeral-shell-v5';
const SHELL = [
  '/',
  '/style.css',
  '/app.js',
  '/crypto.js',
  '/upload.js',
  '/manifest.webmanifest',
  '/favicon.svg',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/icons/icon-maskable-512.png',
  '/icons/apple-touch-icon.png',
];
// Without these the offline shell is useless, so install fails (and the old
// worker stays) rather than activating half-filled. That includes every
// module app.js imports statically: one missing import kills the whole app.
// Everything else is best-effort, so one missing file cannot keep a fixed
// worker from installing.
const CORE = ['/', '/app.js', '/crypto.js', '/upload.js'];
const TIMEOUT = 3000; // ms before a slow network loses to the cache

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    const results = await Promise.allSettled(
      SHELL.map((path) => cache.add(new Request(path, { cache: 'reload' }))),
    );
    if (results.some((r, i) => r.status === 'rejected' && CORE.includes(SHELL[i]))) {
      throw new Error('app shell unavailable');
    }
    await self.skipWaiting();
  })());
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

  const path = url.pathname;
  if (!SHELL.includes(path)) return; // unknown path: let the network 404 it

  // Keyed by path so '/?x=1' reuses '/' instead of piling up entries. Only
  // good responses are stored: a transient 5xx must not replace a working copy.
  let save = Promise.resolve();
  const network = fetch(request.mode === 'navigate' ? request : new Request(request, { cache: 'no-cache' }))
    .then((response) => {
      if (response.ok) {
        const copy = response.clone();
        save = caches.open(CACHE).then((cache) => cache.put(path, copy));
      }
      return response;
    });
  // Keeps the worker alive until the copy is stored, even after a timeout.
  event.waitUntil(network.then(() => save, () => {}).catch(() => {}));

  event.respondWith((async () => {
    let response;
    try {
      response = await Promise.race([network, new Promise((resolve) => setTimeout(resolve, TIMEOUT))]);
      if (response?.ok) return response;
    } catch { /* offline: fall back to the cache */ }
    const cached = await caches.match(path, { cacheName: CACHE });
    if (cached) return cached;
    if (response) return response; // e.g. a 404 with nothing cached
    return network.catch(() => Response.error()); // slow and uncached: keep waiting
  })());
});
