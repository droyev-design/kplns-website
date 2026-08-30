/* Radar PWA service worker.
 *
 * Deliberately minimal, and deliberately NOT a cache-first shell. This page
 * publishes a live escalation level every ~30 minutes; serving a stale copy
 * from cache would be the single worst failure mode this project can have.
 *
 * Rules:
 *   - status.json is NEVER cached and NEVER served from cache. Network only.
 *     If the network is down the page's own error path runs, which is honest.
 *   - Navigations are network-first. The cached copy is a last resort for a
 *     genuinely offline device; the page then shows its own staleness banner
 *     (>90 min amber, >12 h greyed gauges), so an old copy cannot masquerade
 *     as current.
 *   - Static assets (icons, manifest) are cache-first; they never change
 *     without a CACHE version bump.
 */
const CACHE = 'radar-v1';
const STATIC = [
  '/radar/icon-192.png',
  '/radar/icon-512.png',
  '/radar/icon-maskable-512.png',
  '/radar/manifest.webmanifest'
];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(STATIC)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Live data: never cached, never served stale.
  if (url.pathname.endsWith('/status.json')) return;

  // Pages: network first, cache only as an offline fallback.
  if (req.mode === 'navigate') {
    e.respondWith(
      fetch(req)
        .then(res => {
          const copy = res.clone();
          caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(req).then(hit => hit || caches.match('/radar/')))
    );
    return;
  }

  // Static assets under /radar/: cache first.
  if (url.pathname.startsWith('/radar/')) {
    e.respondWith(
      caches.match(req).then(hit => hit || fetch(req).then(res => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {}); }
        return res;
      }))
    );
  }
});
