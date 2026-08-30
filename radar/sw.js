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
 *     (>90 min amber, >12 h greyed gauges) and, when the live fetch fails,
 *     renderError() — so an old copy cannot masquerade as current.
 *   - Pages are cached under a canonical, query-less key. Without this every
 *     ?src=pwa / ?utm_* share link became its own entry and the offline
 *     fallback could miss, or serve an arbitrary one of several copies.
 *   - Only ok() responses are ever stored. A 404/5xx from the edge must not
 *     be allowed to replace a good offline copy.
 *   - The manifest is network-first so editing it does not require
 *     remembering to bump CACHE. Icons stay cache-first; they are immutable
 *     for the life of a cache version.
 */
const CACHE = 'radar-v2';
const PAGE  = '/radar/';
const MANIFEST = '/radar/manifest.webmanifest';
const STATIC = [
  PAGE,                       // so a first-ever launch while offline still renders
  '/radar/icon-192.png',
  '/radar/icon-512.png',
  '/radar/icon-maskable-192.png',
  '/radar/icon-maskable-512.png',
  '/radar/apple-touch-icon.png',
  MANIFEST
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

// Network first, falling back to whatever we have. Only ok() responses are
// stored, and always under `key` so one URL never spawns many entries.
function networkFirst(req, key, fallback) {
  return fetch(req)
    .then(res => {
      if (res.ok) {
        const copy = res.clone();
        caches.open(CACHE).then(c => c.put(key, copy)).catch(() => {});
      }
      return res;
    })
    .catch(() => caches.match(key)
      .then(hit => hit || (fallback ? caches.match(fallback) : undefined))
      .then(hit => hit || Response.error()));
}

self.addEventListener('fetch', e => {
  const req = e.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Live data: never cached, never served stale.
  if (url.pathname.endsWith('/status.json')) return;

  // Pages: network first, cache only as an offline fallback, canonical key.
  if (req.mode === 'navigate') {
    e.respondWith(networkFirst(req, url.pathname, PAGE));
    return;
  }

  // Manifest: network first, so an edit takes effect without a CACHE bump.
  if (url.pathname === MANIFEST) {
    e.respondWith(networkFirst(req, MANIFEST));
    return;
  }

  // Other static assets under /radar/: cache first.
  if (url.pathname.startsWith('/radar/')) {
    e.respondWith(
      caches.match(req).then(hit => hit || fetch(req).then(res => {
        if (res.ok) { const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)).catch(() => {}); }
        return res;
      }))
    );
  }
});
