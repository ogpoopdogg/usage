// E&C Google API Usage — service worker
// Network-first for this app's own files so updates show up right away;
// the cached copy is only used when the network is unavailable.
// Firebase, Google Fonts and Chart.js (other domains) are never touched.

const CACHE_PREFIX = 'ec-api-usage-';
const CACHE = CACHE_PREFIX + 'v2';
const PRECACHE = ['./', './manifest.json', './icon-192.png', './icon-512.png'];

self.addEventListener('install', (event) => {
    event.waitUntil(
        caches.open(CACHE)
            .then((cache) => Promise.all(PRECACHE.map((url) => cache.add(url).catch(() => {}))))
            .then(() => self.skipWaiting())
    );
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        caches.keys()
            .then((keys) => Promise.all(
                keys.filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE).map((k) => caches.delete(k))
            ))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', (event) => {
    const req = event.request;
    if (req.method !== 'GET') return;
    if (new URL(req.url).origin !== self.location.origin) return;

    event.respondWith(
        fetch(req)
            .then((res) => {
                if (res && res.ok && res.type === 'basic' && !res.redirected) {
                    const copy = res.clone();
                    caches.open(CACHE).then((cache) => cache.put(req, copy));
                }
                return res;
            })
            .catch(() =>
                caches.match(req, { ignoreSearch: true })
                    .then((hit) => hit || (req.mode === 'navigate' ? caches.match('./') : undefined))
                    .then((hit) => hit || Response.error())
            )
    );
});
