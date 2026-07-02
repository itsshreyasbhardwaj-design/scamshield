/* ScamShield service worker — offline shell + cache-first static assets. */
const CACHE = "scamshield-v6";
const SHELL = ["/", "/static/app.js", "/static/icon.svg", "/static/icon-192.png",
               "/static/manifest.webmanifest"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;                 // never cache POSTs (scans)
  const url = new URL(req.url);
  if (url.pathname.startsWith("/static/")) {
    e.respondWith(caches.match(req).then((r) => r || fetch(req)));
    return;
  }
  if (req.mode === "navigate") {
    e.respondWith(fetch(req).catch(() => caches.match("/")));
  }
});
