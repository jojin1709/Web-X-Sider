const CACHE_NAME = "web-x-sider-v6";
const ASSETS = [
  "/",
  "/index.html",
  "/style.css",
  "/script.js",
  "/toolkit.js",
  "/toolkit2.js",
  "/toolkit3.js",
  "/toolkit4.js",
  "/toolkit5.js",
  "/toolkit6.js",
  "/i18n.js",
  "/favicon.png"
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE_NAME).then((cache) => cache.addAll(ASSETS)));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  if (e.request.url.includes("/proxy") || e.request.url.includes("dns.google") || e.request.url.includes("crt.sh")) {
    return;
  }
  e.respondWith(caches.match(e.request).then((r) => r || fetch(e.request)));
});
