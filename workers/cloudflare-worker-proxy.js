/* ============================================================
   Web X Sider — Cloudflare Worker Proxy v2.5
   Features: SSRF protection, FlareSolverr fallback,
   multi-cookie forwarding, User-Agent rotation for WAF bypass.
   ============================================================ */

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailers",
  "transfer-encoding",
  "upgrade",
  "content-encoding",
  "content-length"
]);

// User-Agent rotation pool for WAF bypass
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0"
];

// Blocked hostname patterns for SSRF protection
const BLOCKED_HOSTNAME_PATTERNS = [
  /^localhost$/i,
  /^127\./i,
  /^10\./i,
  /^172\.(1[6-9]|2\d|3[01])\./i,
  /^192\.168\./i,
  /^169\.254\./i,
  /^0\./i,
  /^100\.64\./i,
  /^::1$/i,
  /^fc00:/i,
  /^fe80:/i
];

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Origin, Authorization, X-Web-X-Sider-User-Agent",
    "Access-Control-Expose-Headers": "*"
  };
}

function responseFromText(text, status = 200) {
  return new Response(text, { status, headers: corsHeaders() });
}

function getRandomUA() {
  return USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)];
}

function isBlockedHost(hostname) {
  if (!hostname) return true;
  return BLOCKED_HOSTNAME_PATTERNS.some(pattern => pattern.test(hostname));
}

function validateTarget(rawUrl) {
  let target;
  try {
    target = new URL(rawUrl);
  } catch {
    return { error: responseFromText("Invalid URL", 400) };
  }

  if (!["http:", "https:"].includes(target.protocol)) {
    return { error: responseFromText("Only http and https URLs are allowed", 400) };
  }

  if (isBlockedHost(target.hostname)) {
    return { error: responseFromText("Target host is blocked (SSRF protection)", 403) };
  }

  return { target };
}

function copyResponseHeaders(sourceHeaders, extra = {}) {
  const headers = new Headers(corsHeaders());
  Object.entries(extra).forEach(([key, value]) => headers.set(key, value));

  let cookieIndex = 0;
  sourceHeaders.forEach((value, key) => {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered)) return;
    if (lowered.startsWith("access-control-")) return;
    if (lowered === "set-cookie") {
      headers.set(`X-Web-X-Sider-Set-Cookie-${cookieIndex}`, value);
      cookieIndex++;
    } else {
      headers.set(key, value);
    }
  });
  return headers;
}

async function fetchNormally(request, requestUrl, target) {
  const customUA = request.headers.get("X-Web-X-Sider-User-Agent");
  const proxyHeaders = {
    "User-Agent": customUA || getRandomUA(),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0"
  };

  const contentType = request.headers.get("content-type");
  if (contentType) proxyHeaders["Content-Type"] = contentType;

  const origin = requestUrl.searchParams.get("origin");
  if (origin) proxyHeaders.Origin = origin;

  const referer = requestUrl.searchParams.get("referer");
  if (referer) proxyHeaders.Referer = referer;

  const response = await fetch(target.toString(), {
    method: request.method,
    headers: proxyHeaders,
    body: request.method === "POST" ? await request.arrayBuffer() : undefined,
    redirect: "follow"
  });

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: copyResponseHeaders(response.headers)
  });
}

async function fetchViaFlareSolverr(request, env, target) {
  const flaresolverrUrl = env?.FLARESOLVERR_URL || "http://127.0.0.1:8191/v1";

  const payload = {
    cmd: request.method === "POST" ? "request.post" : "request.get",
    url: target.toString(),
    maxTimeout: 60000,
    disableMedia: true
  };

  if (request.method === "POST") {
    payload.postData = await request.text();
  }

  // Add headers to FlareSolverr session
  const customUA = request.headers.get("X-Web-X-Sider-User-Agent");
  if (customUA) {
    payload.userAgent = customUA;
  }

  const solverResponse = await fetch(flaresolverrUrl, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(payload)
  });

  const solverText = await solverResponse.text();
  if (!solverResponse.ok) {
    return responseFromText(`FlareSolverr failed: HTTP ${solverResponse.status} ${solverText.slice(0, 240)}`, 502);
  }

  let parsed;
  try {
    parsed = JSON.parse(solverText);
  } catch {
    return responseFromText(`FlareSolverr returned non-JSON: ${solverText.slice(0, 240)}`, 502);
  }

  if (parsed.status !== "ok") {
    return responseFromText(`FlareSolverr error: ${parsed.message || "unknown error"}`, 502);
  }

  const solution = parsed.solution || {};
  const headers = new Headers(corsHeaders());
  headers.set("X-Web-X-Sider-FlareSolverr", "worker");

  // Forward response headers
  Object.entries(solution.headers || {}).forEach(([key, value]) => {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered)) return;
    if (lowered.startsWith("access-control-")) return;
    if (lowered === "set-cookie") return; // Handle cookies separately
    headers.set(key, String(value));
  });

  // Forward cookies
  (solution.cookies || []).slice(0, 20).forEach((cookie, index) => {
    if (cookie.name && cookie.value) {
      let cookieStr = `${cookie.name}=${cookie.value}`;
      if (cookie.domain) cookieStr += `; Domain=${cookie.domain}`;
      if (cookie.path) cookieStr += `; Path=${cookie.path}`;
      if (cookie.expires) cookieStr += `; Expires=${new Date(cookie.expires * 1000).toUTCString()}`;
      if (cookie.secure) cookieStr += "; Secure";
      if (cookie.httpOnly) cookieStr += "; HttpOnly";
      headers.set(`X-Web-X-Sider-Set-Cookie-${index}`, cookieStr);
    }
  });

  return new Response(solution.response || "", {
    status: Number(solution.status) || 200,
    headers
  });
}

export default {
  async fetch(request, env) {
    const headers = corsHeaders();

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers });
    }

    const requestUrl = new URL(request.url);

    // If no ?url= param, serve static assets or show status
    if (!requestUrl.searchParams.has("url")) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return responseFromText("Web X Sider proxy is running. Add ?url=https://example.com");
    }

    if (!["GET", "HEAD", "POST"].includes(request.method)) {
      return responseFromText("Method not allowed", 405);
    }

    const { target, error } = validateTarget(requestUrl.searchParams.get("url"));
    if (error) return error;

    try {
      if (requestUrl.searchParams.get("solver") === "flaresolverr") {
        return await fetchViaFlareSolverr(request, env, target);
      }
      return await fetchNormally(request, requestUrl, target);
    } catch (error) {
      return responseFromText(`Proxy error: ${error.message}`, 502);
    }
  }
};
