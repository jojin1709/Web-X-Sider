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

  return { target };
}

function copyResponseHeaders(sourceHeaders, extra = {}) {
  const headers = new Headers(corsHeaders());
  Object.entries(extra).forEach(([key, value]) => headers.set(key, value));
  sourceHeaders.forEach((value, key) => {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered)) return;
    if (lowered === "set-cookie") headers.set("X-Web-X-Sider-Set-Cookie-0", value);
    else headers.set(key, value);
  });
  return headers;
}

async function fetchNormally(request, requestUrl, target) {
  const proxyHeaders = {
    "User-Agent": request.headers.get("X-Web-X-Sider-User-Agent") || "WebXSider-Worker/2.0",
    "Accept": "*/*"
  };

  const contentType = request.headers.get("content-type");
  if (contentType) proxyHeaders["Content-Type"] = contentType;

  const origin = requestUrl.searchParams.get("origin");
  if (origin) proxyHeaders.Origin = origin;

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
  const flaresolverrUrl = env?.FLARESOLVERR_URL;
  if (!flaresolverrUrl) {
    return responseFromText("FlareSolverr route is not configured. Set FLARESOLVERR_URL on the Worker.", 501);
  }

  const payload = {
    cmd: request.method === "POST" ? "request.post" : "request.get",
    url: target.toString(),
    maxTimeout: 60000,
    disableMedia: true
  };
  if (request.method === "POST") {
    payload.postData = await request.text();
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

  const solution = parsed.solution || {};
  const headers = new Headers(corsHeaders());
  headers.set("X-Web-X-Sider-FlareSolverr", "worker");
  Object.entries(solution.headers || {}).forEach(([key, value]) => {
    const lowered = key.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(lowered) || lowered === "set-cookie") return;
    headers.set(key, String(value));
  });
  (solution.cookies || []).slice(0, 20).forEach((cookie, index) => {
    if (cookie.name && cookie.value) {
      headers.set(`X-Web-X-Sider-Set-Cookie-${index}`, `${cookie.name}=${cookie.value}`);
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
    if (!requestUrl.searchParams.has("url")) {
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
