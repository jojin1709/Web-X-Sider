export default {
  async fetch(request) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, HEAD, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Origin, Authorization",
      "Access-Control-Expose-Headers": "*"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const requestUrl = new URL(request.url);
    if (!requestUrl.searchParams.has("url")) {
      return new Response("Web X Sider proxy is running. Add ?url=https://example.com", {
        status: 200,
        headers: corsHeaders
      });
    }

    if (!["GET", "HEAD", "POST"].includes(request.method)) {
      return new Response("Method not allowed", {
        status: 405,
        headers: corsHeaders
      });
    }

    const targetUrl = requestUrl.searchParams.get("url");

    let target;
    try {
      target = new URL(targetUrl);
    } catch {
      return new Response("Invalid URL", {
        status: 400,
        headers: corsHeaders
      });
    }

    if (!["http:", "https:"].includes(target.protocol)) {
      return new Response("Only http and https URLs are allowed", {
        status: 400,
        headers: corsHeaders
      });
    }

    const proxyHeaders = {
      "User-Agent": "WebXSider-Worker/2.0",
      "Accept": "*/*"
    };

    const contentType = request.headers.get("content-type");
    if (contentType) {
      proxyHeaders["Content-Type"] = contentType;
    }

    const origin = requestUrl.searchParams.get("origin");
    if (origin) {
      proxyHeaders.Origin = origin;
    }

    try {
      const response = await fetch(target.toString(), {
        method: request.method,
        headers: proxyHeaders,
        body: request.method === "POST" ? await request.arrayBuffer() : undefined,
        redirect: "follow"
      });

      const headers = new Headers(corsHeaders);
      response.headers.forEach((value, key) => {
        const lowered = key.toLowerCase();
        if (["connection", "transfer-encoding", "content-encoding"].includes(lowered)) {
          return;
        }

        if (lowered === "set-cookie") {
          headers.set("X-Web-X-Sider-Set-Cookie", value);
        } else {
          headers.set(key, value);
        }
      });

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers
      });
    } catch (error) {
      return new Response(`Proxy error: ${error.message}`, {
        status: 502,
        headers: corsHeaders
      });
    }
  }
};
