from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import socket
import time
from collections import defaultdict
from sys import argv
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, unquote, urlparse
from urllib.request import Request, urlopen

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}

BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]


class RateLimiter:
    def __init__(self, max_requests=120, window_seconds=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self.counts = defaultdict(list)

    def is_allowed(self, client_ip):
        now = time.time()
        timestamps = self.counts[client_ip]
        self.counts[client_ip] = [t for t in timestamps if now - t < self.window]
        if len(self.counts[client_ip]) >= self.max_requests:
            return False
        self.counts[client_ip].append(now)
        return True


_rate_limiter = RateLimiter()


def is_ssrf_safe(hostname):
    if not hostname:
        return False


def is_flaresolverr_endpoint_safe(endpoint):
    try:
        parsed = urlparse(endpoint)
        host = parsed.hostname or ""
        if parsed.scheme not in ("http", "https"):
            return False
        return host in {"localhost", "127.0.0.1", "::1"}
    except Exception:
        return False
    try:
        resolved = socket.getaddrinfo(hostname, None)
        for family, type_, proto, canonname, sockaddr in resolved:
            ip = ipaddress.ip_address(sockaddr[0])
            for blocked in BLOCKED_NETWORKS:
                if ip in blocked:
                    return False
        return True
    except Exception:
        return False


class WebXSiderHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        if getattr(self, "_is_proxy_response", False):
            self.send_header("X-Web-X-Sider-Proxy", "local")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Web-X-Sider-User-Agent")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/proxy":
            return super().do_GET()

        self._is_proxy_response = True
        client_ip = self.client_address[0]
        if not _rate_limiter.is_allowed(client_ip):
            self.send_error(429, "Rate limit exceeded")
            return

        target_values = parse_qs(parsed.query).get("url")
        if not target_values:
            self.send_error(400, "Missing url parameter")
            return

        origin_values = parse_qs(parsed.query).get("origin")
        solver_values = parse_qs(parsed.query).get("solver")
        fs_url_values = parse_qs(parsed.query).get("fs_url")
        target_url = unquote(target_values[0])
        target = urlparse(target_url)
        if target.scheme not in ("http", "https"):
            self.send_error(400, "Only http and https URLs are allowed")
            return
        if not is_ssrf_safe(target.hostname):
            self.send_error(403, "Target resolves to a blocked IP range")
            return

        if solver_values and solver_values[0] == "flaresolverr":
            self.proxy_with_flaresolverr(target_url, "GET", b"", fs_url_values[0] if fs_url_values else "")
            return

        custom_ua = self.headers.get("X-Web-X-Sider-User-Agent", "WebXSider-local/2.0")
        request_headers = {
            "User-Agent": custom_ua,
            "Accept": "*/*",
        }
        request_headers.update(self.forwardable_client_headers())
        if origin_values:
            request_headers["Origin"] = unquote(origin_values[0])

        request = Request(
            target_url,
            headers=request_headers,
            method="GET",
        )

        try:
            with urlopen(request, timeout=20) as response:
                self.send_response(response.status)
                self.forward_target_headers(response.headers)
                self.end_headers()
                self.wfile.write(response.read())
        except HTTPError as error:
            self.send_response(error.code)
            self.forward_target_headers(error.headers)
            self.end_headers()
            self.wfile.write(error.read())
        except URLError as error:
            self.send_error(502, f"Proxy request failed: {error.reason}")
        except TimeoutError:
            self.send_error(504, "Proxy request timed out")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/proxy":
            self.send_error(404, "Not found")
            return

        self._is_proxy_response = True
        client_ip = self.client_address[0]
        if not _rate_limiter.is_allowed(client_ip):
            self.send_error(429, "Rate limit exceeded")
            return

        target_values = parse_qs(parsed.query).get("url")
        if not target_values:
            self.send_error(400, "Missing url parameter")
            return

        target_url = unquote(target_values[0])
        solver_values = parse_qs(parsed.query).get("solver")
        fs_url_values = parse_qs(parsed.query).get("fs_url")
        target = urlparse(target_url)
        if target.scheme not in ("http", "https"):
            self.send_error(400, "Only http and https URLs are allowed")
            return
        if not is_ssrf_safe(target.hostname):
            self.send_error(403, "Target resolves to a blocked IP range")
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(min(content_length, 10 * 1024 * 1024))
        if solver_values and solver_values[0] == "flaresolverr":
            self.proxy_with_flaresolverr(target_url, "POST", body, fs_url_values[0] if fs_url_values else "")
            return

        custom_ua = self.headers.get("X-Web-X-Sider-User-Agent", "WebXSider-local/2.0")
        request_headers = {
            "User-Agent": custom_ua,
            "Accept": "*/*",
            "Content-Type": self.headers.get("Content-Type", "application/json"),
        }
        request_headers.update(self.forwardable_client_headers())

        request = Request(target_url, headers=request_headers, data=body, method="POST")

        try:
            with urlopen(request, timeout=20) as response:
                self.send_response(response.status)
                self.forward_target_headers(response.headers)
                self.end_headers()
                self.wfile.write(response.read())
        except HTTPError as error:
            self.send_response(error.code)
            self.forward_target_headers(error.headers)
            self.end_headers()
            self.wfile.write(error.read())
        except URLError as error:
            self.send_error(502, f"Proxy POST request failed: {error.reason}")
        except TimeoutError:
            self.send_error(504, "Proxy POST request timed out")

    def forward_target_headers(self, headers):
        cookie_index = 0
        for name, value in headers.items():
            lowered = name.lower()
            if lowered == "set-cookie":
                self.send_header(f"X-Web-X-Sider-Set-Cookie-{cookie_index}", value)
                cookie_index += 1
            elif lowered not in HOP_BY_HOP_HEADERS:
                self.send_header(name, value)

    def proxy_with_flaresolverr(self, target_url, method, body, fs_url):
        flaresolverr_url = unquote(fs_url or "").strip() or "http://127.0.0.1:8191/v1"
        if not is_flaresolverr_endpoint_safe(flaresolverr_url):
            self.send_error(400, "FlareSolverr endpoint must be local, for example http://127.0.0.1:8191/v1")
            return

        payload = {
            "cmd": "request.post" if method == "POST" else "request.get",
            "url": target_url,
            "maxTimeout": 60000,
            "disableMedia": True,
        }
        if method == "POST":
            payload["postData"] = body.decode("utf-8", errors="replace")

        data = json.dumps(payload).encode("utf-8")
        request = Request(
            flaresolverr_url,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            data=data,
            method="POST",
        )

        try:
            with urlopen(request, timeout=75) as response:
                raw = response.read()
            parsed = json.loads(raw.decode("utf-8", errors="replace"))
            solution = parsed.get("solution") or {}
            response_body = (solution.get("response") or "").encode("utf-8", errors="replace")
            status = int(solution.get("status") or 200)
            headers = solution.get("headers") or {}

            self.send_response(status)
            self.send_header("X-Web-X-Sider-FlareSolverr", "local")
            for name, value in headers.items():
                lowered = str(name).lower()
                if lowered in HOP_BY_HOP_HEADERS or lowered == "set-cookie":
                    continue
                self.send_header(str(name), str(value))
            for index, cookie in enumerate(solution.get("cookies") or []):
                name = cookie.get("name")
                value = cookie.get("value")
                if name and value:
                    self.send_header(f"X-Web-X-Sider-Set-Cookie-{index}", f"{name}={value}")
            self.end_headers()
            self.wfile.write(response_body)
        except HTTPError as error:
            self.send_error(error.code, f"FlareSolverr request failed: {error.reason}")
        except URLError as error:
            self.send_error(502, f"FlareSolverr is not reachable: {error.reason}")
        except TimeoutError:
            self.send_error(504, "FlareSolverr request timed out")
        except Exception as error:
            self.send_error(502, f"FlareSolverr failed: {error}")

    def forwardable_client_headers(self):
        allowed = {"authorization", "x-api-key", "x-auth-token", "cookie"}
        forwarded = {}
        for name, value in self.headers.items():
            if name.lower() in allowed:
                forwarded[name] = value
        return forwarded


if __name__ == "__main__":
    port = int(argv[1]) if len(argv) > 1 else 5500
    server = ThreadingHTTPServer(("127.0.0.1", port), WebXSiderHandler)
    print(f"Web X Sider running at http://127.0.0.1:{port}/")
    server.serve_forever()
