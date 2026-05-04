from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
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
}


class WebXSiderHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        if getattr(self, "_is_proxy_response", False):
            self.send_header("X-Web-X-Sider-Proxy", "local")
        else:
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path != "/proxy":
            return super().do_GET()

        self._is_proxy_response = True
        target_values = parse_qs(parsed.query).get("url")
        if not target_values:
            self.send_error(400, "Missing url parameter")
            return

        origin_values = parse_qs(parsed.query).get("origin")
        target_url = unquote(target_values[0])
        target = urlparse(target_url)
        if target.scheme not in ("http", "https"):
            self.send_error(400, "Only http and https URLs are allowed")
            return

        request_headers = {
            "User-Agent": "WebXSider-local/2.0",
            "Accept": "*/*",
        }
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

    def forward_target_headers(self, headers):
        for name, value in headers.items():
            lowered = name.lower()
            if lowered == "set-cookie":
                self.send_header("X-Web-X-Sider-Set-Cookie", value)
            elif lowered not in HOP_BY_HOP_HEADERS:
                self.send_header(name, value)


if __name__ == "__main__":
    port = int(argv[1]) if len(argv) > 1 else 5500
    server = ThreadingHTTPServer(("127.0.0.1", port), WebXSiderHandler)
    print(f"Web X Sider running at http://127.0.0.1:{port}/")
    server.serve_forever()
