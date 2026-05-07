from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        routes = {
            "/": self._index,
            "/routehawk-report": self._routehawk_report,
            "/routehawk-results": self._routehawk_results,
            "/static/main.js": self._javascript,
            "/robots.txt": self._robots,
            "/sitemap.xml": self._sitemap,
            "/.well-known/security.txt": self._security_txt,
            "/swagger.json": self._swagger,
            "/api/users/1/profile": self._json,
            "/api/users/1/billing": self._json,
            "/api/orders/1001": self._json,
            "/internal/metrics": self._json,
            "/debug/config": self._json,
        }
        handler = routes.get(self.path.split("?", 1)[0])
        if handler is None:
            self.send_error(404)
            return
        handler()

    def do_POST(self) -> None:
        if self.path in {"/api/admin/users/1/role", "/graphql"}:
            self._json()
            return
        self.send_error(404)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _index(self) -> None:
        body = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>RouteHawk Demo Target</title>
    <style>
      body { font-family: Segoe UI, Arial, sans-serif; margin: 0; background: #f5f7fb; color: #17202a; }
      header { background: #101828; color: white; padding: 28px 36px; }
      main { max-width: 1040px; margin: 0 auto; padding: 28px; }
      h1 { margin: 0 0 8px; }
      p { color: #556274; }
      header p { color: #d8dee8; }
      .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 14px; }
      .card { background: white; border: 1px solid #d9e0ea; border-radius: 8px; padding: 16px; }
      code { background: #eef2f7; padding: 2px 5px; border-radius: 4px; }
      a { color: #1f5f8b; font-weight: 600; }
      .risk { font-size: 12px; text-transform: uppercase; color: #b42318; font-weight: 700; }
    </style>
  </head>
  <body>
    <header>
      <h1>RouteHawk Demo Target</h1>
      <p>This is the intentionally safe local app that RouteHawk scans.</p>
    </header>
    <main>
      <section class="card">
        <h2>Generated Report</h2>
        <p>The designed RouteHawk report is here: <a href="/routehawk-report">open RouteHawk report</a></p>
        <p>Raw JSON output: <a href="/routehawk-results">open results.json</a></p>
      </section>
      <h2>Demo Surface</h2>
      <div class="grid">
        <div class="card"><span class="risk">IDOR candidate</span><h3><code>GET /api/users/1/billing</code></h3><p>User-owned billing route embedded in JavaScript and OpenAPI.</p></div>
        <div class="card"><span class="risk">Authz candidate</span><h3><code>POST /api/admin/users/1/role</code></h3><p>Admin role-management route for manual authorization review.</p></div>
        <div class="card"><span class="risk">Internal/debug</span><h3><code>GET /internal/metrics</code></h3><p>Internal metadata route exposed for safe local demonstration.</p></div>
        <div class="card"><span class="risk">GraphQL</span><h3><code>POST /graphql</code></h3><p>GraphQL-shaped endpoint for passive detection and checklist generation.</p></div>
      </div>
      <h2>Metadata</h2>
      <div class="grid">
        <div class="card"><h3><a href="/robots.txt">robots.txt</a></h3><p>Includes admin and public API paths.</p></div>
        <div class="card"><h3><a href="/sitemap.xml">sitemap.xml</a></h3><p>Includes one user billing URL.</p></div>
        <div class="card"><h3><a href="/swagger.json">swagger.json</a></h3><p>OpenAPI paths used by RouteHawk.</p></div>
        <div class="card"><h3><a href="/.well-known/security.txt">security.txt</a></h3><p>Contact metadata for reporting policy.</p></div>
      </div>
    </main>
    <script src="/static/main.js"></script>
  </body>
</html>
"""
        self._send("text/html", body)

    def _routehawk_report(self) -> None:
        path = PROJECT_ROOT / "report.html"
        if not path.exists():
            self._send("text/html", "<h1>RouteHawk report not generated yet</h1>")
            return
        self._send("text/html", path.read_text(encoding="utf-8", errors="ignore"))

    def _routehawk_results(self) -> None:
        path = PROJECT_ROOT / "results.json"
        if not path.exists():
            self._send("application/json", "{}")
            return
        self._send("application/json", path.read_text(encoding="utf-8", errors="ignore"))

    def _javascript(self) -> None:
        body = """
const billing = "/api/users/1/billing";
const profile = "/api/users/1/profile";
const order = "/api/orders/1001";
const adminRole = "POST /api/admin/users/1/role";
const metrics = "/internal/metrics";
const debugConfig = "/debug/config";
const gql = "/graphql";
"""
        self._send("application/javascript", body)

    def _robots(self) -> None:
        self._send("text/plain", "User-agent: *\nDisallow: /admin\nAllow: /api/public\n")

    def _sitemap(self) -> None:
        body = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://localhost:8088/api/users/1/billing</loc></url>
</urlset>
"""
        self._send("application/xml", body)

    def _security_txt(self) -> None:
        body = """Contact: mailto:security@example.test
Policy: https://example.test/security-policy
Preferred-Languages: en
"""
        self._send("text/plain", body)

    def _swagger(self) -> None:
        body = {
            "openapi": "3.0.0",
            "paths": {
                "/api/users/{id}/billing": {"get": {}},
                "/api/admin/users/{id}/role": {"post": {}},
                "/internal/metrics": {"get": {}},
            },
        }
        self._send("application/json", json.dumps(body))

    def _json(self) -> None:
        self._send("application/json", json.dumps({"ok": True, "demo": True}))

    def _send(self, content_type: str, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    host, port = _server_address()
    server = ThreadingHTTPServer((host, port), DemoHandler)
    display_host = "localhost" if host in {"0.0.0.0", "127.0.0.1"} else host
    print(f"RouteHawk demo lab running at http://{display_host}:{port}")
    server.serve_forever()


def _server_address() -> tuple[str, int]:
    host = os.environ.get("ROUTEHAWK_LAB_HOST", "127.0.0.1")
    port_text = os.environ.get("ROUTEHAWK_LAB_PORT", "8088")
    try:
        port = int(port_text)
    except ValueError:
        port = 8088
    return host, port


if __name__ == "__main__":
    main()
