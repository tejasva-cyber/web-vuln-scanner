"""A deliberately vulnerable web app — a safe target to point Argus at.

    ⚠  THIS APPLICATION IS INSECURE ON PURPOSE.  ⚠

Every "bug" here is intentional so the scanner has something to find. It binds
to 127.0.0.1 only and must never be deployed or exposed. Use it to demo Argus
and to sanity-check the checks after you change them.

    python examples/vulnerable_app.py 8973
    argus http://127.0.0.1:8973/ --crawl

Built on the standard library alone, so there's nothing to install.
"""
from __future__ import annotations

import re
import sys
import time
from html import escape  # noqa: F401  (kept handy; the app deliberately doesn't use it)
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

_HOME = """<!doctype html><html><head><title>Vuln Corp</title></head><body>
<h1>Vuln Corp Intranet</h1>
<p>Search our knowledge base:</p>
<form action="/search" method="get">
  <input type="text" name="q" placeholder="search...">
  <button type="submit">Go</button>
</form>
<p>Leave a comment (no CSRF token, on purpose):</p>
<form action="/comment" method="post">
  <input type="text" name="body">
  <input type="hidden" name="post_id" value="42">
  <button type="submit">Post</button>
</form>
<ul>
  <li><a href="/search?q=welcome">Featured article</a></li>
  <li><a href="/redirect?next=/dashboard">Go to dashboard</a></li>
</ul>
</body></html>"""


class _Handler(BaseHTTPRequestHandler):
    server_version = "VulnCorp/1.2.3"  # version disclosure, on purpose

    def _send(self, code: int, body: str, headers: dict | None = None) -> None:
        raw = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        # Note the absence of any security headers, and a flag-less cookie.
        self.send_header("Set-Cookie", "session=deadbeef; Path=/")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        path = parsed.path

        if path == "/":
            self._send(200, _HOME)
        elif path == "/search":
            q = params.get("q", [""])[0]
            # Bug 1: reflected XSS — q echoed without encoding.
            # Bug 2: error-based SQLi — a quote "breaks the query".
            if "'" in q or '"' in q:
                self._send(500,
                    "<h1>Database error</h1><pre>You have an error in your SQL syntax; "
                    "check the manual that corresponds to your MySQL server version "
                    f"near '{q}'</pre>")
            else:
                self._send(200, f"<h1>Results for {q}</h1><p>No articles found.</p>")
        elif path == "/redirect":
            # Bug 3: open redirect — Location taken straight from user input.
            target = params.get("next", ["/"])[0]
            self._send_redirect(target)
        elif path == "/.env":
            # Bug 4: sensitive file exposed in the web root.
            self._send(200, "DB_PASSWORD=hunter2\nSECRET_KEY=totally-not-secret\n")
        elif path == "/ping":
            host = params.get("host", [""])[0]
            # Bug 6 (SIMULATED): command injection. A real backend would run
            # `ping <host>` through a shell. To exercise the *time-based*
            # detector without shipping an actual RCE, we emulate a shell
            # honouring an injected `sleep N` — identical observable behaviour,
            # no real command execution. Not linked from the home page, so a
            # plain crawl stays fast; scan it directly to see the check fire.
            match = re.search(r"sleep\s+(\d+)", host)
            if match:
                time.sleep(min(int(match.group(1)), 12))
            self._send(200, f"<h1>Pinging {host} ...</h1>")
        else:
            self._send(404, "<h1>404 Not Found</h1>")

    def do_POST(self) -> None:  # noqa: N802
        # Bug 5: state-changing endpoint with no CSRF protection.
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self._send(200, "<h1>Comment posted</h1>")

    def _send_redirect(self, target: str) -> None:
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *_args) -> None:
        pass  # keep the console quiet during a scan


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8973
    server = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"[vuln-app] listening on http://127.0.0.1:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[vuln-app] bye")
        server.shutdown()


if __name__ == "__main__":
    main()
