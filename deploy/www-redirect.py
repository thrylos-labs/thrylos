#!/usr/bin/env python3
"""Sends www.thrylos.org to thrylos.org, keeping the path and query string.

Listens on loopback only; the Cloudflare Tunnel publishes it as
www.thrylos.org. GET and HEAD get a permanent redirect (301); anything else
gets 308, which keeps the method. Nothing else is served.
"""
from http.server import BaseHTTPRequestHandler, HTTPServer

TARGET = "https://thrylos.org"


class Redirect(BaseHTTPRequestHandler):
    server_version = "redirect"
    sys_version = ""

    def _send(self, status):
        path = self.path if self.path.startswith("/") else "/"
        # A request line cannot hold a line break, but never build a header from
        # anything that could.
        path = "".join(ch for ch in path if ch.isprintable() and ch not in "\r\n")
        self.send_response(status)
        self.send_header("Location", TARGET + path)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()

    def do_GET(self):
        self._send(301)

    do_HEAD = do_GET

    def _keep_method(self):
        self._send(308)

    do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _keep_method

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8085), Redirect).serve_forever()
