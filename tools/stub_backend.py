#!/usr/bin/env python3
"""Neutral stub backend for WAF baseline runs (step-09 T5).

Returns HTTP 200 with a short fixed HTML body for ANY method and path,
including unknown paths. No state, no routing, no errors: the point is a
backend that cannot itself produce 4xx/5xx, so every non-200 response seen
in a run is attributable to the WAF (or to a replay artifact on the client
side, which cannot happen here because nothing is stateful).

stdlib only, so it can run inside a minimal container image.

Usage: python3 stub_backend.py [port]
"""

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = (
    "<!DOCTYPE html>\n"
    "<html><head><title>kortex stub</title></head>\n"
    "<body><h1>ok</h1></body></html>\n"
).encode()


class StubHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _reply(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    do_GET = _reply
    do_POST = _reply
    do_PUT = _reply
    do_DELETE = _reply
    do_PATCH = _reply
    do_HEAD = _reply
    do_OPTIONS = _reply

    def log_message(self, fmt, *args):  # quiet: logs go nowhere useful here
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
    ThreadingHTTPServer(("0.0.0.0", port), StubHandler).serve_forever()


if __name__ == "__main__":
    main()
