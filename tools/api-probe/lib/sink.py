#!/usr/bin/env python3
"""Local traffic sink for the Phase A probe.

Serves a fixed number of zero bytes on GET /blob and drains POST bodies, so the
probe can be driven with transfers of exactly known size while the payload never
leaves the machine. Binds to loopback only.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    total_bytes = 0

    def log_message(self, *args):
        pass

    def do_GET(self):
        remaining = self.total_bytes
        self.send_response(200)
        self.send_header("Content-Length", str(remaining))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        chunk = b"\0" * 65536
        while remaining > 0:
            block = chunk[: min(len(chunk), remaining)]
            try:
                self.wfile.write(block)
            except (BrokenPipeError, ConnectionResetError):
                return
            remaining -= len(block)

    def do_POST(self):
        remaining = int(self.headers.get("Content-Length") or 0)
        while remaining > 0:
            block = self.rfile.read(min(65536, remaining))
            if not block:
                break
            remaining -= len(block)
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description="loopback traffic sink for the Phase A probe")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--bytes", type=int, default=67108864)
    args = parser.parse_args()
    Handler.total_bytes = args.bytes
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    print(f"sink listening on 127.0.0.1:{args.port} serving {args.bytes} bytes", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
