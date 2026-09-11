#!/usr/bin/env python3
"""Local traffic sink for the Phase A probe.

Serves a requested number of zero bytes on GET /blob?bytes=N and drains POST
bodies, so the probe can be driven with transfers of exactly known size while the
payload never leaves the machine. Binds to loopback only.

The per-request ``bytes`` parameter is what makes "half payload" attribution tests
real: the caller's requested size is what is actually transferred, and the sink
refuses anything above the configured cap.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MAX_BYTES = 67108864


def requested_bytes(query, default, cap):
    """Resolve ?bytes=N, rejecting anything that is not a sane positive size."""
    params = parse_qs(query or "")
    if "bytes" not in params:
        return default
    try:
        value = int(params["bytes"][0])
    except (TypeError, ValueError):
        return None
    if value <= 0 or value > cap:
        return None
    return value


class Handler(BaseHTTPRequestHandler):
    total_bytes = 0
    max_bytes = MAX_BYTES

    def log_message(self, *args):
        pass

    def _bad_request(self, reason):
        body = ("invalid bytes parameter: %s\n" % reason).encode()
        self.send_response(400)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        query = urlparse(self.path).query
        total = requested_bytes(query, self.total_bytes, self.max_bytes)
        if total is None:
            self._bad_request("must be a positive integer <= %d" % self.max_bytes)
            return
        remaining = total
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
    parser.add_argument("--bytes", type=int, default=67108864,
                        help="default size for GET without ?bytes=, and the hard cap")
    args = parser.parse_args()
    Handler.total_bytes = args.bytes
    Handler.max_bytes = args.bytes
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    server.daemon_threads = True
    print("sink listening on 127.0.0.1:%d serving up to %d bytes per request"
          % (args.port, args.bytes), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
