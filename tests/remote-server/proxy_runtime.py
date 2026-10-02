"""Exercise the production nginx location through real TLS wire requests."""
import http.server
import pathlib
import socket
import ssl
import subprocess
import sys
import threading
import time

root = pathlib.Path(sys.argv[1])
seen = []
class Capture(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        seen.append((self.request_version, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass
upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Capture)
thread = threading.Thread(target=upstream.serve_forever, daemon=True)
thread.start()
with socket.socket() as reserve:
    reserve.bind(("127.0.0.1", 0))
    port = reserve.getsockname()[1]
ingress = (root / "ingress.conf").read_text()
ingress = ingress.replace("listen 443 ssl;", f"listen 127.0.0.1:{port} ssl;")
ingress = ingress.replace("127.0.0.1:9191", f"127.0.0.1:{upstream.server_port}")
(root / "runtime-ingress.conf").write_text(ingress)
config = (root / "nginx.conf").read_text().replace("ingress.conf", "runtime-ingress.conf")
(root / "runtime.conf").write_text(config)
proc = subprocess.Popen(["nginx", "-p", str(root) + "/", "-c", str(root / "runtime.conf"),
                         "-g", "daemon off; master_process off;"])
context = ssl._create_unverified_context()
headers = {
    "X-Remote-Probe-Id": "fixture-probe",
    "X-Remote-Probe-Sent-Epoch": "1234567890",
    "X-Remote-Probe-Run": "1234567890abcdef",
    "X-Remote-Probe-Seq": "3",
    "X-Remote-Probe-Signature": "a" * 64,
}
body = b'{"x":7}'
def request(version, framing, wire_body):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="probes.example.com") as conn:
            prefix = f"POST /api/v1/remote-probes/ingest {version}\r\nHost: probes.example.com\r\nConnection: close\r\nContent-Type: application/json\r\n"
            wire = prefix + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + framing + "\r\n"
            conn.sendall(wire.encode("ascii") + wire_body)
            return conn.makefile("rb").readline().split()[1]
try:
    deadline = time.monotonic() + 5
    while True:
        if proc.poll() is not None:
            raise RuntimeError("nginx runtime exited")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.05)
    assert request("HTTP/1.1", f"Content-Length: {len(body)}\r\n", body) == b"200"
    assert len(seen) == 1
    version, received, captured = seen[0]
    assert version == "HTTP/1.1" and captured == body
    assert all(received.get(k) == v for k, v in headers.items())
    assert received.get("Content-Length") == str(len(body)) and "Transfer-Encoding" not in received
    print("PASS nginx/legal_request_preserves_body_and_five_headers", flush=True)
    cases = [
        ("http_1_0", "HTTP/1.0", f"Content-Length: {len(body)}\r\n", body),
        ("chunked", "HTTP/1.1", "Transfer-Encoding: chunked\r\n", b"7\r\n" + body + b"\r\n0\r\n\r\n"),
        ("missing_content_length", "HTTP/1.1", "", b""),
    ]
    for label, version, framing, wire_body in cases:
        assert request(version, framing, wire_body) == b"400", label
        assert len(seen) == 1, label + " reached upstream"
        print("PASS nginx/" + label + "_rejected_before_upstream", flush=True)
finally:
    proc.terminate()
    proc.wait(timeout=5)
    upstream.shutdown()
    upstream.server_close()
