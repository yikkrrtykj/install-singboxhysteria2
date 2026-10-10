#!/usr/bin/env python3
"""Opt-in two-core loopback test: actual VLESS Reality + actual Hysteria2.

No downloads, remote servers, user configuration or TUN. Quick mode accelerates
only policy pauses in this lab, never in the operator pilot.
"""
import argparse
import base64
from contextlib import ExitStack
import hashlib
import http.server
import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from quality_failover import pilot
from quality_failover.receiver import Server
from quality_failover.daily import IdentifiedController, DailyOwnership
from quality_failover.policy import NODES
import ssl


class Origin(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET


def load(path):
    spec = importlib.util.spec_from_file_location("pilot_lab_fixture", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mihomo", required=True)
    parser.add_argument("--expect-sha256", required=True)
    parser.add_argument("--openssl", required=True)
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--daily-mode", choices=("rule", "global"))
    args = parser.parse_args()
    binary = pilot.pinned_binary(args.mihomo, args.expect_sha256)
    fixture = load(ROOT / "tests/test_quality_failover.py")
    with tempfile.TemporaryDirectory(prefix="p48-real-protocol-lab-") as directory:
        root = Path(directory)
        receiver_root = root / "receiver"
        pilot.receiver_init(receiver_root, "127.0.0.1", 8448, args.openssl)
        receiver_cfg = json.loads((receiver_root / "receiver.json").read_bytes())
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(receiver_cfg["certificate"], receiver_cfg["private_key"])
        sink = Server(("127.0.0.1", 0), receiver_cfg["token"], context, minute_bytes=4 * 1024 * 1024)
        info_path = receiver_root / "receiver-info.json"
        info = json.loads(info_path.read_bytes())
        info["endpoint"] = "https://127.0.0.1:%d" % sink.server_port
        info_path.write_bytes(json.dumps(info).encode())
        origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
        origin.daemon_threads = True
        for server in (sink, origin):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        key_path = root / "reality-key.pem"
        subprocess.run([args.openssl, "genpkey", "-algorithm", "X25519", "-out", str(key_path)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private = subprocess.run([args.openssl, "pkey", "-in", str(key_path), "-outform", "DER"],
                                 check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        public = subprocess.run([args.openssl, "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL).stdout
        private_key = base64.urlsafe_b64encode(private[-32:]).decode().rstrip("=")
        public_key = base64.urlsafe_b64encode(public[-32:]).decode().rstrip("=")
        reality_port = pilot.tcp_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(("127.0.0.1", 0))
            hy2_port = reserve.getsockname()[1]
        (root / "server-data").mkdir()
        server_certificate = root / "server-data" / "certificate.pem"
        server_key = root / "server-data" / "key.pem"
        pilot.private_file(server_certificate, Path(receiver_cfg["certificate"]).read_bytes())
        pilot.private_file(server_key, Path(receiver_cfg["private_key"]).read_bytes())
        server_config = root / "server.yaml"
        server_text = ["allow-lan: false", "mode: rule", "log-level: silent", "tun:", "  enable: false",
                      "dns:", "  enable: false", "listeners:",
                      "  - name: lab-real", "    type: vless", "    listen: 127.0.0.1",
                      "    port: %d" % reality_port, "    users:",
                      "      - uuid: 11111111-1111-4111-8111-111111111111", "        flow: xtls-rprx-vision",
                      "    reality-config:", "      dest: 127.0.0.1:%d" % sink.server_port,
                      "      private-key: " + private_key, "      short-id:", "        - 0123456789abcdef",
                      "      server-names:", "        - www.example.com",
                      "  - name: lab-hy2", "    type: hysteria2", "    listen: 127.0.0.1",
                      "    port: %d" % hy2_port, "    users:", "      pilot: synthetic-primary-password",
                      "    certificate: " + json.dumps(str(server_certificate)),
                      "    private-key: " + json.dumps(str(server_key)),
                      "    alpn:", "      - h3", "rules:", "  - MATCH,DIRECT", ""]
        pilot.private_file(server_config, "\n".join(server_text).encode())
        process = None
        try:
            subprocess.run([str(binary), "-t", "-d", str(root / "server-data"), "-f", str(server_config)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
            process = subprocess.Popen([str(binary), "-d", str(root / "server-data"), "-f", str(server_config)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            source = root / "event-mihomo.yaml"
            fixture.export(source)
            text = source.read_text(encoding="utf-8").replace("    server: 203.0.113.1", "    server: 127.0.0.1")
            text = text.replace("    port: 8443", "    port: %d" % reality_port)
            text = text.replace("    port: 8444", "    port: %d" % hy2_port)
            text = text.replace("      public-key: " + "A" * 43, "      public-key: " + public_key)
            source.write_bytes(text.encode())
            original_builder, original_clock = pilot.isolated_profile, time.monotonic
            original_runner = pilot.Runner
            marker = "quality-profile-" + "a" * 32
            offset = [0]

            def local_profile(*values):
                text = original_builder(*values)
                text = text.replace("https://www.gstatic.com/generate_204", "http://127.0.0.1:%d/hc" % origin.server_port)
                if args.daily_mode:
                    tag = "  - name: " + marker + "\n    type: select\n    hidden: true\n    proxies:\n      - DIRECT\n\n"
                    text = text.replace("rules:\n", tag + "rules:\n", 1)
                    if args.daily_mode == "global":
                        text = text.replace("mode: rule", "mode: global", 1)
                return text

            class DailyLabRunner(original_runner):
                def __init__(self, cfg):
                    super().__init__(cfg)
                    self.controller = IdentifiedController(cfg["controller"], cfg["controller_secret"], marker, NODES[:2])
                    self.owner = DailyOwnership(self.engine.paths)

            class LabSuite(pilot.Suite):
                def __init__(self, *values, **kwargs):
                    super().__init__(*values, **kwargs)
                    if args.daily_mode == "global":
                        self.outer_group = "GLOBAL"

                def pause(self, seconds):
                    if args.quick and seconds >= 30:
                        offset[0] += seconds
                        if self.cancel.is_set():
                            raise pilot.Cancelled()
                    else:
                        super().pause(seconds)

            with ExitStack() as patches:
                patches.enter_context(patch.object(pilot, "isolated_profile", side_effect=local_profile))
                patches.enter_context(patch.object(pilot, "Suite", LabSuite))
                patches.enter_context(patch.object(time, "monotonic", side_effect=lambda: original_clock() + offset[0]))
                if args.daily_mode:
                    patches.enter_context(patch.object(pilot, "Runner", DailyLabRunner))
                result = pilot.run_pilot(str(source), "event", str(info_path), str(receiver_root / "receiver-ca.pem"),
                                        str(binary), args.expect_sha256, str(root / "result.json"),
                                        emit=lambda item: print(json.dumps(item), flush=True))
            if not result["passed"] or not result["cleanup_complete"]:
                print(json.dumps({"lab": "FAIL", "result": result}), flush=True)
                raise SystemExit(1)
            print("lab: PASS actual Reality/HY2 local endpoints, isolated fault suite; "
                  + (("accelerated policy clock" if args.quick else "wall-clock policy") + "; daily mode=" + str(args.daily_mode)), flush=True)
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            for server in (sink, origin):
                server.shutdown()
                server.server_close()


if __name__ == "__main__":
    main()
