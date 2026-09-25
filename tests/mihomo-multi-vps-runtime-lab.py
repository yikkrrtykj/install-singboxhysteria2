#!/usr/bin/env python3
"""Issue #48 PR-48A -- OPT-IN controlled runtime validation of a merged profile.

Static YAML assertions cannot prove that Mihomo's fallback group really walks
Reality -> Hysteria2 -> Backup-Reality -> Backup-Hysteria2. This harness starts
ONE pinned Mihomo binary, loopback-only, against four local mock relays that
stand in for the four nodes, and drives the failover scenarios of the PR-48A
spec section 13.

It is deliberately NOT part of CI: it needs an operator-supplied, hash-pinned
binary. It refuses to run without both --mihomo and --expect-sha256 matching,
and it never downloads anything.

What is real here: the merged profile produced by
tools/mihomo-multi-vps-merge.py (its group names, member order,
default-selected and fallback semantics). What is substituted: the proxy
bodies (socks5 to a local relay instead of a real VPS), the probe endpoint (a
local origin instead of gstatic), and the probe timing (interval/timeout scaled
down so the wall clock stays sane -- lab only; the shipped profile keeps 60s).

Loopback only, no credentials, no production contact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler

NODE_RELAYS = {
    "Reality": 1081,
    "Hysteria2": 1082,
    "Backup-Reality": 1083,
    "Backup-Hysteria2": 1084,
}
RELAY_OF_PORT = {port: name for name, port in NODE_RELAYS.items()}
RELAY_FLAG = {"Reality": "reality", "Hysteria2": "hy2",
              "Backup-Reality": "backup_reality",
              "Backup-Hysteria2": "backup_hy2"}
EXPECTED_ORDER = ["Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2"]
ORIGIN_PORT = 18080
CONTROLLER = "127.0.0.1:9091"
LAB_SECRET = "lab-harness-secret"
HOLD_SECONDS = 25
SETTLE_DEADLINE = 40.0

PASS = 0
FAIL = 0


def log(message):
    print("%s %s" % (time.strftime("%H:%M:%S"), message), flush=True)


def check(label, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        print("  PASS %s%s" % (label, (" (%s)" % detail) if detail else ""), flush=True)
    else:
        FAIL += 1
        print("  FAIL %s%s" % (label, (" (%s)" % detail) if detail else ""), flush=True)
    return ok


class RelayStats(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.connects = {name: 0 for name in NODE_RELAYS}

    def bump(self, name):
        with self.lock:
            self.connects[name] += 1

    def snapshot(self):
        with self.lock:
            return dict(self.connects)


STATS = RelayStats()
STATE_DIR = ""


class SocksHandler(socketserver.BaseRequestHandler):
    name = "reality"

    def handle(self):
        sock = self.request
        try:
            greeting = self.read_n(sock, 2)
            if not greeting or greeting[0] != 0x05:
                return
            if self.read_n(sock, greeting[1]) is None:
                return
            sock.sendall(b"\x05\x00")
            request = self.read_n(sock, 4)
            if not request or request[0] != 0x05 or request[1] != 0x01:
                return
            if request[3] == 0x01:
                host = socket.inet_ntoa(self.read_n(sock, 4))
            elif request[3] == 0x03:
                length = self.read_n(sock, 1)
                host = self.read_n(sock, length[0]).decode()
            else:
                return
            port = struct.unpack(">H", self.read_n(sock, 2))[0]
            if (host, port) != ("127.0.0.1", ORIGIN_PORT):
                sock.sendall(b"\x05\x02\x00\x01" + socket.inet_aton("0.0.0.0")
                             + struct.pack(">H", 0))
                return
            if not os.path.exists(os.path.join(STATE_DIR, RELAY_FLAG[self.server.node_name] + ".up")):
                # Simulated outage: the tunnel refuses new CONNECTs.
                sock.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("0.0.0.0")
                             + struct.pack(">H", 0))
                return
            STATS.bump(self.server.node_name)
            up = socket.create_connection((host, port), timeout=3)
            up.settimeout(None)
            sock.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0")
                         + struct.pack(">H", 0))
            self.pump(sock, up)
        except OSError:
            pass

    @staticmethod
    def read_n(sock, count):
        buffer_ = b""
        while len(buffer_) < count:
            chunk = sock.recv(count - len(buffer_))
            if not chunk:
                return None
            buffer_ += chunk
        return buffer_

    @staticmethod
    def pump(client, upstream):
        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        threads = [threading.Thread(target=pipe, args=(a, b), daemon=True)
                   for a, b in ((client, upstream), (upstream, client))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()


class RelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


class OriginHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        if self.path.startswith("/hc"):
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path.startswith("/hold"):
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            try:
                time.sleep(self.server.hold_seconds)
                self.wfile.write(b"hold\n")
            except OSError:
                pass
        elif self.path.startswith("/ping"):
            self.send_response(200)
            body = json.dumps(STATS.snapshot()).encode()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *args):
        pass


class OriginServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        pass


# ---------------------------------------------------------------- lab config --
def build_lab_config(source_path, interval, timeout_ms, expected_names):
    """Keep the profile topology, substitute the node bodies and the probe."""
    with open(source_path, encoding="utf-8") as handle:
        text = handle.read()
    names = []
    inside = False
    for line in text.split("\n"):
        if line == "proxies:":
            inside = True
            continue
        if line == "proxy-groups:":
            inside = False
            continue
        if inside and line.startswith("  - name: "):
            names.append(line[len("  - name: "):])
    if names != expected_names:
        raise SystemExit("profile carries an unexpected proxy set: %r (want %r)"
                         % (names, expected_names))

    groups = []
    inside_groups = False
    for line in text.split("\n"):
        if line == "proxy-groups:":
            inside_groups = True
            groups.append(line)
            continue
        if line == "rules:":
            break
        if inside_groups:
            if line.startswith("    url: "):
                line = '    url: "http://127.0.0.1:%d/hc"' % ORIGIN_PORT
            elif line.startswith("    interval: "):
                line = "    interval: %d" % interval
            elif line.startswith("    timeout: "):
                line = "    timeout: %d" % timeout_ms
            groups.append(line)

    out = ["mixed-port: 7890", "allow-lan: false", "mode: rule",
           "log-level: info", "external-controller: %s" % CONTROLLER,
           'secret: "%s"' % LAB_SECRET, "", "profile:", "  store-selected: true",
           "", "proxies:"]
    for name in names:
        out.append("  - name: %s" % name)
        out.append("    type: socks5")
        out.append("    server: 127.0.0.1")
        out.append("    port: %d" % NODE_RELAYS[name])
    out.append("")
    out.extend(groups)
    out.extend(["", "rules:", "  - MATCH,节点选择", ""])
    return "\n".join(out), names


# ------------------------------------------------------------- controller API --
def api(path):
    request = urllib.request.Request("http://%s%s" % (CONTROLLER, path),
                                     headers={"Authorization": "Bearer " + LAB_SECRET})
    with urllib.request.urlopen(request, timeout=3) as response:
        return json.loads(response.read().decode())


def group_state(group):
    return api("/proxies").get("proxies", {}).get(group, {}).get("now")


def wait_for_selection(group, want, deadline=SETTLE_DEADLINE):
    stop = time.time() + deadline
    while time.time() < stop:
        if group_state(group) == want:
            return True
        time.sleep(0.5)
    return False


def set_up(node, up):
    flag = os.path.join(STATE_DIR, RELAY_FLAG[node] + ".up")
    if up:
        with open(flag, "wb") as handle:
            handle.write(b"1")
    else:
        try:
            os.unlink(flag)
        except FileNotFoundError:
            pass


def fetch_through_proxy(path, timeout=10):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": "http://127.0.0.1:7890"}))
    request = urllib.request.Request("http://127.0.0.1:%d%s" % (ORIGIN_PORT, path))
    return opener.open(request, timeout=timeout)


def chain_nodes():
    """The proxy chain of every live connection, as mihomo reports it."""
    return [c.get("chains", []) for c in api("/connections").get("connections", [])]


def api_select(group, member):
    """A lab-only manual pin, exactly what a user click in the client UI does."""
    path = urllib.parse.quote(group, safe="")
    request = urllib.request.Request(
        "http://%s/proxies/%s" % (CONTROLLER, path),
        data=json.dumps({"name": member}).encode(),
        headers={"Authorization": "Bearer " + LAB_SECRET,
                 "Content-Type": "application/json"},
        method="PUT")
    with urllib.request.urlopen(request, timeout=3) as response:
        return response.status


def start_child(binary, config_path, data_dir, workdir, tag):
    log_handle = open(os.path.join(workdir, "mihomo-%s.log" % tag), "wb")
    child = subprocess.Popen([binary, "-d", data_dir, "-f", config_path],
                             stdout=log_handle, stderr=subprocess.STDOUT)
    stop = time.time() + 30
    while time.time() < stop:
        try:
            api("/version")
            return child, log_handle
        except Exception:  # noqa: BLE001 -- still booting
            time.sleep(0.5)
    stop_child(child, log_handle)
    raise SystemExit("mihomo never answered on the controller (phase %s)" % tag)


def stop_child(child, log_handle):
    child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=20)
    except subprocess.TimeoutExpired:
        child.kill()
    log_handle.close()
    time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mihomo", required=True, help="path to the Mihomo binary")
    parser.add_argument("--expect-sha256", required=True,
                        help="the pinned build's SHA-256; a mismatch is fatal")
    parser.add_argument("--merged", required=True,
                        help="profile produced by tools/mihomo-multi-vps-merge.py")
    parser.add_argument("--single", required=True,
                        help="the primary VPS export alone (the pre-upgrade profile)")
    parser.add_argument("--workdir", required=True, help="scratch directory")
    parser.add_argument("--interval", type=int, default=3,
                        help="LAB-ONLY probe interval in seconds")
    parser.add_argument("--timeout", type=int, default=1500,
                        help="LAB-ONLY probe timeout in milliseconds")
    args = parser.parse_args()

    digest = hashlib.sha256(open(args.mihomo, "rb").read()).hexdigest()
    if digest != args.expect_sha256.lower():
        raise SystemExit("binary hash mismatch (got %s): refusing to run" % digest)
    log("pinned build accepted: %s" % digest)

    global STATE_DIR
    STATE_DIR = os.path.join(args.workdir, "state")
    os.makedirs(STATE_DIR, exist_ok=True)
    merged_config = os.path.join(args.workdir, "lab-config.yaml")
    config, names = build_lab_config(args.merged, args.interval, args.timeout,
                                     EXPECTED_ORDER)
    with open(merged_config, "w", encoding="utf-8") as handle:
        handle.write(config)
    log("lab config built from the merged profile (nodes: %s)" % ", ".join(names))
    single_config = os.path.join(args.workdir, "lab-config-single.yaml")
    single_text, single_names = build_lab_config(
        args.single, args.interval, args.timeout, ["Reality", "Hysteria2"])
    with open(single_config, "w", encoding="utf-8") as handle:
        handle.write(single_text)
    log("lab config built from the pre-upgrade single-VPS profile (nodes: %s)"
        % ", ".join(single_names))

    for node in names:
        set_up(node, True)
    for port in NODE_RELAYS.values():
        server = RelayServer(("127.0.0.1", port), SocksHandler)
        server.node_name = RELAY_OF_PORT[port]
        threading.Thread(target=server.serve_forever, daemon=True).start()
    origin = OriginServer(("127.0.0.1", ORIGIN_PORT), OriginHandler)
    origin.hold_seconds = HOLD_SECONDS
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    data_dir = os.path.join(args.workdir, "mihomo-data")
    if os.path.isdir(data_dir):
        shutil.rmtree(data_dir)
    os.makedirs(data_dir)
    child, log_handle = start_child(args.mihomo, merged_config, data_dir,
                                    args.workdir, "failover")
    try:
        log("mihomo version: %s" % api("/version"))

        # S1: everything healthy -> the primary of the primary VPS wins
        time.sleep(args.interval * 2 + 2)
        check("S1 fresh, all healthy: 自动选择 = Reality",
              wait_for_selection("自动选择", "Reality", deadline=15),
              "now=%s" % group_state("自动选择"))
        check("S1 节点选择 defaults to 自动选择",
              group_state("节点选择") == "自动选择",
              "now=%s" % group_state("节点选择"))
        before = STATS.snapshot()
        fetch_through_proxy("/ping").read()
        after = STATS.snapshot()
        check("S1 new connection really egresses the Reality relay",
              after["Reality"] == before["Reality"] + 1
              and after["Backup-Reality"] == before["Backup-Reality"],
              "relays=%s" % after)

        # S2: A Reality dies -> A HY2
        set_up("Reality", False)
        check("S2 A Reality down: 自动选择 moves to Hysteria2",
              wait_for_selection("自动选择", "Hysteria2"),
              "now=%s" % group_state("自动选择"))

        # S3: both A nodes down -> the backup pair takes over
        set_up("Hysteria2", False)
        check("S3 A Reality + A Hysteria2 down: 自动选择 = Backup-Reality",
              wait_for_selection("自动选择", "Backup-Reality"),
              "now=%s" % group_state("自动选择"))

        # S4: backup Reality down as well -> Backup-Hysteria2
        set_up("Backup-Reality", False)
        check("S4 Backup-Reality down: 自动选择 = Backup-Hysteria2",
              wait_for_selection("自动选择", "Backup-Hysteria2"),
              "now=%s" % group_state("自动选择"))

        # S5: A Reality recovers -> priority returns to it (fallback is
        # first-healthy-by-order, not sticky-by-latency)
        set_up("Reality", True)
        check("S5 A Reality restored: 自动选择 eventually returns to Reality",
              wait_for_selection("自动选择", "Reality"),
              "now=%s" % group_state("自动选择"))

        # S6: an ESTABLISHED connection is never migrated; a NEW one follows
        # the new selection.
        for node in EXPECTED_ORDER:
            set_up(node, True)
        time.sleep(args.interval * 2 + 1)
        check("S6 all four healthy again: 自动选择 = Reality",
              wait_for_selection("自动选择", "Reality", deadline=15),
              "now=%s" % group_state("自动选择"))
        hold_result = {}

        def hold():
            try:
                hold_result["body"] = fetch_through_proxy(
                    "/hold", timeout=HOLD_SECONDS + 20).read()
            except Exception as exc:  # noqa: BLE001 -- reported as evidence
                hold_result["error"] = "%s: %s" % (type(exc).__name__, exc)

        hold_thread = threading.Thread(target=hold)
        hold_thread.daemon = True
        hold_thread.start()
        time.sleep(2)
        chains = chain_nodes()
        check("S6 an established session is open, on Reality",
              any("Reality" in chain for chain in chains),
              "chains=%s" % chains)
        set_up("Reality", False)
        check("S6 the group fails over while the session is held",
              wait_for_selection("自动选择", "Hysteria2"),
              "now=%s" % group_state("自动选择"))
        check("S6 the established session is NOT migrated (still chained on Reality)",
              any("Reality" in chain for chain in chain_nodes()),
              "chains=%s" % chain_nodes())
        before = STATS.snapshot()
        fetch_through_proxy("/ping").read()
        after = STATS.snapshot()
        check("S6 a NEW connection uses the new selection (Hysteria2)",
              after["Hysteria2"] == before["Hysteria2"] + 1
              and after["Reality"] == before["Reality"],
              "relays=%s" % after)
        hold_thread.join(timeout=HOLD_SECONDS + 25)
        check("S6 the established session ran to completion on its original path",
              hold_result.get("body") == b"hold\n", "result=%s" % hold_result)
    finally:
        stop_child(child, log_handle)

    # S7: the upgrade path. A client that already ran the single-VPS profile
    # has a warm store-selected cache; loading the merged profile into it must
    # not orphan any persisted value, and must not quietly release a manual pin.
    for node in EXPECTED_ORDER:
        set_up(node, True)
    cache_dir = os.path.join(args.workdir, "mihomo-cache")
    if os.path.isdir(cache_dir):
        shutil.rmtree(cache_dir)
    os.makedirs(cache_dir)
    child, log_handle = start_child(args.mihomo, single_config, cache_dir,
                                    args.workdir, "cache-seed")
    try:
        time.sleep(args.interval * 2 + 1)
        check("S7 pre-upgrade profile starts on Reality",
              wait_for_selection("自动选择", "Reality", deadline=15),
              "now=%s" % group_state("自动选择"))
        # a real user pin: outer on the automatic group, inner manually fixed
        api_select("节点选择", "自动选择")
        api_select("自动选择", "Hysteria2")
        time.sleep(2)
        check("S7 inner pin Hysteria2 is persisted before the upgrade",
              group_state("自动选择") == "Hysteria2",
              "now=%s" % group_state("自动选择"))
        cache_db = os.path.join(cache_dir, "cache.db")
        check("S7 a store-selected cache really exists", os.path.exists(cache_db),
              cache_db)
    finally:
        stop_child(child, log_handle)

    child, log_handle = start_child(args.mihomo, merged_config, cache_dir,
                                    args.workdir, "cache-upgrade")
    try:
        time.sleep(args.interval * 2 + 1)
        check("T34/S7 outer cached 自动选择 still resolves after the upgrade",
              group_state("节点选择") == "自动选择",
              "now=%s" % group_state("节点选择"))
        check("T34/S7 inner cached Hysteria2 still resolves after the upgrade",
              group_state("自动选择") == "Hysteria2",
              "now=%s" % group_state("自动选择"))
        time.sleep(args.interval * 2)
        check("S7 the merged profile does NOT silently clear or re-race the pin",
              group_state("自动选择") == "Hysteria2",
              "now=%s" % group_state("自动选择"))
        # A persisted pin never keeps traffic on a dead node: once the pinned
        # member fails, the group leaves it and #42 priority applies again --
        # first healthy by member order, which is still the primary pair.
        set_up("Hysteria2", False)
        check("S7 a dead pinned member is left behind (back to healthy Reality)",
              wait_for_selection("自动选择", "Reality"),
              "now=%s" % group_state("自动选择"))
        set_up("Reality", False)
        check("S7 the whole primary pair down -> Backup-Reality",
              wait_for_selection("自动选择", "Backup-Reality"),
              "now=%s" % group_state("自动选择"))
    finally:
        stop_child(child, log_handle)

    print("\n== live harness summary ==")
    print("  pass=%d fail=%d" % (PASS, FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
