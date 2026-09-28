"""Behaviour groups for tests/test-monitor-v2-probes.sh (issue #33 P3A).

Every fake server binds 127.0.0.1 ONLY -- the suite has zero public
network dependency. Each check prints one "PASS <id>" or "FAIL <id>..."
line; the shell harness turns that into the counted regression gate.

Sentinel discipline: every planted sentinel (UUID / password / private
IP / host name) must appear NOWHERE in a result JSON, its repr, or any
captured log line.

Cycle-occupancy discipline: the engine holds ONE outstanding worker per
slot across cycles (A4), so the `cycle()` helper drains a slot back to
free before every measured cycle -- except calls that INTENTIONALLY test
occupancy (hold=True). A drain failure surfaces as the next visible
FAIL, never as a silent hang.
"""

import http.server
import json
import logging
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.request
import uuid

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from diagnostics import network_probes as np  # noqa: E402

CERT = os.environ["PROBE_TEST_CERT"]
KEY = os.environ["PROBE_TEST_KEY"]
IS_LINUX = sys.platform.startswith("linux")

SENT_UUID = uuid.uuid4().hex
SENT_PASS = "hunter2-" + uuid.uuid4().hex[:8]
SENT_PRIV = "10.11.12.13"
SENT_HOST = "sentinel-" + uuid.uuid4().hex[:8] + ".invalid"
SENTINELS = (SENT_UUID, SENT_PASS, SENT_PRIV, SENT_HOST)


def report(name, ok, note=""):
    print("%s %s%s" % ("PASS" if ok else "FAIL", name,
                       "" if ok else " <%r>" % (note,)))


def slot_shape(slot, keys):
    return isinstance(slot, dict) and set(slot) == set(keys) \
        and slot["error_code"] in np.ERROR_CODES


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def drain(slot, budget=12.0):
    """Wait for a previous cycle's (abandoned) worker on this slot to
    die, so the next measured cycle starts from a provably free slot."""
    t0 = time.monotonic()
    while time.monotonic() - t0 < budget:
        if not np._worker_busy(slot):
            return True
        time.sleep(0.05)
    return False


def worker_threads(name):
    return sum(1 for t in threading.enumerate() if t.name == name)


# --------------------------------------------------------------------------
# loopback fakes
# --------------------------------------------------------------------------

class Handler(http.server.BaseHTTPRequestHandler):
    mode = "200-ip"

    def do_GET(self):
        if self.mode == "hang":
            time.sleep(30)
            return
        body_map = {
            "200-ip": b"8.8.8.8\n",
            "200-v6": b"2606:4700:4700::64\n",
            "200-priv": b"127.0.0.1\n",
            "200-rfc1918": b"10.1.2.3\n",
            "200-junk": ("not an ip %s\n" % SENT_UUID).encode(),
            "200-nonutf8": b"\xff\xfe\x00bad",
            "200-oversize": b"8.8.8.8" + b"x" * 4096,
            "204": b"",
            "500": ("INTERNAL %s %s" % (SENT_PASS, SENT_HOST)).encode(),
            "404": b"nope",
        }
        code = {"204": 204, "500": 500, "404": 404}.get(self.mode, 200)
        body = body_map[self.mode]
        self.send_response(code)
        if code != 204:
            self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body and code != 204:
            self.wfile.write(body)

    def log_message(self, *args):
        pass


def tls_server(mode):
    srv = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), type("H_" + mode, (Handler,), {"mode": mode}))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


def plaintext_sentinel_server():
    """A NOT-TLS listener that greets with sentinel garbage: the HTTPS
    probe must surface a closed code, never the handshake echo."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    port = srv.getsockname()[1]

    def loop():
        try:
            while True:
                conn, _ = srv.accept()
                try:
                    conn.sendall(("HELLO %s %s\r\n"
                                  % (SENT_UUID, SENT_PASS)).encode())
                except OSError:
                    pass
                conn.close()
        except OSError:
            pass
    threading.Thread(target=loop, daemon=True).start()
    return srv, port


class UdpFake:
    def __init__(self, mode):
        self.mode = mode
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(60)
        self.port = self.sock.getsockname()[1]
        # A second, DIFFERENTLY-SOURCED socket: replies sent through it
        # come from a peer that is NOT the configured resolver.
        self.other = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(65536)
            except OSError:
                return
            rid = struct.unpack("!H", data[:2])[0]
            q = data[12:]
            head = struct.pack("!HHHHHH", rid, 0x8180, 1, 1, 0, 0)
            if self.mode == "drop":
                continue                    # RECEIVED: and then SILENCE
            elif self.mode == "reply":
                self.sock.sendto(head + q, addr)
            elif self.mode == "stray":
                # The configured port stays SILENT: a byte-perfectly-
                # valid reply arrives from a DIFFERENT peer. An
                # unconnected probe accepts it (false positive); the
                # peer-bound socket must let the deadline expire.
                self.other.sendto(head + q, addr)
            elif self.mode == "wrongq":
                # Correct peer, correct id, valid header: only the
                # echoed QUESTION names somebody else's query.
                evil = b"\x05other\x07example\x00" + q[-4:]
                self.sock.sendto(head + evil, addr)
            elif self.mode == "badid":
                self.sock.sendto(struct.pack(
                    "!HHHHHH", rid ^ 0xFFFF, 0x8180, 1, 1, 0, 0) + q, addr)
            elif self.mode == "short":
                self.sock.sendto(b"abc", addr)
            elif self.mode == "tc":
                self.sock.sendto(struct.pack(
                    "!HHHHHH", rid, 0x8380, 1, 1, 0, 0) + q, addr)
            elif self.mode == "rcode":      # NXDOMAIN
                self.sock.sendto(struct.pack(
                    "!HHHHHH", rid, 0x8183, 1, 1, 0, 0) + q, addr)
            elif self.mode == "oversize":
                self.sock.sendto(head + q + b"y" * 4096, addr)
            elif self.mode == "garbage":
                self.sock.sendto((SENT_UUID * 2).encode()[:40], addr)

    def close(self):
        for s in (self.sock, self.other):
            try:
                s.close()
            except OSError:
                pass


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def cycle(targets, total=8.0, hold=False, **kw):
    if not hold:
        for slot in np.PROBE_SLOTS:
            try:
                armed = getattr(targets, slot, None) is not None
            except Exception:
                armed = False
            if armed:
                drain(slot)
    return np.run_probe_cycle(targets, total_deadline_seconds=total, **kw)


def egress_spec(port, **kw):
    kw.setdefault("cafile", CERT)
    kw.setdefault("server_hostname", "localhost")
    kw.setdefault("timeout_seconds", 2.0)
    return np.EgressProbeSpec(host="127.0.0.1", port=port, **kw)


def https_spec(port, **kw):
    kw.setdefault("cafile", CERT)
    kw.setdefault("server_hostname", "localhost")
    kw.setdefault("timeout_seconds", 2.0)
    return np.HttpsProbeSpec(host="127.0.0.1", port=port, **kw)


LOG_CAPTURE = []


class LogTaker(logging.Handler):
    def emit(self, record):
        LOG_CAPTURE.append("LOG:%s" % record.getMessage())


def leak_free(result):
    blob = json.dumps(result) + repr(result) + "\n".join(LOG_CAPTURE)
    return all(sent not in blob for sent in SENTINELS) \
        and "Traceback" not in blob


def is_hex32(value):
    return len(value) == 32 \
        and all(c in "0123456789abcdef" for c in value)


def main():
    logging.root.addHandler(LogTaker())
    logging.root.setLevel(logging.DEBUG)

    # ---------------- group A: closed schema / dark default --------------
    created = []
    real_socket = socket.socket
    real_connect = socket.create_connection

    def counting_socket(*a, **k):
        created.append(1)
        return real_socket(*a, **k)

    def counting_connect(*a, **k):
        created.append(1)
        return real_connect(*a, **k)

    socket.socket = counting_socket
    socket.create_connection = counting_connect
    try:
        r = cycle(np.ProbeTargets(), total=4.0)
    finally:
        socket.socket = real_socket
        socket.create_connection = real_connect
    report("A1 default top-level keys exact", set(r) == set(np.RESULT_KEYS))
    for slot in np.PROBE_SLOTS:
        keys = np.EGRESS_KEYS if slot == "egress" else np.PROBE_KEYS
        report("A2 closed slot %s" % slot, slot_shape(r[slot], keys))
    report("A3 default slots all unavailable",
           all(r[s]["error_code"] == "unavailable" for s in np.PROBE_SLOTS))
    report("A4 zero network I/O on dark default", not created, created[:1])
    report("A5 json round-trip identical", json.loads(json.dumps(r)) == r)
    report("A6 error vocabulary frozen to 9",
           np.ERROR_CODES == frozenset({"NONE", "timeout", "dns_failed",
                                        "connect_failed", "tls_failed",
                                        "bad_response", "protocol_failed",
                                        "parse_failed", "unavailable"}))
    cid = uuid.uuid4().hex
    r = cycle(np.ProbeTargets(), total=2.0, cycle_id=cid)
    report("A7 cycle_id honoured", r["cycle_id"] == cid)
    r2 = cycle(np.ProbeTargets(), total=2.0)
    report("A8 auto cycle_id is 32 hex", is_hex32(r2["cycle_id"]))
    report("A9 epoch is float", isinstance(r["epoch"], float))
    report("A10 v constant", r["v"] == 1)
    # A1 additions (R1-A1): the entry point sanitizes its inputs -- no
    # caller free text can ride toward the result schema.
    r = cycle(np.ProbeTargets(), total=2.0,
              cycle_id="%s %s free-text!" % (SENT_UUID, SENT_PASS))
    report("A11 free-text cycle_id replaced, never echoed",
           is_hex32(r["cycle_id"]) and leak_free(r), r["cycle_id"])
    r = cycle(np.ProbeTargets(), total=2.0, cycle_id="a" * 200)
    report("A12 over-long cycle_id replaced", is_hex32(r["cycle_id"]))
    r = cycle(np.ProbeTargets(), total=2.0, cycle_id=42)
    report("A13 non-str cycle_id replaced, no raise",
           is_hex32(r["cycle_id"]))
    r = cycle(np.ProbeTargets(), total=2.0, cycle_id="run-2026.09_a:X-2")
    report("A14 old-grammar safe id is NOW replaced (only 32-hex survives)",
           is_hex32(r["cycle_id"]) and r["cycle_id"] != "run-2026.09_a:X-2",
           r["cycle_id"])

    def mad_clock():
        raise ValueError("%s %s" % (SENT_UUID, SENT_PASS))
    r = cycle(np.ProbeTargets(), total=2.0, clock=mad_clock)
    report("A15 raising clock cannot break entry; epoch float",
           isinstance(r["epoch"], float) and r["epoch"] >= 0.0
           and leak_free(r))
    junk_clocks = (lambda: "%s!" % SENT_UUID, lambda: float("nan"),
                   lambda: None, lambda: -5.0, lambda: float("inf"),
                   lambda: object())
    epochs_ok = True
    leaks = False
    for junk in junk_clocks:
        rr = cycle(np.ProbeTargets(), total=2.0, clock=junk)
        e = rr["epoch"]
        epochs_ok = epochs_ok and isinstance(e, float) \
            and 0.0 <= e < float("inf")
        leaks = leaks or not leak_free(rr)
    report("A16 junk clock values coerced to finite epoch, no leak",
           epochs_ok and not leaks)
    # R2-A5: the ONLY surviving caller id is exact lowercase 32-hex --
    # uppercase and near-miss lengths are engine ids in shape but not in
    # grammar and must be replaced.
    r = cycle(np.ProbeTargets(), total=2.0, cycle_id=cid.upper())
    report("A17 UPPERCASE 32-hex id replaced, not echoed",
           is_hex32(r["cycle_id"]) and r["cycle_id"] != cid.upper(),
           r["cycle_id"])
    near_miss = ("a" * 31, "a" * 33, "abc" * 11, "0" * 32 + "g")
    all_replaced = True
    for nm in near_miss:
        rr = cycle(np.ProbeTargets(), total=2.0, cycle_id=nm)
        if rr["cycle_id"] == nm or not is_hex32(rr["cycle_id"]):
            all_replaced = False
    keep = cycle(np.ProbeTargets(), total=2.0, cycle_id="f" * 32)
    report("A18 wrong-length/non-hex replaced; exact lowercase 32-hex kept",
           all_replaced and keep["cycle_id"] == "f" * 32,
           keep["cycle_id"])

    # ---------------- group B: DNS ----------------------------------------
    fake_answers = [(2, 1, 6, "", (SENT_PRIV, 443))]
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=1.0,
        resolver=lambda *a, **k: fake_answers)), total=4.0)
    report("B1 resolver success -> ok",
           r["dns"]["status"] == "ok" and r["dns"]["error_code"] == "NONE"
           and isinstance(r["dns"]["latency_ms"], int), r["dns"])
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=1.0,
        resolver=lambda *a, **k: [])), total=4.0)
    report("B2 empty answer -> dns_failed",
           r["dns"]["error_code"] == "dns_failed", r["dns"])

    def boom(*a, **k):
        raise socket.gaierror(-2, "nodename nor servname provided: %s %s"
                              % (SENT_UUID, SENT_PASS))
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname=SENT_HOST, timeout_seconds=1.0, resolver=boom)), total=4.0)
    report("B3 gaierror -> dns_failed",
           r["dns"]["error_code"] == "dns_failed", r["dns"])
    report("B4 no resolver sentinel leak", leak_free(r))
    report("B5 resolved IP never in result", SENT_PRIV not in json.dumps(r))

    def slow(*a, **k):
        time.sleep(2.0)
        return fake_answers
    t0 = time.monotonic()
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=0.4, resolver=slow)),
        total=4.0)
    wall = time.monotonic() - t0
    report("B6 slow resolver -> timeout, bounded",
           r["dns"]["error_code"] == "timeout" and wall < 2.5,
           (r["dns"], wall))

    # ---------------- group C: HTTPS --------------------------------------
    port_204 = tls_server("204")
    port_500 = tls_server("500")
    port_junk = tls_server("200-junk")
    port_hang = tls_server("hang")
    r = cycle(np.ProbeTargets(https=https_spec(
        port_204, allowed_statuses=frozenset({204}))), total=6.0)
    report("C1 allowed 204 -> ok", r["https"]["status"] == "ok", r["https"])
    r = cycle(np.ProbeTargets(https=https_spec(port_204)), total=6.0)
    report("C2 204 outside default {200} -> bad_response",
           r["https"]["error_code"] == "bad_response", r["https"])
    r = cycle(np.ProbeTargets(https=https_spec(
        port_500, allowed_statuses=frozenset({204}))), total=6.0)
    report("C3 500 -> bad_response",
           r["https"]["error_code"] == "bad_response", r["https"])
    report("C4 error body bytes never leak", leak_free(r))
    r = cycle(np.ProbeTargets(https=np.HttpsProbeSpec(
        host="127.0.0.1", port=port_204, server_hostname="localhost",
        timeout_seconds=2.0)), total=6.0)
    report("C5 unknown CA -> tls_failed (verification cannot be off)",
           r["https"]["error_code"] == "tls_failed", r["https"])
    r = cycle(np.ProbeTargets(https=https_spec(
        port_204, server_hostname="other.example")), total=6.0)
    report("C6 hostname mismatch -> tls_failed",
           r["https"]["error_code"] == "tls_failed", r["https"])
    dead = free_port()
    r = cycle(np.ProbeTargets(https=https_spec(dead, timeout_seconds=1.5)),
              total=6.0)
    code = r["https"]["error_code"]
    # Linux CI proves the strict RST discriminator; dev machines with a
    # TUN-style local proxy may swallow the SYN instead (timeout):
    report("C7 refused -> connect_failed",
           code == "connect_failed" if IS_LINUX
           else code in ("connect_failed", "timeout"), code)
    t0 = time.monotonic()
    r = cycle(np.ProbeTargets(
        https=https_spec(port_hang, timeout_seconds=1.0),
        dns=np.DnsProbeSpec(hostname="probe.invalid", timeout_seconds=1.0,
                            resolver=lambda *a, **k: fake_answers)),
        total=6.0)
    wall = time.monotonic() - t0
    report("C8 hanging server -> timeout",
           r["https"]["error_code"] == "timeout", r["https"])
    report("C9 hang does not starve other slots",
           r["dns"]["status"] == "ok" and wall < 4.5, wall)
    os.environ["HTTPS_PROXY"] = "http://127.0.0.1:%d" % dead
    os.environ["HTTP_PROXY"] = "http://127.0.0.1:%d" % dead
    try:
        trust_env_sees = "https" in urllib.request.getproxies()
        r = cycle(np.ProbeTargets(https=https_spec(
            port_204, allowed_statuses=frozenset({204}))), total=6.0)
    finally:
        del os.environ["HTTPS_PROXY"]
        del os.environ["HTTP_PROXY"]
    report("C10 proxy env WAS live (trust_env sees it)", trust_env_sees)
    report("C11 probe bypasses proxy env: direct still ok",
           r["https"]["status"] == "ok", r["https"])
    _plain, port_plain = plaintext_sentinel_server()
    r = cycle(np.ProbeTargets(https=https_spec(port_plain)), total=6.0)
    # the exact code on a non-TLS peer is platform-shaped (OpenSSL
    # handshake error vs a reset recv); the CONTRACT is: never ok, always
    # closed, never an echo. Linux CI observably yields tls_failed.
    report("C12 plaintext peer -> closed failure, never ok",
           r["https"]["status"] == "failed"
           and r["https"]["error_code"] in np.ERROR_CODES
           and r["https"]["error_code"] != np.ERR_NONE, r["https"])
    report("C13 handshake echo sentinels never leak", leak_free(r))
    report("C14 failed slot latency is null", r["https"]["latency_ms"] is None)

    # ---------------- group D: UDP -----------------------------------------
    fakes = {m: UdpFake(m) for m in ("reply", "drop", "badid", "short",
                                     "tc", "rcode", "oversize", "garbage",
                                     "stray", "wrongq")}

    def udp_spec(mode, **kw):
        kw.setdefault("timeout_seconds", 1.2)
        return np.UdpProbeSpec(resolver_host="127.0.0.1",
                               resolver_port=fakes[mode].port,
                               query_hostname="probe.example", **kw)

    def udp_run(mode, **kw):
        return cycle(np.ProbeTargets(udp=udp_spec(mode, **kw)), total=6.0)

    r = udp_run("reply")
    report("D1 valid UDP DNS reply -> ok", r["udp"]["status"] == "ok",
           r["udp"])
    t0 = time.monotonic()
    r = udp_run("drop", timeout_seconds=0.8)
    report("D2 ANTI-FALSE-POSITIVE: delivered sendto + silence -> timeout",
           r["udp"]["error_code"] == "timeout"
           and r["udp"]["status"] == "failed", r["udp"])
    report("D3 silence case stayed in budget", time.monotonic() - t0 < 3.5)
    r = udp_run("badid")
    report("D4 id mismatch -> protocol_failed",
           r["udp"]["error_code"] == "protocol_failed", r["udp"])
    r = udp_run("short")
    report("D5 short reply -> protocol_failed (fail closed)",
           r["udp"]["error_code"] == "protocol_failed", r["udp"])
    r = udp_run("garbage")
    report("D6 garbage reply -> protocol_failed",
           r["udp"]["error_code"] == "protocol_failed", r["udp"])
    report("D7 payload sentinel never retained", leak_free(r))
    r = udp_run("tc")
    report("D8 TC=1 -> bad_response (truncation proves nothing)",
           r["udp"]["error_code"] == "bad_response", r["udp"])
    r = udp_run("rcode")
    report("D9 RCODE!=0 -> bad_response",
           r["udp"]["error_code"] == "bad_response", r["udp"])
    r = udp_run("oversize", max_response_bytes=128)
    report("D10 oversized reply -> bad_response",
           r["udp"]["error_code"] == "bad_response", r["udp"])
    rejected = False
    try:
        np.UdpProbeSpec(resolver_host="probe.example",
                        query_hostname="probe.invalid")
    except np.SpecError:
        rejected = True
    report("D11 resolver_host rejects non-numeric names", rejected)
    # R1-A2 discriminators: the reply must come from the CONFIGURED peer
    # AND answer the question WE sent (both byte-valid, both would have
    # scored a false positive on an unconnected recv / header-only check).
    r = udp_run("stray", timeout_seconds=0.8)
    report("D12 ANTI-FALSE-POSITIVE: valid reply from WRONG peer -> timeout",
           r["udp"]["error_code"] == "timeout", r["udp"])
    r = udp_run("wrongq")
    report("D13 ANTI-FALSE-POSITIVE: valid id but foreign question -> "
           "protocol_failed", r["udp"]["error_code"] == "protocol_failed",
           r["udp"])

    # ---------------- group E: egress --------------------------------------
    p_ip = tls_server("200-ip")
    p_v6 = tls_server("200-v6")
    p_priv = tls_server("200-priv")
    p_rfc = tls_server("200-rfc1918")
    p_nonutf = tls_server("200-nonutf8")
    p_over = tls_server("200-oversize")
    p_404 = tls_server("404")
    p_hang2 = tls_server("hang")
    r = cycle(np.ProbeTargets(egress=egress_spec(p_ip)), total=6.0)
    report("E1 global IPv4 answer -> ok + canonical ip",
           r["egress"]["status"] == "ok" and r["egress"]["ip"] == "8.8.8.8",
           r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_v6)), total=6.0)
    report("E2 global IPv6 answer accepted + canonicalized",
           r["egress"]["status"] == "ok"
           and r["egress"]["ip"] == "2606:4700:4700::64", r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(port_junk)), total=6.0)
    report("E3 malformed body -> parse_failed",
           r["egress"]["error_code"] == "parse_failed", r["egress"])
    report("E4 malformed body never echoed", leak_free(r))
    r = cycle(np.ProbeTargets(egress=egress_spec(p_over,
                                                 max_body_bytes=64)),
              total=6.0)
    report("E5 oversized body -> bad_response",
           r["egress"]["error_code"] == "bad_response", r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_nonutf)), total=6.0)
    report("E6 non-UTF8 body -> parse_failed",
           r["egress"]["error_code"] == "parse_failed", r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_priv)), total=6.0)
    report("E7 loopback answer refused unconditionally",
           r["egress"]["error_code"] == "parse_failed"
           and r["egress"]["ip"] is None, r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_rfc)), total=6.0)
    report("E8 private answer refused unconditionally",
           r["egress"]["error_code"] == "parse_failed", r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_404)), total=6.0)
    report("E9 bad status -> bad_response",
           r["egress"]["error_code"] == "bad_response", r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_hang2,
                                                 timeout_seconds=1.0)),
              total=6.0)
    report("E10 hanging endpoint -> timeout, ip null",
           r["egress"]["error_code"] == "timeout"
           and r["egress"]["ip"] is None, r["egress"])
    r = cycle(np.ProbeTargets(egress=egress_spec(p_ip)), total=6.0)
    report("E11 healthy slot shape exact",
           slot_shape(r["egress"], np.EGRESS_KEYS)
           and isinstance(r["egress"]["latency_ms"], int))
    r = cycle(np.ProbeTargets(egress=egress_spec(
        p_ip, allowed_statuses=frozenset({204}))), total=6.0)
    report("E12 contract mismatch is bad_response not parse_failed",
           r["egress"]["error_code"] == "bad_response", r["egress"])
    # R2-A7: the escape hatch itself must be GONE -- a caller can no
    # longer ask the engine to accept a non-global answer.
    hatch_rejected = False
    try:
        np.EgressProbeSpec(host="127.0.0.1", port=1, require_global=False)
    except TypeError:
        hatch_rejected = True
    report("E13 require_global escape hatch REMOVED (kwarg rejected)",
           hatch_rejected)
    non_global_ok = True
    for local in ("127.0.0.2", "10.11.12.13", "192.168.1.1", "100.64.0.1",
                  "fc00::1", "2001:db8::1", "::1"):
        if np._parse_egress_answer(local.encode())[1] != "parse_failed":
            non_global_ok = False
    report("E14 every non-global class rejected at the parse gate",
           non_global_ok)

    # ---------------- group F: egress-change pure judgement ----------------
    # R2-A7: NON-GLOBAL samples are unknown-terrors on BOTH sides --
    # private/doc-range/loopback/shared addresses can never produce a
    # changed/unchanged verdict, however well-formed they look.
    F = (("8.8.8.8", "8.8.4.4", "changed"),
         ("8.8.8.8", "8.8.8.8", "unchanged"),
         ("2606:4700:4700::64", "2606:4700:4700:0:0:0:0:64", "unchanged"),
         (None, "8.8.8.8", "unknown"),
         ("8.8.8.8", None, "unknown"),
         (None, None, "unknown"),
         ("garbage", "8.8.8.8", "unknown"),
         ("8.8.8.8", "garbage", "unknown"),
         ("", "", "unknown"),
         ("10.11.12.13", "10.11.12.14", "unknown"),
         ("8.8.8.8", "10.0.0.1", "unknown"),
         ("127.0.0.1", "127.0.0.2", "unknown"),
         ("100.64.0.1", "100.64.0.2", "unknown"),
         ("2001:db8::1", "2001:db8::2", "unknown"))
    for i, (a, b, want) in enumerate(F):
        report("F%d classify(%s,%s)=%s" % (i + 1, a or "None", b or "None",
                                           want),
               np.classify_egress_change(a, b) == want)
    report("F15 pure: repeated calls stable",
           np.classify_egress_change("8.8.8.8", "8.8.4.4") == "changed")

    # ---------------- group G: privacy sentinels ----------------------------
    # one combined adversarial cycle: every free-text surface is planted.
    def boom_gai(*a, **k):
        raise socket.gaierror(-2, "%s %s %s %s" % (SENT_UUID, SENT_PASS,
                                                   SENT_PRIV, SENT_HOST))
    targets = np.ProbeTargets(
        dns=np.DnsProbeSpec(hostname=SENT_HOST, timeout_seconds=0.5,
                            resolver=boom_gai),
        https=https_spec(port_junk),
        egress=egress_spec(p_404),
        udp=udp_spec("garbage", timeout_seconds=0.5))
    r = cycle(targets, total=6.0)
    blob = json.dumps(r) + repr(r) + "\n".join(LOG_CAPTURE)
    for i, sent in enumerate(SENTINELS):
        report("G%d sentinel(%s) absent everywhere" % (i + 1, chr(97 + i)),
               sent not in blob)
    report("G5 no traceback / exception text",
           "Traceback" not in blob and "gaierror" not in blob)
    report("G6 result stayed closed under attack",
           set(r) == set(np.RESULT_KEYS)
           and all(slot_shape(r[s], np.EGRESS_KEYS if s == "egress"
                              else np.PROBE_KEYS) for s in np.PROBE_SLOTS))
    for fake in fakes.values():
        fake.close()

    # ---------------- group H: engine containment ---------------------------
    class JunkTargets:
        dns = "not-a-spec"
        https = 42
        udp = object()
        egress = ["nope"]
    r = cycle(JunkTargets(), total=3.0)
    report("H1 junk specs never raise: closed failures",
           all(r[s]["status"] == "failed"
               and r[s]["error_code"] in np.ERROR_CODES
               for s in np.PROBE_SLOTS), r)
    r = cycle(np.ProbeTargets(https=https_spec(port_hang,
                                               timeout_seconds=3.0)),
              total=0.5)
    report("H2 tiny total deadline wins over spec budget",
           r["https"]["error_code"] == "timeout", r["https"])
    base = threading.active_count()
    for _ in range(3):
        cycle(np.ProbeTargets(https=https_spec(port_hang,
                                               timeout_seconds=1.0)),
              total=3.0)
    time.sleep(1.5)
    report("H3 abandoned workers stay bounded",
           threading.active_count() <= base + 8,
           (base, threading.active_count()))
    n = np._normalize_probe({"status": "ok", "latency_ms": 5,
                             "error_code": "totally-free-text-exception"})
    report("H4 out-of-vocabulary code coerced",
           n["error_code"] == "unavailable" and n["status"] == "failed", n)
    n = np._normalize_probe("not a slot")
    report("H5 non-dict slot coerced", n["error_code"] == "unavailable")
    n = np._normalize_egress({"status": "ok", "latency_ms": 5,
                              "error_code": "NONE", "ip": "<script>"})
    report("H6 non-IP 'ok' egress degrades to parse_failed",
           n["status"] == "failed" and n["error_code"] == "parse_failed"
           and n["ip"] is None, n)
    r = cycle(np.ProbeTargets(), total="not-a-number")
    report("H7 invalid total deadline coerced, no raise",
           set(r) == set(np.RESULT_KEYS))
    a = cycle(np.ProbeTargets(), total=2.0)
    b = cycle(np.ProbeTargets(), total=2.0)
    report("H8 cycle ids unique", a["cycle_id"] != b["cycle_id"])
    # R1-A3 discriminators: absolute per-worker deadlines judge EVERY
    # outcome by its recorded completion timestamp -- late is late,
    # whether the worker was about to report success or failure.
    def late_boom(*a, **k):
        time.sleep(1.2)
        raise socket.gaierror(-2, "late failure")
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=0.5,
        resolver=late_boom)), total=4.0)
    report("H9 LATE failure rejected: absolute deadline wins (timeout, "
           "not dns_failed)", r["dns"]["error_code"] == "timeout", r["dns"])

    def late_ok(*a, **k):
        time.sleep(2.4)
        return fake_answers
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=2.5,
        resolver=late_ok)), total=2.0)
    report("H10 late ok beyond the CYCLE deadline rejected as timeout",
           r["dns"]["error_code"] == "timeout"
           and r["dns"]["status"] == "failed", r["dns"])

    def mid_ok(*a, **k):
        time.sleep(1.8)
        return fake_answers
    t0 = time.monotonic()
    r = cycle(np.ProbeTargets(
        https=https_spec(port_hang, timeout_seconds=2.0),
        dns=np.DnsProbeSpec(hostname="probe.invalid", timeout_seconds=2.0,
                            resolver=mid_ok)), total=2.2)
    wall = time.monotonic() - t0
    report("H11 absolute deadlines: a hung slot cannot starve a healthy "
           "one past its own budget",
           r["https"]["error_code"] == "timeout"
           and r["dns"]["status"] == "ok" and wall < 3.5, (r["https"],
                                                           r["dns"], wall))
    # R2-A7 defence-in-depth: even a hypothetically buggy worker that
    # hands the normalize gate a NON-GLOBAL "ok" ip is overwritten --
    # the gate re-enforces globality, it does not trust the parse path.
    n = np._normalize_egress({"status": "ok", "latency_ms": 5,
                              "error_code": "NONE", "ip": "10.11.12.13"})
    report("H12 ok egress with private ip degrades at the final gate",
           n["status"] == "failed" and n["error_code"] == "parse_failed"
           and n["ip"] is None, n)
    n = np._normalize_egress({"status": "ok", "latency_ms": 5,
                              "error_code": "NONE", "ip": "8.8.8.8"})
    report("H13 ok egress with global ip survives the final gate",
           n["status"] == "ok" and n["ip"] == "8.8.8.8", n)

    # ---------------- group I: no cross-cycle worker accumulation (R1-A4) --
    hang_gate = threading.Event()

    def forever(*a, **k):
        hang_gate.wait(8.0)
        return fake_answers

    hang_spec = np.DnsProbeSpec(hostname="probe.invalid",
                                timeout_seconds=0.4, resolver=forever)
    hang_targets = np.ProbeTargets(dns=hang_spec)
    base_dns = worker_threads("probe-dns")
    r1 = cycle(hang_targets, total=4.0)
    report("I1 hanging worker is abandoned as timeout",
           r1["dns"]["error_code"] == "timeout", r1["dns"])
    codes = []
    walls = []
    for _ in range(3):
        t0 = time.monotonic()
        r = cycle(hang_targets, total=4.0, hold=True)
        walls.append(time.monotonic() - t0)
        codes.append(r["dns"]["error_code"])
    report("I2 the hung worker HOLDS its slot: later cycles are "
           "unavailable, not new probes", codes == ["unavailable"] * 3,
           codes)
    report("I3 occupied slot answers instantly (no per-cycle hang cost)",
           all(w < 0.5 for w in walls), walls)
    report("I4 exactly ONE hung worker exists after four cycles",
           worker_threads("probe-dns") - base_dns == 1,
           (base_dns, worker_threads("probe-dns")))
    hang_gate.set()
    freed = drain("dns", budget=10.0)
    r = cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=1.0,
        resolver=lambda *a, **k: fake_answers)), total=4.0)
    report("I5 slot recovers for later cycles once the worker dies",
           freed and r["dns"]["status"] == "ok",
           (freed, r["dns"]))

    # ---------------- group J: concurrent cycles cannot double-claim (R2-A6)
    # Reservation AND start must be ONE atomic critical section: with the
    # old check-under-lock / start-outside-lock split, a concurrent
    # cycle could observe the registered-but-NOT-YET-STARTED thread
    # (is_alive() False) and claim the same slot a second time. A
    # start-delaying Thread subclass widens that window into a CERTAIN
    # trip, so this discriminator is deterministic, not luck-based.
    real_thread_cls = threading.Thread
    j_hang = threading.Event()

    class SlowStartThread(real_thread_cls):
        def start(self, *a, **k):
            time.sleep(0.5)
            real_thread_cls.start(self, *a, **k)

    def forever_j(*a, **k):
        j_hang.wait(30.0)
        return fake_answers

    j_targets = np.ProbeTargets(dns=np.DnsProbeSpec(
        hostname="probe.invalid", timeout_seconds=0.4, resolver=forever_j))
    j_results = []
    j_barrier = threading.Barrier(2)

    def contender():
        j_barrier.wait(10.0)
        try:
            j_results.append(np.run_probe_cycle(
                j_targets, total_deadline_seconds=4.0))
        except Exception as exc:  # noqa: BLE001 -- reported, never swallowed
            j_results.append({"dns": {"error_code": "CRASH:%s" % exc}})

    np.threading.Thread = SlowStartThread
    try:
        base_j = worker_threads("probe-dns")
        racers = [real_thread_cls(target=contender) for _ in range(2)]
        for racer in racers:
            racer.start()
        for racer in racers:
            racer.join(20.0)
        codes = sorted(res["dns"]["error_code"] for res in j_results)
        report("J1 concurrent cycles: outcomes are exactly "
               "timeout + unavailable (never two probes, never a crash)",
               len(j_results) == 2 and codes == ["timeout", "unavailable"],
               codes)
        report("J2 concurrent cycles: exactly ONE worker was spawned",
               worker_threads("probe-dns") - base_j == 1,
               (base_j, worker_threads("probe-dns")))
    finally:
        np.threading.Thread = real_thread_cls
        j_hang.set()
    report("J3 slot releases and works again after the concurrent storm",
           drain("dns", budget=35.0)
           and cycle(np.ProbeTargets(dns=np.DnsProbeSpec(
               hostname="probe.invalid", timeout_seconds=1.0,
               resolver=lambda *a, **k: fake_answers)),
               total=4.0)["dns"]["status"] == "ok")


if __name__ == "__main__":
    main()
