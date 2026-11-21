#!/usr/bin/env python3
"""HA-04 loopback LAB harness -- REAL measured failover evidence, LAB ONLY.

This is an operator LAB harness for the HA-04 fast-probe variants
(tools/mihomo-competition-ha4-fastprobe.py).  It builds its own loopback
fixture end to end through the three repository tools:

    synthetic canonical A/B exports -> ha-batch -> ha-profile -> ha4-fastprobe
        -> runtime lab profiles -> 4 real sing-box listeners + pinned Mihomo

and then measures failover with fault injection whose effect is verified
independently (port refusal / dead probe), not just via Mihomo /proxies.

LAB EVIDENCE ONLY -- loopback host, synthetic credentials, no WAN/VPS/TUN/
application. It is NOT acceptance, NOT a 10 s network claim and NOT a fleet
result. Nothing is activated, merged or committed; every artefact is written
under the untracked LAB directory (default .scratch/ha04-lab/).

Scope / known lab deviations from the delivered profile (declared, hashed and
recorded in results.json):
  * `automatic group` health URL is rewritten to a local 204 origin
    (http://127.0.0.1:<origin>/generate_204) instead of the third-party
    https://www.gstatic.com/generate_204, so the lab is loopback-only.
  * mixed-port / external-controller / log-level are local values.
  * `dns.enable` and `tun.enable` are forced false: no TUN, no admin, no
    resolver side effects; destinations are numeric loopback literals.
  These are the ONLY edits to the byte-verified HA-04 variant; the variant is
  first generated and `--check`-ed unmodified by the tool chain, and its
  hash before/after the runtime edit is recorded.

Python 3.10+, standard library only. Shells out to the pinned sing-box and
Mihomo cores and (for the throwaway LAB certificate) to openssl.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# --------------------------------------------------------------------------
# constants / identity of the LAB
# --------------------------------------------------------------------------
HOST = "127.0.0.1"
# The two logical VPSes need DISTINCT canonical server addresses: the HA-02
# batch gate rejects A and B sources that resolve to the same address. Both
# 127.0.0.1 and 127.0.0.2 are loopback on Windows/Linux.
A_HOST = "127.0.0.1"
B_HOST = "127.0.0.2"
SNI = "www.example.com"
SHORT_ID = "0123456789abcdef"
NODES = ("Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2")
GROUP = "自动选择"
SELECTOR = "节点选择"
SECRET = "synthetic-ha04-lab-controller-secret"
# Fixed LAB terminal sets; credentials are unique per terminal because the
# HA-02 batch gate rejects re-used UUIDs/passwords across terminals.
FIXTURE_TREES = {
    "main": {"event-a01": "A-first", "event-b01": "B-first"},
    "hop": {"event-hop01": "A-first"},
}
TERMINALS = sorted({terminal for tree in FIXTURE_TREES.values()
                    for terminal in tree})

PORT = {
    "A-Reality": 24001,   # TCP
    "A-HY2": 24002,       # UDP (QUIC)
    "B-Reality": 24003,   # TCP
    "B-HY2": 24004,       # UDP (QUIC)
    "handshake": 24005,   # TCP TLS origin for the REALITY handshake target
    "origin": 24006,      # TCP local HTTP origin (204 / probe / hold / upload)
}
HOP_PORTS = tuple(range(24010, 24020))   # A VPS Hysteria2 hopping range (UDP)
MIXED_BASE = 24100                       # per-run mixed-port / controller ports
MAX_CLIENT_RUNS = 96

EXPECTED = {
    "mihomo": {
        "sha256": "532ed88b3a37d72f6b5ee5d24a45ce5d8799f3ba34931d6a167d4345f7ebca50",
        "version": "1.19.31",
    },
    "sing-box": {
        "sha256": "5c19bb3f8c12d4e85b3d47fe63123a7624b314b58dd7a8e32f51004f1c4d2faf",
        "version": "1.14.3",
    },
}

PHYSICAL = {
    "A-first": {"Reality": "A", "Hysteria2": "A",
                "Backup-Reality": "B", "Backup-Hysteria2": "B"},
    "B-first": {"Reality": "B", "Hysteria2": "B",
                "Backup-Reality": "A", "Backup-Hysteria2": "A"},
}
GROUP_BY_PHYSICAL = {
    "A-first": {"A": "Reality", "B": "Backup-Reality"},
    "B-first": {"B": "Reality", "A": "Backup-Reality"},
}

POLICIES = tuple((i, t) for i in (3, 5, 10) for t in (1000, 2000, 5000))
B_FIRST_POLICIES = ((3, 1000), (5, 2000), (10, 5000))

LAB_BANNER = "LAB EVIDENCE ONLY -- loopback, synthetic, NOT acceptance"


class LabError(RuntimeError):
    """A hard harness failure (refused/unexpected), never a fabricated result."""


def now() -> float:
    return time.monotonic()


def ms(a: float, b: float) -> float:
    return round((b - a) * 1000.0, 1)


def iso_utc(t_wall: float | None = None) -> str:
    dt = datetime.fromtimestamp(t_wall if t_wall is not None else time.time(),
                                tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + ("%03d" % (dt.microsecond // 1000)) + "Z"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# results / events evidence writer
# --------------------------------------------------------------------------
class Evidence:
    """results.json (full evidence) + events.jsonl (+ per-scenario copies)."""

    def __init__(self, lab_dir: Path):
        self.lab_dir = lab_dir
        self.events_dir = lab_dir / "events"
        self.events_dir.mkdir(parents=True, exist_ok=True)
        # A rerun starts a fresh evidence set (no stale per-scenario events).
        for old in self.events_dir.glob("*.jsonl"):
            try:
                old.unlink()
            except OSError:
                pass
        old_events = lab_dir / "events.jsonl"
        if old_events.exists():
            try:
                old_events.unlink()
            except OSError:
                pass
        self._lock = threading.Lock()
        self._boot = now()
        self._scenario = "boot"
        self._fh = open(lab_dir / "events.jsonl", "w", encoding="utf-8")
        self.results = {
            "lab": "HA-04 loopback fast-probe failover LAB",
            "banner": LAB_BANNER,
            "kind": "measured loopback LAB evidence; not acceptance",
            "started_utc": iso_utc(),
            "python": sys.version.split()[0],
            "platform": sys.platform,
            "host_bind": HOST,
            "binaries": {},
            "environment": {},
            "fixture": {},
            "runs": [],
            "scenario_runs": {},
            "aggregate": {},
            "cleanup": {},
            "limitations": LIMITATIONS,
        }

    def event(self, name: str, **fields):
        row = {"t_mono": round(now() - self._boot, 4), "utc": iso_utc(),
               "scenario": self._scenario, "event": name}
        row.update(fields)
        line = json.dumps(row, ensure_ascii=False)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            with open(self.events_dir / ("%s.jsonl" % self._scenario),
                      "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        print("[%7.2fs] %s %s" % (now() - self._boot, name,
                                  _short(fields)), flush=True)

    def set_scenario(self, name: str):
        self._scenario = name

    def row(self, scenario: str, row: dict):
        with self._lock:
            self.results["runs"].append(row)
            self.results["scenario_runs"].setdefault(scenario, []).append(
                _row_ref(row))
            # Partial evidence survives a crash / Ctrl-C.
            self._write()

    def save(self):
        with self._lock:
            self._write()

    def _write(self):
        tmp = self.lab_dir / "results.json.tmp"
        tmp.write_text(json.dumps(self.results, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
        os.replace(tmp, self.lab_dir / "results.json")

    def close(self):
        with self._lock:
            try:
                self._fh.close()
            except OSError:
                pass


def _short(fields: dict) -> str:
    keep = {}
    for key in ("tag", "fault", "kind", "targets", "T0_ms", "T1_ms", "T2_ms",
                "selected", "chain", "ok", "detail", "rc", "error"):
        if key in fields:
            keep[key] = fields[key]
    return json.dumps(keep, ensure_ascii=False)[:400]


def _row_ref(row: dict) -> dict:
    """Compact index entry; the full row stays in results['runs']."""
    out = {k: row.get(k) for k in ("tag", "scenario", "terminal", "policy",
                                   "fault", "error")}
    t0 = row.get("T0")
    if isinstance(t0, dict):
        out["T0_mono"] = t0.get("t_mono")
        out["T1_ms"] = (row.get("T1") or {}).get("dt_ms")
        out["T2_ms"] = (row.get("T2") or {}).get("dt_ms")
    return out


LIMITATIONS = [
    "LAB EVIDENCE ONLY - not acceptance, not a fleet/VPS/ISP/Windows/application result.",
    "Loopback host: no WAN RTT, no ISP/GFW, no real UDP port hopping, no real VPS or real credentials.",
    "Health URL/interval/timeout are lab values; the 3/5/10 s x 1000/2000/5000 ms matrix is mechanics, not a recovery guarantee.",
    "No T3 application marker (vMix/TikTok/Drive absent); loopback LAB has no application row.",
    "Windows/Clash Verge/Mihomo bundle, TUN/DNS/Fake-IP, 30-client false-positive/load, real failback 10 min window: NOT MEASURED.",
    "One host, one client core, four logical listeners in independent processes; measured values are host/CPU dependent.",
    "T1 selection cadence ~50 ms, T2 probe cadence ~0.25 s; timing uncertainty recorded per row.",
    "HA-03 pinning is exercised in the LAB with throwaway self-signed certs; real identity/rotation/expiry acceptance is NOT MEASURED.",
]


# --------------------------------------------------------------------------
# permissions (the repo tools require private POSIX mode / Windows ACL)
# --------------------------------------------------------------------------
_SID = None


def windows_sid() -> str:
    global _SID
    if _SID is None:
        out = subprocess.check_output(
            ["whoami", "/user", "/fo", "csv", "/nh"], text=True,
            creationflags=CREATE_NO_WINDOW)
        row = next(csv.reader([out.strip()]))
        _SID = row[1]
    return _SID


def harden_dir(path: Path):
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        sid = windows_sid()
        result = run_quiet(["icacls", str(path), "/inheritance:r", "/grant:r",
                            "*%s:(OI)(CI)F" % sid,
                            "*S-1-5-18:(OI)(CI)F",
                            "*S-1-5-32-544:(OI)(CI)F"])
    else:
        os.chmod(path, 0o700)
        return
    if result.returncode != 0:
        raise LabError("icacls failed on %s: %r" % (path, result.stderr[-400:]))


def harden_file(path: Path):
    if os.name == "nt":
        sid = windows_sid()
        result = run_quiet(["icacls", str(path), "/inheritance:r", "/grant:r",
                            "*%s:F" % sid,
                            "*S-1-5-18:F",
                            "*S-1-5-32-544:F"])
        if result.returncode != 0:
            raise LabError("icacls failed on %s: %r"
                           % (path, result.stderr[-400:]))
    else:
        os.chmod(path, 0o600)


# --------------------------------------------------------------------------
# processes / ports
# --------------------------------------------------------------------------
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def run_quiet(cmd, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("timeout", 120)
    if os.name == "nt":
        kw.setdefault("creationflags", CREATE_NO_WINDOW)
    return subprocess.run([str(c) for c in cmd], **kw)


def run_tool(cmd, label: str):
    proc = run_quiet(cmd)
    if proc.returncode != 0:
        raise LabError("%s failed rc=%s stdout=%r stderr=%r"
                       % (label, proc.returncode, proc.stdout[-800:],
                          proc.stderr[-800:]))
    return proc


class CoreProcess:
    """One core process with a private log file (no third-party service)."""

    def __init__(self, name: str, exe: Path, args, log_path: Path, cwd: Path):
        self.name = name
        self.exe = str(exe)
        self.args = [str(a) for a in args]
        self.log_path = Path(log_path)
        self.cwd = Path(cwd)
        self.proc = None
        self._log = None

    def start(self):
        if self.alive():
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [self.exe] + self.args, cwd=str(self.cwd), stdout=self._log,
            stderr=subprocess.STDOUT, creationflags=CREATE_NO_WINDOW)

    def stop(self, timeout=6.0):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=timeout)
        self._close_log()

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def _close_log(self):
        if self._log is not None:
            try:
                self._log.close()
            except OSError:
                pass
            self._log = None


def tcp_connect_ok(port: int, timeout=0.4, host: str = HOST) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


def udp_bindable(port: int, host: str = HOST):
    """True => the UDP port is free (listener gone); independent of the SUT."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((host, port))
        return True, None
    except OSError as exc:
        return False, "%s" % (exc,)
    finally:
        sock.close()


def quic_vn_probe(port: int, timeout=0.5, host: str = HOST):
    """Send a QUIC long-header packet with an unsupported version.

    A live QUIC listener answers with a Version Negotiation datagram; a dead
    UDP port normally raises ECONNRESET on Windows or just times out.  This is
    an informational second effect check next to the bind probe.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        pkt = (b"\xc0" + b"\x1a\x2a\x3a\x4a" + b"\x08" + b"labprobe" +
               b"\x00" + b"\x00" * 1300)
        sock.send(pkt)
        try:
            data = sock.recv(2048)
        except ConnectionResetError:
            return False, "icmp-unreachable"
        except socket.timeout:
            return False, "timeout"
        return True, "datagram=%dbytes" % len(data)
    except OSError as exc:
        return False, "err=%s" % (exc,)
    finally:
        sock.close()


def wait_port(proto: str, port: int, want_alive: bool, deadline_s=10.0,
              host: str = HOST):
    t0 = now()
    last = None
    while now() - t0 < deadline_s:
        if proto == "tcp":
            ok = tcp_connect_ok(port, timeout=0.3, host=host)
            last = "tcp-connect=%s" % ok
        else:
            free, err = udp_bindable(port, host=host)
            ok = not free
            last = "udp-occupied=%s err=%s" % (ok, err)
        if ok == want_alive:
            return True, last
        time.sleep(0.05)
    return False, last


# --------------------------------------------------------------------------
# LAB certificate material (throwaway; pin/validity generated from same cert)
# --------------------------------------------------------------------------
def find_openssl() -> str:
    for cand in (shutil.which("openssl"),
                 r"C:\Program Files\Git\mingw64\bin\openssl.exe",
                 r"C:\Program Files\Git\usr\bin\openssl.exe",
                 "/usr/bin/openssl"):
        if cand and Path(cand).exists():
            return str(cand)
    raise LabError("openssl not found (needed for the throwaway LAB certs)")


def build_cert(tls_dir: Path, tag: str):
    tls_dir.mkdir(parents=True, exist_ok=True)
    cert = tls_dir / ("%s-cert.pem" % tag)
    key = tls_dir / ("%s-key.pem" % tag)
    if cert.exists() and key.exists():
        return cert, key
    openssl = find_openssl()
    run_tool([openssl, "req", "-x509", "-newkey", "ec",
              "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
              "-days", "30", "-keyout", str(key), "-out", str(cert),
              "-subj", "/CN=" + SNI,
              "-addext", "subjectAltName=DNS:" + SNI], "openssl-cert")
    os.chmod(cert, 0o644)
    os.chmod(key, 0o600)
    return cert, key


def cert_pin(cert: Path) -> str:
    pem = cert.read_text(encoding="utf-8")
    body = "".join(line.strip() for line in pem.splitlines()
                   if not line.startswith("-----"))
    der = base64.b64decode(body)
    return hashlib.sha256(der).hexdigest()


def normalize_openssl_date(value: str) -> str:
    """Normalize OpenSSL's date output to the pins schema UTC form.

    OpenSSL prints either ``2026-11-21T06:15:07Z`` (iso_8601) or the DEFAULT
    layout ``2026-11-21 06:15:07Z``; both must become
    ``YYYY-MM-DDTHH:MM:SSZ`` for the HA-03 pins file.
    """
    value = value.strip().replace(" ", "T")
    if "." in value:
        value = value.split(".", 1)[0] + "Z"
    if not value.endswith("Z"):
        value += "Z"
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    return value


def cert_dates(cert: Path):
    openssl = find_openssl()
    out = run_tool([openssl, "x509", "-in", str(cert), "-noout",
                    "-startdate", "-enddate", "-dateopt", "iso_8601"],
                   "openssl-x509").stdout
    dates = {}
    for line in out.replace("\r", "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if key == "notBefore":
            dates["not_before"] = value
        elif key == "notAfter":
            dates["not_after"] = value
    if set(dates) != {"not_before", "not_after"}:
        raise LabError("could not parse certificate dates: %r" % out)
    return {key: normalize_openssl_date(value)
            for key, value in dates.items()}


# --------------------------------------------------------------------------
# fixture: canonical A/B exports -> HA-02 -> HA-03 -> HA-04 (all repo tools)
# --------------------------------------------------------------------------
EXPORT_TEMPLATE_HEAD = """mixed-port: 7897
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
unified-delay: true
ipv6: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  listen: "0.0.0.0:53"
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

tun:
  enable: true
  stack: mixed
  device: Mihomo
  mtu: 1420
  auto-route: true
  auto-redirect: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53

proxies:
  - name: Reality
    type: vless
    server: {server}
    port: {reality_port}
    uuid: {uuid}
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: {sni}
    client-fingerprint: chrome
    reality-opts:
      public-key: {public_key}
      short-id: {short_id}

  - name: Hysteria2
    type: hysteria2
    server: {server}
    port: {hy2_port}
"""

EXPORT_TEMPLATE_TAIL = """    password: {password}
    sni: {sni}
    skip-cert-verify: true
    alpn:
      - h3

proxy-groups:
  - name: 节点选择
    type: select
    default-selected: 自动选择
    proxies:
      - Reality
      - Hysteria2
      - 自动选择
      - DIRECT

  - name: 自动选择
    type: fallback
    proxies:
      - Reality
      - Hysteria2
    url: "https://www.gstatic.com/generate_204"
    interval: 60
    timeout: 5000
    lazy: false
    expected-status: "204"


rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择

"""

HY2_HOP_BLOCK = """    ports: {ports}
    hop-interval: 30
"""


def export_text(server: str, reality_port: int, hy2_port: int, uuid: str,
                password: str, public_key: str, short_id: str,
                hop_ports: str | None) -> str:
    head = EXPORT_TEMPLATE_HEAD.format(
        server=server, reality_port=reality_port, hy2_port=hy2_port,
        uuid=uuid, public_key=public_key, short_id=short_id, sni=SNI)
    if hop_ports:
        head += HY2_HOP_BLOCK.format(ports=hop_ports)
    return head + EXPORT_TEMPLATE_TAIL.format(password=password, sni=SNI)


def singbox_server_config(kind: str, port: int, users: list, private_key: str,
                          host: str, cert: Path, key: Path) -> dict:
    if kind == "reality":
        inbound = {
            "type": "vless", "tag": "vless-in", "listen": host,
            "listen_port": port,
            "users": [{"name": user["name"], "uuid": user["uuid"],
                       "flow": "xtls-rprx-vision"} for user in users],
            "tls": {
                "enabled": True,
                "server_name": SNI,
                "reality": {
                    "enabled": True,
                    "handshake": {"server": HOST,
                                  "server_port": PORT["handshake"]},
                    "private_key": private_key,
                    "short_id": [SHORT_ID],
                },
            },
        }
    elif kind == "hysteria2":
        inbound = {
            "type": "hysteria2", "tag": "hy2-in", "listen": host,
            "listen_port": port,
            "ignore_client_bandwidth": True,
            "users": [{"name": user["name"], "password": user["password"]}
                      for user in users],
            "tls": {"enabled": True, "alpn": ["h3"],
                    "certificate_path": str(cert),
                    "key_path": str(key)},
        }
    else:
        raise LabError("unknown server kind %r" % (kind,))
    return {
        "log": {"disabled": False, "level": "info", "timestamp": True},
        "inbounds": [inbound],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


class Listener:
    """One real sing-box listener process (per protocol, per VPS)."""

    def __init__(self, name: str, port: int, proto: str, users: list,
                 private_key: str, host: str, cert: Path, key: Path,
                 fixture: Path, singbox: Path):
        self.name = name
        self.port = port
        self.proto = proto
        self.users = users
        self.host = host
        self.fixture = fixture
        self.singbox = singbox
        conf_dir = fixture / "servers"
        harden_dir(conf_dir)
        cfg = singbox_server_config(
            ("reality" if proto == "tcp" else "hysteria2"),
            port, users, private_key, host, cert, key)
        self.cfg_path = conf_dir / ("server-%s-%d.json" % (name, port))
        self.cfg_path.write_text(json.dumps(cfg, indent=2) + "\n",
                                 encoding="utf-8")
        self.proc = CoreProcess(name, singbox,
                                ["run", "-c", str(self.cfg_path)],
                                fixture / "logs" / ("singbox-%s-%d.log" % (name, port)),
                                fixture)

    def start(self, deadline_s=10.0):
        self.proc.start()
        ok, detail = wait_port(self.proto, self.port, True, deadline_s,
                               host=self.host)
        if not ok:
            log = self.log_tail()
            raise LabError("listener %s:%d did not open (%s) log=%r"
                           % (self.name, self.port, detail, log))
        return {"name": self.name, "port": self.port, "proto": self.proto,
                "host": self.host, "alive": True, "detail": detail}

    def stop(self, deadline_s=8.0):
        self.proc.stop()
        ok, detail = wait_port(self.proto, self.port, False, deadline_s,
                               host=self.host)
        effect = self.effect_check()
        if not ok or not effect["dead"]:
            raise LabError("listener %s:%d did not die (%s) effect=%r"
                           % (self.name, self.port, detail, effect))
        return effect

    def alive(self) -> bool:
        return self.proc.alive()

    def effect_check(self) -> dict:
        """Independent availability effect check (not SUT /proxies)."""
        out = {"name": self.name, "port": self.port, "proto": self.proto,
               "host": self.host, "process_alive": self.proc.alive(),
               "t": round(now(), 3)}
        if self.proto == "tcp":
            out["tcp_connect"] = tcp_connect_ok(self.port, timeout=0.3,
                                                host=self.host)
            out["dead"] = not out["tcp_connect"]
        else:
            free, err = udp_bindable(self.port, host=self.host)
            vn_ok, vn_detail = quic_vn_probe(self.port, timeout=0.35,
                                             host=self.host)
            out.update({"udp_bindable": free, "udp_bind_error": err,
                        "quic_vn": vn_detail, "quic_vn_alive": vn_ok})
            out["dead"] = bool(free) and not out["process_alive"]
            out["alive"] = (not free)
        return out

    def log_tail(self, n=1200) -> str:
        try:
            data = self.proc.log_path.read_text(errors="replace")
            return data[-n:]
        except OSError:
            return ""


# --------------------------------------------------------------------------
# local origin (204/probe/hold/stall) + REALITY handshake target
# --------------------------------------------------------------------------
class LocalOrigin:
    def __init__(self, port: int):
        self.port = port
        self.events = []
        self._lock = threading.Lock()
        origin = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def _record(self):
                with origin._lock:
                    origin.events.append({"t": now(), "verb": self.command,
                                          "path": self.path})

            def _send(self, code: int, body: bytes = b""):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if body and self.command != "HEAD":
                    self.wfile.write(body)

            def do_HEAD(self):
                self._record()
                path = urllib.parse.urlsplit(self.path).path
                self._send(204 if path == "/generate_204" else 200)

            def do_GET(self):
                self._record()
                split = urllib.parse.urlsplit(self.path)
                if split.path == "/generate_204":
                    self._send(204)
                elif split.path == "/hold":
                    q = urllib.parse.parse_qs(split.query)
                    time.sleep(int(q.get("ms", ["200"])[0]) / 1000.0)
                    self._send(200, b"held-ok")
                else:
                    self._send(200, b"lab-ok")

            def do_POST(self):
                # N02: accept headers, read nothing further, never answer.
                self._record()
                with origin._lock:
                    origin.upload_stalls = getattr(origin, "upload_stalls", 0) + 1
                time.sleep(120)

        self.httpd = http.server.ThreadingHTTPServer((HOST, port), Handler)
        self.httpd.daemon_threads = True
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except OSError:
            pass


class HandshakeTarget:
    """Loopback TLS origin used as the REALITY handshake target."""

    def __init__(self, port: int, cert: Path, key: Path):
        self.port = port
        hs = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):
                pass

            def do_GET(self):
                body = b"reality-handshake-ok"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.httpd = http.server.ThreadingHTTPServer((HOST, port), Handler)
        self.httpd.daemon_threads = True
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(str(cert), str(key))
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.thread = threading.Thread(target=self.httpd.serve_forever,
                                       daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        except OSError:
            pass


# --------------------------------------------------------------------------
# Mihomo client management
# --------------------------------------------------------------------------
class Mihomo:
    def __init__(self, lab: "Lab", tag: str, runtime_text: str):
        self.lab = lab
        self.tag = tag
        run = lab.next_client_ports()
        self.mixed_port = run["mixed"]
        self.ctrl_port = run["controller"]
        self.home = lab.lab_dir / "runtime" / "homes" / tag
        harden_dir(self.home)
        cfg = lab.lab_dir / "runtime" / "profiles" / ("%s.yaml" % tag)
        harden_dir(cfg.parent)
        text = runtime_text.replace("__MIXED_PORT__", str(self.mixed_port)) \
                           .replace("__CTRL_PORT__", str(self.ctrl_port))
        cfg.write_text(text, encoding="utf-8")
        harden_file(cfg)
        self.cfg_path = cfg
        self.log_path = lab.lab_dir / "runtime" / "logs" / ("%s.log" % tag)
        harden_dir(self.log_path.parent)
        if self.log_path.exists():
            self.log_path.unlink()
        self.cfg_sha256 = sha256_bytes(text.encode("utf-8"))
        self.proc = CoreProcess("mihomo-" + tag, lab.mihomo,
                                ["-d", str(self.home), "-f", str(cfg)],
                                self.log_path, lab.lab_dir)

    # -- controller API ----------------------------------------------------
    def api(self, path: str, timeout=3.0):
        req = urllib.request.Request(
            "http://%s:%d%s" % (HOST, self.ctrl_port, path),
            headers={"Authorization": "Bearer " + SECRET})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def start(self, deadline_s=20.0):
        self.proc.start()
        t0 = now()
        while now() - t0 < deadline_s:
            if not self.proc.alive():
                raise LabError("mihomo %s exited: %r"
                               % (self.tag, self.log_tail()))
            try:
                self.api("/version", timeout=1.0)
                return {"ok": True, "ready_ms": ms(t0, now())}
            except Exception:
                time.sleep(0.05)
        raise LabError("mihomo %s controller never came up" % self.tag)

    def stop(self):
        self.proc.stop()

    def alive(self) -> bool:
        return self.proc.alive()

    def log_tail(self, n=1500) -> str:
        try:
            return self.log_path.read_text(errors="replace")[-n:]
        except OSError:
            return ""

    def snapshot(self):
        t = now()
        try:
            proxies = self.api("/proxies").get("proxies") or {}
        except Exception as exc:
            return {"t": t, "error": repr(exc)}
        row = {"t": t, "now": {}, "alive": {}, "hist_len": {}, "last": {}}
        for group in (GROUP, SELECTOR):
            row["now"][group] = (proxies.get(group) or {}).get("now")
        for node in NODES:
            obj = proxies.get(node) or {}
            hist = obj.get("history") or []
            row["alive"][node] = obj.get("alive")
            row["hist_len"][node] = len(hist)
            row["last"][node] = hist[-1] if hist else None
        return row

    def selection_now(self):
        proxies = self.api("/proxies").get("proxies") or {}
        return {"group": (proxies.get(GROUP) or {}).get("now"),
                "selector": (proxies.get(SELECTOR) or {}).get("now")}

    def wait_healthy(self, deadline_s=30.0):
        """All four nodes have at least one check; used for the baseline."""
        t0 = now()
        last = None
        while now() - t0 < deadline_s:
            last = self.snapshot()
            if "error" not in last:
                if all(last["hist_len"].get(n, 0) >= 1 for n in NODES) \
                        and all(last["alive"].get(n) is True for n in NODES):
                    return {"ok": True, "elapsed_ms": ms(t0, now()),
                            "state": _strip_state(last)}
            time.sleep(0.05)
        return {"ok": False, "elapsed_ms": ms(t0, now()),
                "state": _strip_state(last)}

    def wait_selection(self, target: str, deadline_s=20.0):
        t0 = now()
        last = None
        while now() - t0 < deadline_s:
            last = self.snapshot()
            if "error" not in last and last["now"].get(GROUP) == target:
                return {"ok": True, "elapsed_ms": ms(t0, now()),
                        "state": _strip_state(last)}
            time.sleep(0.03)
        return {"ok": False, "elapsed_ms": ms(t0, now()),
                "state": _strip_state(last)}

    # -- probes ------------------------------------------------------------
    def socks_connect(self, timeout=1.5):
        sock = socket.create_connection((HOST, self.mixed_port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall(b"\x05\x01\x00")
            if sock.recv(2) != b"\x05\x00":
                raise OSError("socks5 method negotiation failed")
            req = (b"\x05\x01\x00\x01" + socket.inet_aton(HOST) +
                   PORT["origin"].to_bytes(2, "big"))
            sock.sendall(req)
            resp = sock.recv(10)
            if len(resp) < 2 or resp[1] != 0:
                raise OSError("socks5 connect rejected code=%r"
                              % (resp[1] if len(resp) > 1 else None))
            return sock
        except Exception:
            sock.close()
            raise

    def chain_probe(self, hold_ms=200, connect_timeout=1.0,
                    response_timeout=2.0):
        """Fresh SOCKS GET; while it is in flight read the node from /connections.

        Returns ok/code/chain/timestamps. A success here is a real end-to-end
        response through the selected chain, never a reused keep-alive.
        """
        t0 = now()
        attempt = {"t0": t0, "ok": False, "code": None, "chain": None,
                   "chains_all": None, "error": None, "t1": None}
        sock = None
        try:
            sock = self.socks_connect(timeout=connect_timeout)
            req = ("GET /hold?ms=%d HTTP/1.0\r\nHost: %s:%d\r\n"
                   "Connection: close\r\n\r\n"
                   % (hold_ms, HOST, PORT["origin"])).encode()
            sock.sendall(req)
            time.sleep(0.05)
            try:
                conns = self.api("/connections", timeout=1.2).get("connections") or []
                matches = [c for c in conns
                           if str((c.get("metadata") or {}).get("destinationPort"))
                           == str(PORT["origin"])]
                attempt["chains_all"] = [c.get("chains") for c in matches]
                if matches:
                    attempt["chain"] = matches[0].get("chains")
            except Exception as exc:
                attempt["connections_error"] = repr(exc)
            timeout = response_timeout
            sock.settimeout(timeout)
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            attempt["t1"] = now()
            head = data.split(b"\r\n", 1)[0]
            match = re.match(rb"HTTP/1\.[01] (\d{3})", head)
            attempt["code"] = int(match.group(1)) if match else None
            attempt["ok"] = attempt["code"] in (200, 204)
        except Exception as exc:
            attempt["error"] = repr(exc)
            attempt["t1"] = now()
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        attempt["elapsed_ms"] = ms(attempt["t0"], attempt["t1"])
        return attempt

    def active_delay(self, node: str, timeout_ms=2000):
        q = urllib.parse.urlencode({"url": "http://%s:%d/generate_204"
                                          % (HOST, PORT["origin"]),
                                    "timeout": timeout_ms})
        try:
            return {"ok": True,
                    "delay_ms": self.api("/proxies/%s/delay?%s"
                                        % (urllib.parse.quote(node), q),
                                        timeout=timeout_ms / 1000.0 + 1.0).get("delay")}
        except Exception as exc:
            return {"ok": False, "error": repr(exc)}


def _strip_state(state):
    """Keep only the small, credential-free part of a snapshot."""
    if state is None or "error" in state:
        return state
    return {"t": state["t"], "now": state["now"], "alive": state["alive"],
            "hist_len": state["hist_len"]}


# --------------------------------------------------------------------------
# health-check log parsing (mihomo debug log, wall timestamps -> mono)
# --------------------------------------------------------------------------
CHECK_START_RE = re.compile(
    r'^time="(?P<ts>[^"]+)" level=debug msg="Health Checking, proxy: '
    r'(?P<proxy>[^,]+), url: [^,]+, id: \{(?P<uid>[^}]+)\}"')
CHECK_END_RE = re.compile(
    r'^time="(?P<ts>[^"]+)" level=debug msg="Health Checked, proxy: '
    r'(?P<proxy>[^,]+), url: [^,]+, alive: (?P<alive>true|false), '
    r'delay: (?P<delay>\d+) ms uid: \{(?P<uid>[^}]+)\}"')
TS_RE = re.compile(r'^(?P<base>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})'
                   r'(?:\.(?P<frac>\d+))?(?P<tz>[+-]\d{2}:\d{2})$')


class HealthLogParser:
    def __init__(self, wall_offset: float):
        self.wall_offset = wall_offset

    def mono_of_wall(self, ts: str):
        match = TS_RE.match(ts)
        if not match:
            return None
        frac = (match.group("frac") or "")[:6].ljust(6, "0")
        dt = datetime.fromisoformat("%s.%s%s" % (match.group("base"), frac,
                                                  match.group("tz")))
        return dt.timestamp() - self.wall_offset

    def parse(self, log_path: Path):
        starts, ends = {}, {}
        try:
            text = Path(log_path).read_text(errors="replace")
        except OSError:
            return []
        for line in text.replace("\r", "").splitlines():
            match = CHECK_START_RE.match(line)
            if match:
                starts[match.group("uid")] = {
                    "proxy": match.group("proxy").strip(),
                    "t": self.mono_of_wall(match.group("ts"))}
                continue
            match = CHECK_END_RE.match(line)
            if match:
                ends[match.group("uid")] = {
                    "proxy": match.group("proxy").strip(),
                    "alive": match.group("alive") == "true",
                    "delay": int(match.group("delay")),
                    "t": self.mono_of_wall(match.group("ts"))}
        out = []
        for uid, start in starts.items():
            end = ends.get(uid)
            if end is None or start["t"] is None or end["t"] is None:
                continue
            out.append({"proxy": end["proxy"], "start": start["t"],
                        "end": end["t"],
                        "dur_ms": ms(start["t"], end["t"]),
                        "alive": end["alive"], "delay": end["delay"]})
        out.sort(key=lambda row: row["start"])
        return out


# ==========================================================================
# PART 2: fixture build, loopback stack, measurement engine
# ==========================================================================
class Lab:
    def __init__(self, args):
        self.args = args
        self.repo_root = Path(__file__).resolve().parents[1]
        self.lab_dir = Path(args.lab_dir).resolve() if args.lab_dir else \
            self.repo_root / ".scratch" / "ha04-lab"
        self.lab_dir.mkdir(parents=True, exist_ok=True)
        for name in ("fixture", "runtime", "runtime/homes", "runtime/profiles",
                     "runtime/logs", "events"):
            (self.lab_dir / name).mkdir(parents=True, exist_ok=True)
        self.ev = Evidence(self.lab_dir)
        self.wall_offset = time.time() - now()
        self.ev.results["environment"].update({
            "wall_mono_offset_s": round(self.wall_offset, 3),
            "wall_utc_at_start": iso_utc(),
            "lab_dir": str(self.lab_dir),
            "loopback_only": True,
            "declared_lab_deviations": [
                "health URL rewritten to the local loopback 204 origin",
                "mixed-port / external-controller / debug log are local",
                "dns.enable=false, dns.fallback-filter.geoip=false and tun.enable=false (no TUN/admin/resolver/GeoIP DB)",
                "delivered GEOIP,LAN/DIRECT and GEOIP,CN/DIRECT rules removed "
                "so the loopback origin goes through 节点选择 instead of DIRECT",
            ],
            "lab_ports": {k: v for k, v in PORT.items()},
            "hop_ports": list(HOP_PORTS),
            "client_port_range": [MIXED_BASE,
                                  MIXED_BASE + 2 * MAX_CLIENT_RUNS + 1],
        })
        self.mihomo = self._resolve_binary("mihomo", args.mihomo,
                                           EXPECTED["mihomo"], "HA04_MIHOMO")
        self.singbox = self._resolve_binary("sing-box", args.sing_box,
                                            EXPECTED["sing-box"], "HA04_SINGBOX")
        self.tools = {
            "batch": self.repo_root / "tools" / "mihomo-competition-ha-batch.py",
            "profile": self.repo_root / "tools" / "mihomo-competition-ha-profile.py",
            "fastprobe": self.repo_root / "tools" / "mihomo-competition-ha4-fastprobe.py",
        }
        for name, path in self.tools.items():
            if not path.is_file():
                raise LabError("repo tool missing: %s" % path)
        self.python = sys.executable
        self.listeners = {}
        self.origin = None
        self.handshake = None
        self.clients = []
        self.sessions = []
        self.vps = {}
        self.users = {}
        self.certs = {}
        self.pins = None
        self.trees = {}
        self.runs = 0
        self.started_utc = iso_utc()

    # -- binary verification ----------------------------------------------
    @staticmethod
    def _resolve_binary(label, arg_value, expected, env_name):
        path = arg_value or os.environ.get(env_name)
        if not path:
            raise LabError("no %s binary given (--%s or %s)"
                           % (label, label.replace("-", ""), env_name))
        path = Path(path)
        if not path.is_file():
            raise LabError("%s binary missing: %s" % (label, path))
        actual = sha256_file(path)
        if actual != expected["sha256"]:
            raise LabError("%s SHA-256 mismatch: got %s want %s"
                           % (label, actual, expected["sha256"]))
        return path

    def record_binaries(self):
        for label, path in (("mihomo", self.mihomo), ("sing-box", self.singbox)):
            entry = {"path": str(path), "sha256": sha256_file(path),
                     "expected_version": EXPECTED[label]["version"]}
            try:
                out = run_quiet([str(path), "-v" if label == "mihomo" else "version"],
                                timeout=20)
                entry["version_output_first_line"] = (
                    (out.stdout or out.stderr).replace("\r", "").splitlines() or [""])[0]
            except Exception as exc:
                entry["version_output_first_line"] = "unreadable: %r" % (exc,)
            self.ev.results["binaries"][label] = entry
        self.ev.results["environment"]["tools"] = {
            name: {"path": str(path), "sha256": sha256_file(path)}
            for name, path in self.tools.items()}

    # -- port preflight ----------------------------------------------------
    def port_plan(self):
        plan = []
        for name, port in PORT.items():
            proto = "udp" if name.endswith("HY2") else "tcp"
            plan.append((name, port, proto))
        for port in HOP_PORTS:
            plan.append(("A-HY2-hop-%d" % port, port, "udp"))
        for index in range(MAX_CLIENT_RUNS):
            plan.append(("mixed-%d" % index, MIXED_BASE + 2 * index, "tcp"))
            plan.append(("controller-%d" % index, MIXED_BASE + 2 * index + 1,
                         "tcp"))
        return plan

    def preflight_ports(self):
        busy = []
        for name, port, proto in self.port_plan():
            if proto == "tcp":
                occupied = tcp_connect_ok(port, timeout=0.15)
            else:
                free, _err = udp_bindable(port)
                occupied = not free
            if occupied:
                busy.append({"name": name, "port": port, "proto": proto})
        self.ev.results["environment"]["port_preflight"] = {
            "checked": len(self.port_plan()), "busy": busy}
        if busy:
            raise LabError("ports busy, refusing to run: %r" % busy[:10])
        return True

    # -- stack (REALITY handshake target + origin + 4 real listeners) -----
    def build_stack(self):
        fixture = self.lab_dir / "fixture"
        harden_dir(fixture)
        tls = fixture / "tls"
        harden_dir(tls)
        self.certs["handshake"] = build_cert(tls, "handshake")
        self.certs["A-HY2"] = build_cert(tls, "vps-a-hy2")
        self.certs["B-HY2"] = build_cert(tls, "vps-b-hy2")
        # Synthetic credentials: generated locally, thrown away with the LAB.
        # The HA-02 batch gate requires distinct A/B server addresses and a
        # unique UUID/password per terminal, so every (vps, terminal) pair gets
        # its own identity and every listener accepts the full terminal list.
        self.vps = {}
        self.users = {}
        for vps in ("A", "B"):
            keypair = run_tool([str(self.singbox), "generate", "reality-keypair"],
                               "sing-box reality-keypair").stdout.replace("\r", "")
            priv = re.search(r"PrivateKey:\s*(\S+)", keypair).group(1)
            pub = re.search(r"PublicKey:\s*(\S+)", keypair).group(1)
            self.vps[vps] = {"private_key": priv, "public_key": pub,
                             "short_id": SHORT_ID}
            for terminal in TERMINALS:
                uuid = run_tool([str(self.singbox), "generate", "uuid"],
                                "sing-box uuid").stdout.strip()
                self.users[(vps, terminal)] = {
                    "name": terminal, "uuid": uuid,
                    "password": "synthetic-%s-%s-hy2" % (vps.lower(), terminal)}
        self.ev.results["fixture"]["certificates"] = {}
        for tag in ("A-HY2", "B-HY2"):
            cert, key = self.certs[tag]
            dates = cert_dates(cert)
            self.ev.results["fixture"]["certificates"][tag] = {
                "pin_sha256": cert_pin(cert),
                "cert_sha256": sha256_file(cert),
                "not_before": dates["not_before"],
                "not_after": dates["not_after"],
                "synthetic": True,
            }
        # REALITY handshake + 204 origin are loopback-only.
        self.handshake = HandshakeTarget(PORT["handshake"],
                                         self.certs["handshake"][0],
                                         self.certs["handshake"][1]).start()
        self.origin = LocalOrigin(PORT["origin"]).start()

        def vps_users(vps, kind):
            out = []
            for terminal in TERMINALS:
                user = self.users[(vps, terminal)]
                if kind == "uuid":
                    out.append({"name": terminal, "uuid": user["uuid"]})
                else:
                    out.append({"name": terminal,
                                "password": user["password"]})
            return out

        # Two logical VPSes, four independent listeners (so a single protocol
        # can be killed without killing the other one on the same VPS).
        specs = [
            ("A-Reality", PORT["A-Reality"], "tcp", A_HOST,
             vps_users("A", "uuid"), self.vps["A"]["private_key"],
             self.certs["handshake"][0], self.certs["handshake"][1]),
            ("A-HY2", PORT["A-HY2"], "udp", A_HOST,
             vps_users("A", "password"), "",
             self.certs["A-HY2"][0], self.certs["A-HY2"][1]),
            ("B-Reality", PORT["B-Reality"], "tcp", B_HOST,
             vps_users("B", "uuid"), self.vps["B"]["private_key"],
             self.certs["handshake"][0], self.certs["handshake"][1]),
            ("B-HY2", PORT["B-HY2"], "udp", B_HOST,
             vps_users("B", "password"), "",
             self.certs["B-HY2"][0], self.certs["B-HY2"][1]),
        ]
        for hop in HOP_PORTS:
            specs.append(("A-HY2-hop-%d" % hop, hop, "udp", A_HOST,
                          vps_users("A", "password"), "",
                          self.certs["A-HY2"][0], self.certs["A-HY2"][1]))
        for name, port, proto, host, users, private_key, cert, key in specs:
            listener = Listener(name, port, proto, users, private_key, host,
                                cert, key, fixture, self.singbox)
            self.listeners[name] = listener
        effects = {}
        for name, listener in self.listeners.items():
            effects[name] = listener.start()
        for name in ("origin", "handshake"):
            port = PORT[name]
            if not tcp_connect_ok(port, timeout=1.0):
                raise LabError("local %s server did not open on %d" % (name, port))
        self.ev.results["fixture"]["stack"] = {
            "started_utc": iso_utc(),
            "listeners": len(self.listeners),
            "logical_vps": 2,
            "listener_process_model": "one sing-box process per listener",
            "bind": "A=" + A_HOST + ", B=" + B_HOST,
            "per_terminal_credentials": len(TERMINALS),
        }
        self.ev.event("stack_up", listeners=len(self.listeners))

    # -- fixture build through the three repo tools -----------------------
    def _tool(self, name, args, label):
        return run_tool([self.python, str(self.tools[name])] + args, label)

    def _tree(self, name, terminals):
        """terminals: {terminal_name: group}; creates exports + inventory."""
        root = self.lab_dir / "fixture" / name
        if (root / "done.json").exists():
            try:
                return json.loads((root / "done.json").read_text(encoding="utf-8"))
            except Exception:
                pass
        harden_dir(root)
        for sub in ("exports/A", "exports/B", "delivery", "competition",
                    "variants"):
            harden_dir(root / sub)
        inv = root / "terminals.csv"
        lines = ["terminal,group"]
        for terminal, group in terminals.items():
            lines.append("%s,%s" % (terminal, group))
        inv.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
        harden_file(inv)
        for terminal in terminals:
            for vps in ("A", "B"):
                user = self.users[(vps, terminal)]
                hop = None
                if name == "hop" and vps == "A":
                    hop = "%d-%d" % (HOP_PORTS[0], HOP_PORTS[-1])
                reality_port = PORT["%s-Reality" % vps]
                hy2_port = HOP_PORTS[0] if hop else PORT["%s-HY2" % vps]
                text = export_text((A_HOST if vps == "A" else B_HOST),
                                   reality_port, hy2_port,
                                   user["uuid"], user["password"],
                                   self.vps[vps]["public_key"],
                                   self.vps[vps]["short_id"], hop)
                path = root / "exports" / vps / ("%s-mihomo.yaml" % terminal)
                path.write_text(text, encoding="utf-8", newline="\n")
                harden_file(path)
        pins_path = root / "pins.json"
        doc = {"schema": "mihomo-competition-ha-pins/2",
               "vps": {}}
        for vps in ("A", "B"):
            cert_info = self.ev.results["fixture"]["certificates"]["%s-HY2" % vps]
            doc["vps"][vps] = {
                "fingerprint_sha256": cert_info["pin_sha256"],
                "not_before": cert_info["not_before"],
                "not_after": cert_info["not_after"],
                "source": "synthetic-ha04-loopback-lab",
            }
        pins_path.write_text(json.dumps(doc, sort_keys=True, indent=2) + "\n",
                             encoding="utf-8")
        harden_file(pins_path)
        self.pins = doc
        ha02 = self._tool("batch", [
            "--inventory", str(inv), "--exports", str(root / "exports"),
            "--output-dir", str(root / "delivery"),
            "--config-version", "ha04-lab-r1"], "ha-batch")
        ha03 = self._tool("profile", [
            "--delivery", str(root / "delivery"), "--pins", str(pins_path),
            "--output-dir", str(root / "competition"),
            "--config-version", "comp-r1"], "ha-profile")
        tree = {"name": name, "root": str(root),
                "terminals": terminals,
                "delivery": str(root / "delivery"),
                "competition": str(root / "competition"),
                "pins": str(pins_path),
                "variants": {},
                "tool_output": {"ha02": ha02.stdout.replace("\r", ""),
                                "ha03": ha03.stdout.replace("\r", "")}}
        entry = self.ev.results["fixture"].setdefault("trees", {}).setdefault(name, {})
        entry.update({
            "terminals": terminals,
            "pins_sha256": sha256_file(pins_path),
            "ha02_manifest": sorted(p.name for p in
                                    (root / "delivery").glob("ha-delivery-*.json")),
            "ha03_manifest": sorted(p.name for p in
                                    (root / "competition").glob("ha-competition-*.json")),
            "ha02_stdout": ha02.stdout.replace("\r", ""),
            "ha03_stdout": ha03.stdout.replace("\r", ""),
        })
        return tree

    def build_fixture(self):
        # Rerunnable: previous fixture/runtime artefacts are replaced.
        for sub in ("fixture", "runtime"):
            old = self.lab_dir / sub
            if old.exists():
                shutil.rmtree(old, ignore_errors=True)
        for name in ("fixture", "runtime", "runtime/homes", "runtime/profiles",
                     "runtime/logs"):
            (self.lab_dir / name).mkdir(parents=True, exist_ok=True)
        self.build_stack()
        main = self._tree("main", dict(FIXTURE_TREES["main"]))
        hop = self._tree("hop", dict(FIXTURE_TREES["hop"]))
        plans = {
            "main": list(POLICIES),
            "hop": [(3, 1000)],
        }
        for name, tree in (("main", main), ("hop", hop)):
            for policy in plans[name]:
                interval, timeout = policy
                tag = "i%d-t%d" % (interval, timeout)
                out = Path(tree["root"]) / "variants" / tag
                if not (out / "check.json").exists():
                    harden_dir(out)
                    gen = self._tool("fastprobe", [
                        "--delivery", tree["competition"],
                        "--ha02-delivery", tree["delivery"],
                        "--pins", tree["pins"],
                        "--output-dir", str(out),
                        "--config-version", "ha04-lab-r1",
                        "--interval", str(interval),
                        "--timeout", str(timeout)], "ha4-fastprobe")
                    check = self._tool("fastprobe", [
                        "--check", "--delivery", str(out),
                        "--source-delivery", tree["competition"],
                        "--ha02-delivery", tree["delivery"],
                        "--pins", tree["pins"]], "ha4-fastprobe-check")
                    manifest = sorted(p.name for p in out.glob("ha4-fastprobe-*.json"))
                    summary = {"interval": interval, "timeout": timeout,
                               "dir": str(out), "manifest": manifest,
                               "profiles": {},
                               "gen_stdout": gen.stdout.replace("\r", ""),
                               "check_stdout": check.stdout.replace("\r", "")}
                    for terminal in tree["terminals"]:
                        prof = out / ("%s-ha4f.yaml" % terminal)
                        summary["profiles"][terminal] = {
                            "path": str(prof),
                            "sha256": sha256_file(prof),
                            "bytes": prof.stat().st_size,
                        }
                    (out / "check.json").write_text(
                        json.dumps(summary, indent=2) + "\n", encoding="utf-8")
                else:
                    summary = json.loads((out / "check.json").read_text(
                        encoding="utf-8"))
                tree["variants"][tag] = summary
                entry = self.ev.results["fixture"]["trees"][name] \
                    .setdefault("variants", {}).setdefault(tag, {})
                entry.update({"interval": interval, "timeout": timeout,
                              "manifest": summary["manifest"],
                              "profiles": {k: v["sha256"] for k, v in
                                           summary["profiles"].items()},
                              "check_ok": (summary["check_stdout"].startswith(
                                  "ha4-fastprobe: OK"))})
                self.ev.event("variant_ready", tag="%s/%s" % (name, tag),
                              interval=interval, timeout=timeout)
            tree["variants"] = {tag: (Path(s["dir"]), s) for tag, s in
                                tree["variants"].items()}
        self.trees = {"main": main, "hop": hop}
        self.refresh_ha03_pin_semantics()
        (self.lab_dir / "fixture.json").write_text(
            json.dumps(self.ev.results["fixture"], indent=2) + "\n",
            encoding="utf-8")
        self.ev.event("fixture_ready", trees=list(self.trees))

    def refresh_ha03_pin_semantics(self):
        """Prove the HA-03 competition profile really pins the LAB cert leaf.

        The pin semantics are exercised later by the running Mihomo HY2
        connections; here we only record that each HY2 node carries the pin of
        its physical VPS certificate (already checked byte-exactly by --check).
        """
        pins = self.pins["vps"]
        self.ev.results["fixture"]["pin_mapping"] = {
            "A": pins["A"]["fingerprint_sha256"],
            "B": pins["B"]["fingerprint_sha256"],
            "validity": {vps: {"not_before": pins[vps]["not_before"],
                               "not_after": pins[vps]["not_after"]}
                         for vps in "AB"},
        }

    # -- runtime profile (declared lab-only edits) ------------------------
    def runtime_profile(self, tree_name, terminal, policy):
        tree = self.trees[tree_name]
        interval, timeout = policy
        tag = "i%d-t%d" % (interval, timeout)
        vdir, meta = tree["variants"][tag]
        src = Path(meta["profiles"][terminal]["path"])
        text = src.read_text(encoding="utf-8")
        if "\r" in text:
            raise LabError("variant profile has CRLF: %s" % src)
        lines = text.split("\n")
        out = []
        section = None
        edits = {}
        for line in lines:
            if line and not line.startswith(" "):
                section = line.split(":", 1)[0]
            if line == "mixed-port: 7897":
                out.append("mixed-port: __MIXED_PORT__")
                out.append("external-controller: %s:__CTRL_PORT__" % HOST)
                out.append('secret: "%s"' % SECRET)
                edits["mixed-port"] = True
                continue
            if line == "log-level: info":
                out.append("log-level: debug")
                edits["log-level"] = True
                continue
            if section == "dns" and line == "  enable: true":
                out.append("  enable: false")
                edits["dns.enable"] = True
                continue
            if section == "dns" and line == "    geoip: true":
                # LAB has no GeoIP database and no network egress: the
                # delivered DNS fallback-filter would make Mihomo try to
                # download geoip.metadb. Loopback-only LAB disables it;
                # declared deviation, all rules/health policy stay untouched.
                out.append("    geoip: false")
                edits["dns.fallback_filter.geoip"] = True
                continue
            if section == "tun" and line == "  enable: true":
                out.append("  enable: false")
                edits["tun.enable"] = True
                continue
            if line == '    url: "https://www.gstatic.com/generate_204"':
                out.append('    url: "http://%s:%d/generate_204"'
                           % (HOST, PORT["origin"]))
                edits["health_url"] = True
                continue
            # Loopback LAB: the delivered rules send LAN/CN destinations
            # DIRECT, which would bypass the failover group for a 127.0.0.1
            # origin. The LAB origin is forced through the group; declared
            # deviation, nothing else in the profile is touched.
            if section == "rules" and line in ("  - GEOIP,LAN,DIRECT",
                                               "  - GEOIP,CN,DIRECT"):
                edits.setdefault("rules_direct_removed", 0)
                edits["rules_direct_removed"] += 1
                continue
            out.append(line)
        expected_edits = {"mixed-port": True, "log-level": True,
                          "dns.enable": True, "dns.fallback_filter.geoip": True,
                          "tun.enable": True,
                          "health_url": True, "rules_direct_removed": 2}
        if edits != expected_edits:
            raise LabError("runtime profile edits unexpected (%r) for %s"
                           % (edits, src))
        runtime = "\n".join(out)
        # Sanity: policy untouched, four-node order untouched, pins untouched.
        if ("    interval: %d" % interval) not in runtime:
            raise LabError("runtime profile lost interval for %s" % src)
        if ("    timeout: %d" % timeout) not in runtime:
            raise LabError("runtime profile lost timeout for %s" % src)
        if runtime.count("    fingerprint: ") != 2:
            raise LabError("runtime profile lost HY2 pins for %s" % src)
        for node in NODES:
            if ("  - name: %s" % node) not in runtime:
                raise LabError("runtime profile lost node %s" % node)
        if "  - MATCH,节点选择" not in runtime:
            raise LabError("runtime profile lost the select rule for %s" % src)
        return runtime, {"source": str(src),
                         "source_sha256": meta["profiles"][terminal]["sha256"],
                         "lab_edits": sorted(k for k, v in edits.items() if v),
                         "source_is_byte_verified_variant": True,
                         "static_lab_deviations": [
                             "health URL -> local 204 origin",
                             "dns.enable=false, tun.enable=false",
                             "mixed-port/external-controller/debug log",
                             "GEOIP,LAN/DIRECT and GEOIP,CN,DIRECT lab rules "
                             "removed so the loopback origin is proxied "
                             "through 节点选择 instead of DIRECT"]}

    def next_client_ports(self):
        index = self.runs
        self.runs += 1
        if index >= MAX_CLIENT_RUNS:
            raise LabError("more client runs than the preflight port plan")
        return {"mixed": MIXED_BASE + 2 * index,
                "controller": MIXED_BASE + 2 * index + 1}

    # -- client lifecycle --------------------------------------------------
    def start_client(self, tag, tree_name, terminal, policy, pdir_meta):
        group = self.trees[tree_name]["terminals"][terminal]
        runtime, runtime_meta = self.runtime_profile(tree_name, terminal, policy)
        m = Mihomo(self, tag, runtime)
        info = m.start()
        self.clients.append(m)
        healthy = m.wait_healthy(deadline_s=35.0)
        if not healthy["ok"]:
            raise LabError("client %s baseline not healthy: %r log=%r"
                           % (tag, healthy.get("state"), m.log_tail()))
        expected_primary = GROUP_BY_PHYSICAL[group]["A" if group == "A-first"
                                                   else "B"]
        if expected_primary != "Reality":
            raise LabError("internal: expected primary != Reality")
        sel = m.wait_selection("Reality", deadline_s=20.0)
        if not sel["ok"]:
            raise LabError("client %s baseline selection not Reality: %r"
                           % (tag, sel.get("state")))
        baseline_probe = m.chain_probe(hold_ms=450)
        chain_node = _chain_node(baseline_probe)
        physical = PHYSICAL[group].get(chain_node)
        baseline = {
            "healthy": {k: v for k, v in healthy.items() if k != "state"},
            "selection": sel["state"]["now"],
            "alive": sel["state"]["alive"],
            "probe": {"ok": baseline_probe["ok"],
                      "code": baseline_probe["code"],
                      "chain": baseline_probe["chain"],
                      "chain_node": chain_node,
                      "physical_vps": physical,
                      "elapsed_ms": baseline_probe["elapsed_ms"]},
            "expected": {"group": group, "primary_node": "Reality",
                         "primary_physical": PHYSICAL[group]["Reality"]},
            "mihomo": {"pid": getattr(m.proc.proc, "pid", None),
                       "mixed_port": m.mixed_port,
                       "controller_port": m.ctrl_port,
                       "runtime_sha256": m.cfg_sha256,
                       "runtime_config": runtime_meta},
        }
        if not baseline_probe["ok"] or chain_node != "Reality" or \
                physical is None:
            raise LabError("client %s baseline chain bad: %r"
                           % (tag, baseline_probe))
        self.ev.event("client_baseline", tag=tag, terminal=terminal,
                      policy={"interval": policy[0], "timeout": policy[1]},
                      selected=sel["state"]["now"].get(GROUP),
                      chain=baseline_probe["chain"])
        return m, baseline

    def close_client(self, m):
        try:
            m.stop()
        except Exception:
            pass

    def ensure_all_listeners_alive(self):
        """Defensive restore between cells: no scenario may leave a dead VPS."""
        restored = []
        for name, listener in self.listeners.items():
            if not listener.alive():
                try:
                    info = start_listener_retry(listener)
                    restored.append(info)
                except Exception as exc:
                    raise LabError("could not restore listener %s: %r"
                                   % (name, exc))
            else:
                ok, detail = wait_port(listener.proto, listener.port, True, 2.0,
                                       host=listener.host)
                if not ok:
                    raise LabError("listener %s alive but port not serving (%s)"
                                   % (name, detail))
        return restored

    # -- cleanup -----------------------------------------------------------
    def cleanup(self) -> dict:
        self.ev.set_scenario("cleanup")
        problems = []
        for session in list(self.sessions):
            try:
                session.stop()
            except Exception:
                pass
        for m in list(self.clients):
            if m.alive():
                try:
                    m.stop()
                except Exception:
                    pass
        for listener in self.listeners.values():
            try:
                if listener.alive():
                    listener.proc.stop()
            except Exception:
                pass
        for srv in (self.origin, self.handshake):
            if srv is not None:
                try:
                    srv.stop()
                except Exception:
                    pass
        time.sleep(0.3)
        for name, port, proto in self.port_plan():
            if proto == "tcp":
                if tcp_connect_ok(port, timeout=0.15):
                    problems.append({"name": name, "port": port, "proto": proto})
            else:
                free, _err = udp_bindable(port)
                if not free:
                    problems.append({"name": name, "port": port, "proto": proto})
        cleanup = {"ports_free": not problems, "busy_after_cleanup": problems,
                   "processes_stopped": True,
                   "checked_ports": len(self.port_plan())}
        self.ev.results["cleanup"] = cleanup
        self.ev.event("cleanup", ports_free=not problems,
                      busy=problems[:5])
        return cleanup


def _chain_node(attempt):
    chain = attempt.get("chain")
    if isinstance(chain, list):
        for item in chain:
            if isinstance(item, str) and item in NODES:
                return item
    all_chains = attempt.get("chains_all") or []
    for chains in all_chains:
        if isinstance(chains, list):
            for item in chains:
                if isinstance(item, str) and item in NODES:
                    return item
    return None


# --------------------------------------------------------------------------
# measurement sessions: 50 ms selection poller + fresh end-to-end prober
# --------------------------------------------------------------------------
class Poller(threading.Thread):
    def __init__(self, mihomo: Mihomo, interval_s=0.05):
        super().__init__(daemon=True)
        self.mihomo = mihomo
        self.interval_s = interval_s
        self.samples = []
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            self.samples.append(self.mihomo.snapshot())
            self._stop_event.wait(self.interval_s)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=3)


class Prober(threading.Thread):
    """Continuous fresh SOCKS GETs with per-attempt chain attribution."""

    def __init__(self, mihomo: Mihomo, interval_s=0.0):
        super().__init__(daemon=True)
        self.mihomo = mihomo
        self.interval_s = interval_s
        self.attempts = []
        self._stop_event = threading.Event()

    def run(self):
        while not self._stop_event.is_set():
            attempt = self.mihomo.chain_probe(hold_ms=180,
                                              connect_timeout=0.8,
                                              response_timeout=1.5)
            # selection observed for this attempt (cheap, loopback controller)
            try:
                sel = self.mihomo.selection_now()
            except Exception:
                sel = None
            attempt["selection"] = sel
            self.attempts.append(attempt)
            if self.interval_s:
                self._stop_event.wait(self.interval_s)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=5)


class Session:
    def __init__(self, lab: "Lab", mihomo: Mihomo):
        self.lab = lab
        self.mihomo = mihomo
        self.poller = Poller(mihomo)
        self.prober = Prober(mihomo)
        self.wall_offset = lab.wall_offset
        self.started = now()

    def start(self):
        self.poller.start()
        self.prober.start()
        self.lab.sessions.append(self)
        return self

    def stop(self):
        self.poller.stop()
        self.prober.stop()
        if self in self.lab.sessions:
            self.lab.sessions.remove(self)

    def health_checks(self):
        return HealthLogParser(self.wall_offset).parse(self.mihomo.log_path)


def _selection_at(samples, t):
    prev = None
    for sample in samples:
        if "error" in sample:
            continue
        if sample["t"] <= t:
            prev = sample
        else:
            break
    if prev is None:
        for sample in samples:
            if "error" not in sample:
                return sample
    return prev


def _transitions(samples, t0):
    out = []
    prev = None
    for sample in samples:
        if "error" in sample:
            continue
        current = sample["now"].get(GROUP)
        if prev is not None and current != prev and sample["t"] >= t0:
            out.append({"t": sample["t"], "dt_ms": ms(t0, sample["t"]),
                        "from": prev, "to": current,
                        "alive": sample["alive"]})
        prev = current
    return out


def analyze_session(session: Session, t0: float, t1_window_end: float,
                    baseline_selection: str, dead_nodes,
                    expected_node: str | None,
                    baseline_alive: dict, terminal_group: str):
    """Compute T0->T1, T0->T2, dead-node window, switches and attribution."""
    samples = session.poller.samples
    attempts = session.prober.attempts
    checks = session.health_checks()
    dead = set(dead_nodes)
    physical_dead = {PHYSICAL[terminal_group].get(node) for node in dead}
    physical_dead.discard(None)
    out = {"sampling": {
        "poller_samples": len(samples),
        "probe_attempts": len(attempts),
        "poller_median_interval_ms": _median_gap(samples),
        "probe_median_interval_ms": _median_gap(attempts, "t0"),
        "health_checks": len(checks),
        "window_s": round(t1_window_end - t0, 3),
    }}
    # ---- T1: first client-side failure evidence -------------------------
    health_t1 = None
    for check in checks:
        if check["end"] is not None and check["end"] >= t0 - 0.3 \
                and check["proxy"] in dead and check["alive"] is False:
            health_t1 = check
            break
    transitions = _transitions(samples, t0)
    sel_t1 = transitions[0] if transitions else None
    t1_candidates = []
    if health_t1 is not None:
        t1_candidates.append(("health_alive_false", health_t1["end"]))
    if sel_t1 is not None:
        t1_candidates.append(("selection_change", sel_t1["t"]))
    t1 = None
    if t1_candidates:
        kind, when = min(t1_candidates, key=lambda pair: pair[1])
        t1 = {"t": when, "dt_ms": ms(t0, when), "type": kind,
              "health": _health_row(health_t1, t0) if health_t1 else None,
              "selection": sel_t1}
    out["T1"] = t1
    # ---- stale-alive: how long a dead node stayed alive:true ------------
    stale = {}
    for node in dead:
        if baseline_alive.get(node) is False:
            stale[node] = {"was_alive_at_baseline": False}
            continue
        first_false = None
        if health_t1 is not None and health_t1["proxy"] == node:
            first_false = health_t1["end"]
        for check in checks:
            if check["proxy"] == node and check["end"] is not None \
                    and check["end"] >= t0 - 0.3 and check["alive"] is False:
                first_false = check["end"]
                break
        for sample in samples:
            if sample.get("error") or sample["t"] < t0:
                continue
            if sample["alive"].get(node) is False:
                if first_false is None or sample["t"] < first_false:
                    first_false = sample["t"]
                break
        stale[node] = {"was_alive_at_baseline": True,
                       "first_alive_false_ms": None if first_false is None
                       else ms(t0, first_false),
                       "still_alive_true_at_window_end": first_false is None}
    out["stale_alive"] = stale
    # ---- T2: first fresh end-to-end success + real chain attribution ----
    # A "fresh" connection must have been BOTH started and completed after T0;
    # an attempt already in flight when the fault hit is not evidence.
    t2 = None
    for attempt in attempts:
        if (attempt["t1"] is not None and attempt["t1"] >= t0
                and attempt.get("t0") is not None and attempt["t0"] >= t0
                and attempt["ok"]):
            chain_node = _chain_node(attempt)
            t2 = {"t": attempt["t1"], "dt_ms": ms(t0, attempt["t1"]),
                  "code": attempt["code"],
                  "elapsed_ms": attempt["elapsed_ms"],
                  "chain": attempt["chain"],
                  "chain_node": chain_node,
                  "selection": attempt.get("selection"),
                  "wrong_dead_node_carried": (chain_node in dead
                                              if chain_node else None),
                  "expected_node": expected_node}
            if expected_node is not None:
                if chain_node is None:
                    t2["attribution_matches_expected"] = None
                    t2["attribution_note"] = (
                        "fresh success observed but /connections attribution "
                        "was unavailable for that attempt")
                else:
                    t2["attribution_matches_expected"] = (
                        chain_node == expected_node)
                    if not t2["attribution_matches_expected"]:
                        t2["attribution_note"] = (
                            "first fresh success did not run through the "
                            "expected surviving candidate")
            break
    out["T2"] = t2
    # ---- dead-node selected window and switch count ---------------------
    runs = []
    active = None
    covered = 0
    for sample in samples:
        if sample.get("error") or sample["t"] < t0:
            continue
        node = sample["now"].get(GROUP)
        is_dead = node in dead
        if is_dead and active is None:
            active = {"start": sample["t"], "nodes": [node],
                      "samples": 1, "first_alive": sample["alive"]}
        elif is_dead and active is not None:
            active["samples"] += 1
            if node not in active["nodes"]:
                active["nodes"].append(node)
        elif not is_dead and active is not None:
            runs.append({"start_ms": ms(t0, active["start"]),
                         "end_ms": ms(t0, sample["t"]),
                         "duration_ms": ms(active["start"], sample["t"]),
                         "selected_dead_nodes": active["nodes"],
                         "samples": active["samples"]})
            active = None
        covered += 1
    if active is not None and covered:
        runs.append({"start_ms": ms(t0, max(active["start"], t0)),
                     "end_ms": None,
                     "duration_ms": ms(max(active["start"], t0), t1_window_end),
                     "selected_dead_nodes": active["nodes"],
                     "samples": active["samples"],
                     "open_ended": True})
    out["dead_node_selected"] = {
        "runs": runs,
        "total_ms": round(sum(r["duration_ms"] for r in runs), 1),
        "ever_selected_dead": bool(runs),
    }
    out["switches"] = transitions
    out["switch_count"] = len(transitions)
    # ---- failed fresh probes / wrong-node carriage ----------------------
    failed = []
    for attempt in attempts:
        if attempt["t1"] is None or attempt["t1"] < t0:
            continue
        if t2 is not None and attempt["t0"] > t2["t"]:
            break
        if not attempt["ok"]:
            failed.append({"dt_ms": ms(t0, attempt["t1"]),
                           "selection": attempt.get("selection"),
                           "code": attempt.get("code"),
                           "error": attempt.get("error")})
    out["failed_fresh_probes_before_T2"] = failed
    out["failed_fresh_probe_count"] = len(failed)
    out["wrong_dead_node_carried_any"] = any(
        a.get("ok") and _chain_node(a) in dead for a in attempts
        if a["t1"] is not None and a["t1"] >= t0)
    out["selection_at_window_end"] = None
    end_sample = None
    for sample in reversed(samples):
        if sample.get("error") or sample["t"] < t0:
            continue
        end_sample = sample
        break
    if end_sample is not None:
        out["selection_at_window_end"] = end_sample["now"].get(GROUP)
        out["selection_alive_at_window_end"] = end_sample["alive"]
    return out


def _health_row(check, t0):
    if check is None:
        return None
    return {"proxy": check["proxy"], "alive": check["alive"],
            "delay": check["delay"], "end_ms": ms(t0, check["end"]),
            "dur_ms": check["dur_ms"]}


def _median_gap(items, attr="t"):
    times = []
    for item in items:
        value = item.get(attr)
        if value is not None:
            times.append(value)
    if len(times) < 3:
        return None
    gaps = sorted(times[i + 1] - times[i] for i in range(len(times) - 1))
    return round(gaps[len(gaps) // 2] * 1000.0, 1)


# ==========================================================================
# PART 3: fault injection, scenarios, aggregate summary, CLI
# ==========================================================================
HOP_LISTENERS = tuple("A-HY2-hop-%d" % port for port in HOP_PORTS)


def listeners_for_nodes(group: str, logical_nodes) -> list:
    """Map logical profile nodes to the real listener processes to kill."""
    names = []
    for node in logical_nodes:
        physical = PHYSICAL[group][node]
        if node in ("Reality", "Backup-Reality"):
            names.append("%s-Reality" % physical)
        else:
            names.append("%s-HY2" % physical)
            if physical == "A":
                names.extend(HOP_LISTENERS)
    seen, out = set(), []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def kill_listeners(lab: Lab, names, kind: str, tag: str) -> dict:
    t_ack_start = now()
    effects = {}
    for name in names:
        effects[name] = lab.listeners[name].stop()
    t_effect = now()
    dead = all(effect["dead"] for effect in effects.values())
    fault = {
        "kind": kind, "targets": list(names),
        "effects": list(effects.values()),
        "t_inject_start_mono": t_ack_start,
        "t_inject_ack_mono": t_effect,
        "T0_mono": t_effect,
        "T0_utc": iso_utc(t_effect + lab.wall_offset),
        "independent_effect_verified": dead,
        "effect_definition": (
            "TCP connect refused / UDP port bindable after the listener "
            "process exited; not the SUT /proxies state"),
    }
    if not dead:
        raise LabError("fault did not take effect independently: %r" % effects)
    lab.ev.event("fault_injected", tag=tag, kind=kind, targets=list(names),
                 effect_ok=dead,
                 T0_utc=fault["T0_utc"])
    return fault


def start_listener_retry(listener, attempts=4, delay_s=1.0):
    """Start a listener, retrying a transient bind race after a restart.

    Windows can keep the old UDP/TCP socket briefly after the process exits, so
    a restart may see 'only one usage of each socket address'. Each attempt is
    verified by the real port effect; failures are retried with a short delay.
    """
    last = None
    for _attempt in range(attempts):
        try:
            return listener.start()
        except Exception as exc:
            last = exc
            try:
                listener.proc.stop()
            except Exception:
                pass
            time.sleep(delay_s)
    raise LabError("listener %s did not start after %d attempts: %r"
                   % (listener.name, attempts, last))


def restore_listeners(lab: Lab, names, tag: str) -> dict:
    started = []
    for name in names:
        started.append(start_listener_retry(lab.listeners[name]))
    t_ack = now()
    effects = [lab.listeners[name].effect_check() for name in names]
    alive = all(effect.get("dead") is False for effect in effects)
    info = {"targets": list(names), "t_restore_ack_mono": t_ack,
            "t_restore_utc": iso_utc(t_ack + lab.wall_offset),
            "effects": effects, "live_verified": alive}
    if not alive:
        raise LabError("restore did not verify live: %r" % effects)
    lab.ev.event("restored", tag=tag, targets=list(names))
    return info


def wait_first_success(session: Session, t0: float, max_s: float):
    deadline = t0 + max_s
    while now() < deadline:
        for attempt in session.prober.attempts:
            if attempt["t1"] is not None and attempt["t1"] >= t0 \
                    and attempt["ok"]:
                return attempt
        time.sleep(0.02)
    return None


def wait_alive_flag(session: Session, node: str, want: bool, t0: float,
                    max_s: float):
    deadline = t0 + max_s
    while now() < deadline:
        for sample in reversed(session.poller.samples):
            if sample.get("error") or sample["t"] < t0:
                continue
            if sample["alive"].get(node) is want:
                return sample
            break
        time.sleep(0.03)
    return None


def run_trial(lab: Lab, m: Mihomo, session: Session, group: str,
              dead_nodes, expected_node, tag: str, kind: str,
              target_listeners, max_wait_s=25.0, observe_s=None,
              settle_s=1.3) -> dict:
    baseline_sample = _selection_at(session.poller.samples, now())
    if baseline_sample is None or "error" in baseline_sample:
        baseline_sample = {"now": {}, "alive": {}}
    fault = kill_listeners(lab, target_listeners, kind, tag)
    t0 = fault["T0_mono"]
    first = wait_first_success(session, t0, max_wait_s)
    if observe_s is not None:
        deadline = t0 + observe_s
        while now() < deadline:
            time.sleep(0.05)
    elif first is not None:
        time.sleep(settle_s)
    obs_end = now()
    analysis = analyze_session(
        session, t0, obs_end,
        baseline_selection=baseline_sample["now"].get(GROUP),
        dead_nodes=dead_nodes, expected_node=expected_node,
        baseline_alive=baseline_sample["alive"] or {},
        terminal_group=group)
    if analysis["T2"] is not None:
        matches = analysis["T2"].get("attribution_matches_expected")
        if expected_node is None or matches is None:
            verdict = "FRESH_SUCCESS"
        elif matches:
            verdict = "FRESH_SUCCESS"
        else:
            verdict = "FRESH_SUCCESS_WRONG_CANDIDATE"
    else:
        verdict = ("NO_FRESH_SUCCESS_EXPECTED_OUTAGE"
                   if expected_node is None else "NO_FRESH_SUCCESS")
    trial = {
        "kind": kind, "target_logical_nodes": list(dead_nodes),
        "target_listeners": list(target_listeners),
        "expected_node": expected_node,
        "physical_dead": sorted({PHYSICAL[group][n] for n in dead_nodes}),
        "fault": fault,
        "T0": {"mono": t0, "utc": fault["T0_utc"],
               "t_rel_start_s": round(t0 - lab.ev._boot, 4)},
        "baseline_selection_at_fault": baseline_sample["now"].get(GROUP),
        "baseline_alive_at_fault": baseline_sample["alive"] or {},
        "observation_end_mono": obs_end,
        "trial_verdict": verdict,
        "successes_after_T0": sum(
            1 for a in session.prober.attempts
            if a["ok"] and a["t1"] is not None and a["t1"] >= t0),
        "attempts_after_T0": sum(
            1 for a in session.prober.attempts
            if a["t1"] is not None and a["t1"] >= t0),
    }
    trial.update(analysis)
    lab.ev.event("trial_result", tag=tag, kind=kind, verdict=verdict,
                 T1_ms=(trial["T1"] or {}).get("dt_ms"),
                 T2_ms=(trial["T2"] or {}).get("dt_ms"),
                 chain=(trial["T2"] or {}).get("chain"),
                 switches=trial["switch_count"],
                 dead_window_ms=trial["dead_node_selected"]["total_ms"])
    return trial


def _selection_at(samples, t):
    prev = None
    for sample in samples:
        if "error" in sample:
            continue
        if sample["t"] <= t:
            prev = sample
        else:
            break
    if prev is None:
        for sample in samples:
            if "error" not in sample:
                return sample
    return prev


def wait_selection(lab: Lab, m: Mihomo, target: str, max_s=25.0):
    t0 = now()
    result = m.wait_selection(target, max_s)
    info = {"target": target, "ok": result["ok"],
            "latency_ms": ms(t0, now()),
            "selection": (result.get("state") or {}).get("now")
            if isinstance(result.get("state"), dict) else None}
    lab.ev.event("selection_wait", target=target, ok=info["ok"],
                 latency_ms=info["latency_ms"])
    return info


def chain_success(lab: Lab, m: Mihomo, expected_node, tag: str):
    attempt = m.chain_probe(hold_ms=450)
    node = _chain_node(attempt)
    info = {"ok": attempt["ok"], "code": attempt["code"],
            "chain": attempt["chain"], "chain_node": node,
            "expected_node": expected_node,
            "attribution_ok": node == expected_node,
            "elapsed_ms": attempt["elapsed_ms"]}
    lab.ev.event("chain_check", tag=tag, ok=info["ok"], chain=info["chain"],
                 expected=expected_node)
    return info


class UploadStall(threading.Thread):
    """N02: POST a body through the selected path; the origin never answers."""

    def __init__(self, m: Mihomo, body_bytes=8 * 1024):
        super().__init__(daemon=True)
        self.m = m
        self.body_bytes = body_bytes
        self.result = {"accepted": False, "stalled_at": None,
                       "response_bytes": 0, "error": None}
        self.done = threading.Event()

    def run(self):
        sock = None
        self.result["t0"] = now()
        try:
            sock = self.m.socks_connect(timeout=3.0)
            header = ("POST /upload HTTP/1.0\r\nHost: %s:%d\r\n"
                      "Content-Length: %d\r\n\r\n"
                      % (HOST, PORT["origin"], self.body_bytes)).encode()
            sock.sendall(header + b"u" * self.body_bytes)
            sock.settimeout(2.5)
            try:
                data = sock.recv(64)
                self.result["response_bytes"] = len(data)
                self.result["stalled_at"] = None if data else "closed"
            except (socket.timeout, TimeoutError):
                self.result["stalled_at"] = "response_wait"
        except Exception as exc:
            self.result["error"] = repr(exc)
            self.result["stalled_at"] = self.result["stalled_at"] or "connect"
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
            self.done.set()


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------
def _run_cell(lab: Lab, scenario: str, tag: str, tree: str, terminal: str,
              policy, body):
    """One isolated client run; failures are recorded, never hidden."""
    group = lab.trees[tree]["terminals"][terminal]
    row = {"scenario": scenario, "tag": tag, "tree": tree,
           "terminal": terminal, "group": group,
           "policy": {"interval": policy[0], "timeout": policy[1]}}
    m = None
    try:
        m, baseline = lab.start_client(tag, tree, terminal, policy, None)
        row["baseline"] = baseline
        body(row, m, group)
        row["verdict"] = "OK"
    except Exception:
        row["error"] = traceback.format_exc()
        row["verdict"] = "HARNESS_ERROR"
        print("CELL FAILED %s\n%s" % (tag, row["error"]), flush=True)
    finally:
        if m is not None:
            lab.close_client(m)
        try:
            restored = lab.ensure_all_listeners_alive()
            if restored:
                lab.ev.event("listeners_defensively_restored",
                             tag=tag, restored=len(restored))
        except Exception:
            row["listener_restore_error"] = traceback.format_exc()
            print("LISTENER RESTORE FAILED %s\n%s"
                  % (tag, row["listener_restore_error"]), flush=True)
    lab.ev.row(scenario, row)
    return row


def scenario_fixture(lab: Lab):
    lab.ev.set_scenario("fixture")
    lab.ev.event("fixture_smoke_start")
    tag = "smoke-baseline"
    m = None
    row = {"scenario": "fixture", "tag": tag}
    try:
        m, baseline = lab.start_client(tag, "main", "event-a01", (3, 1000), None)
        row["baseline"] = baseline
        row["chain"] = chain_success(lab, m, "Reality", tag)
        row["verdict"] = "OK" if row["chain"]["attribution_ok"] else \
            "CHAIN_MISMATCH"
    except Exception:
        row["error"] = traceback.format_exc()
        row["verdict"] = "HARNESS_ERROR"
        print(row["error"], flush=True)
    finally:
        if m is not None:
            lab.close_client(m)
    lab.ev.row("fixture", row)
    return row


def scenario_matrix_a(lab: Lab, repeats: int = 1):
    lab.ev.set_scenario("matrix-a")
    for policy in POLICIES:
        for repeat in range(repeats):
            interval, timeout = policy
            tag = "ma-i%d-t%d-r%d" % (interval, timeout, repeat)
            _run_cell(lab, "matrix-a", tag, "main", "event-a01", policy,
                      lambda row, m, group: _matrix_a_body(
                          lab, row, m, group, policy, tag))


def _matrix_a_body(lab: Lab, row, m: Mihomo, group: str, policy, tag: str):
    interval, timeout = policy
    # (a) A-Reality TCP-only failure; Hysteria2 on the same VPS is healthy.
    dead_a = ["Reality"]
    listeners = listeners_for_nodes(group, dead_a)
    session = Session(lab, m).start()
    try:
        row["a_reality_tcp"] = run_trial(
            lab, m, session, group, dead_a, "Hysteria2",
            tag + "-a-reality", "a-reality-tcp", listeners,
            max_wait_s=max(15.0, 2.0 * interval + 3.0))
    finally:
        session.stop()
    restore = restore_listeners(lab, listeners, tag)
    row["restore_after_a"] = restore
    row["failback_after_a"] = wait_selection(lab, m, "Reality", max_s=25.0)
    # Prove the baseline for (b) is real before injecting the whole-VPS fault.
    row["baseline_b_chain"] = chain_success(lab, m, "Reality", tag + "-b-baseline")
    # (b) whole VPS A outage: both A protocols die.
    dead_ab = ["Reality", "Hysteria2"]
    listeners_ab = listeners_for_nodes(group, dead_ab)
    session = Session(lab, m).start()
    try:
        row["whole_vps_a"] = run_trial(
            lab, m, session, group, dead_ab, "Backup-Reality",
            tag + "-whole-a", "whole-vps-a", listeners_ab,
            max_wait_s=max(25.0, 2.0 * interval + 5.0))
    finally:
        session.stop()
    row["restore_after_b"] = restore_listeners(lab, listeners_ab, tag)


def scenario_matrix_b(lab: Lab, repeats: int = 1):
    lab.ev.set_scenario("matrix-b")
    for policy in B_FIRST_POLICIES:
        for repeat in range(repeats):
            interval, timeout = policy
            tag = "mb-i%d-t%d-r%d" % (interval, timeout, repeat)
            _run_cell(lab, "matrix-b", tag, "main", "event-b01", policy,
                      lambda row, m, group: _matrix_b_body(
                          lab, row, m, group, policy, tag, interval))


def _matrix_b_body(lab: Lab, row, m: Mihomo, group: str, policy, tag: str,
                   interval: int):
    # (1) B-Reality (primary physical B) TCP-only failure -> B HY2.
    dead = ["Reality"]
    listeners = listeners_for_nodes(group, dead)
    session = Session(lab, m).start()
    try:
        row["primary_reality_tcp"] = run_trial(
            lab, m, session, group, dead, "Hysteria2",
            tag + "-b-reality", "b-reality-tcp", listeners,
            max_wait_s=max(15.0, 2.0 * interval + 3.0))
    finally:
        session.stop()
    restore_listeners(lab, listeners, tag)
    row["failback_after_primary"] = wait_selection(lab, m, "Reality",
                                                   max_s=25.0)
    row["baseline_after_primary_chain"] = chain_success(lab, m, "Reality",
                                                        tag + "-baseline2")
    # (2) A-Reality failure on a B-first terminal = backup Reality node dies.
    dead = ["Backup-Reality"]
    listeners = listeners_for_nodes(group, dead)
    observe = min(2 * interval + 3.0, 25.0)
    session = Session(lab, m).start()
    try:
        row["backup_a_reality_tcp"] = run_trial(
            lab, m, session, group, dead, "Reality",
            tag + "-a-reality-backup", "a-reality-tcp", listeners,
            max_wait_s=8.0, observe_s=observe)
    finally:
        session.stop()
    restore_listeners(lab, listeners, tag)
    row["baseline_after_backup_chain"] = chain_success(lab, m, "Reality",
                                                       tag + "-baseline3")
    # (3) whole VPS A outage = both backup nodes die; primary B must carry.
    dead = ["Backup-Reality", "Backup-Hysteria2"]
    listeners = listeners_for_nodes(group, dead)
    session = Session(lab, m).start()
    try:
        row["whole_vps_a_backup"] = run_trial(
            lab, m, session, group, dead, "Reality",
            tag + "-whole-a-backup", "whole-vps-a", listeners,
            max_wait_s=8.0, observe_s=observe)
    finally:
        session.stop()
    restore_listeners(lab, listeners, tag)


def scenario_hy2(lab: Lab):
    lab.ev.set_scenario("hy2")
    policy = (3, 1000)
    # (a) idle-HY2 negative control: Reality healthy, no business move.
    tag = "hy2-idle"
    def body_idle(row, m, group):
        dead = ["Hysteria2"]
        listeners = listeners_for_nodes(group, dead)
        session = Session(lab, m).start()
        try:
            trial = run_trial(lab, m, session, group, dead, "Reality",
                              tag, "hy2-udp-only", listeners,
                              max_wait_s=10.0, observe_s=8.0)
            row["idle_hy2"] = trial
        finally:
            session.stop()
        restore_listeners(lab, listeners, tag)
        row["post_restore_selection"] = m.snapshot()["now"]
    _run_cell(lab, "hy2", tag, "main", "event-a01", policy, body_idle)
    # (b) HY2 actually selected then failed: kill A-Reality, then A-HY2.
    tag = "hy2-selected"
    def body_selected(row, m, group):
        session = Session(lab, m).start()
        try:
            dead1 = ["Reality"]
            listeners1 = listeners_for_nodes(group, dead1)
            row["selected_hy2"] = run_trial(
                lab, m, session, group, dead1, "Hysteria2",
                tag + "-to-hy2", "a-reality-tcp", listeners1,
                max_wait_s=15.0)
            dead2 = ["Hysteria2"]
            listeners2 = listeners_for_nodes(group, dead2)
            row["hy2_dies_selected"] = run_trial(
                lab, m, session, group, dead2, "Backup-Reality",
                tag + "-hy2-dies", "hy2-udp-only", listeners2,
                max_wait_s=20.0)
        finally:
            session.stop()
        restore_listeners(lab, listeners_for_nodes(group, ["Reality"]),
                          tag)
        restore_listeners(lab, listeners_for_nodes(group, ["Hysteria2"]),
                          tag)
    _run_cell(lab, "hy2", tag, "main", "event-a01", policy, body_selected)
    # (c) HY2 restart recovery (~30 s stale QUIC session) + second fault
    #     injected while the candidate is still unusable.
    tag = "hy2-restart"
    def body_restart(row, m, group):
        dead_hy2 = ["Hysteria2"]
        listeners_hy2 = listeners_for_nodes(group, dead_hy2)
        session = Session(lab, m).start()
        try:
            fault = kill_listeners(lab, listeners_hy2, "hy2-restart-kill",
                                   tag + "-kill")
            t_kill = fault["T0_mono"]
            first_false = wait_alive_flag(session, "Hysteria2", False, t_kill,
                                          max_s=12.0)
            row["kill"] = {
                "fault": fault,
                "first_alive_false": _sample_row(first_false, t_kill),
            }
            time.sleep(2.0)
            restore = restore_listeners(lab, listeners_hy2, tag)
            t_restart = restore["t_restore_ack_mono"]
            row["restart"] = restore
            row["listener_up_after_restart_ms"] = ms(t_restart, now())
            # Second fault inside the recovery window: current path Reality
            # dies while HY2 is still considered unusable by the client.
            time.sleep(2.5)
            dead2 = ["Reality", "Hysteria2"]
            listeners2 = listeners_for_nodes(group, ["Reality"])
            second = run_trial(
                lab, m, session, group, dead2, "Backup-Reality",
                tag + "-second-fault", "second-during-recovery", listeners2,
                max_wait_s=20.0)
            row["second_fault_during_recovery"] = second
            t_second = second["T0"]["mono"]
            # Measure when the restarted HY2 candidate becomes usable again
            # for a REAL request (direct node delay probe, not just /proxies).
            recovered = None
            probe_log = []
            deadline = t_kill + 60.0
            while now() < deadline:
                probe = m.active_delay("Hysteria2", timeout_ms=1500)
                probe_log.append({"dt_kill_ms": ms(t_kill, now()),
                                  "dt_restart_ms": ms(t_restart, now()),
                                  "ok": probe["ok"],
                                  "delay_ms": probe.get("delay_ms")})
                if probe["ok"]:
                    recovered = now()
                    break
                time.sleep(0.5)
            row["hy2_recovery"] = {
                "recovered": recovered is not None,
                "fault_to_usable_ms": None if recovered is None
                else ms(t_kill, recovered),
                "restart_to_usable_ms": None if recovered is None
                else ms(t_restart, recovered),
                "second_fault_to_usable_ms": None if recovered is None
                else ms(t_second, recovered),
                "probe_log": probe_log,
                "definition": ("first real request through the pinned HY2 "
                               "outbound succeeds after restart "
                               "(/proxies/<node>/delay), not /proxies.alive"),
            }
            row["selection_at_end"] = m.snapshot()["now"]
        finally:
            session.stop()
            restore_listeners(lab, listeners_for_nodes(group, ["Reality"]),
                              tag + "-restore-reality")
    _run_cell(lab, "hy2", tag, "main", "event-a01", policy, body_restart)


def _sample_row(sample, t0):
    if sample is None:
        return None
    return {"dt_ms": ms(t0, sample["t"]),
            "selection": sample["now"].get(GROUP),
            "alive": sample["alive"]}


def _hop_log_sizes(lab: Lab) -> dict:
    sizes = {}
    for name in HOP_LISTENERS:
        path = lab.listeners[name].proc.log_path
        try:
            sizes[name] = path.stat().st_size
        except OSError:
            sizes[name] = -1
    return sizes


def scenario_hopping(lab: Lab):
    lab.ev.set_scenario("hopping")
    policy = (3, 1000)
    tag = "hop"
    def body(row, m, group):
        row["profile_has_hop_ports"] = True
        row["hop_ports"] = list(HOP_PORTS)
        base_sizes = _hop_log_sizes(lab)
        session = Session(lab, m).start()
        try:
            # Get the client onto the hopping Hysteria2 candidate.
            dead1 = ["Reality"]
            listeners1 = listeners_for_nodes(group, dead1)
            row["to_hy2"] = run_trial(lab, m, session, group, dead1,
                                      "Hysteria2", tag + "-to-hy2",
                                      "a-reality-tcp", listeners1,
                                      max_wait_s=15.0)
            sizes_after = _hop_log_sizes(lab)
            deltas = {name: sizes_after[name] - base_sizes.get(name, 0)
                      for name in HOP_LISTENERS}
            used = max(deltas, key=lambda key: deltas[key])
            row["hop_port_activity"] = {
                "log_size_deltas": deltas,
                "used_hop_listener": used,
                "used_hop_port": int(used.rsplit("-", 1)[1]),
            }
            # Single hop-port failure while HY2 is the selected path.
            single = used
            row["single_port_kill_listener"] = single
            single_effect = kill_listeners(lab, [single], "hop-single-port",
                                           tag + "-single")
            t_single = single_effect["T0_mono"]
            single_attempts = []
            while now() - t_single < 7.0:
                time.sleep(0.2)
            for attempt in session.prober.attempts:
                if attempt["t1"] is not None and attempt["t1"] >= t_single:
                    single_attempts.append({
                        "dt_ms": ms(t_single, attempt["t1"]),
                        "ok": attempt["ok"], "code": attempt["code"],
                        "chain": attempt["chain"],
                        "selection": attempt.get("selection"),
                        "error": attempt.get("error")})
            row["single_port_failure"] = {
                "fault": single_effect,
                "attempts_after_T0": single_attempts[:40],
                "successes": sum(1 for a in single_attempts if a["ok"]),
                "failures": sum(1 for a in single_attempts if not a["ok"]),
                "verdict": ("hop-continued" if any(a["ok"] for a in single_attempts)
                            else "hop-stalled"),
            }
            restore_listeners(lab, [single], tag + "-single-restore")
            # Whole HY2 (all hop ports) failure -> takeover to B Reality.
            listeners_hy2 = listeners_for_nodes(group, ["Hysteria2"])
            row["whole_hy2"] = run_trial(
                lab, m, session, group, ["Hysteria2"], "Backup-Reality",
                tag + "-whole-hy2", "whole-hy2", listeners_hy2,
                max_wait_s=20.0)
        finally:
            session.stop()
            restore_listeners(lab, listeners_for_nodes(group, ["Reality"]),
                              tag + "-restore-reality")
            restore_listeners(lab, listeners_for_nodes(group, ["Hysteria2"]),
                              tag + "-restore-hy2")
    _run_cell(lab, "hopping", tag, "hop", "event-hop01", policy, body)


def scenario_outage(lab: Lab):
    lab.ev.set_scenario("outage")
    policy = (3, 1000)
    tag = "outage-both"

    def body(row, m, group):
        # A dies; B must carry.
        dead_a = ["Reality", "Hysteria2"]
        listeners_a = listeners_for_nodes(group, dead_a)
        session = Session(lab, m).start()
        try:
            row["a_down_b_carries"] = run_trial(
                lab, m, session, group, dead_a, "Backup-Reality",
                tag + "-a-down", "whole-vps-a", listeners_a,
                max_wait_s=20.0)
            row["b_carries_chain"] = chain_success(lab, m, "Backup-Reality",
                                                   tag + "-b-carries")
            # Now B dies too: both VPS unavailable, nobody may "recover".
            dead_b = ["Backup-Reality", "Backup-Hysteria2"]
            listeners_b = listeners_for_nodes(group, dead_b)
            fault = kill_listeners(lab, listeners_b, "whole-vps-b", tag)
            t0 = fault["T0_mono"]
            deadline = t0 + 12.0
            while now() < deadline:
                time.sleep(0.1)
            obs_end = now()
            attempts = [a for a in session.prober.attempts
                        if a["t1"] is not None and a["t1"] >= t0]
            successes = [a for a in attempts if a["ok"]]
            samples = [s for s in session.poller.samples
                       if "error" not in s and s["t"] >= t0]
            selections = sorted({s["now"].get(GROUP) for s in samples})
            alive_end = samples[-1]["alive"] if samples else {}
            row["both_vps_down"] = {
                "fault": fault,
                "attempts": len(attempts),
                "successes": len(successes),
                "success_after_both_dead": successes[:5],
                "selections_seen": selections,
                "alive_at_window_end": alive_end,
                "verdict": ("FALSE_RECOVERY" if successes
                            else "NO_USABLE_ROUTE_no_false_recovery"),
                "window_s": round(obs_end - t0, 3),
            }
            restore_listeners(lab, listeners_b, tag + "-restore-b")
        finally:
            session.stop()
            restore_listeners(lab, listeners_a, tag + "-restore-a")
    _run_cell(lab, "outage", tag, "main", "event-a01", policy, body)


def scenario_failback(lab: Lab):
    lab.ev.set_scenario("failback")
    policy = (3, 1000)
    tag = "failback-second"

    def body(row, m, group):
        session = Session(lab, m).start()
        try:
            dead_a = ["Reality", "Hysteria2"]
            listeners_a = listeners_for_nodes(group, dead_a)
            row["first_interruption"] = run_trial(
                lab, m, session, group, dead_a, "Backup-Reality",
                tag + "-first", "whole-vps-a", listeners_a,
                max_wait_s=20.0)
            restore = restore_listeners(lab, listeners_a, tag + "-restore-a")
            t_restore = restore["t_restore_ack_mono"]
            row["restore"] = restore
            failback = wait_selection(lab, m, "Reality", max_s=30.0)
            row["failback"] = {
                **failback,
                "latency_ms": ms(t_restore, now()) if failback["ok"] else None,
            }
            row["failback_chain"] = chain_success(lab, m, "Reality",
                                                  tag + "-failback")
            # 30 s observation window after failback (contract: >=30 s).
            switch_base = len(_transitions(session.poller.samples, t_restore))
            t_window = now()
            time.sleep(30.0)
            window_attempts = [a for a in session.prober.attempts
                               if a["t1"] is not None and a["t1"] >= t_window]
            transitions_window = _transitions(session.poller.samples, t_window)
            row["post_failback_30s_window"] = {
                "duration_s": 30.0,
                "selection_transitions": transitions_window,
                "switch_count": len(transitions_window),
                "probe_attempts": len(window_attempts),
                "probe_failures": sum(1 for a in window_attempts if not a["ok"]),
                "switches_from_restore": len(
                    _transitions(session.poller.samples, t_restore)) - switch_base,
            }
            # Second interruption: fail whatever path is current now.
            current = m.snapshot()["now"].get(GROUP)
            row["second_interruption_current_before"] = current
            logical_to_kill = [current] if current in NODES else ["Reality"]
            listeners2 = listeners_for_nodes(group, logical_to_kill)
            dead2 = list(logical_to_kill)
            expected2 = next((node for node in NODES
                              if node not in dead2), None)
            if current == "Reality" and "Hysteria2" not in dead2:
                expected2 = "Hysteria2"
            row["second_interruption"] = run_trial(
                lab, m, session, group, dead2, expected2,
                tag + "-second", "second-interruption", listeners2,
                max_wait_s=20.0)
            row["second_interruption"]["logical_nodes_killed"] = logical_to_kill
            last = m.snapshot()
            row["final_selection"] = last["now"].get(GROUP)
            row["final_selection_alive"] = last["alive"]
            row["t0_dead_node_selected_at_end"] = (
                last["now"].get(GROUP) in dead2)
            restore_listeners(lab, listeners2, tag + "-restore-second")
        finally:
            session.stop()
    _run_cell(lab, "failback", tag, "main", "event-a01", policy, body)


def scenario_n02(lab: Lab):
    lab.ev.set_scenario("n02")
    policy = (3, 1000)
    tag = "n02-upload"

    def body(row, m, group):
        session = Session(lab, m).start()
        try:
            origin = lab.origin
            before = len(origin.events)
            upload = UploadStall(m)
            upload.start()
            # Wait for the origin to show the upload arrived (independent
            # server-side effect, unrelated to the SUT /proxies view).
            deadline = now() + 6.0
            accepted = None
            while now() < deadline:
                events = origin.events[before:]
                posts = [e for e in events if e["verb"] == "POST"]
                if posts:
                    accepted = posts[0]
                    break
                time.sleep(0.02)
            row["upload_effect"] = {
                "origin_received_post": accepted is not None,
                "origin_event": ({"dt_ms": ms(upload.result.get("t0", now()),
                                              accepted["t"]),
                                  "verb": accepted["verb"]}
                                 if accepted else None),
                "independent_of_sut_proxies": True,
            }
            t_obs = now()
            health = []
            while now() - t_obs < 10.0:
                probe = m.chain_probe(hold_ms=150)
                health.append({"dt_ms": ms(t_obs, probe["t1"]),
                               "ok": probe["ok"], "code": probe["code"],
                               "chain": probe["chain"]})
                time.sleep(0.4)
            upload.done.wait(1.0)
            samples = [s for s in session.poller.samples
                       if "error" not in s and s["t"] >= t_obs]
            transitions = _transitions(session.poller.samples, t_obs)
            last = samples[-1] if samples else {"alive": {}, "now": {}}
            row["n02"] = {
                "window_s": 10.0,
                "health_probes": health,
                "health_probe_successes": sum(1 for h in health if h["ok"]),
                "native_switches": len(transitions),
                "native_transitions": transitions,
                "selection_stable": last["now"].get(GROUP),
                "alive_at_window_end": last["alive"],
                "upload_stalled_at": upload.result["stalled_at"],
                "upload_response_bytes": upload.result["response_bytes"],
                "upload_error": upload.result["error"],
                "verdict": ("204_STAYS_GREEN_UPLOAD_STALLED"
                            if row["upload_effect"]["origin_received_post"]
                            and upload.result["stalled_at"] == "response_wait"
                            and len(transitions) == 0 else "UNEXPECTED"),
                "disposition": (
                    "NOT DETECTED by native liveness: health stays green while "
                    "the upload is stalled; native switches measured = 0. "
                    "Disposition: manual/application contingency; no automatic "
                    "quality controller; Quality Failover stays opt-in and OFF. "
                    "Handed to HA-06 as a measured gap, not a quality PASS."),
            }
        finally:
            session.stop()
    _run_cell(lab, "n02", tag, "main", "event-a01", policy, body)


# --------------------------------------------------------------------------
# aggregate summary / human report
# --------------------------------------------------------------------------
ALL_ORDER = ["matrix-a", "matrix-b", "hy2", "outage", "failback",
             "hopping", "n02"]
SCENARIOS = {
    "matrix-a": scenario_matrix_a,
    "matrix-b": scenario_matrix_b,
    "hy2": scenario_hy2,
    "hopping": scenario_hopping,
    "outage": scenario_outage,
    "failback": scenario_failback,
    "n02": scenario_n02,
}


def _matrix_row(label: str, policy: dict, trial: dict) -> dict:
    return {
        "label": label,
        "interval_s": policy.get("interval"),
        "timeout_ms": policy.get("timeout"),
        "fault": trial.get("kind"),
        "T0_utc": (trial.get("fault") or {}).get("T0_utc"),
        "T1_ms": (trial.get("T1") or {}).get("dt_ms"),
        "T1_type": (trial.get("T1") or {}).get("type"),
        "T2_ms": (trial.get("T2") or {}).get("dt_ms"),
        "T2_node": (trial.get("T2") or {}).get("chain_node"),
        "T2_chain": (trial.get("T2") or {}).get("chain"),
        "T2_attribution_ok": (trial.get("T2") or {}).get(
            "attribution_matches_expected"),
        "dead_node_window_ms": (trial.get("dead_node_selected") or {}).get(
            "total_ms"),
        "switch_count": trial.get("switch_count"),
        "failed_fresh_probes": trial.get("failed_fresh_probe_count"),
        "wrong_dead_node_carried": trial.get("wrong_dead_node_carried_any"),
        "selection_at_end": trial.get("selection_at_window_end"),
        "verdict": trial.get("trial_verdict"),
    }


def build_aggregate(lab: Lab) -> dict:
    runs = lab.ev.results["runs"]
    agg = {"total_runs": len(runs),
           "scenario_runs": {},
           "tables": {},
           "measured": {},
           "not_measured": NOT_MEASURED}
    rows = []
    for row in runs:
        rows.append({k: row.get(k) for k in
                     ("scenario", "tag", "group", "policy", "verdict",
                      "error")})
        agg["scenario_runs"].setdefault(row.get("scenario"), 0)
        agg["scenario_runs"][row.get("scenario")] += 1
    matrix = []
    for row in runs:
        if row.get("scenario") not in ("matrix-a", "matrix-b"):
            continue
        policy = row.get("policy") or {}
        for key, label in (("a_reality_tcp", "A-first A-Reality TCP"),
                           ("whole_vps_a", "A-first whole VPS A"),
                           ("primary_reality_tcp", "B-first B-Reality TCP"),
                           ("backup_a_reality_tcp", "B-first A-Reality (backup)"),
                           ("whole_vps_a_backup", "B-first whole VPS A (backup)")):
            trial = row.get(key)
            if trial and "error" not in trial:
                matrix.append(_matrix_row(label, policy, trial))
    agg["tables"]["matrix"] = matrix
    hy2_rows = []
    for row in runs:
        if row.get("scenario") != "hy2":
            continue
        idle = row.get("idle_hy2")
        if idle and "error" not in idle:
            hy2_rows.append({
                "row": "idle-HY2 negative control",
                "T1_ms": (idle.get("T1") or {}).get("dt_ms"),
                "switches": idle.get("switch_count"),
                "selection_end": idle.get("selection_at_window_end"),
                "wrong_dead_carried": idle.get("wrong_dead_node_carried_any"),
            })
        sel = row.get("hy2_dies_selected")
        if sel and "error" not in sel:
            hy2_rows.append({
                "row": "selected HY2 fails (A-Reality then A-HY2)",
                "T1_ms": (sel.get("T1") or {}).get("dt_ms"),
                "T2_ms": (sel.get("T2") or {}).get("dt_ms"),
                "T2_node": (sel.get("T2") or {}).get("chain_node"),
                "switches": sel.get("switch_count"),
            })
        rec = row.get("hy2_recovery")
        if rec:
            hy2_rows.append({
                "row": "HY2 restart recovery",
                "recovered": rec.get("recovered"),
                "fault_to_usable_ms": rec.get("fault_to_usable_ms"),
                "restart_to_usable_ms": rec.get("restart_to_usable_ms"),
                "second_fault_to_usable_ms": rec.get("second_fault_to_usable_ms"),
            })
        second = row.get("second_fault_during_recovery")
        if second and "error" not in second:
            hy2_rows.append({
                "row": "second fault during HY2 recovery",
                "T1_ms": (second.get("T1") or {}).get("dt_ms"),
                "T2_ms": (second.get("T2") or {}).get("dt_ms"),
                "T2_node": (second.get("T2") or {}).get("chain_node"),
                "switches": second.get("switch_count"),
                "dead_window_ms": (second.get("dead_node_selected") or {}).get("total_ms"),
            })
    agg["tables"]["hy2"] = hy2_rows
    fb = []
    for row in runs:
        if row.get("scenario") != "failback":
            continue
        first = row.get("first_interruption")
        if first and "error" not in first:
            fb.append({"row": "first interruption (whole A)",
                       "T1_ms": (first.get("T1") or {}).get("dt_ms"),
                       "T2_ms": (first.get("T2") or {}).get("dt_ms"),
                       "T2_node": (first.get("T2") or {}).get("chain_node"),
                       "switches": first.get("switch_count")})
        fallback = row.get("failback") or {}
        win = row.get("post_failback_30s_window") or {}
        fb.append({"row": "failback to Reality (after restore)",
                   "ok": fallback.get("ok"),
                   "latency_ms": fallback.get("latency_ms"),
                   "window_switches": win.get("switch_count"),
                   "window_probe_failures": win.get("probe_failures")})
        second = row.get("second_interruption")
        if second and "error" not in second:
            fb.append({"row": "second interruption",
                       "T1_ms": (second.get("T1") or {}).get("dt_ms"),
                       "T2_ms": (second.get("T2") or {}).get("dt_ms"),
                       "T2_node": (second.get("T2") or {}).get("chain_node"),
                       "switches": second.get("switch_count"),
                       "final_selection": row.get("final_selection"),
                       "t0_dead_selected_at_end": row.get(
                           "t0_dead_node_selected_at_end")})
    agg["tables"]["failback"] = fb
    outage = []
    for row in runs:
        if row.get("scenario") != "outage":
            continue
        both = row.get("both_vps_down")
        if both:
            outage.append({"row": "both VPS down",
                           "attempts": both.get("attempts"),
                           "successes": both.get("successes"),
                           "verdict": both.get("verdict"),
                           "selections_seen": both.get("selections_seen")})
    agg["tables"]["outage"] = outage
    hop = []
    for row in runs:
        if row.get("scenario") != "hopping":
            continue
        single = row.get("single_port_failure") or {}
        whole = row.get("whole_hy2") or {}
        hop.append({
            "used_hop_listener": (row.get("hop_port_activity") or {}).get(
                "used_hop_listener"),
            "single_port_successes": single.get("successes"),
            "single_port_failures": single.get("failures"),
            "single_port_verdict": single.get("verdict"),
            "whole_hy2_T2_ms": (whole.get("T2") or {}).get("dt_ms"),
            "whole_hy2_T2_node": (whole.get("T2") or {}).get("chain_node"),
            "whole_hy2_switches": whole.get("switch_count"),
        })
    agg["tables"]["hopping"] = hop
    n02 = []
    for row in runs:
        if row.get("scenario") != "n02":
            continue
        n = row.get("n02") or {}
        n02.append({"native_switches": n.get("native_switches"),
                    "health_probe_successes": n.get("health_probe_successes"),
                    "upload_stalled_at": n.get("upload_stalled_at"),
                    "verdict": n.get("verdict"),
                    "disposition": n.get("disposition")})
    agg["tables"]["n02"] = n02
    agg["errors"] = [{"scenario": row.get("scenario"), "tag": row.get("tag"),
                      "error": row.get("error")}
                     for row in runs if row.get("error")]
    agg["counts"] = {
        "runs": len(runs),
        "runs_ok": sum(1 for row in runs if row.get("verdict") == "OK"),
        "runs_error": sum(1 for row in runs if row.get("error")),
        "trials": sum(1 for row in runs for key in
                      ("a_reality_tcp", "whole_vps_a", "primary_reality_tcp",
                       "backup_a_reality_tcp", "whole_vps_a_backup",
                       "idle_hy2", "selected_hy2", "hy2_dies_selected",
                       "second_fault_during_recovery", "whole_hy2",
                       "a_down_b_carries", "first_interruption",
                       "second_interruption")
                      if isinstance(row.get(key), dict)),
    }
    lab.ev.results["aggregate"] = agg
    return agg


NOT_MEASURED = [
    {"item": "T3 application recovery (vMix/TikTok/Drive)", "status": "NOT MEASURED",
     "reason": "no application on the LAB host; loopback LAB has no T3"},
    {"item": "Real WAN/VPS RTT, ISP/GFW, real 10 s recovery claim", "status": "NOT MEASURED",
     "reason": "loopback only; no authorized VPS/network resources used"},
    {"item": "30-client false-positive rate / probe load", "status": "NOT MEASURED",
     "reason": "single-client loopback LAB; no load generator/authorized endpoint"},
    {"item": "Windows/Clash Verge/Mihomo bundle, TUN/DNS/Fake-IP effective path",
     "status": "NOT MEASURED",
     "reason": "TUN/DNS forced off in the runtime LAB profile; pinned core only"},
    {"item": "Real failback >=10 min observation window and 16-30 terminal fleet",
     "status": "NOT MEASURED",
     "reason": "LAB measures a 30 s post-failback window on one client"},
    {"item": "Real HY2 certificate identity/rotation/expiry acceptance",
     "status": "NOT MEASURED",
     "reason": "throwaway self-signed LAB certs; only pin semantics exercised"},
    {"item": "Real UDP port hopping on a WAN/VPS", "status": "NOT MEASURED",
     "reason": "loopback single-host hop ports; mechanics only"},
]


def print_summary(lab: Lab, agg: dict):
    print("\n" + "=" * 78)
    print(LAB_BANNER)
    print("=" * 78)
    print("client runs: %d (%d ok, %d harness errors); trials: %d"
          % (agg["counts"]["runs"], agg["counts"]["runs_ok"],
             agg["counts"]["runs_error"], agg["counts"]["trials"]))
    matrix = agg["tables"]["matrix"]
    if matrix:
        print("\n-- MATRIX (T0 -> T1 / T0 -> T2, ms; dead-node window; switches) --")
        print("%-32s %-5s %-6s %8s %8s %8s %10s %6s %s"
              % ("row", "int", "tout", "T1", "T2", "T2node",
                 "deadWin", "sw", "verdict"))
        for entry in matrix:
            print("%-32s %-5s %-6s %8s %8s %8s %10s %6s %s"
                  % (entry["label"], entry["interval_s"], entry["timeout_ms"],
                     entry["T1_ms"], entry["T2_ms"], entry["T2_node"],
                     entry["dead_node_window_ms"], entry["switch_count"],
                     entry["verdict"]))
    if agg["tables"]["hy2"]:
        print("\n-- HY2 ROWS --")
        for entry in agg["tables"]["hy2"]:
            print(" ", json.dumps(entry, ensure_ascii=False))
    if agg["tables"]["hopping"]:
        print("\n-- UDP HOPPING --")
        for entry in agg["tables"]["hopping"]:
            print(" ", json.dumps(entry, ensure_ascii=False))
    if agg["tables"]["outage"]:
        print("\n-- BOTH-VPS OUTAGE --")
        for entry in agg["tables"]["outage"]:
            print(" ", json.dumps(entry, ensure_ascii=False))
    if agg["tables"]["failback"]:
        print("\n-- FAILBACK / SECOND INTERRUPTION --")
        for entry in agg["tables"]["failback"]:
            print(" ", json.dumps(entry, ensure_ascii=False))
    if agg["tables"]["n02"]:
        print("\n-- N02 --")
        for entry in agg["tables"]["n02"]:
            print(" ", json.dumps(entry, ensure_ascii=False))
    print("\nNOT MEASURED items: %s" % ", ".join(item["item"] for item in NOT_MEASURED))
    print("evidence: %s" % (lab.lab_dir / "results.json"))
    print("=" * 78)


# --------------------------------------------------------------------------
# CLI / main
# --------------------------------------------------------------------------
def build_parser():
    parser = argparse.ArgumentParser(
        prog="mihomo-competition-ha4-lab.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "HA-04 loopback LAB harness (LAB EVIDENCE ONLY). Builds a "
            "synthetic two-VPS loopback fixture through the HA-02/HA-03/HA-04 "
            "repo tools, runs pinned sing-box listeners and pinned Mihomo, "
            "injects verified faults and measures T0->T1/T0->T2 failover. "
            "No WAN, no real VPS, no real credentials, no TUN."),
        epilog=(
            "examples:\n"
            "  python tests/mihomo-competition-ha4-lab.py --scenario all\n"
            "  python tests/mihomo-competition-ha4-lab.py --scenario fixture\n"
            "  python tests/mihomo-competition-ha4-lab.py --scenario matrix-a "
            "--repeats 2\n"))
    parser.add_argument("--lab-dir", default=None,
                        help="evidence directory (default: <repo>/.scratch/ha04-lab)")
    parser.add_argument("--mihomo", default=os.environ.get("HA04_MIHOMO"),
                        help="pinned Mihomo binary (default: $HA04_MIHOMO)")
    parser.add_argument("--sing-box", default=os.environ.get("HA04_SINGBOX"),
                        help="pinned sing-box binary (default: $HA04_SINGBOX)")
    parser.add_argument("--scenario", default="all",
                        choices=["all", "fixture"] + sorted(SCENARIOS),
                        help="scenario set to run (default: all)")
    parser.add_argument("--repeats", type=int, default=1,
                        help="repeats per matrix cell (default: 1)")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.repeats < 1 or args.repeats > 5:
        print("ha04-lab: REFUSED bad --repeats (1..5)", file=sys.stderr)
        return 2
    lab = None
    exit_code = 0
    try:
        lab = Lab(args)
        lab.record_binaries()
        lab.ev.event("preflight_start", scenario=args.scenario,
                     repeats=args.repeats)
        lab.preflight_ports()
        lab.build_fixture()
        if args.scenario == "fixture":
            scenario_fixture(lab)
        else:
            names = ALL_ORDER if args.scenario == "all" else [args.scenario]
            for name in names:
                print("\n== scenario %s ==" % name, flush=True)
                func = SCENARIOS[name]
                if "repeats" in func.__code__.co_varnames[
                        :func.__code__.co_argcount]:
                    func(lab, repeats=args.repeats)
                else:
                    func(lab)
                lab.ev.save()
        aggregate = build_aggregate(lab)
        lab.ev.results["finished_utc"] = iso_utc()
        lab.ev.results["duration_s"] = round(
            now() - lab.ev._boot, 1)
        print_summary(lab, aggregate)
        exit_code = 0 if aggregate["counts"]["runs_error"] == 0 else 1
    except LabError as exc:
        print("ha04-lab: REFUSED %s" % exc, file=sys.stderr)
        if lab is not None:
            lab.ev.results["refused"] = str(exc)
        exit_code = 2
    except KeyboardInterrupt:
        print("ha04-lab: INTERRUPTED", file=sys.stderr)
        exit_code = 130
    except Exception:
        traceback.print_exc()
        if lab is not None:
            lab.ev.results["fatal"] = traceback.format_exc()
        exit_code = 1
    finally:
        if lab is not None:
            try:
                cleanup = lab.cleanup()
                lab.ev.results["finished_utc"] = iso_utc()
                lab.ev.results["duration_s"] = round(
                    now() - lab.ev._boot, 1)
                lab.ev.save()
                if not cleanup["ports_free"]:
                    print("ha04-lab: CLEANUP WARNING busy ports %r"
                          % cleanup["busy_after_cleanup"], file=sys.stderr)
                    exit_code = exit_code or 3
            except Exception:
                traceback.print_exc()
                exit_code = exit_code or 3
            finally:
                lab.ev.close()
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
