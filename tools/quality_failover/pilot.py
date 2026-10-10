"""Explicit, disposable real-protocol pilot; never attaches to a live Clash core."""
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote

from .config import read_json
from .controller import alive
from .policy import AUTO, GROUP, OUTER, number
from .relay import TCPWire, UDPWire
from .runtime import Runner
from .transport import Probe, decode_json, endpoint, socks_connect


class Cancelled(Exception):
    pass


REASONS = {"binary_digest", "binary", "certificate_digest", "certificate_file", "receiver_info",
           "client_name", "canonical_profile", "canonical_name", "pilot_thresholds", "native_state",
           "isolated_core_unavailable", "local_port_collision", "stage_failed", "session_route",
           "session_migrated", "session_receipt", "session_selection", "session_restore",
           "control_suspended", "hard_failure_setup", "pilot_hopping_too_wide", "result_exists_or_parent_missing"}


def error_code(exception):
    code = exception.args[0] if isinstance(exception, ValueError) and exception.args else None
    return code if type(code) is str and code in REASONS else "preparation_or_acceptance_incomplete"


def private_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def private_directory(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise ValueError("directory_exists")
    path.mkdir(mode=0o700)
    return path.resolve()


def receiver_init(directory, address, port, openssl="openssl"):
    """Run explicitly on the receiver host. No bind, firewall, units or trust writes."""
    address = str(ipaddress.ip_address(address))
    if type(port) is not int or not 1024 <= port <= 65535:
        raise ValueError("receiver_port")
    root = private_directory(directory)
    certificate, key = root / "receiver-ca.pem", root / "receiver-key.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", str(key), "-out", str(certificate), "-days", "7",
                    "-subj", "/CN=p48-disposable-pilot",
                    "-addext", "subjectAltName=IP:" + address], check=True,
                   timeout=30, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    certificate.chmod(0o600)
    token = secrets.token_hex(32)
    configuration = {"v": 1, "listen": "::" if ":" in address else "0.0.0.0",
                     "port": port, "token": token, "certificate": str(certificate),
                     "private_key": str(key), "minute_bytes": 4 * 1024 * 1024}
    host = "[%s]" % address if ":" in address else address
    info = {"v": 1, "endpoint": "https://%s:%s" % (host, port), "token": token,
            "certificate_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest()}
    private_file(root / "receiver.json", json.dumps(configuration).encode())
    private_file(root / "receiver-info.json", json.dumps(info).encode())
    return {"v": 1, "prepared": True, "started": False, "certificate_days": 7}


def receiver_info(info_path, ca_path):
    value = read_json(info_path)
    if (type(value) is not dict or set(value) != {"v", "endpoint", "token", "certificate_sha256"}
            or type(value["v"]) is not int or value["v"] != 1
            or type(value["token"]) is not str or not re.fullmatch(r"[a-zA-Z0-9]{32,128}", value["token"])
            or type(value["certificate_sha256"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", value["certificate_sha256"])):
        raise ValueError("receiver_info")
    endpoint(value["endpoint"])
    path = Path(ca_path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 16384:
        raise ValueError("certificate_file")
    if hashlib.sha256(path.read_bytes()).hexdigest() != value["certificate_sha256"]:
        raise ValueError("certificate_digest")
    ssl.create_default_context(cafile=str(path))
    return value


def pinned_binary(path, digest):
    path = Path(path)
    if (type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or path.is_symlink() or not path.is_file()):
        raise ValueError("binary")
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            hasher.update(block)
    if hasher.hexdigest() != digest:
        raise ValueError("binary_digest")
    return path.resolve()


def module(filename, name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def tcp_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def isolated_profile(profile, prepared, wires, controller_port, mixed_port, secret):
    listeners = prepared[prepared.index("listeners:"):prepared.index("proxies:\n")]
    groups = prepared[prepared.index("proxy-groups:"):prepared.index("rules:\n")]
    # Only the disposable core accelerates native reachability refresh to 5s.
    # Production fallback cadence and original exported file are unchanged.
    groups = groups.replace("    interval: 60", "    interval: 5")
    blocks = []
    for which, wire in zip(("reality", "hysteria"), wires):
        for line in profile.block(which):
            if line.startswith("    server: "):
                line = "    server: 127.0.0.1"
            elif line.startswith("    port: "):
                line = "    port: %d" % wire.port
            elif line.startswith("    ports: "):
                line = "    ports: %d-%d" % wire.port_range
            blocks.append(line)
        blocks.append("")
    return "\n".join([
        "allow-lan: false", "bind-address: 127.0.0.1", "mode: rule", "log-level: silent",
        "ipv6: false", "tun:", "  enable: false", "dns:", "  enable: false",
        "profile:", "  store-selected: false", "  store-fake-ip: false",
        "mixed-port: %d" % mixed_port,
        "external-controller: 127.0.0.1:%d" % controller_port,
        'secret: "%s"' % secret, listeners, "proxies:", *blocks,
        groups, "rules:", "  - MATCH,节点选择", ""])


def ordinary_route(controller, source, host, port, node):
    rows = controller.request("GET", "/connections").get("connections")
    if type(rows) is not list or len(rows) > 4096:
        return False
    found = []
    for row in rows:
        metadata = row.get("metadata", {}) if type(row) is dict else {}
        if metadata.get("sourceIP") == "127.0.0.1" and metadata.get("sourcePort") == str(source):
            chain = row.get("chains", [])
            found.append(metadata.get("destinationIP") == host
                         and metadata.get("destinationPort") == str(port)
                         and node in chain and ("Reality" if node == "Hysteria2" else "Hysteria2") not in chain)
    return found == [True]


def connections_check(runner, mixed_port):
    """Hold one bounded upload across a selection; don't close/migrate old flows."""
    controller, probe = runner.controller, runner.probes["Reality"]
    prior = runner.owner.expected
    if not controller.select("Reality", runner.owner):
        raise ValueError("session_selection")
    sock = socks_connect(mixed_port, probe.host, probe.port, time.monotonic() + 3)
    tls = None
    try:
        sock.settimeout(3)
        tls = probe.context.wrap_socket(sock, server_hostname=probe.host)
        source = tls.getsockname()[1]
        if not ordinary_route(controller, source, probe.host, probe.port, "Reality"):
            raise ValueError("session_route")
        nonce, body = secrets.token_hex(16), b"\0" * 32768
        tls.sendall(("POST /quality-v1/upload HTTP/1.1\r\nHost: pilot\r\n"
                     "Authorization: Bearer %s\r\nX-Probe-Nonce: %s\r\n"
                     "Content-Length: 32768\r\nConnection: close\r\n\r\n" % (probe.token, nonce)).encode())
        tls.sendall(body[:8192])
        if not controller.select("Hysteria2", runner.owner):
            raise ValueError("session_selection")
        if not ordinary_route(controller, source, probe.host, probe.port, "Reality"):
            raise ValueError("session_migrated")
        probe.request(mixed_port, "ready", verifier=lambda port: ordinary_route(
            controller, port, probe.host, probe.port, "Hysteria2"))
        tls.sendall(body[8192:])
        response = http.client.HTTPResponse(tls)
        response.begin()
        receipt = decode_json(response.read(1025))
        if (response.status != 200 or type(receipt) is not dict
                or receipt.get("nonce") != nonce or receipt.get("bytes") != len(body)
                or receipt.get("sha256") != hashlib.sha256(body).hexdigest()):
            raise ValueError("session_receipt")
        if not controller.select(prior, runner.owner):
            raise ValueError("session_restore")
    finally:
        (tls or sock).close()


class Suite:
    def __init__(self, runner, wires, mixed_port, cancel=None, emit=None):
        self.runner, self.wires, self.mixed_port = runner, wires, mixed_port
        self.cancel = cancel or threading.Event()
        self.emit = emit or (lambda record: None)
        self.records = []
        self.started = time.monotonic()
        self.stage = "baseline"
        self.outer_group = OUTER

    def choose_outer(self, node):
        self.runner.controller.request("PUT", "/proxies/" + quote(self.outer_group, safe=""), {"name": node})

    def record(self, stage, passed, states=None):
        value = {"stage": stage, "passed": passed, "elapsed_seconds": round(time.monotonic() - self.started, 1)}
        if states is not None:
            value["paths"] = states
        self.records.append(value)
        self.emit(value)
        if not passed:
            raise ValueError("stage_failed")

    def pause(self, seconds):
        if self.cancel.wait(seconds):
            raise Cancelled()

    def await_native(self, node, up, timeout=20):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            item = self.runner.controller.proxies().get(node, {})
            if alive(item, time.time(), self.runner.engine.policies[node].freshness_seconds) is up:
                return
            self.pause(.5)
        raise ValueError("native_state")

    def cycle(self):
        if self.cancel.is_set():
            raise Cancelled()
        result = self.runner.cycle(confirm=True)
        if result["action"] == "control_suspended":
            raise ValueError("control_suspended")
        return result

    def rounds(self, stage, count, expected):
        self.stage = stage
        result = None
        for index in range(count):
            # Real wall clock, production byte budget and >=30s per-path spacing.
            if index:
                self.pause(30)
            result = self.cycle()
            self.emit({"stage": stage, "sample": index + 1, "paths": result["paths"]})
        self.record(stage, expected(result), result["paths"])

    def execute(self):
        controller = self.runner.controller
        self.await_native("Reality", True)
        self.await_native("Hysteria2", True)
        result = self.cycle()
        verified = all(path.usable(time.monotonic(), self.runner.engine.policies[name])
                       for name, path in self.runner.engine.paths.items())
        self.record("baseline", verified, result["paths"])
        self.choose_outer(GROUP)
        self.pause(30)
        self.wires[0].fault(rate=1)
        self.rounds("reality_degraded", 2, lambda r:
                    r["paths"]["Reality"]["state"] == "DEGRADED"
                    and r["paths"]["Hysteria2"]["state"] == "UP"
                    and controller.proxies()[GROUP].get("now") == "Hysteria2"
                    and controller.proxies()["Reality"].get("alive") is True)
        self.wires[0].fault()
        self.pause(30)
        self.rounds("recovery", 3, lambda r:
                    r["paths"]["Reality"]["state"] == "UP"
                    and controller.proxies()[GROUP].get("now") == "Hysteria2"
                    and controller.proxies()[GROUP].get("fixed") == "Hysteria2")
        self.stage = "existing_and_new_connections"
        self.record(self.stage, connections_check(self.runner, self.mixed_port) is None)
        self.pause(30)
        if not controller.select("Hysteria2", self.runner.owner):
            raise ValueError("hard_failure_setup")
        self.stage = "hy2_hard_failure"
        self.wires[1].fault(up=False)
        self.await_native("Hysteria2", False)
        result = self.cycle()
        self.record("hy2_hard_failure", result["paths"]["Hysteria2"]["state"] == "DOWN"
                    and result["paths"]["Reality"]["state"] == "UP"
                    and controller.proxies()[GROUP].get("now") == "Reality", result["paths"])
        self.wires[1].fault()
        self.stage = "hy2_recovery"
        self.await_native("Hysteria2", True)
        self.pause(30)
        self.rounds("hy2_recovery", 3, lambda r: r["paths"]["Hysteria2"]["state"] == "UP"
                    and controller.proxies()[GROUP].get("now") == "Reality"
                    and controller.proxies()[GROUP].get("fixed") == "Reality")
        self.stage = "manual_override"
        self.choose_outer("Reality")
        result = self.cycle()
        self.record("manual_override", result["action"] == "manual_override"
                    and controller.proxies()[self.outer_group].get("now") == "Reality")
        return self.records


def run_pilot(profile_path, name, info_path, ca_path, binary_path, binary_digest,
              result_path, cancel=None, emit=None, fail_mbps=4, recover_mbps=8):
    if not (number(fail_mbps, 1.5, 10) and number(recover_mbps, 2, 12)
            and fail_mbps < recover_mbps):
        raise ValueError("pilot_thresholds")
    binary = pinned_binary(binary_path, binary_digest)
    info = receiver_info(info_path, ca_path)
    merge = module("mihomo-multi-vps-merge.py", "pilot_canonical_merge")
    cli = module("mihomo-quality-failover.py", "pilot_quality_cli")
    if type(name) is not str or not merge.CLIENT_NAME_RE.fullmatch(name):
        raise ValueError("client_name")
    profile = merge.parse_export(profile_path, lambda: ValueError("canonical_profile"))
    merge.check_provenance(profile_path, name, lambda: ValueError("canonical_name"))
    # DNS cannot be attributed/bounded at this relay boundary. V1 accepts
    # numeric canonical node addresses only rather than rewriting a hostname.
    for fields in (profile.reality, profile.hysteria):
        ipaddress.ip_address(fields["server"])
    output = Path(result_path)
    if output.exists() or output.is_symlink() or not output.parent.is_dir():
        raise ValueError("result_exists_or_parent_missing")
    wires, process, runner, suite = [], None, None, None
    result = {"v": 1, "mode": "isolated_real_protocol_simulated_wire_faults",
              "selection_policy": "retain_healthy_current",
              "passed": False, "cancelled": False, "cleanup_complete": False,
              "real_provider_outage_proven": False, "records": []}
    root = Path(tempfile.mkdtemp(prefix="p48-isolated-")).resolve()
    temporary_parent = root.parent.resolve()
    try:
        wires.append(TCPWire((profile.reality["server"], int(profile.reality["port"]))))
        hopping = profile.hysteria.get("ports")
        wires.append(UDPWire((profile.hysteria["server"], int(profile.hysteria["port"])), hopping))
        controller_port, mixed_port = tcp_port(), tcp_port()
        cfg = {"v": 1, "controller": "http://127.0.0.1:%s" % controller_port,
               "controller_secret": secrets.token_hex(32), "control_enabled": True,
               "cycle_seconds": 5, "probe_interval_seconds": 30,
               "probe_bytes_per_minute": 4 * 1024 * 1024, "churn_connections": 3, "paths": []}
        if controller_port == mixed_port:
            raise ValueError("local_port_collision")
        reserved = {controller_port, mixed_port, wires[0].port}
        for node in ("Reality", "Hysteria2"):
            port = tcp_port()
            if port in reserved:
                raise ValueError("local_port_collision")
            reserved.add(port)
            cfg["paths"].append({"name": node, "listener_port": port,
                "endpoint": info["endpoint"], "token": info["token"], "ca_file": str(Path(ca_path).resolve()),
                "payload_bytes": 524288, "rate_mbps": 20, "timeout_seconds": 15,
                "policy": {"fail_mbps": fail_mbps, "recover_mbps": recover_mbps,
                           "hold_seconds": 30, "freshness_seconds": 90,
                           "fail_samples": 2, "recover_samples": 3}})
        prepared = root / "prepared.yaml"
        cli.prepare(name, profile_path, None, str(prepared), cfg)
        core_config = root / "core.yaml"
        private_file(core_config, isolated_profile(profile, prepared.read_text(encoding="utf-8"),
                     wires, controller_port, mixed_port, cfg["controller_secret"]).encode())
        subprocess.run([str(binary), "-t", "-d", str(root), "-f", str(core_config)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=20)
        process = subprocess.Popen([str(binary), "-d", str(root), "-f", str(core_config)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        runner = Runner(cfg)
        until = time.monotonic() + 15
        while True:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            if process.poll() is not None or time.monotonic() >= until:
                raise ValueError("isolated_core_unavailable")
            try:
                runner.controller.proxies()
                break
            except (OSError, ValueError):
                time.sleep(.2)
        suite = Suite(runner, wires, mixed_port, cancel, emit)
        result["records"] = suite.execute()
        result["passed"] = True
        runner.close()
        runner = None
        process.terminate()
        process.wait(timeout=5)
        process = None
        for wire in wires:
            wire.close()
        wires.clear()
    except (Cancelled, KeyboardInterrupt):
        result["passed"] = False
        result["cancelled"] = True
    except Exception as exception:
        result["passed"] = False
        result["error"] = error_code(exception)
        if suite is not None:
            result["failed_stage"] = suite.stage
    finally:
        if suite is not None:
            result["records"] = suite.records
        if len(wires) > 1:
            result["test_udp_packets"] = {"sent": wires[1].sent_packets, "received": wires[1].received_packets}
        if runner is not None:
            try:
                runner.close()
            except Exception:
                pass  # only our disposable process below, never an existing core
        cleanup_ok = True
        if process is not None:
            try:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            except Exception:
                cleanup_ok = False
        for wire in wires:
            try:
                wire.close()
            except Exception:
                cleanup_ok = False
        if cleanup_ok:
            try:
                # Verify the explicit absolute temporary target before recursive
                # removal; never derive a deletion target from input profile.
                if root.parent.resolve() != temporary_parent or root.is_symlink() or not root.name.startswith("p48-isolated-"):
                    raise OSError("temporary_target_changed")
                shutil.rmtree(root)
            except OSError:
                cleanup_ok = False
        result["cleanup_complete"] = cleanup_ok
        if not cleanup_ok:
            result["passed"] = False
            result["error"] = "cleanup_incomplete"
        private_file(output, json.dumps(result, ensure_ascii=False, indent=2).encode())
    return result
