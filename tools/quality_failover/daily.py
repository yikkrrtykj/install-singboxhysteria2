"""Explicit daily-Clash opt-in; only an identified added group is writable."""
import csv
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import threading
import time
import tempfile

from .config import client, read_json
from .controller import Controller
from .pilot import module, private_file, receiver_info
from .policy import AUTO, GROUP, NODES, OUTER, Ownership, Policy
from .runtime import Runner

REASONS = {"clash_settings", "clash_controller", "live_profile_not_loaded", "profile_shape",
           "working_directory", "working_permissions", "bundle", "bundle_file",
           "probe_ports", "canonical_profile", "canonical_name", "receiver_info",
           "certificate_file", "certificate_digest", "already_running", "control_not_ready",
           "manual_choice", "restore_unconfirmed", "record_unavailable",
           "routing_mode_unavailable", "routing_mode_changed",
           "selection_handoff_required", "selection_handoff_changed"}


def error_code(exception):
    value = exception.args[0] if isinstance(exception, ValueError) and exception.args else None
    return value if type(value) is str and value in REASONS else "operation_unavailable"


def scalar(value):
    """Only literal scalar spellings of controller address/secret; never general YAML."""
    if value.startswith('"'):
        value = json.loads(value)
    elif value.startswith("'"):
        if not value.endswith("'") or len(value) < 2:
            raise ValueError("clash_settings")
        value = value[1:-1].replace("''", "'")
    elif any(c in value for c in " \t#&*!{}[]|"):
        raise ValueError("clash_settings")
    if type(value) is not str or not value or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("clash_settings")
    return value


def clash_credentials(home):
    """Read active Clash Verge scalars; do not rewrite settings or return raw diagnostics."""
    home = Path(home)
    path = home / "clash-verge.yaml"
    if path.is_symlink() or home.is_symlink():
        raise ValueError("clash_settings")
    with path.open("rb") as handle:
        row = os.fstat(handle.fileno())
        if not stat.S_ISREG(row.st_mode) or row.st_size > 256 * 1024:
            raise ValueError("clash_settings")
        raw = handle.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError("clash_settings")
    text = raw.decode("utf-8-sig")
    values = {}
    for name in ("external-controller", "secret"):
        matches = re.findall(r"^" + name + r":[ \t]*(.*)$", text, re.MULTILINE)
        if len(matches) != 1:
            raise ValueError("clash_settings")
        values[name] = scalar(matches[0].strip())
    address = values["external-controller"]
    if address.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:([0-9]{1,5})", address)
    else:
        match = re.fullmatch(r"([^:]+):([0-9]{1,5})", address)
    if not match or not ipaddress.ip_address(match[1]).is_loopback or not 1 <= int(match[2]) <= 65535:
        raise ValueError("clash_controller")
    url = "http://" + address
    # Existing authenticated loopback settings are reused, including Verge's default secret.
    Controller(url, values["secret"])
    return url, values["secret"]


def directory_check(path):
    row = path.lstat()
    if not stat.S_ISDIR(row.st_mode) or path.is_symlink():
        raise ValueError("working_directory")
    if os.name != "nt" and (row.st_uid != os.geteuid() or stat.S_IMODE(row.st_mode) & 0o077):
        raise ValueError("working_permissions")


def working_directory(path):
    path = Path(path)
    if os.path.lexists(path):
        directory_check(path)
        if read_json(path / "quality-workspace.json") != {"v": 1, "kind": "quality-client"}:
            raise ValueError("working_directory")
    else:
        path.mkdir(mode=0o700)
        if os.name == "nt":
            result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
                                    creationflags=0x08000000)
            rows = list(csv.reader(result.stdout.decode("utf-8", errors="replace").splitlines()))
            sid = rows[0][-1] if len(rows) == 1 and len(rows[0]) == 2 else ""
            if not re.fullmatch(r"S-1-[0-9-]{4,160}", sid):
                raise ValueError("working_permissions")
            subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                            "*" + sid + ":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5,
                           creationflags=0x08000000)
        private_file(path / "quality-workspace.json", b'{"v":1,"kind":"quality-client"}')
    return path.resolve()


def marker_shape(proxies, marker, nodes):
    expected = {marker: ("Selector", ["DIRECT"]), OUTER: ("Selector", [*nodes, AUTO, GROUP, "DIRECT"]),
                GROUP: ("Fallback", list(nodes)), AUTO: ("Fallback", list(nodes))}
    if type(proxies) is not dict or any(type(proxies.get(name)) is not dict for name in expected):
        raise ValueError("live_profile_not_loaded")
    for name, (kind, members) in expected.items():
        value = proxies[name]
        if value.get("type") != kind or value.get("all") != members:
            raise ValueError("profile_shape")
    if proxies[marker].get("hidden") is not True or proxies[GROUP].get("hidden") is not True:
        raise ValueError("profile_shape")
    for index, node in enumerate(nodes):
        if type(proxies.get(node)) is not dict or proxies[node].get("type") != ("Vless" if index % 2 == 0 else "Hysteria2"):
            raise ValueError("profile_shape")


class RoutingSnapshot(dict):
    """Proxy records plus separately observed routing mode; no synthetic proxy edits."""
    def __init__(self, proxies, mode):
        super().__init__(proxies)
        self.routing_mode = mode


class DailyOwnership(Ownership):
    """Use the active routing selection, never rewrite GLOBAL/outer/mode."""
    def permitted(self, proxies, require_outer=True):
        if not super().permitted(proxies, require_outer=False):
            return False
        if not require_outer:
            return True
        mode = proxies.routing_mode if isinstance(proxies, RoutingSnapshot) else None
        if mode == "rule":
            return super().permitted(proxies, require_outer=True)
        if mode == "global":
            group = proxies.get("GLOBAL")
            return (type(group) is dict and group.get("type") == "Selector"
                    and type(group.get("all")) is list and GROUP in group["all"]
                    and group.get("now") == GROUP)
        # Direct/unknown modes have no effective quality opt-in. Missing mode
        # does not inherit an unrelated remembered rule-mode outer selection.
        return False


class IdentifiedController(Controller):
    def __init__(self, url, secret, marker, nodes):
        super().__init__(url, secret)
        self.marker, self.nodes = marker, nodes
        self.last_routing_mode = None

    def routing_mode(self):
        value = self.request("GET", "/configs")
        mode = value.get("mode") if type(value) is dict else None
        if type(mode) is not str or mode not in ("rule", "global", "direct"):
            raise ValueError("routing_mode_unavailable")
        return mode

    def proxies(self):
        self.last_routing_mode = None
        before = self.routing_mode()
        value = super().proxies()
        marker_shape(value, self.marker, self.nodes)
        after = self.routing_mode()
        if before != after:
            raise ValueError("routing_mode_changed")
        self.last_routing_mode = after
        return RoutingSnapshot(value, after)


def choose_ports(count):
    sockets, ports = [], []
    try:
        for port in range(19200, 19328):
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                sock.close()
                continue
            sockets.append(sock)
            ports.append(port)
            if len(ports) == count:
                return ports
        raise ValueError("probe_ports")
    finally:
        for sock in sockets:
            sock.close()


def prepare_bundle(workspace, profile_path, name, info_path, home, backup_path=None,
                   fail_mbps=4, recover_mbps=8, hold_seconds=120):
    root = working_directory(workspace)
    source = Path(profile_path)
    ca_path = Path(info_path).with_name("receiver-ca.pem")
    info = receiver_info(info_path, ca_path)
    url, secret = clash_credentials(home)
    # Validate all source/policy inputs before writing a credential-bearing bundle.
    merge = module("mihomo-multi-vps-merge.py", "daily_merge")
    primary = merge.parse_export(source, lambda: ValueError("canonical_profile"))
    merge.check_provenance(source, name, lambda: ValueError("canonical_name"))
    backup = None
    if backup_path:
        backup = merge.parse_export(backup_path, lambda: ValueError("canonical_profile"))
        merge.check_provenance(backup_path, name, lambda: ValueError("canonical_name"))
        merge.check_sources(primary, backup)
        merge.check_credentials(primary, backup)
    policy = Policy(fail_mbps, recover_mbps, hold_seconds=hold_seconds)
    nodes = NODES if backup is not None else NODES[:2]
    ports = choose_ports(len(nodes))
    directory = root / ("bundle-" + secrets.token_hex(8))
    directory.mkdir(mode=0o700)
    marker = "quality-profile-" + secrets.token_hex(16)
    certificate = directory / "receiver-ca.pem"
    private_file(certificate, ca_path.read_bytes())
    config = {"v": 1, "controller": url, "controller_secret": secret, "control_enabled": False,
              "cycle_seconds": 5, "probe_interval_seconds": 30, "probe_bytes_per_minute": 2097152,
              "churn_connections": 3, "paths": [
                  {"name": node, "listener_port": ports[index], "endpoint": info["endpoint"],
                   "token": info["token"], "ca_file": str(certificate), "payload_bytes": 524288,
                   "rate_mbps": 20, "timeout_seconds": 6, "policy": {
                       "fail_mbps": policy.fail_mbps, "recover_mbps": policy.recover_mbps,
                       "hold_seconds": policy.hold_seconds, "freshness_seconds": 90,
                       "fail_samples": 2, "recover_samples": 3}}
                  for index, node in enumerate(nodes)]}
    client(config)
    cli = module("mihomo-quality-failover.py", "daily_cli")
    output = directory / (name + "-quality.yaml")
    cli.prepare(name, str(source), str(backup_path) if backup_path else None, str(output), config)
    raw = output.read_bytes()
    tag = ("  - name: " + marker + "\n    type: select\n    hidden: true\n    proxies:\n      - DIRECT\n\n").encode()
    # This new private file has not been published/imported. Source files are never rewritten.
    with output.open("wb") as handle:
        handle.write(raw.replace(b"rules:\n", tag + b"rules:\n", 1))
        handle.flush()
        os.fsync(handle.fileno())
    saved = {key: value for key, value in config.items() if key not in ("controller", "controller_secret")}
    private_file(directory / "client.json", json.dumps(saved).encode())
    meta = {"v": 1, "marker": marker, "name": name, "nodes": list(nodes), "profile": output.name,
            "profile_sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
            "certificate_sha256": hashlib.sha256(certificate.read_bytes()).hexdigest()}
    private_file(directory / "bundle.json", json.dumps(meta).encode())
    return directory / "bundle.json"


def load_bundle(path, home):
    path = Path(path)
    if path.name != "bundle.json" or path.parent.is_symlink():
        raise ValueError("bundle")
    directory_check(path.parent)
    meta = read_json(path)
    if (type(meta) is not dict or set(meta) != {"v", "marker", "name", "nodes", "profile", "profile_sha256", "certificate_sha256"}
            or type(meta["v"]) is not int or meta["v"] != 1 or type(meta["marker"]) is not str
            or not re.fullmatch(r"quality-profile-[0-9a-f]{32}", meta["marker"])
            or type(meta["name"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,31}", meta["name"])
            or meta["profile"] != meta["name"] + "-quality.yaml"
            or meta["nodes"] not in (list(NODES[:2]), list(NODES))):
        raise ValueError("bundle")
    profile, ca = path.parent / meta["profile"], path.parent / "receiver-ca.pem"
    for file, digest, maximum in ((profile, meta["profile_sha256"], 65536), (ca, meta["certificate_sha256"], 16384)):
        if file.is_symlink() or not file.is_file() or file.stat().st_size > maximum:
            raise ValueError("bundle_file")
        if hashlib.sha256(file.read_bytes()).hexdigest() != digest:
            raise ValueError("bundle_file")
    config = read_json(path.parent / "client.json")
    if type(config) is not dict or "controller" in config or "controller_secret" in config or config.get("control_enabled") is not False:
        raise ValueError("bundle")
    url, secret = clash_credentials(home)
    config = dict(config, controller=url, controller_secret=secret)
    engine, _, _, _ = client(config)
    if list(engine.paths) != meta["nodes"] or any(item["ca_file"] != str(ca) for item in config["paths"]):
        raise ValueError("bundle")
    return meta, config


class WorkerLock:
    """One window worker per prepared bundle; external CLI writers remain unsupported."""
    def __init__(self, path):
        self.path, self.fd = Path(path), None

    def acquire(self):
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        row = os.fstat(self.fd)
        if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1 or row.st_size > 1 or self.path.is_symlink():
            self.close()
            raise ValueError("already_running")
        try:
            if row.st_size == 0:
                os.write(self.fd, b"0")
            os.lseek(self.fd, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.close()
            raise ValueError("already_running") from None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def write_state(path, value):
    """Bounded, atomic last-state receipt in the already-private bundle directory."""
    path = Path(path)
    directory_check(path.parent)
    if os.path.lexists(path):
        row = path.lstat()
        if not stat.S_ISREG(row.st_mode) or row.st_nlink != 1 or row.st_size > 16384:
            raise ValueError("record_unavailable")
    raw = json.dumps(value).encode()
    if len(raw) > 16384:
        raise ValueError("record_unavailable")
    fd, temporary = tempfile.mkstemp(prefix=".quality-state-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw); handle.flush(); os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Session:
    """Observation first. Never writes the outer choice, reloads profiles or kills flows."""
    def __init__(self, bundle_path, home):
        self.bundle_path, self.home = Path(bundle_path), home
        self.stop_event, self.enable_event, self.confirm_event = (threading.Event() for _ in range(3))
        self.runner = None
        self.finished = False
        self.cycles, self.confirmed_both, self.enabled_once, self.manual_seen = 0, False, False, False
        self.record_failed = False
        self.session_id, self.started_epoch = secrets.token_hex(16), round(time.time(), 3)
        self.lock = WorkerLock(self.bundle_path.parent / "worker.lock")

    def start(self, acknowledged_pin=None):
        self.lock.acquire()
        try:
            meta, config = load_bundle(self.bundle_path, self.home)
            self.runner = Runner(config)
            self.runner.controller = IdentifiedController(config["controller"], config["controller_secret"],
                                                          meta["marker"], meta["nodes"])
            self.runner.owner = DailyOwnership(self.runner.engine.paths)
            owner = self.runner.owner
            proxies = self.runner.controller.proxies()
            fixed = proxies[GROUP].get("fixed")
            if type(fixed) is not str or (fixed and fixed not in meta["nodes"]):
                raise ValueError("profile_shape")
            if acknowledged_pin is not None:
                if (acknowledged_pin not in meta["nodes"] or fixed != acknowledged_pin
                        or proxies[GROUP].get("now") != acknowledged_pin):
                    raise ValueError("selection_handoff_changed")
                # Explicit acknowledgement transfers only the matching dedicated
                # pin into memory. No controller write or implicit enable occurs.
                owner.committed(acknowledged_pin)
            elif fixed:
                raise ValueError("selection_handoff_required", fixed)
            owner.permitted(proxies, require_outer=False)
            if owner.suspended:
                raise ValueError("profile_shape")
        except Exception:
            self.lock.close()
            raise

    def enable(self):
        self.enable_event.set()

    def confirm(self):
        self.confirm_event.set()

    def stop(self):
        self.stop_event.set()

    def publish(self, record, emit):
        mode = self.runner.controller.last_routing_mode
        if type(mode) is str and mode in ("rule", "global", "direct"):
            record = dict(record, routing_mode=mode)
        self.enabled_once |= self.runner.config["control_enabled"]
        self.manual_seen |= record.get("action") == "manual_override"
        allowed = ("v", "action", "mode", "observed_epoch", "paths", "suggested", "owned_selection", "restore_confirmed", "routing_mode", "selection_policy")
        closed = {key: record[key] for key in allowed if key in record}
        state = {"v": 1, "mode": "daily_clash_session", "cycles": self.cycles,
                 "session_id": self.session_id, "started_epoch": self.started_epoch, "written_epoch": round(time.time(), 3),
                 "quality_confirmed_both": self.confirmed_both, "control_enabled_once": self.enabled_once,
                 "manual_override_observed": self.manual_seen, "stopped": self.finished, "last": closed}
        try:
            write_state(self.bundle_path.parent / "state.json", state)
        except Exception:
            self.record_failed = True
            self.stop_event.set()
            emit({"v": 1, "action": "record_unavailable"})
        emit(record)

    def loop(self, emit):
        baseline_until = time.monotonic() + 90  # Explicit start request, bounded initial confirmation window.
        callback = lambda record: self.publish(record, emit)
        try:
            while not self.stop_event.is_set():
                started = time.monotonic()
                if self.confirm_event.is_set():
                    self.confirm_event.clear()
                    baseline_until = started + 90
                try:
                    if self.enable_event.is_set():
                        self.enable_event.clear()
                        now = time.monotonic()
                        if not all(path.usable(now, self.runner.engine.policies[node])
                                   for node, path in self.runner.engine.paths.items()):
                            callback({"v": 1, "action": "control_not_ready"})
                        else:
                            proxies = self.runner.controller.proxies()
                            if self.runner.owner.permitted(proxies):
                                self.runner.config["control_enabled"] = True
                            else:
                                callback({"v": 1, "action": "control_suspended" if self.runner.owner.suspended else "manual_choice"})
                    confirming = started < baseline_until
                    result = self.runner.cycle(confirm=confirming)
                    self.cycles += 1
                    if all(path.usable(time.monotonic(), self.runner.engine.policies[node])
                           for node, path in self.runner.engine.paths.items()):
                        baseline_until = 0
                        self.confirmed_both = True
                    callback(result)
                except Exception as exception:
                    self.runner.engine.update(time.monotonic(), {})
                    callback({"v": 1, "action": error_code(exception)})
                self.stop_event.wait(max(.01, self.runner.config["cycle_seconds"] - (time.monotonic() - started)))
        finally:
            restored = not (self.runner.config["control_enabled"] and self.runner.owner.suspended)
            try:
                self.runner.close()
            except Exception:
                restored = False
            self.lock.close()
            self.finished = True
            callback({"v": 1, "action": "stopped", "restore_confirmed": restored})
