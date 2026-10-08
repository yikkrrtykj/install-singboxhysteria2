"""Explicit opt-in configuration; secrets are file content, never arguments."""
import json
import os
import stat
from .policy import Engine, NODES, Policy, number
from .transport import Probe
from .controller import Controller


def read_json(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        link_info = os.lstat(path)
        if stat.S_ISLNK(link_info.st_mode) or (link_info.st_dev, link_info.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("config_link")
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 16384:
            raise ValueError("config_file")
        if os.name != "nt" and (info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("config_permissions")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            raw = handle.read(16385)
        if len(raw) > 16384:
            raise ValueError("config_size")
        def pairs(items):
            value = {}
            for key, item in items:
                if key in value:
                    raise ValueError("duplicate")
                value[key] = item
            return value
        return json.loads(raw, object_pairs_hook=pairs)
    finally:
        if fd != -1:
            os.close(fd)


def client(value):
    keys = {"v", "controller", "controller_secret", "control_enabled",
            "cycle_seconds", "probe_interval_seconds", "probe_bytes_per_minute",
            "churn_connections", "paths"}
    if type(value) is not dict or set(value) != keys or type(value["v"]) is not int or value["v"] != 1:
        raise ValueError("config")
    if (type(value["control_enabled"]) is not bool
            or not number(value["cycle_seconds"], 5, 60)
            or not number(value["probe_interval_seconds"], 30, 600)
            or type(value["probe_bytes_per_minute"]) is not int
            or not 32768 <= value["probe_bytes_per_minute"] <= 4 * 1024 * 1024
            or type(value["churn_connections"]) is not int or not 2 <= value["churn_connections"] <= 100):
        raise ValueError("config")
    entries = value["paths"]
    if type(entries) is not list or len(entries) not in (2, 4):
        raise ValueError("paths")
    names = [item.get("name") for item in entries if type(item) is dict]
    if tuple(names) not in (NODES[:2], NODES):
        raise ValueError("order")
    policies, probes, ports = {}, {}, {}
    for entry in entries:
        if set(entry) != {"name", "listener_port", "endpoint", "token", "ca_file",
                          "payload_bytes", "rate_mbps", "timeout_seconds", "policy"}:
            raise ValueError("path")
        name, port = entry["name"], entry["listener_port"]
        if type(port) is not int or not 1024 <= port <= 65535 or port in ports.values():
            raise ValueError("port")
        if type(entry["policy"]) is not dict:
            raise ValueError("policy")
        policy = Policy(**entry["policy"])
        probe = Probe(entry["endpoint"], entry["token"], entry["ca_file"], entry["payload_bytes"],
                      entry["rate_mbps"], entry["timeout_seconds"])
        if (probe.rate < 1.5 * policy.recover_mbps
                or probe.size > value["probe_bytes_per_minute"]
                or policy.freshness_seconds < value["probe_interval_seconds"]):
            raise ValueError("unattainable_probe")
        policies[name], probes[name], ports[name] = policy, probe, port
    controller = Controller(value["controller"], value["controller_secret"])
    if controller.port in ports.values() or any(port in ports.values() for port in (7890, 7897, 9090)):
        raise ValueError("port")
    return Engine(policies), probes, ports, controller
