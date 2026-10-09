"""Small loopback-only Mihomo adapter. No secret/request payload in diagnostics."""
import http.client
import ipaddress
import json
import time
import threading
import socket
from urllib.parse import quote, urlsplit
from .policy import AUTO, GROUP, OUTER, number
from .transport import decode_json

MAX_RESPONSE = 1024 * 1024


class Controller:
    def __init__(self, url, secret):
        parts = urlsplit(url)
        if (parts.scheme != "http" or not parts.hostname
                or not ipaddress.ip_address(parts.hostname).is_loopback
                or not parts.port or parts.path not in ("", "/")
                or parts.query or parts.fragment or parts.username or parts.password
                or type(secret) is not str or not 1 <= len(secret) <= 256
                or any(ord(c) < 33 or ord(c) > 126 for c in secret)):
            raise ValueError("controller")
        self.host, self.port, self.secret = parts.hostname, parts.port, secret

    def request(self, method, path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        conn = http.client.HTTPConnection(self.host, self.port, timeout=2)
        deadline = time.monotonic() + 2
        timer = None
        try:
            conn.request(method, path, body, {"Authorization": "Bearer " + self.secret,
                         "Content-Type": "application/json", "Connection": "close"})
            sock = conn.sock
            def abort():
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(max(.001, deadline - time.monotonic()), abort)
            timer.daemon = True
            timer.start()
            sock.settimeout(max(.001, deadline - time.monotonic()))
            response = conn.getresponse()
            data = bytearray()
            while len(data) <= MAX_RESPONSE:
                if conn.sock is not None:
                    conn.sock.settimeout(max(.001, deadline - time.monotonic()))
                if time.monotonic() >= deadline:
                    raise TimeoutError()
                chunk = response.read1(min(4096, MAX_RESPONSE + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if time.monotonic() > deadline or len(data) > MAX_RESPONSE or response.status not in (200, 204):
                raise ValueError("controller_response")
            return decode_json(data) if data else {}
        finally:
            if timer is not None:
                timer.cancel()
            conn.close()

    def proxies(self):
        value = self.request("GET", "/proxies")
        if type(value) is not dict or type(value.get("proxies")) is not dict:
            raise ValueError("controller_shape")
        return value["proxies"]

    def confirm_route(self, name, inbound, source_port, host, remote_port):
        payload = self.request("GET", "/connections")
        rows = payload.get("connections") if type(payload) is dict else None
        if type(rows) is not list or len(rows) > 4096:
            return False
        matched = []
        for row in rows:
            if type(row) is not dict:
                return False
            metadata = row.get("metadata", {})
            if (type(metadata) is dict and metadata.get("sourceIP") == "127.0.0.1"
                    and metadata.get("sourcePort") == str(source_port)):
                chains = row.get("chains")
                matched.append(metadata.get("inboundName") == inbound
                    and metadata.get("destinationIP") == host
                    and metadata.get("destinationPort") == str(remote_port)
                    and metadata.get("specialProxy") == name
                    and type(chains) is list and name in chains
                    and not any(node != name and node in chains for node in
                                ("Reality", "Hysteria2", "Backup-Reality", "Backup-Hysteria2")))
        return matched == [True]

    def select(self, name, ownership):
        # Re-read immediately before mutation. Never touch outer or legacy
        # automatic groups and never DELETE live connections.
        if name not in ownership.members or not ownership.permitted(self.proxies()):
            return False
        if name == AUTO:
            self.request("DELETE", "/proxies/" + quote(GROUP, safe=""))
        else:
            self.request("PUT", "/proxies/" + quote(GROUP, safe=""), {"name": name})
        ownership.committed(name)
        return True


    def restore(self, ownership):
        if not ownership.permitted(self.proxies(), require_outer=False):
            raise ValueError("restore_ownership")
        self.request("DELETE", "/proxies/" + quote(GROUP, safe=""))
        ownership.committed(AUTO)


def alive(node, now, freshness):
    # Mihomo's current alive alone can outlive its last probe; require a recent
    # history item. Missing/wrong/future history is UNKNOWN.
    if type(node) is not dict or type(node.get("alive")) is not bool:
        return None
    history = node.get("history")
    if type(history) is not list or not history or len(history) > 100:
        return None
    from datetime import datetime
    try:
        item = history[-1]
        timestamp = datetime.fromisoformat(item["time"].replace("Z", "+00:00"))
        if timestamp.tzinfo is None or not 0 <= now - timestamp.timestamp() <= freshness:
            return None
        if not number(item.get("delay"), 0, 120000):
            return None
        return node["alive"] and item["delay"] > 0
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
        return None


class Passive:
    """Only churn triggers suspicion; low demand alone never triggers a verdict."""
    def __init__(self, nodes, churn_connections, fail_mbps=None):
        from collections import deque
        self.nodes, self.threshold, self.previous = nodes, churn_connections, None
        self.rates = {node: deque(maxlen=3) for node in nodes}
        self.drops = {node: 0 for node in nodes}
        self.fail_mbps = fail_mbps or {}
        self.uploads = {}
        self.previous_at = None

    def suspicion(self, payload, now=None):
        if type(payload) is not dict or type(payload.get("connections")) is not list:
            self.previous = None
            return set()
        connections = payload["connections"]
        if len(connections) > 4096:
            self.previous = None
            return set()
        current = {node: set() for node in self.nodes}
        uploads = {}
        for item in connections:
            if (type(item) is not dict or type(item.get("id")) is not str
                    or len(item["id"]) > 128 or type(item.get("chains")) is not list):
                self.previous = None
                return set()
            metadata = item.get("metadata", {})
            if (type(metadata) is dict and type(metadata.get("inboundName")) is str
                    and metadata["inboundName"].startswith("quality-probe-")):
                continue
            upload = item.get("upload")
            if type(upload) is int and 0 <= upload <= 2**63 - 1:
                uploads[item["id"]] = upload
            for node in current:
                if node in item["chains"]:
                    current[node].add(item["id"])
        result = set()
        if self.previous is not None:
            for node in current:
                # Disappearance alone may just be an app finishing; require both
                # disappearing and newly established paths in this sample.
                if (len(self.previous[node] - current[node]) >= self.threshold
                        and len(current[node] - self.previous[node]) >= self.threshold):
                    result.add(node)
        if now is not None and self.previous_at is not None and now > self.previous_at:
            for node in current:
                common = current[node] & (self.previous or {}).get(node, set())
                deltas = [uploads[ident] - self.uploads[ident] for ident in common
                          if ident in uploads and ident in self.uploads
                          and uploads[ident] >= self.uploads[ident]]
                if deltas:
                    rate = sum(deltas) * 8 / (now - self.previous_at) / 1e6
                    threshold = self.fail_mbps.get(node)
                    if (threshold is not None and rate < threshold / 2
                            and len(self.rates[node]) == 3
                            and max(self.rates[node]) >= threshold):
                        self.drops[node] += 1
                        if self.drops[node] >= 2:
                            result.add(node)
                    else:
                        self.drops[node] = 0
                    self.rates[node].append(rate)
                else:
                    self.rates[node].clear()
                    self.drops[node] = 0
        self.previous, self.uploads, self.previous_at = current, uploads, now
        return result
