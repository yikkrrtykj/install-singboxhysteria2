"""IP whitelist for the Monitor v2 web dashboard (Phase E2).

Gate order for every ordinary request:

    socket peer address -> whitelist -> admin session -> dashboard

Only the socket peer address is ever consulted. ``X-Forwarded-For`` and
``X-Real-IP`` are NEVER read: any caller behind a reverse proxy can set
both, so trusting them would bypass this gate entirely. A trusted-proxy
deployment, if ever wanted, is a separate explicit design -- not here.

The whitelist defaults to EMPTY: no public source may reach the dashboard.
The loopback addresses 127.0.0.1 and ::1 are implicitly allowed so a local
admin (SSH port-forward, local curl, the localhost canary) can always reach
the login page. Every other address must match one stored entry, which may
be a host (``1.2.3.4/32``, ``2001:db8::1/128``) or a CIDR range
(``10.10.10.0/24``).

Storage is ``<data-dir>/access.json`` and is strictly separate from the
sing-box configuration: Phase C credentials are never read or written here,
and changing the whitelist never reloads or restarts sing-box.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import threading

from web.storage import atomic_write_json, ensure_private_dir, read_json

LOOPBACK_ALLOW = frozenset({"127.0.0.1", "::1"})

ACCESS_VERSION = 1


def parse_network(value):
    """Canonicalize a whitelist entry; raises ValueError when invalid.

    Accepts single hosts ("1.2.3.4" -> /32, "2001:db8::1" -> /128) and CIDR
    ranges ("10.10.10.0/24"). Invalid input (/33, garbage, empty) raises.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("empty whitelist entry")
    network = ipaddress.ip_network(value.strip(), strict=False)
    return str(network)


def host_entry_for_ip(address):
    """The /32 (IPv4) or /128 (IPv6) host entry for a concrete source IP."""
    parsed = ipaddress.ip_address(address)
    prefix = 32 if parsed.version == 4 else 128
    return str(ipaddress.ip_network("%s/%d" % (parsed, prefix), strict=False))


def _atomic_write_json(path, payload):
    atomic_write_json(path, payload)


class AccessPolicy:
    """The persisted IP whitelist (access.json) + source-IP decision.

    Thread-safe: request threads may add/remove entries concurrently with
    gate checks, so every read of the entry list takes the lock. Mutations
    are STORAGE-FIRST: the candidate list is written atomically BEFORE the
    in-memory list is replaced, so a failed write can never produce a
    200 response with disk left stale (the exception propagates and the
    server answers 500 with memory == disk).
    """

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.path = os.path.join(data_dir, "access.json")
        self._lock = threading.RLock()
        self._entries = []
        self.updated_at = None
        self.load()

    # -- persistence ---------------------------------------------------------

    def load(self):
        with self._lock:
            self._entries = []
            self.updated_at = None
            data = read_json(self.path)
            if not isinstance(data, dict):
                return
            entries = data.get("whitelist")
            if not isinstance(entries, list):
                return
            for entry in entries:
                try:
                    self._entries.append(parse_network(entry))
                except ValueError:
                    continue  # never let a corrupt entry open the gate
            self.updated_at = data.get("updated_at")

    def _commit(self, entries):
        """Atomically persist the candidate list; raises on failure."""
        ensure_private_dir(self.data_dir)
        atomic_write_json(self.path, {
            "version": ACCESS_VERSION,
            "whitelist": entries,
            "updated_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
        })

    # -- entries -------------------------------------------------------------

    def entries(self):
        with self._lock:
            return tuple(self._entries)

    def contains(self, entry):
        try:
            canonical = parse_network(entry)
        except ValueError:
            return False
        with self._lock:
            return canonical in self._entries

    def add(self, entry):
        canonical = parse_network(entry)
        with self._lock:
            if canonical in self._entries:
                return canonical
            candidate = sorted(self._entries + [canonical])
            self._commit(candidate)  # storage first; raises -> no change
            self._entries = candidate
            return canonical

    def remove(self, entry):
        try:
            canonical = parse_network(entry)
        except ValueError:
            return False
        with self._lock:
            if canonical not in self._entries:
                return False
            candidate = [e for e in self._entries if e != canonical]
            self._commit(candidate)  # storage first; raises -> no change
            self._entries = candidate
            return True

    def covers(self, entry, remote_ip):
        """True when the entry network contains the given source address."""
        try:
            network = ipaddress.ip_network(parse_network(entry))
        except ValueError:
            return False
        return any(addr.version == network.version and addr in network
                   for addr in self._address_candidates(remote_ip))

    # -- decision ------------------------------------------------------------

    def is_allowed(self, remote_ip):
        """Whitelist decision for the socket peer address ONLY."""
        candidates = self._address_candidates(remote_ip)
        if not candidates:
            return False
        if any(str(addr) in LOOPBACK_ALLOW for addr in candidates):
            return True
        with self._lock:
            entries = list(self._entries)
        for entry in entries:
            network = ipaddress.ip_network(entry)
            for addr in candidates:
                if addr.version == network.version and addr in network:
                    return True
        return False

    @staticmethod
    def _address_candidates(remote_ip):
        """Parse the peer address; expand IPv4-mapped IPv6 to both forms."""
        if not remote_ip:
            return []
        try:
            addr = ipaddress.ip_address(remote_ip)
        except ValueError:
            return []
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return [addr, addr.ipv4_mapped]
        return [addr]
