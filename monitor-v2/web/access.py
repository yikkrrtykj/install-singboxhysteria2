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
import json
import os
import tempfile

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
    directory = os.path.dirname(path) or "."
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                                         prefix=".access-", suffix=".tmp",
                                         delete=False)
    try:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(handle.name, path)
    except BaseException:
        handle.close()
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
    _restrict_permissions(path)


def _restrict_permissions(path):
    # POSIX: keep secrets root-only. Non-POSIX hosts (Windows dev) ignore.
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


class AccessPolicy:
    """The persisted IP whitelist (access.json) + source-IP decision."""

    def __init__(self, data_dir):
        self.data_dir = data_dir
        self.path = os.path.join(data_dir, "access.json")
        self._entries = []
        self.updated_at = None
        self.load()

    # -- persistence ---------------------------------------------------------

    def load(self):
        self._entries = []
        self.updated_at = None
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            return  # unreadable/corrupt file == empty whitelist (fail-closed)
        entries = data.get("whitelist")
        if not isinstance(entries, list):
            return
        for entry in entries:
            try:
                self._entries.append(parse_network(entry))
            except ValueError:
                continue  # never let a corrupt entry open the gate
        self.updated_at = data.get("updated_at")

    def save(self):
        os.makedirs(self.data_dir, exist_ok=True)
        if os.name == "posix":
            try:
                os.chmod(self.data_dir, 0o700)
            except OSError:
                pass
        _atomic_write_json(self.path, {
            "version": ACCESS_VERSION,
            "whitelist": self._entries,
            "updated_at": datetime.datetime.now(
                datetime.timezone.utc).isoformat(),
        })

    # -- entries -------------------------------------------------------------

    def entries(self):
        return tuple(self._entries)

    def contains(self, entry):
        try:
            canonical = parse_network(entry)
        except ValueError:
            return False
        return canonical in self._entries

    def add(self, entry):
        canonical = parse_network(entry)
        if canonical not in self._entries:
            self._entries.append(canonical)
            self._entries.sort()
            self.save()
        return canonical

    def remove(self, entry):
        try:
            canonical = parse_network(entry)
        except ValueError:
            return False
        if canonical not in self._entries:
            return False
        self._entries.remove(canonical)
        self.save()
        return True

    # -- decision ------------------------------------------------------------

    def is_allowed(self, remote_ip):
        """Whitelist decision for the socket peer address ONLY."""
        candidates = self._address_candidates(remote_ip)
        if not candidates:
            return False
        if any(str(addr) in LOOPBACK_ALLOW for addr in candidates):
            return True
        for entry in self._entries:
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
