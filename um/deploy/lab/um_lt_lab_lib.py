#!/usr/bin/env python3
"""Shared helpers for the UM-LT real-protocol traffic E2E lab.

This module is deliberately pure Python standard library (Python 3.10+) so the
lab can run on an Ubuntu 24.04 GitHub runner without adding dependencies. It
contains ONLY reusable pieces:

* the pinned sing-box release identity + SHA-256 verification/download;
* synthetic credential generation (VLESS UUID, Hysteria2 password, Reality
  x25519 keypair, short id, service.api secret, monitor admin password,
  center admin token) and self-signed TLS material generation;
* real sing-box server/client JSON generation (Reality VLESS `vless-in` +
  Hysteria2 `hy2-in`, no mixed inbound substitution) plus validation helpers;
* strict allow-list validators for the monitor-v2 restricted traffic export
  document, the rev-7 `traffic_observation` report object and its semantics;
* privacy scanners (forbidden sentinel substrings + raw network literals);
* read-only SQLite helpers for the center's normalized traffic tables;
* tiny HTTP helpers, managed-process helpers, loopback HTTP payload servers,
  a loopback TLS camouflage target for the Reality handshake, a request-capture
  loopback proxy, and a traffic ledger.

Nothing in this module performs production/network/cloud operations. The only
external network operation in the whole lab is downloading the pinned official
sing-box release tarball and verifying its pinned SHA-256.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import http.client
import http.cookiejar
import http.server
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.request
import uuid as uuid_mod

# ---------------------------------------------------------------------------
# Pinned real-protocol binary (the ONLY external download in the lab)
# ---------------------------------------------------------------------------

PINNED_SINGBOX_VERSION = "1.14.5"
PINNED_SINGBOX_ARCHIVE = "sing-box-1.14.5-linux-amd64.tar.gz"
PINNED_SINGBOX_URL = (
    "https://github.com/SagerNet/sing-box/releases/download/v%s/%s"
    % (PINNED_SINGBOX_VERSION, PINNED_SINGBOX_ARCHIVE)
)
# SHA-256 of the official GitHub release asset, cross-checked against the
# GitHub release API asset "digest" field for tag v1.14.5 (2026-11-26).
PINNED_SINGBOX_SHA256 = (
    "ca57e405be6b7dc79a0efa91823a0cc4d81138cbe4a9aacbfd749c65e6fca3b2"
)
# The pinned release is only used when the runner has no pre-provisioned
# binary. The lab never substitutes a different release silently: a
# user-supplied binary must report the same version.
SINGBOX_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Label used by the agent config source switch. The report/export wire token
# is different on purpose (see EXPORT_SOURCE / REPORT_SOURCE below).
AGENT_SOURCE_KEY = "monitor_export"
AGENT_MONITOR_EXPORT_FLAG = "--monitor-export-file"
AGENT_MONITOR_EXPORT_ENV = "UM_AGENT_MONITOR_EXPORT_FILE"
MONITOR_EXPORT_FILE_FLAG = "--traffic-export-file"
MONITOR_EXPORT_INBOUND_FLAG = "--traffic-export-inbound"

# The center expects the rev-7 contract schemas in the single contracts dir.
REV7_SNAPSHOT_SCHEMA_FILE = "report-snapshot.rev7.schema.json"
REV7_AGENT_CONFIG_SCHEMA_FILE = "agent-config.rev7.schema.json"
FROZEN_CONTRACTS_DIR_REL = os.path.join("docs", "um", "contracts", "v1")

# The real protocol inbounds the lab always configures. The tag:kind pairs are
# also the center-authorized expected tags and the monitor operator allow-list.
REALITY_TAG = "vless-in"
REALITY_KIND = "reality"
HYSTERIA2_TAG = "hy2-in"
HYSTERIA2_KIND = "hysteria2"
EXPECTED_TAGS = ((REALITY_TAG, REALITY_KIND), (HYSTERIA2_TAG, HYSTERIA2_KIND))

# Synthetic only: RFC 2606 reserved .test domain, never resolved or dialed
# beyond the loopback camouflage listener.
SYNTHETIC_SERVER_NAME = "www.example.test"
SYNTHETIC_USER_REALITY = "um-lt-lab-device-reality"
SYNTHETIC_USER_HYSTERIA2 = "um-lt-lab-device-hysteria2"
SYNTHETIC_ADMIN_PASSWORD = "um-lt-lab-monitor-admin-pw"
SYNTHETIC_ADMIN_TOKEN = "um-lt-lab-center-admin-token"
SYNTHETIC_API_SECRET = "um-lt-lab-service-api-secret"

# ---------------------------------------------------------------------------
# Restricted monitor-v2 traffic export document (schema_version 1) -- the
# canonical shape agreed in the rev-7 reconciliation. Closed allow-lists: a
# document carrying any other member is refused (the export is not a carrier
# for ids/users/IPs/secrets).
# ---------------------------------------------------------------------------

EXPORT_SCHEMA = "singbox-monitor-traffic-export"
EXPORT_SCHEMA_VERSION = 1
EXPORT_SOURCE = "monitor-v2"
REPORT_SOURCE = "monitor_readonly_export"
COUNTER_SCOPE = "observation_epoch"
EXACTNESS = "lower_bound"

EXPORT_KEYS = frozenset({
    "schema", "schema_version", "source", "source_epoch", "sequence",
    "generated_at", "observed_at", "monitor_stale",
    "monitor_last_success_at", "counter_scope", "exactness",
    "active_connections", "rate_window_seconds", "inbounds",
})
EXPORT_INBOUND_KEYS = frozenset({
    "inbound_tag", "kind", "observed_uplink_bytes",
    "observed_downlink_bytes", "uplink_observed_rate_bps",
    "downlink_observed_rate_bps", "active_connections", "observed_at",
    "quality",
})
# Legacy draft shape (docs-only, superseded by the canonical shape above). The
# lab still RECOGNIZES it so a stale monitor build fails with a precise message
# instead of a generic contract error, but it is never accepted as canonical.
LEGACY_EXPORT_KEYS = frozenset({
    "export_version", "source", "source_epoch", "sequence", "observed_at",
    "availability", "active_connections", "rate_window_seconds", "inbounds",
})
LEGACY_EXPORT_INBOUND_KEYS = frozenset({
    "inbound_tag", "kind", "observed_at", "availability", "quality",
    "uplink_observed_lower_bound_bytes", "downlink_observed_lower_bound_bytes",
    "uplink_observed_rate_bps", "downlink_observed_rate_bps",
    "active_connections",
})

KINDS = frozenset({"reality", "hysteria2", "other"})
QUALITIES = frozenset({"lower_bound", "partial", "unavailable"})
AVAILABILITY = frozenset({"ok", "partial", "unavailable"})
FRESHNESS = frozenset({"fresh", "stale", "unavailable"})
ZERO_SOURCE_EPOCH = "0" * 32
SOURCE_EPOCH_RE = re.compile(r"^[0-9a-f]{32}$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

SAFE_INT_MAX = 9007199254740991  # 2**53 - 1, largest exact JSON integer
MAX_INBOUNDS = 8
MAX_EXPORT_BYTES = 64 * 1024
MAX_TIMESTAMP = 1000000000000
MAX_ACTIVE_CONNECTIONS = 1000000
MAX_RATE_BPS = 1e12
MAX_RATE_WINDOW_SECONDS = 3600.0
MAX_COHORT_SECONDS = 86400
MAX_AGE_SECONDS = 86400
FRESH_MAX_AGE_SECONDS = 15
FUTURE_TOLERANCE_SECONDS = 5

# rev-7 report body.
CONTRACT_REVISION_7 = 7
REPORT_OBSERVATION_KEYS = frozenset({
    "source", "source_epoch", "sequence", "observed_at", "age_seconds",
    "freshness", "availability", "counter_scope", "exactness",
    "active_connections", "rate_window_seconds", "inbounds",
})
REPORT_OBSERVATION_INBOUND_KEYS = frozenset({
    "inbound_tag", "kind", "observed_at", "availability", "quality",
    "uplink_observed_lower_bound_bytes", "downlink_observed_lower_bound_bytes",
    "uplink_observed_rate_bps", "downlink_observed_rate_bps",
    "active_connections",
})

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class LabError(Exception):
    """A lab configuration/precondition problem (actionable message)."""


class LabSkipped(Exception):
    """The lab cannot run in this environment and skipping was allowed."""


class LabAssertionFailed(AssertionError):
    """An evidence-backed assertion of the lab failed."""


class ExportValidationError(LabAssertionFailed):
    """The restricted export document violated its closed contract."""


class ReportValidationError(LabAssertionFailed):
    """A captured rev-7 report body violated its closed contract."""


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def utc_now_epoch() -> int:
    return int(time.time())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_dir(path: str, mode: int = 0o700) -> str:
    os.makedirs(path, mode=mode, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass
    return path


def write_bytes(path: str, data: bytes, mode: int = 0o600) -> None:
    ensure_dir(os.path.dirname(path) or ".")
    if os.path.lexists(path):
        os.unlink(path)
    with open(path, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(path, mode)


def write_text(path: str, text: str, mode: int = 0o600) -> None:
    write_bytes(path, text.encode("utf-8"), mode)


def write_json(path: str, document, mode: int = 0o600) -> None:
    write_text(path, json.dumps(document, indent=2, sort_keys=False) + "\n", mode)


def read_json(path: str):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def try_read_json(path: str):
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def format_bytes(value) -> str:
    if value is None:
        return "null"
    value = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if abs(value) < 1024.0 or unit == "GiB":
            return "%.1f%s" % (value, unit)
        value /= 1024.0
    return "%.1fGiB" % value


def redact_text(text: str, secrets_to_redact) -> str:
    """Replace every synthetic secret with [REDACTED] for artifacts/logging."""
    if not text:
        return text
    redacted = text
    for secret in secrets_to_redact:
        if secret and len(secret) >= 8:
            redacted = redacted.replace(secret, "[REDACTED]")
    return redacted


def free_port(kind: str = "tcp") -> int:
    """Reserve an ephemeral loopback port.

    There is an unavoidable race between closing this socket and the child
    process binding it; the lab only uses loopback and fails loudly if a bind
    fails, so the race is a retry-level problem, not a correctness problem.
    """
    family = socket.AF_INET
    socktype = socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM
    sock = socket.socket(family, socktype)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def wait_port(host: str, port: int, timeout: float = 20.0,
              kind: str = "tcp") -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if kind == "tcp":
                conn = socket.create_connection((host, port), timeout=0.5)
                conn.close()
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    sock.connect((host, port))
                finally:
                    sock.close()
            return True
        except OSError:
            time.sleep(0.1)
    return False


def wait_until(predicate, timeout: float, interval: float, description: str):
    """Poll predicate until truthy; return its value or raise with context."""
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            value = predicate()
        except Exception as exc:  # noqa: BLE001 - polled diagnostics only
            last_error = exc
        else:
            if value:
                return value
            last_error = None
        time.sleep(interval)
    detail = "" if last_error is None else " (last error: %s)" % (last_error,)
    raise LabAssertionFailed("timed out after %.1fs waiting for %s%s"
                             % (timeout, description, detail))


# ---------------------------------------------------------------------------
# Synthetic credential generation
# ---------------------------------------------------------------------------


def generate_uuid() -> str:
    return str(uuid_mod.uuid4())


def generate_short_id() -> str:
    return secrets.token_hex(8)


def generate_hysteria2_password() -> str:
    return "um-lt-lab-hy2-" + secrets.token_urlsafe(24)


def generate_service_api_secret() -> str:
    return "um-lt-lab-api-" + secrets.token_urlsafe(24)


def generate_admin_token() -> str:
    return "um-lt-lab-admin-" + secrets.token_urlsafe(32)


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


# --- pure-Python X25519 (RFC 7748) fallback --------------------------------

_X25519_P = 2 ** 255 - 19
_X25519_A24 = 121665


def _x25519_clamp(scalar: bytes) -> int:
    if len(scalar) != 32:
        raise ValueError("x25519 scalar must be 32 bytes")
    value = int.from_bytes(scalar, "little")
    value &= ~7
    value &= ~(1 << 255)
    value |= 1 << 254
    return value


def x25519_scalarmult(scalar: bytes, u_bytes: bytes) -> bytes:
    """RFC 7748 X25519(sk, u) in pure Python (test-only fallback)."""
    if len(u_bytes) != 32:
        raise ValueError("x25519 u-coordinate must be 32 bytes")
    k = _x25519_clamp(scalar)
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _X25519_P
        aa = (a * a) % _X25519_P
        b = (x2 - z2) % _X25519_P
        bb = (b * b) % _X25519_P
        e = (aa - bb) % _X25519_P
        c = (x3 + z3) % _X25519_P
        d = (x3 - z3) % _X25519_P
        da = (d * a) % _X25519_P
        cb = (c * b) % _X25519_P
        # RFC 7748 ladder step: x3=(DA+CB)^2, z3=x1*(DA-CB)^2,
        # x2=AA*BB, z2=E*(AA+a24*E).
        next_x3 = ((da + cb) * (da + cb)) % _X25519_P
        next_z3 = (x1 * ((da - cb) * (da - cb) % _X25519_P)) % _X25519_P
        next_x2 = (aa * bb) % _X25519_P
        next_z2 = (e * ((aa + _X25519_A24 * e) % _X25519_P)) % _X25519_P
        x2, z2, x3, z3 = next_x2, next_z2, next_x3, next_z3
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = (x2 * pow(z2, _X25519_P - 2, _X25519_P)) % _X25519_P
    return result.to_bytes(32, "little")


_X25519_BASE = (9).to_bytes(32, "little")


def x25519_keypair(private_raw: bytes | None = None) -> tuple[str, str]:
    """Return (private_b64url, public_b64url), sing-box Reality encoding."""
    raw = private_raw if private_raw is not None else secrets.token_bytes(32)
    public = x25519_scalarmult(raw, _X25519_BASE)
    return _b64url_no_pad(raw), _b64url_no_pad(public)


def generate_reality_keypair(singbox_bin: str | None = None) -> tuple[str, str]:
    """Generate a REALITY x25519 keypair, preferring sing-box's own generator.

    A binary-provided generator is canonical for the pinned release; the pure
    Python fallback is only used when the binary is unavailable (self-check and
    unit tests), and it is validated against RFC 7748 in the unit tests.
    """
    if singbox_bin and os.path.exists(singbox_bin):
        result = run_capture([singbox_bin, "generate", "reality-keypair"])
        if result.returncode != 0:
            raise LabError("sing-box generate reality-keypair failed: %s"
                           % (result.stderr or result.stdout or "").strip()[-400:])
        private_key = re.search(r"PrivateKey:\s*(\S+)", result.stdout)
        public_key = re.search(r"PublicKey:\s*(\S+)", result.stdout)
        if not private_key or not public_key:
            raise LabError("could not parse sing-box reality-keypair output")
        return private_key.group(1), public_key.group(1)
    return x25519_keypair()


def resolve_singbox_bin(explicit: str | None) -> str | None:
    """Return an existing sing-box binary path or None (never raises)."""
    for candidate in (explicit, os.environ.get("SINGBOX_BIN")):
        if candidate and os.path.isfile(candidate):
            return candidate
    found = shutil.which("sing-box")
    return found if found else None


_PEM_PRIVATE_RE = re.compile(
    r"-----BEGIN PRIVATE KEY-----.*?-----END PRIVATE KEY-----", re.S)
_PEM_CERT_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


def generate_self_signed_cert(server_name: str, cert_path: str,
                              key_path: str,
                              singbox_bin: str | None = None) -> None:
    """Write synthetic self-signed cert/key pairs for the .test server name.

    Prefers `sing-box generate tls-keypair`; falls back to `openssl req` when
    the binary is unavailable. Both outputs are synthetic and local-only.
    """
    if singbox_bin and os.path.exists(singbox_bin):
        result = run_capture([singbox_bin, "generate", "tls-keypair", server_name])
        if result.returncode == 0:
            cert = _PEM_CERT_RE.search(result.stdout)
            key = _PEM_PRIVATE_RE.search(result.stdout)
            if cert and key:
                write_text(cert_path, cert.group(0) + "\n", 0o644)
                write_text(key_path, key.group(0) + "\n", 0o600)
                return
        raise LabError("sing-box generate tls-keypair failed: %s"
                       % (result.stderr or result.stdout or "").strip()[-400:])
    openssl = shutil.which("openssl")
    if not openssl:
        raise LabError(
            "no cert generator available: pass --singbox-bin or install openssl "
            "(the lab never downloads certificates from the network)")
    result = run_capture([
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", key_path, "-out", cert_path, "-days", "2",
        "-subj", "/CN=%s" % server_name,
        "-addext", "subjectAltName=DNS:%s" % server_name,
    ])
    if result.returncode != 0:
        raise LabError("openssl synthetic certificate generation failed: %s"
                       % (result.stderr or "").strip()[-400:])
    os.chmod(key_path, 0o600)
    os.chmod(cert_path, 0o644)


@dataclasses.dataclass
class Credentials:
    """All synthetic credentials of one lab run (never real/production)."""

    vless_uuid: str
    hysteria2_password: str
    reality_private_key: str
    reality_public_key: str
    reality_short_id: str
    service_api_secret: str
    monitor_admin_password: str
    center_admin_token: str
    server_name: str = SYNTHETIC_SERVER_NAME
    cert_path: str = ""
    key_path: str = ""
    reality_user: str = SYNTHETIC_USER_REALITY
    hysteria2_user: str = SYNTHETIC_USER_HYSTERIA2

    def secret_values(self) -> list[str]:
        values = [
            self.vless_uuid, self.hysteria2_password, self.reality_private_key,
            self.reality_public_key, self.reality_short_id,
            self.service_api_secret, self.monitor_admin_password,
            self.center_admin_token, self.server_name,
        ]
        if self.cert_path and os.path.exists(self.cert_path):
            cert_pem = open(self.cert_path, "r", encoding="utf-8").read()
            body = "\n".join(
                line for line in cert_pem.splitlines()
                if line and not line.startswith("-----"))
            values.extend([body, body[:64], body[-64:]])
        if self.key_path and os.path.exists(self.key_path):
            key_pem = open(self.key_path, "r", encoding="utf-8").read()
            body = "\n".join(
                line for line in key_pem.splitlines()
                if line and not line.startswith("-----"))
            values.extend([body[:64], body[-64:]])
        values.extend([self.reality_user, self.hysteria2_user])
        return [value for value in values if value]


def build_credentials(cert_dir: str, singbox_bin: str | None) -> Credentials:
    ensure_dir(cert_dir)
    cert_path = os.path.join(cert_dir, "server.crt")
    key_path = os.path.join(cert_dir, "server.key")
    private_key, public_key = generate_reality_keypair(singbox_bin)
    creds = Credentials(
        vless_uuid=generate_uuid(),
        hysteria2_password=generate_hysteria2_password(),
        reality_private_key=private_key,
        reality_public_key=public_key,
        reality_short_id=generate_short_id(),
        service_api_secret=generate_service_api_secret(),
        monitor_admin_password=SYNTHETIC_ADMIN_PASSWORD,
        center_admin_token=generate_admin_token(),
        cert_path=cert_path,
        key_path=key_path,
    )
    generate_self_signed_cert(creds.server_name, cert_path, key_path, singbox_bin)
    return creds


# ---------------------------------------------------------------------------
# Ports + sing-box configuration generation (REAL Reality + Hysteria2)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class PortPlan:
    reality_tcp: int
    hysteria2_udp: int
    handshake_tls: int
    service_api: int
    http_fixture: int
    monitor_web: int
    center_ingest: int
    center_admin: int
    center_web: int
    socks_reality: int
    socks_hysteria2: int
    capture_proxy: int

    @classmethod
    def allocate(cls) -> "PortPlan":
        return cls(
            reality_tcp=free_port("tcp"),
            hysteria2_udp=free_port("udp"),
            handshake_tls=free_port("tcp"),
            service_api=free_port("tcp"),
            http_fixture=free_port("tcp"),
            monitor_web=free_port("tcp"),
            center_ingest=free_port("tcp"),
            center_admin=free_port("tcp"),
            center_web=free_port("tcp"),
            socks_reality=free_port("tcp"),
            socks_hysteria2=free_port("tcp"),
            capture_proxy=free_port("tcp"),
        )


def build_singbox_server_config(creds: Credentials, ports: PortPlan) -> dict:
    """Real sing-box server config: one Reality VLESS inbound + one Hysteria2.

    No `mixed` inbound is ever used here: both protocols are real inbounds on
    real listeners, and the service.api is the official loopback listener the
    production monitor consumes. All addresses are loopback; the synthetic
    Reality handshake target is a local loopback TLS server.
    """
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [
            {
                "type": "vless",
                "tag": REALITY_TAG,
                "listen": "127.0.0.1",
                "listen_port": ports.reality_tcp,
                "users": [{
                    "name": creds.reality_user,
                    "uuid": creds.vless_uuid,
                    "flow": "xtls-rprx-vision",
                }],
                "tls": {
                    "enabled": True,
                    "server_name": creds.server_name,
                    "reality": {
                        "enabled": True,
                        "handshake": {
                            "server": "127.0.0.1",
                            "server_port": ports.handshake_tls,
                        },
                        "private_key": creds.reality_private_key,
                        "short_id": [creds.reality_short_id],
                    },
                },
            },
            {
                "type": "hysteria2",
                "tag": HYSTERIA2_TAG,
                "listen": "127.0.0.1",
                "listen_port": ports.hysteria2_udp,
                "users": [{
                    "name": creds.hysteria2_user,
                    "password": creds.hysteria2_password,
                }],
                "tls": {
                    "enabled": True,
                    "server_name": creds.server_name,
                    "certificate_path": creds.cert_path,
                    "key_path": creds.key_path,
                },
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "services": [{
            "type": "api",
            "tag": "monitor-api",
            "listen": "127.0.0.1",
            "listen_port": ports.service_api,
            "secret": creds.service_api_secret,
        }],
    }


def build_singbox_client_config(creds: Credentials, ports: PortPlan,
                                protocol: str) -> dict:
    """One real sing-box client per protocol, each exposing a loopback socks."""
    if protocol == "reality":
        inbound_port = ports.socks_reality
        outbound = {
            "type": "vless",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": ports.reality_tcp,
            "uuid": creds.vless_uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": creds.server_name,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {
                    "enabled": True,
                    "public_key": creds.reality_public_key,
                    "short_id": creds.reality_short_id,
                },
            },
        }
    elif protocol == "hysteria2":
        inbound_port = ports.socks_hysteria2
        outbound = {
            "type": "hysteria2",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": ports.hysteria2_udp,
            "password": creds.hysteria2_password,
            "tls": {
                "enabled": True,
                "server_name": creds.server_name,
                "insecure": True,  # synthetic self-signed cert, loopback only
            },
        }
    else:
        raise LabError("unknown protocol %r (expected reality|hysteria2)" % (protocol,))
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": inbound_port,
        }],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


def write_singbox_configs(workdir: str, creds: Credentials,
                          ports: PortPlan) -> dict:
    """Write + return paths of the server and both client configurations."""
    ensure_dir(workdir)
    paths = {
        "server": os.path.join(workdir, "singbox-server.json"),
        "client_reality": os.path.join(workdir, "singbox-client-reality.json"),
        "client_hysteria2": os.path.join(workdir, "singbox-client-hysteria2.json"),
    }
    write_json(paths["server"], build_singbox_server_config(creds, ports), 0o600)
    write_json(paths["client_reality"],
               build_singbox_client_config(creds, ports, "reality"), 0o600)
    write_json(paths["client_hysteria2"],
               build_singbox_client_config(creds, ports, "hysteria2"), 0o600)
    return paths


def singbox_check(singbox_bin: str, config_path: str) -> subprocess.CompletedProcess:
    return run_capture([singbox_bin, "check", "-c", config_path], timeout=120)


def singbox_version(singbox_bin: str) -> str:
    result = run_capture([singbox_bin, "version"], timeout=60)
    match = re.search(r"sing-box version\s+(\S+)", result.stdout or "")
    if not match:
        raise LabError("could not determine sing-box version from %r"
                       % (singbox_bin,))
    return match.group(1)


def assert_singbox_version(singbox_bin: str, expected: str = PINNED_SINGBOX_VERSION):
    actual = singbox_version(singbox_bin)
    if actual != expected:
        raise LabError(
            "sing-box binary version %s does not match the pinned real-protocol "
            "release %s; the lab refuses to substitute a different protocol "
            "build" % (actual, expected))
    return actual


# ---------------------------------------------------------------------------
# Pinned release download (only external network operation in the lab)
# ---------------------------------------------------------------------------


def download_pinned_singbox(workdir: str, timeout: float = 300.0) -> str:
    """Download, SHA-256 verify and extract the pinned official release."""
    ensure_dir(workdir)
    archive_path = os.path.join(workdir, PINNED_SINGBOX_ARCHIVE)
    if not (os.path.isfile(archive_path)
            and sha256_file(archive_path) == PINNED_SINGBOX_SHA256):
        request = urllib.request.Request(
            PINNED_SINGBOX_URL, headers={"User-Agent": "um-lt-e2e-lab/1"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = response.read()
        except (urllib.error.URLError, OSError) as exc:
            raise LabError(
                "cannot download the pinned sing-box release from %s: %s\n"
                "The lab needs either network access to the official GitHub "
                "release or a pre-downloaded binary (--singbox-bin / "
                "SINGBOX_BIN); no other network target is used."
                % (PINNED_SINGBOX_URL, exc)) from exc
        if len(data) > 128 * 1024 * 1024:
            raise LabError("downloaded sing-box archive is implausibly large "
                           "(%d bytes)" % len(data))
        actual = sha256_bytes(data)
        if actual != PINNED_SINGBOX_SHA256:
            raise LabError(
                "pinned sing-box SHA-256 mismatch: expected %s got %s "
                "(refusing to run a substituted binary)"
                % (PINNED_SINGBOX_SHA256, actual))
        write_bytes(archive_path, data, 0o600)
    actual = sha256_file(archive_path)
    if actual != PINNED_SINGBOX_SHA256:
        raise LabError("pinned sing-box SHA-256 mismatch after download: %s"
                       % actual)
    extract_dir = ensure_dir(os.path.join(workdir, "extracted"))
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name
            if name.startswith("/") or ".." in name.split("/"):
                raise LabError("pinned archive contains an unsafe path: %r" % name)
            if not (member.isfile() or member.isdir()):
                continue
            archive.extract(member, extract_dir, filter="data")
    for root, _dirs, files in os.walk(extract_dir):
        for filename in files:
            if filename == "sing-box":
                candidate = os.path.join(root, filename)
                os.chmod(candidate, 0o755)
                return candidate
    raise LabError("pinned sing-box archive did not contain a sing-box binary")


# ---------------------------------------------------------------------------
# Managed child processes (all children are cleaned up by the lab)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ManagedProcess:
    name: str
    command: list
    log_path: str
    cwd: str | None = None
    env: dict | None = None
    process: subprocess.Popen | None = None
    _log_handle: object = None

    def start(self) -> "ManagedProcess":
        ensure_dir(os.path.dirname(self.log_path) or ".")
        handle = open(self.log_path, "ab")
        env = dict(os.environ)
        if self.env:
            env.update(self.env)
        self._log_handle = handle
        self.process = subprocess.Popen(
            self.command, cwd=self.cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=handle, stderr=subprocess.STDOUT,
            start_new_session=(os.name == "posix"))
        return self

    def alive(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def returncode(self):
        return None if self.process is None else self.process.returncode

    def wait(self, timeout: float) -> int:
        if self.process is None:
            raise LabError("%s was never started" % self.name)
        return self.process.wait(timeout=timeout)

    def terminate(self, timeout: float = 10.0) -> None:
        if self.process is None or self.process.poll() is not None:
            self._close_log()
            return
        try:
            self.process.terminate()
        except OSError:
            pass
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
        self._close_log()

    def kill(self) -> None:
        if self.process is None:
            return
        try:
            if os.name == "posix":
                os.killpg(os.getpgid(self.process.pid), 9)
            else:
                self.process.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        self._close_log()

    def _close_log(self) -> None:
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except OSError:
                pass
            self._log_handle = None

    def log_tail(self, max_bytes: int = 6000) -> str:
        try:
            with open(self.log_path, "rb") as handle:
                handle.seek(0, os.SEEK_END)
                size = handle.tell()
                handle.seek(max(0, size - max_bytes))
                return handle.read().decode("utf-8", "replace")
        except OSError:
            return ""


def run_capture(command: list, timeout: float = 120.0,
                cwd: str | None = None, env: dict | None = None,
                input_text: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        command, capture_output=True, text=True, timeout=timeout, cwd=cwd,
        env=env, input=input_text, check=False)


# ---------------------------------------------------------------------------
# Loopback HTTP payload fixture (deterministic known up/down payloads)
# ---------------------------------------------------------------------------


class PayloadServer:
    """Local deterministic HTTP server used as the real traffic destination.

    Endpoints:
      GET  /payload/<size>     -> exactly <size> deterministic bytes
      POST /upload/<size>      -> reads+discards <size> bytes, returns count
      GET  /slow               -> streams <size> bytes with pacing (long conn)
      GET  /hold               -> sends headers then idles (idle connection)
      GET  /health             -> tiny JSON
    """

    def __init__(self, port: int):
        self.port = port
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def _send_bytes(self, data: bytes):
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                self.wfile.flush()

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                query = {}
                if "?" in self.path:
                    from urllib.parse import parse_qs
                    query = parse_qs(self.path.split("?", 1)[1])
                try:
                    if path == "/health":
                        self._send_bytes(b'{"ok":true}')
                        return
                    if path.startswith("/payload/"):
                        size = int(path.rsplit("/", 1)[-1])
                        if size < 0 or size > 64 * 1024 * 1024:
                            raise ValueError("size out of range")
                        self._send_bytes(b"P" * size)
                        return
                    if path == "/slow":
                        size = int(query.get("size", ["2097152"])[0])
                        delay = float(query.get("delay", ["4.0"])[0])
                        chunk = max(1, size // 20)
                        self.send_response(200)
                        self.send_header("Content-Type",
                                         "application/octet-stream")
                        self.send_header("Content-Length", str(size))
                        self.end_headers()
                        sent = 0
                        step = max(delay / 20.0, 0.01)
                        while sent < size:
                            piece = min(chunk, size - sent)
                            self.wfile.write(b"S" * piece)
                            self.wfile.flush()
                            sent += piece
                            time.sleep(step)
                        return
                    if path == "/hold":
                        seconds = float(query.get("seconds", ["4"])[0])
                        body = b"hold"
                        self.send_response(200)
                        self.send_header("Content-Type", "text/plain")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.flush()
                        time.sleep(min(max(seconds, 0.1), 20.0))
                        try:
                            self.wfile.write(body)
                            self.wfile.flush()
                        except OSError:
                            pass
                        return
                except (ValueError, OSError):
                    pass
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                path = self.path.split("?", 1)[0]
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if path == "/upload/echo":
                    data = self.rfile.read(length) if length else b""
                    self._send_bytes(data)
                    return
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(remaining, 1 << 20))
                    if not chunk:
                        break
                    remaining -= len(chunk)
                body = json.dumps({"received": length}).encode("utf-8")
                self._send_bytes(body)

        self._server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", port), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="um-lt-payload",
            daemon=True)

    def start(self) -> "PayloadServer":
        self._thread.start()
        wait_port("127.0.0.1", self.port, timeout=10)
        return self

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:  # noqa: BLE001 - best-effort teardown
            pass
        try:
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass


class TlsCamouflageServer:
    """Loopback TLS server acting as the Reality handshake target.

    It presents the synthetic self-signed certificate for the .test server
    name. Reality relays the TLS handshake to this target; the lab client uses
    uTLS+REALITY so no real/third-party site is contacted.
    """

    def __init__(self, port: int, cert_path: str, key_path: str):
        self.port = port
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args):
                pass

            def do_GET(self):
                body = b"camouflage-ok"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert_path, key_path)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
        server.daemon_threads = True
        server.socket = context.wrap_socket(server.socket, server_side=True)
        self._server = server
        self._thread = threading.Thread(
            target=server.serve_forever, name="um-lt-tls-camouflage",
            daemon=True)

    def start(self) -> "TlsCamouflageServer":
        self._thread.start()
        wait_port("127.0.0.1", self.port, timeout=10)
        return self

    def stop(self) -> None:
        try:
            self._server.shutdown()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------------------
# Traffic generation through the real sing-box clients (curl through socks)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class CurlResult:
    ok: bool
    http_code: int
    size_download: int
    size_upload: int
    time_total: float
    returncode: int
    stderr: str = ""


def run_curl_socks(socks_port: int, url: str, method: str = "GET",
                   upload_bytes: bytes | None = None,
                   max_time: float = 120.0, extra_args: list | None = None,
                   limit_rate: str | None = None) -> CurlResult:
    """Run curl through a real sing-box socks inbound and measure bytes.

    The curl byte counts are the INDEPENDENT expected payload measurement for
    the directional assertions; they are not read from sing-box/monitor.
    """
    curl = shutil.which("curl")
    if not curl:
        raise LabError("curl is required for the lab's independent payload "
                       "measurement but was not found on PATH")
    command = [
        curl, "-sS", "--max-time", "%.0f" % max_time,
        "--socks5-hostname", "127.0.0.1:%d" % socks_port,
        "-o", os.devnull if os.name != "nt" else "NUL",
        "-w", "%{http_code} %{size_download} %{size_upload} %{time_total}",
    ]
    temp_path = None
    try:
        if method == "POST":
            payload = upload_bytes if upload_bytes is not None else b"U" * 65536
            fd, temp_path = tempfile_mkstemp()
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            command += ["-X", "POST", "--data-binary", "@" + temp_path,
                        "-H", "Content-Type: application/octet-stream",
                        "-H", "Expect:"]
        if limit_rate:
            command += ["--limit-rate", limit_rate]
        if extra_args:
            command += list(extra_args)
        command.append(url)
        result = run_capture(command, timeout=max_time + 30)
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
    parsed = {"http_code": 0, "size_download": 0, "size_upload": 0,
              "time_total": 0.0}
    fields = (result.stdout or "").strip().split()
    if len(fields) >= 4:
        try:
            parsed = {"http_code": int(fields[0]),
                      "size_download": int(fields[1]),
                      "size_upload": int(fields[2]),
                      "time_total": float(fields[3])}
        except ValueError:
            pass
    return CurlResult(
        ok=(result.returncode == 0 and parsed["http_code"] == 200),
        returncode=result.returncode,
        stderr=(result.stderr or "").strip()[-500:],
        **parsed)


def tempfile_mkstemp(suffix: str = ".bin") -> tuple[int, str]:
    import tempfile
    return tempfile.mkstemp(prefix="um-lt-", suffix=suffix)


class TrafficLedger:
    """Independent measured-payload ledger used to bound observed counters.

    Expected payload bytes are measured with curl (size_download /
    size_upload); observed monitor/agent bytes must be >= the measured payload
    after settling and must never exceed the measured payload plus a bounded
    protocol-overhead tolerance for the matching direction.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.downloads = {}  # inbound_tag -> bytes
        self.uploads = {}
        self.records = []  # list of dict records (phase, protocol, direction, bytes)

    def record(self, inbound_tag: str, direction: str, nbytes: int,
               phase: str = "", note: str = "") -> None:
        if nbytes < 0:
            raise LabError("negative measured payload")
        with self._lock:
            target = self.downloads if direction == "downlink" else self.uploads
            target[inbound_tag] = target.get(inbound_tag, 0) + int(nbytes)
            self.records.append({
                "phase": phase, "inbound_tag": inbound_tag,
                "direction": direction, "bytes": int(nbytes),
                "note": note,
            })

    def expected(self, inbound_tag: str, direction: str) -> int:
        with self._lock:
            target = self.downloads if direction == "downlink" else self.uploads
            return target.get(inbound_tag, 0)


def overhead_tolerance(expected: int) -> int:
    """Bounded protocol overhead allowance for one direction.

    TLS/QUIC/HTTP framing adds per-record overhead but never the same order of
    magnitude as the payload; 2% + 128 KiB is generous for lab-size transfers
    while still catching cross-attribution or double counting.
    """
    return max(128 * 1024, int(expected * 0.02))


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


class HttpClient:
    """Minimal cookie-aware HTTP client for the loopback lab planes."""

    def __init__(self):
        self.jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, method: str, url: str, body=None,
                headers: dict | None = None,
                timeout: float = 20.0) -> tuple[int, dict, bytes]:
        data = None
        if body is not None:
            data = (body if isinstance(body, bytes)
                    else json.dumps(body).encode("utf-8"))
        request = urllib.request.Request(url, data=data, method=method)
        if data is not None:
            request.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return (response.status, dict(response.headers),
                        response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers or {}), exc.read()

    def get_json(self, url: str, timeout: float = 20.0):
        status, _headers, raw = self.request("GET", url, timeout=timeout)
        try:
            return status, json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None

    def post_json(self, url: str, body, timeout: float = 20.0):
        status, _headers, raw = self.request("POST", url, body, timeout=timeout)
        try:
            return status, json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return status, None


def http_get(url: str, timeout: float = 20.0) -> tuple[int, bytes]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


# ---------------------------------------------------------------------------
# Export document validation (canonical monitor-v2 v1 shape)
# ---------------------------------------------------------------------------


def _require_int(value, path: str, minimum: int = 0,
                 maximum: int = MAX_TIMESTAMP) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ExportValidationError("%s must be a JSON integer" % path)
    if value < minimum or value > maximum:
        raise ExportValidationError("%s is outside [%d, %d]"
                                    % (path, minimum, maximum))
    return value


def _require_int_or_none(value, path: str, minimum: int = 0,
                         maximum: int = MAX_TIMESTAMP):
    if value is None:
        return None
    return _require_int(value, path, minimum, maximum)


def _require_number_or_none(value, path: str, maximum: float):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ExportValidationError("%s must be a JSON number or null" % path)
    numeric = float(value)
    if numeric != numeric or numeric in (float("inf"), float("-inf")):
        raise ExportValidationError("%s must be finite" % path)
    if numeric < 0 or numeric > maximum:
        raise ExportValidationError("%s is outside [0, %s]" % (path, maximum))
    return numeric


def _require_bool(value, path: str) -> bool:
    if not isinstance(value, bool):
        raise ExportValidationError("%s must be a JSON boolean" % path)
    return value


def _require_exact_keys(document: dict, expected: frozenset, where: str,
                        error_cls=ExportValidationError) -> None:
    if not isinstance(document, dict):
        raise error_cls("%s must be a JSON object" % where)
    actual = set(document)
    missing = expected - actual
    unknown = actual - expected
    if missing:
        raise error_cls("%s is missing required member(s): %s"
                        % (where, ", ".join(sorted(missing))))
    if unknown:
        raise error_cls(
            "%s carries forbidden/unknown member(s): %s (the export is a "
            "closed allow-list and must not carry ids/users/IPs/secrets/raw "
            "monitor data)" % (where, ", ".join(sorted(unknown))))


def detect_export_shape(document) -> str:
    if not isinstance(document, dict):
        raise ExportValidationError("export document must be a JSON object")
    if "schema" in document or "schema_version" in document:
        return "monitor-v2-v1"
    if "export_version" in document:
        return "legacy-draft-v1"
    raise ExportValidationError(
        "unrecognized export document: no 'schema'/'schema_version' "
        "(canonical monitor-v2 v1) and no 'export_version' (legacy draft) "
        "member found; refusing to interpret an unknown local export")


def validate_export_document(document) -> dict:
    """Strictly validate the canonical monitor-v2 export; return normalized dict.

    Every member is checked against the closed allow-list, numeric bounds are
    exact-integer checked (a float like 1048576.0 is NOT accepted for a byte
    counter), null means unavailable (never zero), and the coherence rules the
    JSON shape cannot express are enforced here.
    """
    shape = detect_export_shape(document)
    if shape == "legacy-draft-v1":
        raise ExportValidationError(
            "the monitor export uses the superseded draft shape "
            "('export_version', 'availability', 'uplink_observed_lower_bound_"
            "bytes'); the reconciled rev-7 contract requires the canonical "
            "'schema'/'schema_version'/'source':'monitor-v2' shape with "
            "'observed_uplink_bytes'/'observed_downlink_bytes'. Update the "
            "monitor-v2 writer before running the real-protocol lab.")
    _require_exact_keys(document, EXPORT_KEYS, "export document")
    if document["schema"] != EXPORT_SCHEMA:
        raise ExportValidationError("export.schema must be %r" % EXPORT_SCHEMA)
    if document["schema_version"] != EXPORT_SCHEMA_VERSION:
        raise ExportValidationError("export.schema_version must be %d"
                                    % EXPORT_SCHEMA_VERSION)
    if document["source"] != EXPORT_SOURCE:
        raise ExportValidationError("export.source must be %r (the report-only "
                                    "token %r is not allowed in the file)"
                                    % (EXPORT_SOURCE, REPORT_SOURCE))
    source_epoch = document["source_epoch"]
    if not isinstance(source_epoch, str) or not SOURCE_EPOCH_RE.match(source_epoch):
        raise ExportValidationError(
            "export.source_epoch must be 32 lowercase hex characters")
    sequence = _require_int(document["sequence"], "export.sequence",
                            maximum=SAFE_INT_MAX)
    generated_at = _require_int(document["generated_at"], "export.generated_at")
    observed_at = _require_int(document["observed_at"], "export.observed_at")
    if observed_at > generated_at:
        raise ExportValidationError(
            "export.observed_at must be <= export.generated_at")
    if generated_at - observed_at > MAX_COHORT_SECONDS:
        raise ExportValidationError(
            "export.generated_at/observed_at coherence window is unbounded")
    monitor_stale = _require_bool(document["monitor_stale"],
                                  "export.monitor_stale")
    last_success = _require_int_or_none(
        document["monitor_last_success_at"],
        "export.monitor_last_success_at")
    if last_success is not None and last_success > generated_at:
        raise ExportValidationError(
            "export.monitor_last_success_at must not be in the future")
    if document["counter_scope"] != COUNTER_SCOPE:
        raise ExportValidationError("export.counter_scope must be %r"
                                    % COUNTER_SCOPE)
    if document["exactness"] != EXACTNESS:
        raise ExportValidationError("export.exactness must be %r" % EXACTNESS)
    active_connections = _require_int_or_none(
        document["active_connections"], "export.active_connections",
        maximum=MAX_ACTIVE_CONNECTIONS)
    rate_window = _require_number_or_none(
        document["rate_window_seconds"], "export.rate_window_seconds",
        MAX_RATE_WINDOW_SECONDS)
    if rate_window is not None and rate_window <= 0:
        raise ExportValidationError(
            "export.rate_window_seconds must be > 0 when present")
    raw_inbounds = document["inbounds"]
    if not isinstance(raw_inbounds, list):
        raise ExportValidationError("export.inbounds must be a JSON array")
    if len(raw_inbounds) > MAX_INBOUNDS:
        raise ExportValidationError("export.inbounds exceeds %d entries"
                                    % MAX_INBOUNDS)
    rows = []
    seen_tags = set()
    active_sum = 0
    any_rate = False
    for index, raw_row in enumerate(raw_inbounds):
        label = "export.inbounds[%d]" % index
        _require_exact_keys(raw_row, EXPORT_INBOUND_KEYS, label)
        tag = raw_row["inbound_tag"]
        if not isinstance(tag, str) or not TAG_RE.match(tag):
            raise ExportValidationError("%s.inbound_tag is not contract-shaped"
                                        % label)
        if tag in seen_tags:
            raise ExportValidationError("%s carries a duplicate inbound_tag %r"
                                        % (label, tag))
        seen_tags.add(tag)
        kind = raw_row["kind"]
        if kind not in KINDS:
            raise ExportValidationError("%s.kind is not one of %s"
                                        % (label, "/".join(sorted(KINDS))))
        row_observed_at = _require_int(raw_row["observed_at"],
                                       label + ".observed_at")
        if row_observed_at > generated_at + FUTURE_TOLERANCE_SECONDS:
            raise ExportValidationError(
                "%s.observed_at is in the future beyond tolerance" % label)
        if row_observed_at < generated_at - MAX_COHORT_SECONDS:
            raise ExportValidationError(
                "%s.observed_at is older than the coherence window" % label)
        row_active = _require_int(raw_row["active_connections"],
                                  label + ".active_connections",
                                  maximum=MAX_ACTIVE_CONNECTIONS)
        active_sum += row_active
        uplink = _require_int_or_none(
            raw_row["observed_uplink_bytes"],
            label + ".observed_uplink_bytes", maximum=SAFE_INT_MAX)
        downlink = _require_int_or_none(
            raw_row["observed_downlink_bytes"],
            label + ".observed_downlink_bytes", maximum=SAFE_INT_MAX)
        uplink_rate = _require_number_or_none(
            raw_row["uplink_observed_rate_bps"],
            label + ".uplink_observed_rate_bps", MAX_RATE_BPS)
        downlink_rate = _require_number_or_none(
            raw_row["downlink_observed_rate_bps"],
            label + ".downlink_observed_rate_bps", MAX_RATE_BPS)
        quality = raw_row["quality"]
        if quality not in QUALITIES:
            raise ExportValidationError("%s.quality is not one of %s"
                                        % (label, "/".join(sorted(QUALITIES))))
        if quality == "lower_bound" and (uplink is None or downlink is None):
            raise ExportValidationError(
                "%s claims quality=lower_bound without both byte counters"
                % label)
        if quality == "unavailable" and (
                uplink is not None or downlink is not None
                or uplink_rate is not None or downlink_rate is not None):
            raise ExportValidationError(
                "%s claims quality=unavailable while carrying observed data"
                % label)
        if quality == "partial" and (
                uplink is None and downlink is None
                and uplink_rate is None and downlink_rate is None):
            raise ExportValidationError(
                "%s claims quality=partial without any observed value" % label)
        if uplink_rate is not None or downlink_rate is not None:
            any_rate = True
            if rate_window is None:
                raise ExportValidationError(
                    "%s carries observed rates without a rate window (export.rate_window_seconds)"
                    % label)
        if monitor_stale and quality != "partial":
            raise ExportValidationError(
                "%s must be quality=partial while the monitor declares stale"
                % label)
        if monitor_stale and (uplink_rate is not None
                              or downlink_rate is not None):
            raise ExportValidationError(
                "%s must not carry rates while the monitor is stale" % label)
        rows.append({
            "inbound_tag": tag,
            "kind": kind,
            "uplink": uplink,
            "downlink": downlink,
            "uplink_rate": uplink_rate,
            "downlink_rate": downlink_rate,
            "active": row_active,
            "observed_at": row_observed_at,
            "quality": quality,
        })
    if any_rate and rate_window is None:
        raise ExportValidationError("export carries rates without a rate window")
    if active_connections is not None and active_connections < active_sum:
        raise ExportValidationError(
            "export.active_connections is smaller than the sum of the "
            "per-inbound active counts")
    return {
        "shape": shape,
        "source_epoch": source_epoch,
        "sequence": sequence,
        "generated_at": generated_at,
        "observed_at": observed_at,
        "monitor_stale": monitor_stale,
        "monitor_last_success_at": last_success,
        "active_connections": active_connections,
        "rate_window_seconds": rate_window,
        "inbounds": rows,
        "raw": document,
    }


def export_row(normalized: dict, inbound_tag: str):
    for row in normalized["inbounds"]:
        if row["inbound_tag"] == inbound_tag:
            return row
    return None


def export_observed(normalized: dict, inbound_tag: str,
                    direction: str):
    row = export_row(normalized, inbound_tag)
    if row is None or row["quality"] == "unavailable":
        return None
    return row["uplink" if direction == "uplink" else "downlink"]


def validate_export_file(path: str) -> dict:
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_EXPORT_BYTES + 1)
    except OSError as exc:
        raise ExportValidationError("cannot read export file: %s" % exc) from exc
    if len(raw) > MAX_EXPORT_BYTES:
        raise ExportValidationError("export file exceeds %d bytes"
                                    % MAX_EXPORT_BYTES)
    if not raw.strip():
        raise ExportValidationError("export file is empty")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise ExportValidationError("export file is not valid UTF-8 JSON: %s"
                                    % exc) from exc
    normalized = validate_export_document(document)
    normalized["raw_bytes"] = raw
    return normalized


def wait_for_export(path: str, timeout: float, predicate=None,
                    description: str = "a valid monitor traffic export") -> dict:
    """Wait until the export file is valid and (optionally) satisfies predicate."""

    def _check():
        try:
            normalized = validate_export_file(path)
        except ExportValidationError:
            return None
        if predicate is None or predicate(normalized):
            return normalized
        return None

    # Manual loop so the timeout error is stage-specific and printable.
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            value = _check()
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            value = None
        if value:
            return value
        time.sleep(0.15)
    raise LabAssertionFailed("timed out after %.0fs waiting for %s%s"
                             % (timeout, description,
                                "" if last_error is None
                                else " (last error: %s)" % last_error))


# ---------------------------------------------------------------------------
# rev-7 report body validation (captured from the real agent HTTP request)
# ---------------------------------------------------------------------------


def _find_report_kind(report: dict) -> str:
    return report.get("type", "")


def validate_rev7_snapshot_report(report: dict, expected_tags=EXPECTED_TAGS,
                                  expected_availability=None) -> dict:
    """Validate the rev-7 additions of a real captured agent snapshot report."""
    try:
        return _validate_rev7_snapshot_report(report, expected_tags,
                                             expected_availability)
    except ReportValidationError:
        raise
    except ExportValidationError as exc:
        raise ReportValidationError(str(exc)) from None


def _validate_rev7_snapshot_report(report: dict,
                                  expected_tags=EXPECTED_TAGS,
                                  expected_availability=None) -> dict:
    if not isinstance(report, dict):
        raise ReportValidationError("report body is not a JSON object")
    if report.get("v") != 1:
        raise ReportValidationError("report.v must be 1")
    if report.get("type") != "snapshot":
        raise ReportValidationError("expected a snapshot report, got %r"
                                    % report.get("type"))
    observation = report.get("traffic_observation")
    if report.get("contract_revision") == CONTRACT_REVISION_7:
        if not isinstance(observation, dict):
            raise ReportValidationError(
                "rev-7 snapshot report must carry a traffic_observation object")
        _require_exact_keys(observation, REPORT_OBSERVATION_KEYS,
                            "report.traffic_observation",
                            ReportValidationError)
        if observation["source"] != REPORT_SOURCE:
            raise ReportValidationError(
                "traffic_observation.source must be %r" % REPORT_SOURCE)
        if observation["counter_scope"] != COUNTER_SCOPE:
            raise ReportValidationError(
                "traffic_observation.counter_scope must be %r" % COUNTER_SCOPE)
        if observation["exactness"] != EXACTNESS:
            raise ReportValidationError(
                "traffic_observation.exactness must be %r" % EXACTNESS)
        source_epoch = observation["source_epoch"]
        if not isinstance(source_epoch, str) or not SOURCE_EPOCH_RE.match(source_epoch):
            raise ReportValidationError(
                "traffic_observation.source_epoch must be 32 lowercase hex")
        sequence = _require_int(observation["sequence"],
                                "traffic_observation.sequence",
                                maximum=SAFE_INT_MAX)
        observed_at = _require_int(observation["observed_at"],
                                   "traffic_observation.observed_at")
        collected_at = _require_int(report.get("collected_at", -1),
                                    "report.collected_at")
        if observed_at > collected_at + FUTURE_TOLERANCE_SECONDS:
            raise ReportValidationError(
                "traffic_observation.observed_at is after collected_at")
        age = _require_int(observation["age_seconds"],
                           "traffic_observation.age_seconds",
                           maximum=MAX_AGE_SECONDS)
        freshness = observation["freshness"]
        if freshness not in FRESHNESS:
            raise ReportValidationError("traffic_observation.freshness invalid")
        availability = observation["availability"]
        if availability not in AVAILABILITY:
            raise ReportValidationError(
                "traffic_observation.availability invalid")
        if observation["rate_window_seconds"] is not None:
            _require_number_or_none(observation["rate_window_seconds"],
                                    "traffic_observation.rate_window_seconds",
                                    MAX_RATE_WINDOW_SECONDS)
        active = _require_int_or_none(
            observation["active_connections"],
            "traffic_observation.active_connections",
            maximum=MAX_ACTIVE_CONNECTIONS)
        rows = observation["inbounds"]
        if not isinstance(rows, list) or len(rows) > MAX_INBOUNDS:
            raise ReportValidationError(
                "traffic_observation.inbounds must be an array of <= %d rows"
                % MAX_INBOUNDS)
        parsed_rows = []
        seen = set()
        for index, row in enumerate(rows):
            label = "traffic_observation.inbounds[%d]" % index
            _require_exact_keys(row, REPORT_OBSERVATION_INBOUND_KEYS, label,
                                ReportValidationError)
            tag = row["inbound_tag"]
            if not isinstance(tag, str) or not TAG_RE.match(tag):
                raise ReportValidationError("%s.inbound_tag invalid" % label)
            if tag in seen:
                raise ReportValidationError("%s duplicate inbound_tag" % label)
            seen.add(tag)
            if row["kind"] not in KINDS:
                raise ReportValidationError("%s.kind invalid" % label)
            if row["availability"] not in AVAILABILITY:
                raise ReportValidationError("%s.availability invalid" % label)
            if row["quality"] not in QUALITIES:
                raise ReportValidationError("%s.quality invalid" % label)
            row_observed_at = _require_int(row["observed_at"],
                                           label + ".observed_at")
            if row_observed_at > collected_at + FUTURE_TOLERANCE_SECONDS:
                raise ReportValidationError("%s.observed_at is after "
                                            "collected_at" % label)
            row_active = _require_int(row["active_connections"],
                                      label + ".active_connections",
                                      maximum=MAX_ACTIVE_CONNECTIONS)
            uplink = _require_int_or_none(
                row["uplink_observed_lower_bound_bytes"],
                label + ".uplink_observed_lower_bound_bytes",
                maximum=SAFE_INT_MAX)
            downlink = _require_int_or_none(
                row["downlink_observed_lower_bound_bytes"],
                label + ".downlink_observed_lower_bound_bytes",
                maximum=SAFE_INT_MAX)
            if row["quality"] == "lower_bound" and (uplink is None
                                                    or downlink is None):
                raise ReportValidationError(
                    "%s claims lower_bound without both counters" % label)
            parsed_rows.append({
                "inbound_tag": tag,
                "kind": row["kind"],
                "uplink": uplink,
                "downlink": downlink,
                "active": row_active,
                "observed_at": row_observed_at,
                "availability": row["availability"],
                "quality": row["quality"],
            })
        expected_map = dict(expected_tags)
        for row in parsed_rows:
            if row["inbound_tag"] not in expected_map:
                raise ReportValidationError(
                    "traffic_observation carries an inbound tag not present in "
                    "the center-authorized expected tags")
            if expected_map[row["inbound_tag"]] != row["kind"]:
                raise ReportValidationError(
                    "traffic_observation kind does not match the authorized "
                    "kind for its inbound tag")
        if expected_availability is not None:
            if availability != expected_availability:
                raise ReportValidationError(
                    "traffic_observation.availability %r != expected %r"
                    % (availability, expected_availability))
        return {
            "source": observation["source"],
            "source_epoch": source_epoch,
            "sequence": sequence,
            "observed_at": observed_at,
            "age_seconds": age,
            "freshness": freshness,
            "availability": availability,
            "active_connections": active,
            "counter_scope": observation["counter_scope"],
            "exactness": observation["exactness"],
            "inbounds": parsed_rows,
        }
    if observation is not None:
        raise ReportValidationError(
            "report carries a traffic_observation without contract_revision=7")
    # Rev-5 body: the source is disabled, so the base traffic array must stay
    # empty and no rev-7 members may leak.
    if report.get("traffic") not in ([], None):
        raise ReportValidationError(
            "rev-5 body must keep the frozen base traffic array empty")
    return {"rev5": True}


# ---------------------------------------------------------------------------
# Privacy scanners
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(
    r"(?<![0-9A-Za-z_.-])(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(?![0-9A-Za-z_.-])")
_IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_URL_RE = re.compile(r"\b(?:https?|socks5h?|quic|hysteria2?|vless|trojan|"
                     r"shadowsocks)://\S+", re.I)
_HOSTPORT_RE = re.compile(
    r"(?<![0-9A-Za-z_.-])[A-Za-z0-9][A-Za-z0-9._-]*\.[A-Za-z]{2,63}"
    r":[0-9]{1,5}(?![0-9])")
_PATH_RE = re.compile(r"(?:[A-Za-z]:\\|(?<![\w.])/(?:[A-Za-z0-9._-]+/){2,})")


def _iter_strings(value, path="$"):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_strings(child, "%s.%s" % (path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _iter_strings(child, "%s[%d]" % (path, index))


def scan_document_for_network_literals(document) -> list[dict]:
    """Find IP addresses / URLs / host:port / filesystem paths in string values."""
    findings = []
    for path, text in _iter_strings(document):
        checks = (
            ("ipv4", _IPV4_RE), ("ipv6", _IPV6_RE), ("url", _URL_RE),
            ("host_port", _HOSTPORT_RE), ("filesystem_path", _PATH_RE),
        )
        for kind, pattern in checks:
            match = pattern.search(text)
            if match:
                findings.append({"path": path, "kind": kind})
    return findings


def scan_for_sentinels(raw: bytes, sentinels: list[str]) -> list[dict]:
    """Find synthetic secret sentinels in raw bytes without echoing them."""
    findings = []
    for index, sentinel in enumerate(sentinels):
        if not sentinel or len(sentinel) < 8:
            continue
        try:
            needle = sentinel.encode("utf-8")
        except UnicodeEncodeError:
            continue
        if needle in raw:
            findings.append({"sentinel_index": index, "length": len(sentinel)})
    return findings


def privacy_scan_export(document, raw_bytes: bytes,
                        sentinels: list[str]) -> list[dict]:
    """Return all privacy findings for one export document (empty = clean)."""
    findings = []
    for finding in scan_for_sentinels(raw_bytes, sentinels):
        findings.append({"kind": "secret-sentinel", **finding})
    for finding in scan_document_for_network_literals(document):
        findings.append({"kind": "network-literal",
                         "pattern": finding["kind"],
                         "path": finding["path"]})
    return findings


def privacy_scan_report(report: dict, raw_bytes: bytes,
                        sentinels: list[str],
                        allowed_report_id: str | None = None) -> list[dict]:
    findings = []
    for finding in scan_for_sentinels(raw_bytes, sentinels):
        findings.append({"kind": "secret-sentinel", **finding})
    for finding in scan_document_for_network_literals(report):
        findings.append({"kind": "network-literal", **finding})
    # report_id is the one contract-required UUID; no OTHER UUID-shaped value
    # may appear in a snapshot report body.
    for path, text in _iter_strings(report):
        if not UUID_RE.match(text):
            continue
        if allowed_report_id and text == allowed_report_id:
            continue
        findings.append({"kind": "unexpected-uuid", "path": path})
    return findings


# ---------------------------------------------------------------------------
# Read-only SQLite helpers for the center normalized traffic store
# ---------------------------------------------------------------------------

TRAFFIC_REPORT_TABLE = "traffic_observation_reports"
TRAFFIC_OBSERVATION_TABLE = "traffic_observations"


def open_sqlite_readonly(db_path: str):
    import sqlite3
    if not os.path.isfile(db_path):
        raise LabError("center database does not exist: %s" % db_path)
    uri = "file:%s?mode=ro" % db_path.replace("?", "%3f").replace("#", "%23")
    connection = sqlite3.connect(uri, uri=True, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def sqlite_table_exists(connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table,)).fetchone()
    return row is not None


def sqlite_table_columns(connection, table: str) -> list[str]:
    rows = connection.execute("PRAGMA table_info(%s)" % table).fetchall()
    return [row["name"] for row in rows]


def sqlite_schema_version(connection) -> int:
    if not sqlite_table_exists(connection, "schema_migrations"):
        return 0
    row = connection.execute("SELECT MAX(version) AS v FROM schema_migrations"
                             ).fetchone()
    return int(row["v"] or 0)


def fetch_traffic_reports(connection) -> list[dict]:
    if not sqlite_table_exists(connection, TRAFFIC_REPORT_TABLE):
        return []
    rows = connection.execute(
        "SELECT * FROM %s ORDER BY report_row_id" % TRAFFIC_REPORT_TABLE
    ).fetchall()
    return [dict(row) for row in rows]


def fetch_traffic_observations(connection) -> list[dict]:
    if not sqlite_table_exists(connection, TRAFFIC_OBSERVATION_TABLE):
        return []
    reports_present = sqlite_table_exists(connection,
                                          TRAFFIC_REPORT_TABLE)
    if reports_present:
        query = (
            "SELECT o.*, r.source_epoch AS source_epoch, "
            "r.sequence AS report_sequence, "
            "r.availability AS report_availability, "
            "r.freshness AS report_freshness "
            "FROM %s o LEFT JOIN %s r "
            "ON r.report_row_id = o.report_row_id "
            "ORDER BY o.id") % (TRAFFIC_OBSERVATION_TABLE,
                                TRAFFIC_REPORT_TABLE)
    else:
        query = "SELECT * FROM %s ORDER BY id" % TRAFFIC_OBSERVATION_TABLE
    rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]


def traffic_series(observations: list[dict]) -> dict:
    """Aggregate normalized observation rows by (source_epoch, tag) series.

    Rows are lower bounds for one monitor observation epoch; the lab never sums
    across epochs (that would fabricate a lifetime total).
    """
    series = {}
    for row in observations:
        key = (row.get("source_epoch") or "", row.get("inbound_tag") or "")
        slot = series.setdefault(key, {
            "source_epoch": key[0],
            "inbound_tag": key[1],
            "kind": row.get("kind"),
            "max_uplink_lower_bound": None,
            "max_downlink_lower_bound": None,
            "reports": 0,
            "qualities": set(),
            "availabilities": set(),
        })
        slot["reports"] += 1
        for column, target in (("uplink_observed_lower_bound_bytes",
                                "max_uplink_lower_bound"),
                               ("downlink_observed_lower_bound_bytes",
                                "max_downlink_lower_bound")):
            value = row.get(column)
            if value is None:
                continue
            current = slot[target]
            slot[target] = value if current is None else max(current, value)
        if row.get("quality"):
            slot["qualities"].add(row["quality"])
        if row.get("availability"):
            slot["availabilities"].add(row["availability"])
    return series


def latest_traffic_values(observations: list[dict]) -> dict:
    """Latest observed row per (node, tag, kind) series keyed by epoch+tag."""
    latest = {}
    for row in observations:
        epoch = row.get("source_epoch") or ""
        tag = row.get("inbound_tag") or ""
        key = (epoch, tag)
        observed = int(row.get("observed_at") or 0)
        if key not in latest or observed >= int(latest[key].get("observed_at") or 0):
            latest[key] = row
    return latest


# ---------------------------------------------------------------------------
# Loopback capture proxy (evidence for duplicate/replay + report-body privacy)
# ---------------------------------------------------------------------------


class CaptureProxy:
    """Loopback HTTP proxy between the real agent and the real center.

    The agent's `--center` URL always points at this proxy, which forwards every
    request to the real center ingest listener and records the raw report
    request bytes. Those raw bytes are replayed verbatim in the duplicate/replay
    stage and privacy-scanned in the report-body stage. The proxy stores only
    report bodies in memory (never writes them to disk before the privacy scan
    passes) and never records Authorization/credential headers.
    """

    MAX_BODY_BYTES = 2 * 1024 * 1024

    def __init__(self, listen_port: int, backend_host: str, backend_port: int):
        self.listen_port = listen_port
        self._backend = (backend_host, backend_port)
        self._lock = threading.Lock()
        self._reports = []  # list of {"request": bytes, "body": bytes, "path": str}
        self._counts = {}
        self._server = None
        self._thread = None
        self._closed = threading.Event()

    # -- lifecycle -----------------------------------------------------------
    def start(self) -> "CaptureProxy":
        self._closed.clear()
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", self.listen_port))
        server.listen(64)
        server.settimeout(0.5)
        self._server = server
        self._thread = threading.Thread(target=self._accept_loop,
                                        name="um-lt-capture-proxy", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._closed.set()
        try:
            if self._server is not None:
                self._server.close()
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=5)

    def set_backend(self, host: str, port: int) -> None:
        with self._lock:
            self._backend = (host, port)

    # -- evidence ------------------------------------------------------------
    def report_count(self) -> int:
        with self._lock:
            return len(self._reports)

    def request_counts(self) -> dict:
        with self._lock:
            return dict(self._counts)

    def reports(self) -> list[dict]:
        with self._lock:
            return [dict(item) for item in self._reports]

    def last_report(self):
        with self._lock:
            return dict(self._reports[-1]) if self._reports else None

    def clear_reports(self) -> None:
        with self._lock:
            self._reports = []

    # -- internals -----------------------------------------------------------
    def _accept_loop(self) -> None:
        while not self._closed.is_set():
            try:
                client, _addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._serve_connection, args=(client,),
                             daemon=True).start()

    def _serve_connection(self, client: socket.socket) -> None:
        client.settimeout(30)
        try:
            request_bytes, method, path, headers, body = self._read_request(client)
            if request_bytes is None:
                return
            with self._lock:
                self._counts[path] = self._counts.get(path, 0) + 1
            if path == "/v1/agent/report" and len(body) <= self.MAX_BODY_BYTES:
                with self._lock:
                    self._reports.append({
                        "request": request_bytes,
                        "body": body,
                        "path": path,
                    })
            status, response_headers, response_body = self._forward(
                method, path, headers, body)
            self._write_response(client, status, response_headers, response_body)
        except (OSError, ValueError):
            try:
                client.close()
            except OSError:
                pass
            return
        finally:
            try:
                client.close()
            except OSError:
                pass

    @staticmethod
    def _recv_until(sock: socket.socket, marker: bytes,
                    max_bytes: int = 256 * 1024) -> bytes:
        data = b""
        while marker not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
            if len(data) > max_bytes:
                raise ValueError("request/response header block too large")
        return data

    def _read_request(self, client: socket.socket):
        header_blob = self._recv_until(client, b"\r\n\r\n")
        if not header_blob:
            return None, None, None, None, b""
        head, _, rest = header_blob.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) != 3:
            raise ValueError("malformed request line")
        method = parts[0].decode("ascii", "replace")
        path = parts[1].decode("ascii", "replace")
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            key, _, value = line.partition(b":")
            headers[key.decode("ascii", "replace").strip().lower()] = \
                value.decode("utf-8", "replace").strip()
        body = b""
        if headers.get("transfer-encoding", "").lower() == "chunked":
            raise ValueError("chunked request encoding is not supported by the "
                             "lab capture proxy")
        if "content-length" in headers:
            length = int(headers["content-length"])
            if length < 0 or length > self.MAX_BODY_BYTES:
                raise ValueError("request body too large")
            body = rest
            while len(body) < length:
                chunk = client.recv(length - len(body))
                if not chunk:
                    break
                body += chunk
            body = body[:length]
        raw = head + b"\r\n\r\n" + body
        return raw, method, path, headers, body

    def _forward(self, method: str, path: str, headers: dict, body: bytes):
        with self._lock:
            backend_host, backend_port = self._backend
        backend = socket.create_connection((backend_host, backend_port),
                                           timeout=20)
        backend.settimeout(30)
        try:
            lines = ["%s %s HTTP/1.1" % (method, path),
                     "Host: %s:%d" % (backend_host, backend_port),
                     "Connection: close"]
            for key, value in headers.items():
                if key in ("host", "connection", "content-length",
                           "transfer-encoding"):
                    continue
                lines.append("%s: %s" % (key, value))
            if body or method in ("POST", "PUT", "PATCH"):
                lines.append("Content-Length: %d" % len(body))
            request = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
            backend.sendall(request)
            response_blob = b""
            while True:
                chunk = backend.recv(65536)
                if not chunk:
                    break
                response_blob += chunk
            status, response_headers, response_body = self._parse_response(
                response_blob)
            return status, response_headers, response_body
        finally:
            try:
                backend.close()
            except OSError:
                pass

    @staticmethod
    def _parse_response(blob: bytes):
        head, _, body = blob.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        status_parts = lines[0].split(b" ", 2)
        if len(status_parts) < 2:
            raise ValueError("malformed backend response")
        status = int(status_parts[1])
        headers = {}
        for line in lines[1:]:
            if not line:
                continue
            key, _, value = line.partition(b":")
            headers[key.decode("ascii", "replace").strip().lower()] = \
                value.decode("utf-8", "replace").strip()
        if headers.get("transfer-encoding", "").lower() == "chunked":
            body = CaptureProxy._decode_chunked(body)
        return status, headers, body

    @staticmethod
    def _decode_chunked(data: bytes) -> bytes:
        out = b""
        index = 0
        while True:
            end = data.find(b"\r\n", index)
            if end < 0:
                break
            try:
                size = int(data[index:end].split(b";")[0].strip(), 16)
            except ValueError:
                break
            index = end + 2
            if size == 0:
                break
            out += data[index:index + size]
            index += size + 2
        return out

    @staticmethod
    def _write_response(client: socket.socket, status: int,
                        headers: dict, body: bytes) -> None:
        lines = ["HTTP/1.1 %d %s" % (status, "OK" if status == 200 else
                                      ("Bad Gateway" if status == 502 else
                                       "Response")),
                 "Content-Length: %d" % len(body),
                 "Connection: close"]
        for key in ("content-type", "retry-after", "cache-control"):
            if key in headers:
                lines.append("%s: %s" % (key.title(), headers[key]))
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8") + body
        client.sendall(payload)


def replay_raw_http_request(raw_request: bytes, host: str,
                            port: int) -> tuple[int, bytes]:
    """Send captured raw request bytes to a loopback HTTP listener verbatim."""
    connection = http.client.HTTPConnection(host, port, timeout=20)
    try:
        header_blob, _, body = raw_request.partition(b"\r\n\r\n")
        lines = header_blob.split(b"\r\n")
        method, path, _version = lines[0].decode("ascii").split(" ")
        headers = {}
        for line in lines[1:]:
            key, _, value = line.partition(b":")
            headers[key.decode("ascii").strip()] = value.decode("utf-8").strip()
        headers.pop("Host", None)
        headers.pop("Connection", None)
        headers.pop("Content-Length", None)
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


# ---------------------------------------------------------------------------
# Monitor-v2 web runtime helpers
# ---------------------------------------------------------------------------


def monitor_setup_command(python: str, webapp_path: str, data_dir: str,
                          password: str, recovery_out: str) -> list:
    return [python, webapp_path, "setup", "--data-dir", data_dir,
            "--assume-yes", "--password", password,
            "--recovery-out", recovery_out]


def monitor_serve_command(python: str, webapp_path: str, data_dir: str,
                          listen_port: int, service_api_port: int,
                          secret_file: str, poll: float, interval: float,
                          closed_ttl: float, export_file: str | None,
                          export_inbounds=(), health_file: str | None = None
                          ) -> list:
    command = [python, webapp_path, "serve",
               "--listen", "127.0.0.1", "--port", str(listen_port),
               "--url", "http://127.0.0.1:%d" % service_api_port,
               "--secret-file", secret_file, "--data-dir", data_dir,
               "--poll", "%.2f" % poll, "--interval", "%.2f" % interval,
               "--closed-ttl", "%.0f" % closed_ttl]
    if health_file:
        command += ["--health-file", health_file]
    if export_file:
        command += [MONITOR_EXPORT_FILE_FLAG, export_file]
        for tag, kind in export_inbounds:
            command += [MONITOR_EXPORT_INBOUND_FLAG, "%s:%s" % (tag, kind)]
    return command


class MonitorWebClient:
    """Loopback client for the real monitor-v2 dashboard/snapshot endpoints."""

    def __init__(self, base_url: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.password = password
        self.http = HttpClient()

    def health(self) -> int:
        status, _body = http_get(self.base_url + "/", timeout=10)
        return status

    def session(self):
        status, document = self.http.get_json(self.base_url + "/api/v1/session")
        return status, document

    def login(self) -> int:
        status, _document = self.http.post_json(
            self.base_url + "/api/v1/login", {"password": self.password})
        return status

    def snapshot(self):
        return self.http.get_json(self.base_url + "/api/v1/snapshot")

    def wait_ready(self, timeout: float = 30.0) -> dict:
        def _ready():
            if self.health() != 200:
                return None
            status, session = self.session()
            if status != 200 or not isinstance(session, dict):
                return None
            if not session.get("monitor_running"):
                return None
            if self.login() != 200:
                return None
            status, snapshot = self.snapshot()
            if status != 200 or not isinstance(snapshot, dict):
                return None
            return snapshot
        return wait_until(_ready, timeout, 0.25,
                          "the monitor dashboard + authenticated snapshot")


# ---------------------------------------------------------------------------
# Center / agent helper structures (real Go binaries invoked by the lab)
# ---------------------------------------------------------------------------


def build_center_admin_auth(admin_token: str) -> dict:
    """Build the protected local admin-auth JSON from one synthetic token."""
    return {
        "principals": [{
            "id": "um-lt-lab-platform-admin",
            "role": "platform_admin",
            "event_ids": [],
        }],
        "tokens": [{
            "sha256": sha256_bytes(admin_token.encode("utf-8")),
            "principal_id": "um-lt-lab-platform-admin",
        }],
    }


def build_collect_sources(monitor_export_enabled: bool) -> dict:
    """The rev-7 collect object: the six frozen sources + monitor_export."""
    return {
        "system": False,
        "services": False,
        "singbox_api": False,
        "mihomo_api": False,
        "terminal": False,
        "events": True,
        AGENT_SOURCE_KEY: bool(monitor_export_enabled),
    }


def build_expected_tags(tags=EXPECTED_TAGS) -> list:
    return [{"inbound_tag": tag, "kind": kind} for tag, kind in tags]


def run_admin_cli(center_bin: str, admin_url: str, token_file: str,
                  args: list, timeout: float = 60.0) -> dict:
    """Run `um-center admin --json ...` and return parsed JSON."""
    command = [center_bin, "admin", "--url", admin_url,
               "--token-file", token_file, "--json"] + list(args)
    result = run_capture(command, timeout=timeout)
    if result.returncode != 0:
        raise LabError(
            "center admin command failed (%s): %s"
            % (" ".join(args),
               (result.stderr or result.stdout or "").strip()[-600:]))
    try:
        return json.loads(result.stdout)
    except ValueError as exc:
        raise LabError("center admin command returned non-JSON output (%s): %s"
                       % (" ".join(args), (result.stdout or "")[:300])) from exc


def extract_latest_snapshot(node_view: dict):
    """Return the parsed latest_snapshot body from an admin node-show view."""
    if not isinstance(node_view, dict):
        return None
    snapshot = node_view.get("latest_snapshot")
    if snapshot is None:
        return None
    if isinstance(snapshot, str):
        try:
            return json.loads(snapshot)
        except ValueError:
            return None
    if isinstance(snapshot, dict):
        return snapshot
    return None


# ---------------------------------------------------------------------------
# Evidence/artifact helpers
# ---------------------------------------------------------------------------


def redact_file(src_path: str, dest_path: str, sentinels: list[str]) -> bool:
    """Copy a text file to the artifacts dir with synthetic secrets removed."""
    try:
        with open(src_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError:
        return False
    ensure_dir(os.path.dirname(dest_path) or ".")
    write_text(dest_path, redact_text(text, sentinels), 0o600)
    return True


def copy_json_artifact(document, dest_path: str, mode: int = 0o600) -> None:
    ensure_dir(os.path.dirname(dest_path) or ".")
    write_json(dest_path, document, mode)


def require_loopback_url(url: str) -> None:
    """Fail closed if the lab was pointed at a non-loopback HTTP target."""
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise LabError("refusing non-HTTP lab URL: %r" % url)
    host = (parts.hostname or "").strip()
    if host not in ("127.0.0.1", "::1", "localhost"):
        raise LabError("refusing non-loopback lab URL host %r: the lab never "
                       "contacts external targets" % host)
