"""Outbound probe engine (issue #33 Phase 3, PR-3A -- DARK delivery).

Standalone, unprivileged, closed-schema probes that a future Monitor
integration can use to answer: does this VPS' system DNS resolve; does a
plain TCP+TLS+HTTPS round trip succeed; is there a verifiable UDP
request/response RETURN path; what is the current public egress IP.

Nothing in this module is wired into production: no caller exists in
webapp/broker/server, the packaged release tree does not even ship this
package, and the engine carries NO default endpoint -- every probe target
must be injected explicitly through ``ProbeTargets`` (an empty target set
is the dark state: four ``unavailable`` slots and zero network I/O).

Safety contract (all enforced, all tested):

* Output is a CLOSED object, never free text: exception messages,
  response bodies, resolved addresses, peer socket addresses and host
  name echoes have no field to travel in. ``error_code`` is a frozen
  9-member vocabulary; the only string an ``ok`` probe may emit beyond
  the vocabulary is the canonical public egress IP (the reviewed P1
  exception, see docs/monitor-v2-network-probes-p3a.md section 9).
* Every network operation is bounded twice: a per-probe socket timeout
  and the per-slot join budget inside the cycle deadline. A hanging
  probe is abandoned as ``timeout`` (daemon worker + own socket timeout
  as the backstop); it can neither delay the other slots past the cycle
  deadline nor tear the result apart -- the result is built from a
  fully-populated default and each slot is replaced at most once.
* The public entry point NEVER raises to a future publisher loop.
* stdlib only, no listeners, no filesystem writes, no privileged calls,
  no configuration mutation, no logging of results or exceptions.

The UDP probe is an application-level DNS round trip (``udp_dns_roundtrip``
semantics): a successful ``sendto()`` proves nothing and is never
reported as health; it evidences generic UDP egress + return path ONLY,
never "all UDP / Hysteria2 paths are healthy".
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import struct
import threading
import time
import uuid
from dataclasses import dataclass

RESULT_VERSION = 1

STATUS_OK = "ok"
STATUS_FAILED = "failed"

ERR_NONE = "NONE"
ERR_TIMEOUT = "timeout"
ERR_DNS_FAILED = "dns_failed"
ERR_CONNECT_FAILED = "connect_failed"
ERR_TLS_FAILED = "tls_failed"
ERR_BAD_RESPONSE = "bad_response"
ERR_PROTOCOL_FAILED = "protocol_failed"
ERR_PARSE_FAILED = "parse_failed"
ERR_UNAVAILABLE = "unavailable"

# Frozen closed vocabulary. The result builders are the only writers and
# they pass every value through the ERROR_CODES gate (anything outside
# the vocabulary is coerced to ERR_UNAVAILABLE), so free text can never
# become an error_code even from a hypothetically buggy caller.
ERROR_CODES = frozenset({
    ERR_NONE, ERR_TIMEOUT, ERR_DNS_FAILED, ERR_CONNECT_FAILED,
    ERR_TLS_FAILED, ERR_BAD_RESPONSE, ERR_PROTOCOL_FAILED,
    ERR_PARSE_FAILED, ERR_UNAVAILABLE,
})

PROBE_SLOTS = ("dns", "https", "udp", "egress")

RESULT_KEYS = ("v", "epoch", "cycle_id", "dns", "https", "udp", "egress")
PROBE_KEYS = ("status", "latency_ms", "error_code")
EGRESS_KEYS = PROBE_KEYS + ("ip",)

CHANGE_UNCHANGED = "unchanged"
CHANGE_CHANGED = "changed"
CHANGE_UNKNOWN = "unknown"

# Per-probe defaults (seconds). Production cadence is a PR-3B scheduler
# decision; these are the probe budgets themselves.
DNS_TIMEOUT_SECONDS = 2.0
HTTPS_TIMEOUT_SECONDS = 5.0
UDP_TIMEOUT_SECONDS = 3.0
EGRESS_TIMEOUT_SECONDS = 5.0
CYCLE_DEADLINE_SECONDS = 12.0

# Response bodies are read into a bounded discard buffer, never kept.
_HTTP_BODY_READ_CAP = 65536
_UDP_DEFAULT_MAX_REPLY = 2048


class SpecError(ValueError):
    """A probe spec is not constructible. Raised at BUILD time by the
    caller (outside the result channel), never by ``run_probe_cycle``."""


def _require_positive_timeout(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SpecError("%s must be a number" % name)
    if not (0 < float(value) < 3600.0):
        raise SpecError("%s out of range" % name)
    return float(value)


def _require_text(value, name, max_len=253):
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise SpecError("%s must be a non-empty short string" % name)
    return value


def _require_int(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError("%s must be an int" % name)
    if not low <= value <= high:
        raise SpecError("%s out of range" % name)
    return value


def _require_ip_literal(value, name):
    """Numeric-IP-only validation (no resolver involvement, ever)."""
    if not isinstance(value, str):
        raise SpecError("%s must be a numeric IP literal" % name)
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise SpecError("%s must be a numeric IP literal" % name) from None


def _require_statuses(value, name):
    statuses = frozenset(value)
    if (not statuses
            or not all(isinstance(s, int) and not isinstance(s, bool)
                       and 100 <= s <= 599 for s in statuses)):
        raise SpecError("%s must be a non-empty set of HTTP status ints"
                        % name)
    return statuses


@dataclass(frozen=True)
class DnsProbeSpec:
    """System-resolver probe. ``resolver`` is the TEST injection point
    (signature-compatible with ``socket.getaddrinfo``); production leaves
    it None and therefore uses the real system resolver path."""
    hostname: str
    timeout_seconds: float = DNS_TIMEOUT_SECONDS
    resolver: object = None

    def __post_init__(self):
        _require_text(self.hostname, "hostname")
        _require_positive_timeout(self.timeout_seconds, "timeout_seconds")


@dataclass(frozen=True)
class HttpsProbeSpec:
    """Direct-egress HTTPS probe (http.client NEVER consults
    HTTP_PROXY/HTTPS_PROXY, unlike urllib.request). TLS verification is
    structurally on: ``create_default_context`` is the only context
    factory on this path and no verification-bypass field exists."""
    host: str
    port: int = 443
    path: str = "/"
    timeout_seconds: float = HTTPS_TIMEOUT_SECONDS
    allowed_statuses: frozenset = frozenset({200})
    cafile: object = None
    server_hostname: object = None

    def __post_init__(self):
        _require_text(self.host, "host")
        _require_int(self.port, "port", 1, 65535)
        _require_text(self.path, "path", 2048)
        _require_positive_timeout(self.timeout_seconds, "timeout_seconds")
        object.__setattr__(self, "allowed_statuses",
                           _require_statuses(self.allowed_statuses,
                                             "allowed_statuses"))
        if self.server_hostname is not None:
            _require_text(self.server_hostname, "server_hostname")


@dataclass(frozen=True)
class UdpProbeSpec:
    """Bounded UDP DNS round trip. ``resolver_host`` MUST be a numeric IP
    literal: the UDP slot proves egress + return path for a KNOWN peer
    and must never depend on (or duplicate) the system-resolver slot."""
    resolver_host: str
    query_hostname: str
    resolver_port: int = 53
    timeout_seconds: float = UDP_TIMEOUT_SECONDS
    max_response_bytes: int = _UDP_DEFAULT_MAX_REPLY

    def __post_init__(self):
        object.__setattr__(self, "resolver_host",
                           _require_ip_literal(self.resolver_host,
                                               "resolver_host"))
        _require_text(self.query_hostname, "query_hostname")
        _require_int(self.resolver_port, "resolver_port", 1, 65535)
        _require_positive_timeout(self.timeout_seconds, "timeout_seconds")
        _require_int(self.max_response_bytes, "max_response_bytes",
                     12, 65535)


@dataclass(frozen=True)
class EgressProbeSpec:
    """Public egress IP probe: the ONLY slot allowed to emit an IP
    string, and only the canonical form of what the endpoint ANSWERED
    (never a connection-level address). ``require_global`` rejects
    loopback/private/reserved answers by default so the reviewed "server
    public egress IP" exception can never be used to smuggle a
    connection address toward persistence."""
    host: str
    port: int = 443
    path: str = "/"
    timeout_seconds: float = EGRESS_TIMEOUT_SECONDS
    allowed_statuses: frozenset = frozenset({200})
    max_body_bytes: int = 64
    cafile: object = None
    server_hostname: object = None
    require_global: bool = True

    def __post_init__(self):
        _require_text(self.host, "host")
        _require_int(self.port, "port", 1, 65535)
        _require_text(self.path, "path", 2048)
        _require_positive_timeout(self.timeout_seconds, "timeout_seconds")
        object.__setattr__(self, "allowed_statuses",
                           _require_statuses(self.allowed_statuses,
                                             "allowed_statuses"))
        _require_int(self.max_body_bytes, "max_body_bytes", 1, 4096)
        if self.server_hostname is not None:
            _require_text(self.server_hostname, "server_hostname")


@dataclass(frozen=True)
class ProbeTargets:
    """Explicit, injectable endpoint policy. Every slot defaults to None
    (= not configured = dark): this module ships NO third-party endpoint
    default; production candidates are review material for PR-3B."""
    dns: object = None
    https: object = None
    udp: object = None
    egress: object = None


# -- closed slot builders ------------------------------------------------------

def _probe_slot(error_code):
    """Fully-populated failure slot: builders start from this and only
    ever replace closed fields, so a torn result is unconstructible."""
    if error_code not in ERROR_CODES or error_code == ERR_NONE:
        error_code = ERR_UNAVAILABLE
    return {"status": STATUS_FAILED, "latency_ms": None,
            "error_code": error_code}


def _egress_slot(error_code):
    """The egress failure shape ALWAYS carries ip=None: the closed
    schema has no half-slot."""
    return _probe_slot(error_code) | {"ip": None}


def _ok_slot(latency_ms):
    return {"status": STATUS_OK,
            "latency_ms": max(0, int(round(latency_ms))),
            "error_code": ERR_NONE}


def _finish_slot(started, code, timeout_seconds):
    """Close one probe observation into a slot. ``code`` decides ok vs
    failed; latency is emitted only on the ok path. An ok observation
    that outlived its own budget returns None: the cycle join has
    already (or will) record the slot as timeout, and a late worker must
    never overwrite an already-adjudicated slot."""
    cap_ms = timeout_seconds * 1000.0
    elapsed_ms = (time.monotonic() - started) * 1000.0
    if code == ERR_NONE:
        if elapsed_ms > cap_ms:
            return None
        return _ok_slot(elapsed_ms)
    return _probe_slot(code)


# -- probe workers (each returns exactly one closed slot) ----------------------

def _classify_client_error(exc):
    """Map an http.client/socket/ssl failure to the closed vocabulary.
    The exception is consumed for its TYPE only -- str(exc) is never
    inspected, formatted or propagated, so no free text can ride it."""
    if isinstance(exc, socket.gaierror):
        return ERR_DNS_FAILED
    if isinstance(exc, ssl.SSLError):  # covers SSLCertVerificationError
        return ERR_TLS_FAILED
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return ERR_TIMEOUT
    if isinstance(exc, http.client.HTTPException):
        return ERR_PROTOCOL_FAILED
    if isinstance(exc, OSError):
        return ERR_CONNECT_FAILED
    return ERR_UNAVAILABLE


def _make_tls_context(spec):
    # Verification is structurally ON: create_default_context() sets
    # CERT_REQUIRED + check_hostname, and no knob on this spec can turn
    # either off. cafile only WIDENS the trust store (test fakes).
    return ssl.create_default_context(cafile=spec.cafile)


def _https_get(spec, read_cap):
    """Shared direct-egress HTTPS GET. Returns
    ``(started, response_status, body_bytes)``; every failure surfaces
    as an exception for the caller's closed mapping.

    The TLS socket is wrapped explicitly so the SNI/verification name
    (``server_hostname``) is under spec control on every Python version;
    ``http.client`` then runs on the pre-connected socket (it skips its
    own connect when ``sock`` is already set). host:port stays numeric/
    literal -- the request NEVER routes through any proxy environment.
    """
    conn = None
    started = time.monotonic()
    try:
        context = _make_tls_context(spec)
        raw = socket.create_connection((spec.host, spec.port),
                                       timeout=spec.timeout_seconds)
        try:
            tls = context.wrap_socket(
                raw, server_hostname=spec.server_hostname or spec.host)
        except BaseException:
            raw.close()
            raise
        tls.settimeout(spec.timeout_seconds)
        conn = http.client.HTTPSConnection(spec.host, spec.port,
                                           context=context)
        conn.sock = tls
        conn.request("GET", spec.path)
        response = conn.getresponse()
        body = response.read(read_cap)
        return started, response.status, body
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:  # noqa: BLE001 -- teardown, closed path
                pass


def _run_https_probe(spec):
    try:
        started, status, _body = _https_get(spec, _HTTP_BODY_READ_CAP)
        # _body is DISCARDED unexamined: the success contract is the
        # status code only, so no response byte can travel anywhere.
        code = ERR_NONE if status in spec.allowed_statuses \
            else ERR_BAD_RESPONSE
    except Exception as exc:  # noqa: BLE001 -- closed mapping only
        started = time.monotonic()
        code = _classify_client_error(exc)
    return _finish_slot(started, code, spec.timeout_seconds)


def _parse_egress_answer(body, require_global):
    """Strict answer contract: decodable text that IS exactly one
    canonical IPv4/IPv6 literal. Everything else is refused with a
    closed code and zero content retention."""
    try:
        text = body.decode("utf-8").strip()
    except UnicodeDecodeError:
        return None, ERR_PARSE_FAILED
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None, ERR_PARSE_FAILED
    if require_global and not address.is_global:
        return None, ERR_PARSE_FAILED
    return str(address), ERR_NONE


def _run_egress_probe(spec):
    ip = None
    try:
        started, status, body = _https_get(spec, spec.max_body_bytes + 1)
        if status not in spec.allowed_statuses:
            code = ERR_BAD_RESPONSE
        elif len(body) > spec.max_body_bytes:
            code = ERR_BAD_RESPONSE      # oversized answer: transport lie
        else:
            ip, code = _parse_egress_answer(body, spec.require_global)
    except Exception as exc:  # noqa: BLE001 -- closed mapping only
        started = time.monotonic()
        code = _classify_client_error(exc)
    slot = _finish_slot(started, code, spec.timeout_seconds)
    if slot is not None:
        slot["ip"] = ip if code == ERR_NONE else None
    return slot


def _udp_encode_query(hostname, query_id):
    labels = hostname.split(".")
    if (not hostname.isascii() or not hostname
            or len(labels) > 126
            or any(not 1 <= len(label) <= 63 for label in labels)):
        raise SpecError("query_hostname is not encodable")
    name = b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in labels) + b"\x00"
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    question = name + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


def _udp_classify_reply(data, query_id, max_bytes):
    """Closed code for one received datagram (ERR_NONE = the round-trip
    contract is satisfied)."""
    if len(data) > max_bytes:
        return ERR_BAD_RESPONSE
    if len(data) < 12:
        return ERR_PROTOCOL_FAILED
    rid, flags, qd = struct.unpack("!HHH", data[:6])
    if rid != query_id or (flags & 0x8000) == 0 or qd != 1:
        return ERR_PROTOCOL_FAILED
    if flags & 0x0200:               # TC: a truncated answer proves nothing
        return ERR_BAD_RESPONSE
    if flags & 0x000F:               # non-NOERROR: endpoint contract broken
        return ERR_BAD_RESPONSE
    return ERR_NONE


def _run_udp_probe(spec):
    started = time.monotonic()
    sock = None
    try:
        try:
            # A fresh random 16-bit id per attempt: a reply that does
            # not match it is not our round trip.
            query_id = struct.unpack("!H", uuid.uuid4().bytes[:2])[0]
            packet = _udp_encode_query(spec.query_hostname, query_id)
        except SpecError:
            return _finish_slot(started, ERR_PROTOCOL_FAILED,
                                spec.timeout_seconds)
        family = (socket.AF_INET6 if ":" in spec.resolver_host
                  else socket.AF_INET)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(spec.timeout_seconds)
        sock.sendto(packet, (spec.resolver_host, spec.resolver_port))
        deadline = started + spec.timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _finish_slot(started, ERR_TIMEOUT,
                                    spec.timeout_seconds)
            sock.settimeout(remaining)
            try:
                data = sock.recv(spec.max_response_bytes + 1)
            except (TimeoutError, socket.timeout):
                # sendto() success is DELIBERATELY NOT health: silence
                # on the return path is exactly this probe's failure
                # mode it exists to catch.
                return _finish_slot(started, ERR_TIMEOUT,
                                    spec.timeout_seconds)
            except OSError as exc:
                # Windows raises WSAEMSGSIZE where POSIX truncates: an
                # over-cap datagram is the SAME contract violation.
                if getattr(exc, "winerror", None) == 10040:
                    return _finish_slot(started, ERR_BAD_RESPONSE,
                                        spec.timeout_seconds)
                raise
            # STRICT first-reply adjudication: the answer's contract
            # (id match, header shape, flags) is decided on the datagram
            # that arrives, not on a re-listen loop a noisy or hostile
            # peer could use to stall the slot.
            return _finish_slot(started,
                                _udp_classify_reply(data, query_id,
                                                    spec.max_response_bytes),
                                spec.timeout_seconds)
    except Exception as exc:  # noqa: BLE001 -- closed mapping only
        code = (ERR_TIMEOUT if isinstance(exc, (TimeoutError,
                                                socket.timeout))
                else ERR_CONNECT_FAILED if isinstance(exc, OSError)
                else ERR_UNAVAILABLE)
        return _finish_slot(started, code, spec.timeout_seconds)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _run_dns_probe(spec):
    started = time.monotonic()
    try:
        resolver = spec.resolver or socket.getaddrinfo
        answers = resolver(spec.hostname, 0, socket.AF_UNSPEC,
                           socket.SOCK_STREAM)
    except (socket.gaierror, OSError):
        return _finish_slot(started, ERR_DNS_FAILED, spec.timeout_seconds)
    except Exception:  # noqa: BLE001 -- type-only classification
        return _finish_slot(started, ERR_UNAVAILABLE, spec.timeout_seconds)
    # The RESOLVED ADDRESSES ARE DISCARDED unexamined: only the FACT of
    # success is reported, so no resolved IP can ever ride toward a
    # persistence boundary through this slot.
    count = len(answers) if isinstance(answers, (list, tuple)) else 0
    return _finish_slot(started,
                        ERR_NONE if count > 0 else ERR_DNS_FAILED,
                        spec.timeout_seconds)


_WORKERS = {"dns": _run_dns_probe, "https": _run_https_probe,
            "udp": _run_udp_probe, "egress": _run_egress_probe}


# -- cycle engine ---------------------------------------------------------------

def run_probe_cycle(targets=None, cycle_id=None, clock=time.time,
                    total_deadline_seconds=CYCLE_DEADLINE_SECONDS):
    """Run one bounded probe cycle; returns the CLOSED result dict.

    Never raises: caller mistakes (bad targets objects, junk specs, even
    an invalid total deadline -- coerced to the default) can only widen
    failure codes, never escape. Each configured probe gets its own
    worker thread and its own join budget
    (``min(spec.timeout_seconds, cycle remaining)``); a worker that
    misses its budget is abandoned as ``timeout`` (daemon thread + own
    socket timeout as backstops). The result always carries all six
    top-level keys and one complete slot per probe: partial
    "exception text + half a struct" outcomes are unconstructible.
    """
    if targets is None:
        targets = ProbeTargets()
    try:
        total_deadline_seconds = _require_positive_timeout(
            total_deadline_seconds, "total_deadline_seconds")
    except SpecError:
        total_deadline_seconds = CYCLE_DEADLINE_SECONDS
    cycle_started = time.monotonic()
    slots = {slot: _probe_slot(ERR_UNAVAILABLE) for slot in PROBE_SLOTS}
    slots["egress"] = _egress_slot(ERR_UNAVAILABLE)
    outcomes = {}
    threads = {}
    for slot in PROBE_SLOTS:
        spec = getattr(targets, slot, None)
        if spec is None:
            continue  # not configured: stays the default unavailable slot
        worker = _WORKERS[slot]

        def _runner(slot=slot, spec=spec, worker=worker):
            try:
                outcomes[slot] = worker(spec)
            except Exception:  # noqa: BLE001 -- last containment line
                outcomes[slot] = None

        thread = threading.Thread(target=_runner, name="probe-" + slot,
                                  daemon=True)
        threads[slot] = thread
        thread.start()
    for slot in PROBE_SLOTS:
        thread = threads.get(slot)
        if thread is None:
            continue
        spec = getattr(targets, slot)
        spec_timeout = getattr(spec, "timeout_seconds", None)
        try:
            spec_timeout = _require_positive_timeout(spec_timeout,
                                                     "timeout_seconds")
        except SpecError:
            spec_timeout = CYCLE_DEADLINE_SECONDS
        remaining = (cycle_started + total_deadline_seconds
                     - time.monotonic())
        thread.join(timeout=max(0.0, min(spec_timeout, remaining)))
        outcome = outcomes.get(slot)
        if outcome is None and thread.is_alive():
            slots[slot] = (_egress_slot if slot == "egress"
                           else _probe_slot)(ERR_TIMEOUT)  # abandoned worker
        elif outcome is None:
            slots[slot] = (_egress_slot if slot == "egress"
                           else _probe_slot)(ERR_UNAVAILABLE)
        elif slot == "egress":
            slots[slot] = _normalize_egress(outcome)
        else:
            slots[slot] = _normalize_probe(outcome)
    result = {"v": RESULT_VERSION, "epoch": float(clock()),
              "cycle_id": cycle_id or uuid.uuid4().hex}
    result.update(slots)
    return result


def _normalize_probe(slot):
    """Final closed-shape gate: only whitelisted values survive, so even
    a hypothetically buggy worker cannot widen the schema."""
    if not isinstance(slot, dict):
        return _probe_slot(ERR_UNAVAILABLE)
    status = slot.get("status")
    code = slot.get("error_code")
    latency = slot.get("latency_ms")
    if code not in ERROR_CODES:
        code = ERR_UNAVAILABLE
    if status == STATUS_OK and code == ERR_NONE:
        if isinstance(latency, bool) or not isinstance(latency, int):
            latency = 0
        return {"status": STATUS_OK, "latency_ms": max(0, latency),
                "error_code": ERR_NONE}
    return _probe_slot(code if code != ERR_NONE else ERR_UNAVAILABLE)


def _normalize_egress(slot):
    """Egress keeps ONLY a re-canonicalized answer string on the ok
    path; every other shape (missing/invalid/private on require_global
    re-check) degrades to failed/parse_failed with ip=None."""
    keep_ip = slot.get("ip") if isinstance(slot, dict) else None
    slot = _normalize_probe(slot)
    slot["ip"] = None
    if slot["status"] == STATUS_OK:
        canonical = _canonical_ip(keep_ip)
        if canonical is None:
            return _egress_slot(ERR_PARSE_FAILED)
        slot["ip"] = canonical
    return slot


# -- pure egress-change judgement (PR-3B event source) --------------------------

def _canonical_ip(value):
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def classify_egress_change(previous, current):
    """Pure judgement over two SUCCESSFUL egress answers.

    ``changed`` requires two independently valid canonical IPs that
    differ; any transition that involves a failure (None / invalid /
    missing sample) is ``unknown`` and must NEVER be surfaced as a
    change event by a future integrator. Equal valid samples are
    ``unchanged``.
    """
    before = _canonical_ip(previous)
    after = _canonical_ip(current)
    if before is None or after is None:
        return CHANGE_UNKNOWN
    return CHANGE_CHANGED if before != after else CHANGE_UNCHANGED
