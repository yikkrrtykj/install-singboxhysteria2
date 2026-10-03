"""Bounded direct (non-Mihomo) office-side evidence collection.

Every slot is bounded three ways: an absolute per-slot budget, the enclosing
cycle deadline, and a hard cap on how many bytes/records any slot may read.
A slot that does not finish inside its budget is adjudicated ``timeout`` and
its late result is discarded -- the same discipline the audited server-side
probe engine uses, implemented here so the office agent never imports
server-side Monitor code.

Vocabulary is a documented MIRROR of the audited VPS-side outbound-probe
engine under ``monitor-v2/diagnostics/``; the PR-6A lane imports that engine
and asserts this mirror equals its live tuples, so a drift cannot pass
silently. (The engine module is deliberately not named here: an existing lane
keeps the set of files that name it to the staging manifest and the history
mirror, and P6 is not a third one.)
"""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import threading

# -- closed vocabularies (mirrored, lane-equality-gated) ----------------------

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUSES = (STATUS_OK, STATUS_FAILED)

ERR_NONE = "NONE"
ERR_TIMEOUT = "timeout"
ERR_DNS_FAILED = "dns_failed"
ERR_CONNECT_FAILED = "connect_failed"
ERR_TLS_FAILED = "tls_failed"
ERR_BAD_RESPONSE = "bad_response"
ERR_PROTOCOL_FAILED = "protocol_failed"
ERR_PARSE_FAILED = "parse_failed"
ERR_UNAVAILABLE = "unavailable"
# EXACTLY the audited engine's nine-member closed vocabulary, in its order.
# protocol_failed means "an answer arrived that is not ours" and is part of the
# domain even though no v1 slot emits it today; the lane proves the mirror.
ERROR_CODES = (ERR_NONE, ERR_TIMEOUT, ERR_DNS_FAILED, ERR_CONNECT_FAILED,
               ERR_TLS_FAILED, ERR_BAD_RESPONSE, ERR_PROTOCOL_FAILED,
               ERR_PARSE_FAILED, ERR_UNAVAILABLE)

CHANGE_UNCHANGED = "unchanged"
CHANGE_CHANGED = "changed"
CHANGE_UNKNOWN = "unknown"
CHANGE_VALUES = (CHANGE_UNCHANGED, CHANGE_CHANGED, CHANGE_UNKNOWN)

# Per-slot budgets (seconds). Deliberately tight: one cycle must fit inside the
# 20 s whole-cycle deadline with room for both active delay tests.
DNS_TIMEOUT_SECONDS = 2.0
HTTPS_TIMEOUT_SECONDS = 5.0
TCP_TIMEOUT_SECONDS = 3.0
EGRESS_TIMEOUT_SECONDS = 5.0
# Bytes read from any reviewed endpoint before the connection is abandoned.
MAX_RESPONSE_BYTES = 4096
# Plausible latency ceiling (ms): anything larger is a broken clock/timer, not
# evidence, and is refused rather than stored.
LATENCY_MAX_MS = 120000


def _now():
    import time
    return time.monotonic()


def run_bounded(fn, budget, join_slack=0.05):
    """Run ``fn`` in a daemon worker bounded by ``budget`` seconds.

    Returns ``(completed, value)``: ``completed`` is False when the worker did
    not finish inside its budget (its result is then DISCARDED -- a late
    answer is never evidence). Exceptions inside ``fn`` propagate to the
    caller, which adjudicates them; nothing here raises on timeout.
    """
    box = {}

    def runner():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 -- handed to the caller
            box["error"] = exc

    worker = threading.Thread(target=runner, daemon=True)
    worker.start()
    worker.join(max(0.01, float(budget)))
    if worker.is_alive():
        return False, None
    if "error" in box:
        raise box["error"]
    return True, box.get("value")


def _slot(status, latency_ms=None, error_code=ERR_NONE):
    return {"status": status, "latency_ms": latency_ms,
            "error_code": error_code}


def _failed(code):
    return _slot(STATUS_FAILED, None, code)


def failed_slot(code):
    """Public failure constructor for the three plain slots (closed codes)."""
    if code not in ERROR_CODES or code == ERR_NONE:
        code = ERR_UNAVAILABLE
    return _failed(code)


def failed_egress(code):
    """The EGRESS-shaped failure slot.

    Egress carries two extra fields (``ip``/``change``), so a deadline-exhausted
    or unadjudicable egress slot MUST use this shape: a plain slot here fails
    the wire schema and would throw away every other slot's evidence for the
    cycle."""
    if code not in ERROR_CODES or code == ERR_NONE:
        code = ERR_UNAVAILABLE
    return {"status": STATUS_FAILED, "latency_ms": None, "error_code": code,
            "ip": None, "change": CHANGE_UNKNOWN}


def _latency_ms(start_epoch_seconds):
    value = int(round((_now() - start_epoch_seconds) * 1000.0))
    if value < 0 or value > LATENCY_MAX_MS:
        return None
    return value


# -- address validation (mirror of the audited canonical global-IP gate) -----

def canonical_global_ip(value):
    """Canonical form of a PUBLIC GLOBAL UNICAST literal, else None.

    Loopback/private/reserved/document/multicast addresses are refused, and a
    multicast group is a destination, never an egress address."""
    if type(value) is not str:
        return None
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not address.is_global or address.is_multicast:
        return None
    return str(address)


def classify_egress_change(previous, current):
    """Mirror of the audited change judgement: ``changed`` only when BOTH
    sides are independently valid canonical global IPs and differ; any
    invalid/absent side is ``unknown`` (never a fabricated change)."""
    before = canonical_global_ip(previous)
    after = canonical_global_ip(current)
    if before is None or after is None:
        return CHANGE_UNKNOWN
    return CHANGE_CHANGED if before != after else CHANGE_UNCHANGED


# -- slots -------------------------------------------------------------------

def probe_dns(host, port=443, budget=DNS_TIMEOUT_SECONDS):
    """System DNS resolution for one reviewed hostname."""
    start = _now()
    try:
        completed, value = run_bounded(
            lambda: socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP),
            budget)
    except (socket.gaierror, OSError):
        return _failed(ERR_DNS_FAILED)
    except Exception:  # noqa: BLE001 -- bounded slot: never propagate
        return _failed(ERR_UNAVAILABLE)
    if not completed:
        return _failed(ERR_TIMEOUT)
    if not value:
        return _failed(ERR_DNS_FAILED)
    return _slot(STATUS_OK, _latency_ms(start))


def probe_https(host, path="/", port=443, budget=HTTPS_TIMEOUT_SECONDS,
                context=None, expected_status=200):
    """Direct HTTPS request with NORMAL TLS validation (a failed certificate
    is a failure, never silently accepted)."""
    if type(expected_status) is not int or expected_status not in (200, 204):
        return _failed(ERR_UNAVAILABLE)
    start = _now()

    def request():
        ctx = context if context is not None else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=budget,
                                           context=ctx)
        try:
            conn.request("GET", path, headers={"Accept": "*/*",
                                               "User-Agent": "p6-remote-probe/1"})
            response = conn.getresponse()
            response.read(MAX_RESPONSE_BYTES)
            return response.status
        finally:
            conn.close()

    try:
        completed, status = run_bounded(request, budget)
    except ssl.SSLError:
        return _failed(ERR_TLS_FAILED)
    except (socket.timeout, TimeoutError):
        return _failed(ERR_TIMEOUT)
    except (ConnectionError, OSError):
        return _failed(ERR_CONNECT_FAILED)
    except http.client.HTTPException:
        return _failed(ERR_BAD_RESPONSE)
    except Exception:  # noqa: BLE001 -- bounded slot: never propagate
        return _failed(ERR_UNAVAILABLE)
    if not completed:
        return _failed(ERR_TIMEOUT)
    if status != expected_status:
        return _failed(ERR_BAD_RESPONSE)
    return _slot(STATUS_OK, _latency_ms(start))


def probe_tcp(host, port, budget=TCP_TIMEOUT_SECONDS):
    """Direct TCP connect to the configured VPS listener.

    TRANSPORT REACHABILITY ONLY. A success here proves a TCP handshake to the
    listener; it does NOT prove a Reality handshake, and no caller may render
    it as protocol-path health.
    """
    start = _now()

    def connect():
        sock = socket.create_connection((host, port), timeout=budget)
        sock.close()
        return True

    try:
        completed, _value = run_bounded(connect, budget)
    except (socket.timeout, TimeoutError):
        return _failed(ERR_TIMEOUT)
    except (ConnectionError, OSError):
        return _failed(ERR_CONNECT_FAILED)
    except Exception:  # noqa: BLE001 -- bounded slot: never propagate
        return _failed(ERR_UNAVAILABLE)
    if not completed:
        return _failed(ERR_TIMEOUT)
    return _slot(STATUS_OK, _latency_ms(start))


def probe_egress(host, path="/", port=443, budget=EGRESS_TIMEOUT_SECONDS,
                 previous=None, context=None):
    """Office public egress IP through the reviewed egress endpoint.

    The answer text is validated by the SAME canonical global-IP gate as the
    audited engine (loopback/private/reserved/multicast are refused), so a
    broken endpoint can never inject a private address as an egress identity.
    """
    start = _now()

    def request():
        ctx = context if context is not None else ssl.create_default_context()
        conn = http.client.HTTPSConnection(host, port, timeout=budget,
                                           context=ctx)
        try:
            conn.request("GET", path, headers={"Accept": "text/plain",
                                               "User-Agent": "p6-remote-probe/1"})
            response = conn.getresponse()
            body = response.read(MAX_RESPONSE_BYTES)
            return response.status, body
        finally:
            conn.close()

    try:
        completed, result = run_bounded(request, budget)
    except ssl.SSLError:
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_TLS_FAILED, "ip": None,
                "change": CHANGE_UNKNOWN}
    except (socket.timeout, TimeoutError):
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_TIMEOUT, "ip": None,
                "change": CHANGE_UNKNOWN}
    except (ConnectionError, OSError):
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_CONNECT_FAILED, "ip": None,
                "change": CHANGE_UNKNOWN}
    except Exception:  # noqa: BLE001 -- bounded slot: never propagate
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_UNAVAILABLE, "ip": None,
                "change": CHANGE_UNKNOWN}
    if not completed:
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_TIMEOUT, "ip": None,
                "change": CHANGE_UNKNOWN}
    status, body = result
    if status != 200:
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_BAD_RESPONSE, "ip": None,
                "change": CHANGE_UNKNOWN}
    try:
        text = body.decode("utf-8", "strict").strip()
    except UnicodeDecodeError:
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_PARSE_FAILED, "ip": None,
                "change": CHANGE_UNKNOWN}
    # An endpoint may answer with a single token or a small "ip=..." style
    # line: take the first whitespace/comma-separated token that parses as a
    # canonical global address, and refuse anything else.
    candidate = None
    for token in text.replace(",", " ").split():
        if canonical_global_ip(token) is not None:
            candidate = token
            break
    if candidate is None:
        return {"status": STATUS_FAILED, "latency_ms": None,
                "error_code": ERR_PARSE_FAILED, "ip": None,
                "change": CHANGE_UNKNOWN}
    ip = canonical_global_ip(candidate)
    return {"status": STATUS_OK, "latency_ms": _latency_ms(start),
            "error_code": ERR_NONE, "ip": ip,
            "change": classify_egress_change(previous, ip)}
