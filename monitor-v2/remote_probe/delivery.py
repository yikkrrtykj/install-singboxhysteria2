"""Upload disposition and retry machinery (issue #67 §7/§8).

The disposition matrix is TOTAL over response classes: every possible answer
maps to exactly one of ACK / RETRY / PERMANENT, so an implementation can never
fall into an undefined state (infinite busy-loop or silent evidence loss).

ACK      2xx whose body matches the frozen success schema.
PERMANENT  2xx with a malformed body, every 3xx (NEVER followed), 400/401/403/
           404/405/409/413, and every other 4xx except 408/429.
RETRY     408, 429, 5xx, and any network/TLS transport failure.
UNKNOWN   anything else: bounded retries, then sanitized quarantine. A
           permanently-rejected record is resolved out of the queue, so it can
           never block later samples.

Nothing here persists a response body or an error string: only closed tokens
and counters do.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import ssl
import urllib.parse

from . import INGEST_PATH, MAX_BODY_BYTES
from .payload import headers, sign
from .spool import (QUARANTINE_CLIENT_ERROR, QUARANTINE_MALFORMED_2XX,
                    QUARANTINE_OVERSIZE, QUARANTINE_REDIRECT,
                    QUARANTINE_UNKNOWN_RESPONSE, SpoolError)

ACK = "ack"
RETRY = "retry"
PERMANENT = "permanent"

# A retry count that could not be persisted is NOT a consumed attempt: the
# pass stops with this closed reason instead of reporting progress.
RETRY_STATE_NOT_DURABLE = "retry_state_not_durable"

# Backoff: bounded exponential. Deterministic when a jitter source is injected.
BACKOFF_BASE_SECONDS = 1.0
BACKOFF_CAP_SECONDS = 60.0
UNKNOWN_RESPONSE_MAX_ATTEMPTS = 5

# The frozen success schema (exactly two keys, one closed enum).
SUCCESS_KEYS = frozenset({"v", "result"})
SUCCESS_RESULTS = ("accepted", "duplicate")
SUCCESS_VERSION = 1

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})


class UploadConfigError(Exception):
    """The upload target violates the transport contract."""


def classify_url(url):
    """Validate the ingest URL. HTTPS is REQUIRED for any non-loopback host
    (HTTP is allowed only for loopback fixtures); credentials, query strings
    and fragments are refused so no secret or signature can ever ride in a
    URL. Returns ``(host, port, scheme, path)``."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise UploadConfigError("ingest URL scheme must be http(s)")
    if parts.username or parts.password or "@" in (parts.netloc or ""):
        raise UploadConfigError("ingest URL must not embed credentials")
    host = (parts.hostname or "").lower()
    if not host:
        raise UploadConfigError("ingest URL host missing")
    if parts.query or parts.fragment:
        raise UploadConfigError(
            "ingest URL must not carry a query string or fragment")
    try:
        port = parts.port
    except ValueError:
        raise UploadConfigError("ingest URL port invalid") from None
    if parts.scheme == "http" and host not in LOOPBACK_HOSTS:
        raise UploadConfigError(
            "non-loopback ingest requires HTTPS")
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    if not 0 < port < 65536:
        raise UploadConfigError("ingest URL port out of range")
    path = parts.path or "/"
    if path != INGEST_PATH:
        # The signature binds this exact path, and a typo must never send a
        # signed body + signature to some other endpoint.
        raise UploadConfigError("ingest URL path must be %s" % INGEST_PATH)
    return host, port, parts.scheme, path


def success_body_response(body):
    """ACE only when the 2xx body IS the frozen success schema."""
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError):
        return False
    if not isinstance(payload, dict) or set(payload) != SUCCESS_KEYS:
        return False
    if payload.get("v") != SUCCESS_VERSION \
            or isinstance(payload.get("v"), bool):
        return False
    return payload.get("result") in SUCCESS_RESULTS


def classify_response(status, body=b""):
    """TOTAL response classification -> ``(disposition, quarantine_token)``.

    ``quarantine_token`` is a closed token (never response text) and is set
    exactly for PERMANENT and for the exhausted UNKNOWN case.
    """
    if type(status) is not int or isinstance(status, bool):
        return UNKNOWN_RESPONSE_TOKEN_DISPOSITION
    if 200 <= status < 300:
        if success_body_response(body):
            return ACK, None
        return PERMANENT, QUARANTINE_MALFORMED_2XX
    if 300 <= status < 400:
        return PERMANENT, QUARANTINE_REDIRECT
    if status == 408 or status == 429:
        return RETRY, None
    if status == 413:
        return PERMANENT, QUARANTINE_OVERSIZE
    if 400 <= status < 500:
        return PERMANENT, QUARANTINE_CLIENT_ERROR
    if 500 <= status < 600:
        return RETRY, None
    return PERMANENT, QUARANTINE_UNKNOWN_RESPONSE


# A non-int status is itself an unknown class; kept as a tuple for symmetry
# with the classifier's return shape.
UNKNOWN_RESPONSE_TOKEN_DISPOSITION = (PERMANENT,
                                      QUARANTINE_UNKNOWN_RESPONSE)


def backoff_delay(attempt, jitter=None):
    """Bounded exponential backoff. ``jitter`` is an injectable callable
    returning a float in [0,1); the default is deterministic in tests."""
    if attempt < 0:
        attempt = 0
    raw = min(BACKOFF_CAP_SECONDS, BACKOFF_BASE_SECONDS * (2 ** attempt))
    if not callable(jitter):
        return raw          # deterministic: the full bounded budget
    span = jitter()
    if span < 0.0:
        span = 0.0
    if span > 1.0:
        span = 1.0
    return raw * (0.5 + 0.5 * span)


class HttpsIngest:
    """The real upload transport: HTTPS, TLS identity validated, no redirects
    (http.client never follows one), secret only inside the signed headers."""

    def __init__(self, url, timeout=10.0, context=None):
        self.host, self.port, self.scheme, self.path = classify_url(url)
        self.timeout = float(timeout)
        self.context = context

    def post(self, body, header_map):
        """One bounded POST -> ``(status, response_body)``. Raises the
        transport exception on a network/TLS failure (the caller maps that to
        RETRY)."""
        if len(body) > MAX_BODY_BYTES:
            raise UploadConfigError("body exceeds the wire bound")
        if self.scheme == "https":
            context = self.context if self.context is not None \
                else ssl.create_default_context()
            conn = http.client.HTTPSConnection(self.host, self.port,
                                               timeout=self.timeout,
                                               context=context)
        else:
            conn = http.client.HTTPConnection(self.host, self.port,
                                              timeout=self.timeout)
        try:
            conn.request("POST", self.path, body=body, headers=header_map)
            response = conn.getresponse()
            payload = response.read(4096)
            return response.status, payload
        finally:
            conn.close()


def canonical_sent_epoch(value):
    """The signed ``sent_epoch`` is canonical base-10 integer text, so the
    wire string has no ambiguous formatting. A plain int/float epoch is
    accepted and truncated; anything else (bool, string, NaN, negative) is
    refused fail-closed."""
    import math
    if type(value) not in (int, float) or isinstance(value, bool):
        raise UploadConfigError("sent_epoch must be numeric")
    if not math.isfinite(value) or value < 0:
        raise UploadConfigError("sent_epoch out of range")
    return int(value)


def sign_record(secret, probe_id, run, seq, body, sent_epoch):
    """Produce the retry-fresh headers: exact body bytes, unchanged tuple
    (probe_id/run/seq), a fresh ``sent_epoch`` and a fresh signature."""
    sent_epoch = canonical_sent_epoch(sent_epoch)
    signature = sign(secret, probe_id, sent_epoch, run, seq, body)
    return headers(probe_id, sent_epoch, run, seq, signature)


def deliver_pending(spool, secret, probe_id, poster, now_epoch=None, limit=None,
                    jitter=None, max_unknown_attempts=UNKNOWN_RESPONSE_MAX_ATTEMPTS,
                    clock=None):
    """Drain the spool in order against ``poster``.

    ``poster(body, header_map) -> (status, response_body)`` is injected, so
    PR-6A never needs a live server (fixtures/mocks only).

    Retry state lives in the SPOOL (``spool.attempts`` / ``spool.note_attempt``),
    durably, so that a new call -- or a restarted agent -- continues the same
    retry budget rather than starting from zero. Consequences that matter:

    * an unknown response class can never become a poison head: it is retried
      only until ``max_unknown_attempts``, then quarantined and the queue
      advances;
    * every retryable outcome (408/429/5xx/network/TLS and a bounded unknown)
      returns ``retry_after`` seconds of BOUNDED EXPONENTIAL BACKOFF, which the
      agent's own loop consumes -- the helper is not decoration;
    * a pass stops at the first retryable/unknown outcome and leaves the record
      queued, so ordering is preserved.

    Every terminal record is resolved exactly once.
    """
    if clock is None:
        # A caller that pins one scalar keeps the old behaviour; the agent
        # passes its own clock so every request gets FRESH transport freshness.
        pinned = int(now_epoch if now_epoch is not None else __import__("time").time())

        def clock():
            return pinned

    summary = {"acked": 0, "quarantined": 0, "retries": 0, "attempts": 0,
               "stopped": None, "retry_after": 0.0}

    def note(record_id):
        """Charge one attempt against the DURABLE budget, or report that the
        count could not be persisted. ``None`` means no progress was made."""
        try:
            return spool.note_attempt(record_id)
        except (SpoolError, OSError):
            return None

    def stop_undurable():
        """A non-durable attempt stops the pass: nothing is claimed as sent,
        nothing is charged, and the record stays queued."""
        summary["stopped"] = RETRY_STATE_NOT_DURABLE
        summary["retry_after"] = backoff_delay(1, jitter=jitter)
        return summary

    for record in spool.pending():
        if limit is not None and summary["attempts"] >= limit:
            break
        summary["attempts"] += 1
        record_id = record["record_id"]
        # FRESH PER REQUEST: a long backlog pass may outlive the +/-300 s
        # freshness window, so sent_epoch is read immediately before THIS send
        # (the body bytes and the (probe_id, run, seq) identity are unchanged).
        header_map = sign_record(secret, probe_id, record["run"],
                                 record["seq"], record["body"], clock())
        try:
            status, response_body = poster(record["body"], header_map)
        except Exception as exc:  # noqa: BLE001 -- any transport failure
            attempt = note(record_id)
            if attempt is None:
                return stop_undurable()
            summary["attempt"] = attempt
            summary["retries"] += 1
            summary["stopped"] = type(exc).__name__
            summary["retry_after"] = backoff_delay(attempt, jitter=jitter)
            return summary
        disposition, token = classify_response(status, response_body)
        if disposition == ACK:
            spool.resolve(record_id)
            summary["acked"] += 1
            continue
        if disposition == PERMANENT:
            if token == QUARANTINE_UNKNOWN_RESPONSE:
                count = note(record_id)
                if count is None:
                    return stop_undurable()
                if count < max_unknown_attempts:
                    summary["attempt"] = count
                    summary["retries"] += 1
                    summary["stopped"] = "unknown_bounded"
                    summary["retry_after"] = backoff_delay(count, jitter=jitter)
                    return summary
            spool.resolve(record_id, quarantine_token=token)
            summary["quarantined"] += 1
            continue
        attempt = note(record_id)
        if attempt is None:
            # The record is NOT resolved: an un-chargeable attempt must never
            # leave a terminal state behind (no poison head from a failed
            # persistence).
            return stop_undurable()
        summary["attempt"] = attempt
        summary["retries"] += 1
        summary["stopped"] = "retryable"
        summary["retry_after"] = backoff_delay(attempt, jitter=jitter)
        return summary
    return summary


def next_retry_delay(attempt, jitter=None):
    """Public alias so the agent loop and the lane share one backoff rule."""
    return backoff_delay(attempt, jitter=jitter)
