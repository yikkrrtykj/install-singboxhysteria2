"""Restricted traffic-export contract: schema, allow-list config, validation.

This module is pure stdlib and side-effect free: it parses the operator's
allow-list, validates the export destination path, and builds/validates the
EXACT ``schema_version 1`` document. Nothing here writes a file, starts a
thread or touches sing-box/Monitor state.

Security posture
----------------

The export file is deliberately a small, closed document. It is NOT a
serialization of Monitor state: it carries aggregate per-operator-configured
inbound counters only, with an explicit key allow-list for both the document
and every inbound row (``EXPORT_KEYS`` / ``INBOUND_KEYS``). Adding a field
requires editing this contract file and the tests that pin the key sets.

Byte counters are exact integers (protobuf int64/uint64 upstream, exact
Python ints in the collector). They are published only while they are
*exactly* representable as IEEE-754 safe integers (``0..2**53-1``); anything
outside that range is reported as ``null`` ("unavailable"), never rounded or
clamped.

The file path is operator-supplied through argv (never center/agent input)
and MUST be absolute. Relative paths, symlinked final paths/directories and
existing non-regular files are refused fail-closed -- there is NO fallback to
/tmp or the current working directory.
"""

from __future__ import annotations

import math
import os
import re
import stat
from collections import namedtuple

# ---------------------------------------------------------------------------
# Frozen schema (schema_version 1)
# ---------------------------------------------------------------------------

SCHEMA = "singbox-monitor-traffic-export"
SCHEMA_VERSION = 1
SOURCE = "monitor-v2"
COUNTER_SCOPE = "observation_epoch"
EXACTNESS = "lower_bound"

KIND_REALITY = "reality"
KIND_HYSTERIA2 = "hysteria2"
KIND_OTHER = "other"
KINDS = frozenset({KIND_REALITY, KIND_HYSTERIA2, KIND_OTHER})

QUALITY_LOWER_BOUND = "lower_bound"
QUALITY_PARTIAL = "partial"
QUALITY_UNAVAILABLE = "unavailable"
QUALITIES = frozenset({QUALITY_LOWER_BOUND, QUALITY_PARTIAL,
                       QUALITY_UNAVAILABLE})

# Largest exactly representable IEEE-754 integer (2**53 - 1).
SAFE_INT_MAX = 9007199254740991

# Bounds shared with the rev-7 consumer: observed rates/window are bounded so a
# hostile/buggy projection is refused instead of published as misleading data.
MAX_RATE_BPS = 1e12
MAX_RATE_WINDOW_SECONDS = 3600.0

# Bounds that keep publication cheap and bounded: at most 8 operator-declared
# inbounds and at most 64 KiB of JSON (the payload is a fixed tiny shape, so
# the document is O(inbounds), not O(traffic)).
MAX_INBOUNDS = 8
MAX_EXPORT_BYTES = 64 * 1024

SOURCE_EPOCH_HEX_BYTES = 16  # secrets.token_hex(16) -> 32 lowercase hex chars
SOURCE_EPOCH_RE = re.compile(r"^[0-9a-f]{32}$")

# Inbound tag grammar: allows the normal sing-box tag alphabet, rejects
# whitespace/colon/control/unbounded input. Kept narrow on purpose.
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

EXPORT_KEYS = frozenset({
    "schema", "schema_version", "source", "source_epoch", "sequence",
    "generated_at", "observed_at", "monitor_stale",
    "monitor_last_success_at", "counter_scope", "exactness",
    "active_connections", "rate_window_seconds", "inbounds",
})

INBOUND_KEYS = frozenset({
    "inbound_tag", "kind", "observed_uplink_bytes",
    "observed_downlink_bytes", "uplink_observed_rate_bps",
    "downlink_observed_rate_bps", "active_connections", "observed_at",
    "quality",
})

# The traffic-only projection a Tracker hands to the writer (the writer adds
# the schema identity, per-process epoch, sequence and generated_at).
PROJECTION_KEYS = frozenset({
    "observed_at", "monitor_stale", "monitor_last_success_at",
    "active_connections", "rate_window_seconds", "inbounds",
})


class TrafficExportConfigError(ValueError):
    """Invalid operator configuration / unsafe destination path (fail closed)."""


class TrafficExportDocumentError(ValueError):
    """The traffic projection cannot be published as a valid document."""


InboundSpec = namedtuple("InboundSpec", "tag kind")


# ---------------------------------------------------------------------------
# Operator configuration
# ---------------------------------------------------------------------------

def parse_inbound_specs(values):
    """Parse repeated ``TAG:KIND`` operator arguments into a validated tuple.

    Fail-closed rules: at least 1 and at most ``MAX_INBOUNDS``, strict tag
    grammar, kind must be one of the three frozen enum values, duplicate tags
    are refused (one inbound may not be declared twice with different kinds).
    """
    if not values:
        raise TrafficExportConfigError(
            "--traffic-export-inbound is required when --traffic-export-file "
            "is set (at least 1 TAG:KIND pair)")
    if len(values) > MAX_INBOUNDS:
        raise TrafficExportConfigError(
            "at most %d --traffic-export-inbound pairs are allowed"
            % MAX_INBOUNDS)
    specs = []
    seen_tags = set()
    for value in values:
        if not isinstance(value, str):
            raise TrafficExportConfigError(
                "--traffic-export-inbound values must be TAG:KIND strings")
        if value.count(":") != 1:
            raise TrafficExportConfigError(
                "--traffic-export-inbound must be exactly TAG:KIND "
                "(one colon separator)")
        tag, kind = value.split(":", 1)
        if TAG_RE.fullmatch(tag) is None:
            raise TrafficExportConfigError(
                "inbound tag %r violates the strict tag grammar "
                "([A-Za-z0-9][A-Za-z0-9._-]{0,63})" % (tag,))
        if kind not in KINDS:
            raise TrafficExportConfigError(
                "inbound kind %r is not one of %s"
                % (kind, "/".join(sorted(KINDS))))
        if tag in seen_tags:
            raise TrafficExportConfigError(
                "duplicate inbound tag %r in the allow-list" % (tag,))
        seen_tags.add(tag)
        specs.append(InboundSpec(tag=tag, kind=kind))
    return tuple(specs)


def validate_export_path(path):
    """Fail-closed validation of the operator-supplied absolute export path.

    Returns the normalized path. Refuses (``TrafficExportConfigError``):
    empty/relative paths, a missing or non-directory parent, a symlinked
    parent directory, a symlinked final path and an existing non-regular
    file. On POSIX it additionally requires the parent directory to be
    writable/executable by this process. It never creates the directory and
    never falls back to /tmp or the current working directory.
    """
    if not isinstance(path, str) or not path:
        raise TrafficExportConfigError(
            "--traffic-export-file must name an absolute file path")
    if not os.path.isabs(path):
        raise TrafficExportConfigError(
            "--traffic-export-file must be an ABSOLUTE path (no relative "
            "paths, no /tmp or cwd fallback)")
    normalized = os.path.normpath(path)
    if os.path.basename(normalized) in ("", ".", ".."):
        raise TrafficExportConfigError(
            "--traffic-export-file must name a file, not a directory")
    parent = os.path.dirname(normalized)
    if not parent:
        raise TrafficExportConfigError(
            "--traffic-export-file must name a file inside a directory")
    try:
        parent_stat = os.lstat(parent)
    except OSError:
        raise TrafficExportConfigError(
            "the --traffic-export-file parent directory does not exist or is "
            "not accessible (it is never created by the monitor)") from None
    if stat.S_ISLNK(parent_stat.st_mode):
        raise TrafficExportConfigError(
            "the --traffic-export-file parent directory is a symlink "
            "(refused: fixed real path required)")
    if not stat.S_ISDIR(parent_stat.st_mode):
        raise TrafficExportConfigError(
            "the --traffic-export-file parent is not a directory")
    try:
        final_stat = os.lstat(normalized)
    except FileNotFoundError:
        final_stat = None
    except OSError:
        raise TrafficExportConfigError(
            "the existing --traffic-export-file cannot be inspected") from None
    if final_stat is not None:
        if stat.S_ISLNK(final_stat.st_mode):
            raise TrafficExportConfigError(
                "the existing --traffic-export-file is a symlink (refused)")
        if not stat.S_ISREG(final_stat.st_mode):
            raise TrafficExportConfigError(
                "the existing --traffic-export-file is not a regular file "
                "(refused)")
    if os.name == "posix":
        if not os.access(parent, os.W_OK | os.X_OK):
            raise TrafficExportConfigError(
                "the --traffic-export-file parent directory is not writable "
                "by the monitor service user")
        if final_stat is not None and not os.access(normalized, os.W_OK):
            raise TrafficExportConfigError(
                "the existing --traffic-export-file is not writable by the "
                "monitor service user")
    return normalized


# ---------------------------------------------------------------------------
# Document validation / construction
# ---------------------------------------------------------------------------

def _error(label, message):
    return TrafficExportDocumentError("%s: %s" % (label, message))


def _exact_int(value, label, allow_none=False):
    if value is None:
        if allow_none:
            return None
        raise _error(label, "null is not allowed")
    if isinstance(value, bool) or not isinstance(value, int):
        raise _error(label, "expected an exact integer, got %r"
                     % (type(value).__name__,))
    if value < 0 or value > SAFE_INT_MAX:
        raise _error(label, "integer outside the safe range 0..%d"
                     % SAFE_INT_MAX)
    return value


def _rate(value, label):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _error(label, "expected a number or null")
    number = float(value)
    if not math.isfinite(number):
        raise _error(label, "expected a finite number")
    if number < 0 or number > MAX_RATE_BPS:
        raise _error(label,
                     "expected a non-negative bounded number (<= %g bps)"
                     % MAX_RATE_BPS)
    return number


def _window(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _error("rate_window_seconds", "expected a number or null")
    number = float(value)
    if not math.isfinite(number) or number <= 0 \
            or number > MAX_RATE_WINDOW_SECONDS:
        raise _error("rate_window_seconds",
                     "expected a finite number in (0, %g]"
                     % MAX_RATE_WINDOW_SECONDS)
    return number


def _sequence(value):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _error("sequence", "expected a non-negative exact integer")
    return value


def _epoch(value):
    if not isinstance(value, str) or SOURCE_EPOCH_RE.fullmatch(value) is None:
        raise _error("source_epoch",
                     "expected exactly 32 lowercase hex characters")
    return value


def build_document(projection, *, source_epoch, sequence, generated_at):
    """Build AND strictly validate one schema_version 1 export document.

    The projection is the sanitized traffic-only dict returned by
    ``Tracker.export_traffic``. The result contains EXACTLY the frozen
    ``EXPORT_KEYS``; any unknown/missing projection or row key is a hard
    error (the contract is an allow-list, not a passthrough).
    """
    if not isinstance(projection, dict):
        raise _error("projection", "expected a mapping")
    extra = set(projection) - PROJECTION_KEYS
    missing = PROJECTION_KEYS - set(projection)
    if extra:
        raise _error("projection", "unexpected field(s): %s"
                     % ", ".join(sorted(extra)))
    if missing:
        raise _error("projection", "missing field(s): %s"
                     % ", ".join(sorted(missing)))

    source_epoch = _epoch(source_epoch)
    sequence = _sequence(sequence)
    generated_at = _exact_int(generated_at, "generated_at")
    observed_at = _exact_int(projection["observed_at"], "observed_at")
    if observed_at > generated_at:
        # The document invariant is observed_at <= generated_at. The writer
        # receives an observation built from the same process clock; a
        # synthetic/fake clock could invert them, so clamp on the way out
        # instead of publishing an impossible timestamp.
        observed_at = generated_at

    monitor_stale = projection["monitor_stale"]
    if not isinstance(monitor_stale, bool):
        raise _error("monitor_stale", "expected a boolean")
    monitor_last_success_at = projection["monitor_last_success_at"]
    if monitor_last_success_at is not None:
        monitor_last_success_at = _exact_int(
            monitor_last_success_at, "monitor_last_success_at")
        if monitor_last_success_at > generated_at:
            # A monitor clock can only have succeeded before it publishes; a
            # synthetic/fake-clock inversion is clamped rather than published
            # (the rev-7 consumer refuses a future last-success timestamp).
            monitor_last_success_at = generated_at
    if not monitor_stale and monitor_last_success_at is None:
        # The rev-7 consumer refuses a "fresh" export without a last
        # successful observation: a monitor that never succeeded cannot claim
        # freshness. Fail closed instead of publishing a rejected document.
        raise _error("monitor_last_success_at",
                     "a non-stale document requires the last successful "
                     "observation timestamp")

    active_connections = projection["active_connections"]
    if active_connections is not None:
        active_connections = _exact_int(
            active_connections, "active_connections")
    rate_window_seconds = _window(projection["rate_window_seconds"])

    inbounds = projection["inbounds"]
    if not isinstance(inbounds, (list, tuple)):
        raise _error("inbounds", "expected a list")
    if len(inbounds) > MAX_INBOUNDS:
        raise _error("inbounds", "more than %d inbounds" % MAX_INBOUNDS)

    rows = []
    seen_tags = set()
    for index, row in enumerate(inbounds):
        label = "inbounds[%d]" % index
        if not isinstance(row, dict):
            raise _error(label, "expected a mapping")
        extra = set(row) - INBOUND_KEYS
        missing = INBOUND_KEYS - set(row)
        if extra:
            raise _error(label, "unexpected field(s): %s"
                         % ", ".join(sorted(extra)))
        if missing:
            raise _error(label, "missing field(s): %s"
                         % ", ".join(sorted(missing)))
        tag = row["inbound_tag"]
        if not isinstance(tag, str) or TAG_RE.fullmatch(tag) is None:
            raise _error(label, "invalid inbound_tag")
        if tag in seen_tags:
            raise _error(label, "duplicate inbound_tag %r" % (tag,))
        seen_tags.add(tag)
        kind = row["kind"]
        if kind not in KINDS:
            raise _error(label, "invalid kind")
        uplink = _exact_int(row["observed_uplink_bytes"],
                            label + ".observed_uplink_bytes", allow_none=True)
        downlink = _exact_int(row["observed_downlink_bytes"],
                              label + ".observed_downlink_bytes",
                              allow_none=True)
        uplink_rate = _rate(row["uplink_observed_rate_bps"],
                            label + ".uplink_observed_rate_bps")
        downlink_rate = _rate(row["downlink_observed_rate_bps"],
                              label + ".downlink_observed_rate_bps")
        row_active = _exact_int(row["active_connections"],
                                label + ".active_connections")
        row_observed = _exact_int(row["observed_at"],
                                  label + ".observed_at")
        if row_observed > generated_at:
            row_observed = generated_at
        quality = row["quality"]
        if quality not in QUALITIES:
            raise _error(label, "invalid quality")
        if quality == QUALITY_LOWER_BOUND:
            if monitor_stale or uplink is None or downlink is None:
                raise _error(label, "lower_bound requires fresh exact counters")
        elif quality == QUALITY_UNAVAILABLE:
            if uplink is not None or downlink is not None:
                raise _error(label, "unavailable requires null counters")
        elif quality == QUALITY_PARTIAL:
            if uplink is None and downlink is None \
                    and uplink_rate is None and downlink_rate is None:
                raise _error(label, "partial requires at least one observed "
                                    "counter or rate")
        if monitor_stale:
            if uplink_rate is not None or downlink_rate is not None:
                raise _error(label, "stale monitor requires null rates")
            if quality != QUALITY_PARTIAL:
                # The rev-7 consumer refuses a stale export that also claims a
                # lower_bound or unavailable reading; unobserved tags must be
                # omitted by the producer while stale.
                raise _error(label,
                             "stale monitor only allows partial rows")
        rows.append({
            "inbound_tag": tag,
            "kind": kind,
            "observed_uplink_bytes": uplink,
            "observed_downlink_bytes": downlink,
            "uplink_observed_rate_bps": uplink_rate,
            "downlink_observed_rate_bps": downlink_rate,
            "active_connections": row_active,
            "observed_at": row_observed,
            "quality": quality,
        })

    if rate_window_seconds is None and any(
            row["uplink_observed_rate_bps"] is not None
            or row["downlink_observed_rate_bps"] is not None
            for row in rows):
        # The rev-7 consumer refuses observed rates without their window.
        raise _error("rate_window_seconds",
                     "observed rates require a rate window")
    if active_connections is not None \
            and active_connections < sum(row["active_connections"]
                                         for row in rows):
        # The rev-7 consumer refuses a total that does not cover its rows.
        raise _error("active_connections",
                     "total must cover the per-inbound active sum")

    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "source": SOURCE,
        "source_epoch": source_epoch,
        "sequence": sequence,
        "generated_at": generated_at,
        "observed_at": observed_at,
        "monitor_stale": monitor_stale,
        "monitor_last_success_at": monitor_last_success_at,
        "counter_scope": COUNTER_SCOPE,
        "exactness": EXACTNESS,
        "active_connections": active_connections,
        "rate_window_seconds": rate_window_seconds,
        "inbounds": rows,
    }
