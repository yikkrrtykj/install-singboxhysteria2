"""Canonical body + HMAC signing for the P6 machine wire (issue #67 §6).

The body is EXACT canonical compact JSON with a closed schema: fixed key sets,
closed enums, bounded values and no free text. Two properties matter and are
both enforced here rather than trusted:

* **Byte stability.** The spool stores the exact bytes produced here and the
  retry path re-sends them unchanged, so the wire hash is stable across
  restarts. ``canonical_roundtrip_ok`` proves the encoder is idempotent on
  its own output.
* **Size.** The 16 KiB route cap is enforced on the ENCODED bytes before
  anything is signed or spooled.

The signature input is frozen:

``p6-v1\\nPOST\\n/api/v1/remote-probes/ingest\\n<probe_id>\\n<sent_epoch>\\n<run>\\n<seq>\\n<sha256(raw_body_bytes)>``

with ``HMAC-SHA256(per_probe_secret, signature_input)``. ``probe_id`` is
cryptographically bound and ``p6-v1`` is the domain/version separator, so a
signature can never be replayed under another identity or another protocol.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re

from . import (ACTIVE_OUTCOMES, BODY_VERSION, INGEST_METHOD, INGEST_PATH,
               MAX_BODY_BYTES, P6_PROTOCOL, PROBE_ID_PATTERN, ROLES,
               RUN_PATTERN, SEQ_MAX, SEQ_MIN)
from .direct_probe import (CHANGE_VALUES, ERROR_CODES, STATUSES, STATUS_OK)

_PROBE_ID_RE = re.compile(r"\A%s\Z" % PROBE_ID_PATTERN)
_RUN_RE = re.compile(r"\A%s\Z" % RUN_PATTERN)

def ev_sources():
    """Closed evidence-source vocabulary (single definition; the wire schema
    is validated against it without importing the evidence module)."""
    return ("active_delay", "passive_cache")


SLOT_KEYS = frozenset({"status", "latency_ms", "error_code"})
EGRESS_KEYS = SLOT_KEYS | {"ip", "change"}
ACTIVE_KEYS = frozenset({"role", "source", "outcome", "delay_ms", "test_id",
                         "independent"})
MIHOMO_KEYS = frozenset({"status"})
FLAGS_KEYS = frozenset({"truncated", "source_unavailable"})
SAMPLE_KEYS = frozenset({"v", "probe_id", "run", "seq", "sample_epoch", "dns",
                         "https", "vps_tcp", "egress", "mihomo_api", "active",
                         "flags"})

# Closed tokens a sample may name as an unavailable evidence source.
SOURCE_TOKENS = ("passive_cache", "egress", "mihomo_api")
MIHOMO_API_STATUSES = ("ok", "unavailable", "invalid")
# At most ONE entry per (role, source): an active measurement and a
# passive cache observation for the same role are both legitimate, but a
# second entry of the same kind would be a duplicate source.
MAX_ACTIVE_ENTRIES = len(ROLES) * 2
MAX_SOURCE_TOKENS = len(SOURCE_TOKENS)
MAX_TEST_ID_LEN = 64
MAX_NODE_LEN = 128


# -- grammar gates -----------------------------------------------------------

def valid_probe_id(value):
    return type(value) is str and _PROBE_ID_RE.match(value) is not None


def valid_run(value):
    return type(value) is str and _RUN_RE.match(value) is not None


def valid_seq(value):
    return (type(value) is int and not isinstance(value, bool)
            and SEQ_MIN <= value <= SEQ_MAX)


def valid_sample_epoch(value):
    return (type(value) in (int, float) and not isinstance(value, bool)
            and math.isfinite(value) and value >= 0)


# -- canonical encoding ------------------------------------------------------

def canonical_bytes(obj):
    """The one canonical encoding: sorted keys, compact separators, no NaN,
    ASCII-escaped. Two runs over the same object always produce one byte
    string."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def canonical_roundtrip_ok(raw):
    """True iff ``raw`` already IS the canonical encoding of its own value."""
    if type(raw) is not bytes:
        return False
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False
    try:
        return canonical_bytes(obj) == raw
    except (TypeError, ValueError):
        return False


# -- closed-schema validation ------------------------------------------------

def _slot_violations(name, slot):
    problems = []
    if not isinstance(slot, dict) or set(slot) != SLOT_KEYS:
        return ["%s: shape" % name]
    status = slot["status"]
    latency = slot["latency_ms"]
    code = slot["error_code"]
    if type(status) is not str or status not in STATUSES:
        problems.append("%s: status" % name)
    if type(code) is not str or code not in ERROR_CODES:
        problems.append("%s: error_code" % name)
    if latency is not None and (type(latency) is not int
                                or isinstance(latency, bool) or latency < 0):
        problems.append("%s: latency_ms" % name)
    if status == STATUS_OK:
        if code != "NONE" or latency is None:
            problems.append("%s: ok-invariant" % name)
    else:
        if code == "NONE" or latency is not None:
            problems.append("%s: failed-invariant" % name)
    return problems


def validate_sample(sample):
    """Return the list of schema violations (empty == valid). Pure and total:
    it is the single gate every produced body must pass before signing."""
    if not isinstance(sample, dict):
        return ["root: shape"]
    if set(sample) != SAMPLE_KEYS:
        return ["root: key-set"]
    problems = []
    if sample["v"] != BODY_VERSION or isinstance(sample["v"], bool):
        problems.append("v")
    if not valid_probe_id(sample["probe_id"]):
        problems.append("probe_id")
    if not valid_run(sample["run"]):
        problems.append("run")
    if not valid_seq(sample["seq"]):
        problems.append("seq")
    if not valid_sample_epoch(sample["sample_epoch"]):
        problems.append("sample_epoch")
    for name in ("dns", "https", "vps_tcp"):
        problems.extend(_slot_violations(name, sample[name]))
    egress = sample["egress"]
    if not isinstance(egress, dict) or set(egress) != EGRESS_KEYS:
        problems.append("egress: shape")
    else:
        problems.extend(_slot_violations(
            "egress", {key: egress[key] for key in SLOT_KEYS}))
        ip = egress["ip"]
        if egress["change"] not in CHANGE_VALUES:
            problems.append("egress: change")
        if ip is None:
            pass
        elif (type(ip) is not str or len(ip) > 64
                or any(ch not in "0123456789abcdefABCDEF:." for ch in ip)):
            problems.append("egress: ip")
        if egress["status"] != STATUS_OK and ip is not None:
            problems.append("egress: ip-on-failure")
    mihomo = sample["mihomo_api"]
    if (not isinstance(mihomo, dict) or set(mihomo) != MIHOMO_KEYS
            or mihomo["status"] not in MIHOMO_API_STATUSES):
        problems.append("mihomo_api")
    active = sample["active"]
    if not isinstance(active, list) or len(active) > MAX_ACTIVE_ENTRIES:
        problems.append("active: shape")
    else:
        seen_pairs = set()
        for entry in active:
            if not isinstance(entry, dict) or set(entry) != ACTIVE_KEYS:
                problems.append("active: entry-shape")
                continue
            pair = (entry["role"], entry["source"])
            if entry["role"] not in ROLES or pair in seen_pairs:
                problems.append("active: role")
            seen_pairs.add(pair)
            source = entry["source"]
            if source not in ev_sources():
                problems.append("active: source")
            elif source == "active_delay" and entry["independent"] is not True:
                # our own active measurement is always a real source
                problems.append("active: active-not-independent")
            if entry["outcome"] not in ACTIVE_OUTCOMES:
                problems.append("active: outcome")
            delay = entry["delay_ms"]
            if delay is not None and (type(delay) is not int
                                      or isinstance(delay, bool) or delay <= 0):
                # a positive delay only; 0 is a FAILED test, never a latency
                problems.append("active: delay_ms")
            if entry["outcome"] == "ok" and delay is None:
                problems.append("active: ok-without-delay")
            if entry["outcome"] != "ok" and delay is not None:
                problems.append("active: delay-without-ok")
            test_id = entry["test_id"]
            if (type(test_id) is not str or not test_id
                    or len(test_id) > MAX_TEST_ID_LEN):
                problems.append("active: test_id")
            if type(entry["independent"]) is not bool:
                problems.append("active: independent")
    flags = sample["flags"]
    if not isinstance(flags, dict) or set(flags) != FLAGS_KEYS:
        problems.append("flags: shape")
    else:
        if type(flags["truncated"]) is not bool:
            problems.append("flags: truncated")
        sources = flags["source_unavailable"]
        if (not isinstance(sources, list) or len(sources) > MAX_SOURCE_TOKENS
                or any(token not in SOURCE_TOKENS for token in sources)):
            problems.append("flags: source_unavailable")
    return problems


# -- signing -----------------------------------------------------------------

def signature_input(probe_id, sent_epoch, run, seq, raw_body):
    """The exact frozen signing string. ``sent_epoch`` and ``seq`` use
    canonical base-10 integer text, so the string has no ambiguous spacing and
    no signed field can contain a newline (all are grammar-gated)."""
    if not valid_probe_id(probe_id):
        raise ValueError("probe_id grammar")
    if not valid_run(run):
        raise ValueError("run grammar")
    if not valid_seq(seq):
        raise ValueError("seq grammar")
    if type(sent_epoch) is not int or isinstance(sent_epoch, bool) \
            or sent_epoch < 0:
        raise ValueError("sent_epoch must be a canonical non-negative integer")
    if type(raw_body) is not bytes:
        raise ValueError("raw_body must be bytes")
    digest = hashlib.sha256(raw_body).hexdigest()
    return ("%s\n%s\n%s\n%s\n%d\n%s\n%d\n%s"
            % (P6_PROTOCOL, INGEST_METHOD, INGEST_PATH, probe_id,
               sent_epoch, run, seq, digest)).encode("ascii")


def sign(secret, probe_id, sent_epoch, run, seq, raw_body):
    """HMAC-SHA256 over the frozen input, lowercase hex."""
    if type(secret) is not bytes or not secret:
        raise ValueError("probe secret must be non-empty bytes")
    message = signature_input(probe_id, sent_epoch, run, seq, raw_body)
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_signature(secret, probe_id, sent_epoch, run, seq, raw_body,
                     claimed):
    """Constant-time verification (the server-side rule's reference
    implementation, exercised by the lane). Never raises."""
    if type(claimed) is not str:
        return False
    try:
        expected = sign(secret, probe_id, sent_epoch, run, seq, raw_body)
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(expected, claimed)


def headers(probe_id, sent_epoch, run, seq, signature):
    """The five frozen machine headers."""
    return {
        "X-Remote-Probe-Id": probe_id,
        "X-Remote-Probe-Sent-Epoch": str(int(sent_epoch)),
        "X-Remote-Probe-Run": run,
        "X-Remote-Probe-Seq": str(int(seq)),
        "X-Remote-Probe-Signature": signature,
        "Content-Type": "application/json",
    }


def encode_sample(sample):
    """Validate, encode and size-check one sample. Raises ``ValueError`` on
    any violation -- an unencodable sample is never spooled."""
    problems = validate_sample(sample)
    if problems:
        raise ValueError("sample schema: %s" % ",".join(sorted(set(problems))))
    raw = canonical_bytes(sample)
    if len(raw) > MAX_BODY_BYTES:
        raise ValueError("sample exceeds %d bytes" % MAX_BODY_BYTES)
    if not canonical_roundtrip_ok(raw):
        raise ValueError("encoder is not idempotent")
    return raw
