"""The reviewed exchange boundary format, v5 (issue #33 P2 design §5.2).

TWO line kinds, EXACT key sets, deny-by-default. There is NO free-text
field anywhere: every string is a closed enum or fixed hex, so even a
cooperating producer cannot pass a raw log line -- the record schema
physically has nowhere to put one. Validation here is shared by the reader
(construction) and the Monitor-side ingest contract (re-validation); an
extra key, missing key, wrong type or out-of-range value invalidates the
WHOLE file (§7.2 fail-closed per file).

header: {"t":"h","v":1,"cv":1,"seq":I,"run":"<32hex>","epoch":I,
         "boundary":"NONE"|"COLD_START"|"SOURCE_GAP","lines":I,"eligible":I,
         "info_dropped":I,"nomatch_dropped":I,"priority_unusable":I,
         "pfail":I,"limited":I}
event:  {"t":"e","ts":F,"cls":CLASS,"proto":PROTO,"port":1..65535|null,
         "dcls":DCLS|null,"fp":"<16hex>"|null,"n":I>=1}

Wire nullability is per v2-R1: the Monitor maps null to the reviewed
non-NULL DB sentinels (0 / 'NONE'); the exchange itself keeps null.
"""

import json
import re

FORMAT_VERSION = 1
CLASSIFIER_VERSION = 1

BOUNDS = ("NONE", "COLD_START", "SOURCE_GAP")
CLASSES = (
    "dns",
    "dial_timeout",
    "reset",
    "net_unreachable",
    "tls_handshake",
    "quic_error",
    "eof_cancel",
    "other",
)
PROTOS = ("Reality", "Hysteria2", "OTHER")
DCLS = ("https443", "http80", "quic", "dns53", "dot853", "smtpish", "other")

RUN_RE = re.compile(r"\A[0-9a-f]{32}\Z")
FP_RE = re.compile(r"\A[0-9a-f]{16}\Z")
FILENAME_RE = re.compile(r"\Aev-([0-9]{1,20})\.jsonl\Z")

_HEADER_KEYS = frozenset(
    {"t", "v", "cv", "seq", "run", "epoch", "boundary", "lines", "eligible",
     "info_dropped", "nomatch_dropped", "priority_unusable", "pfail",
     "limited"}
)
_EVENT_KEYS = frozenset({"t", "ts", "cls", "proto", "port", "dcls", "fp", "n"})
_INT_FIELDS = ("seq", "epoch", "lines", "eligible", "info_dropped",
               "nomatch_dropped", "priority_unusable", "pfail", "limited")


def _is_int(value):
    # bool is a subclass of int in Python: reject it at the boundary.
    return isinstance(value, int) and not isinstance(value, bool)


def validate_header(obj):
    """True iff obj is an exact, in-range v5 header record."""
    if not isinstance(obj, dict) or set(obj) != _HEADER_KEYS:
        return False
    if obj["t"] != "h" or obj["v"] != FORMAT_VERSION:
        return False
    if obj["cv"] != CLASSIFIER_VERSION:
        return False
    if not _is_int(obj["seq"]) or obj["seq"] < 1:
        return False
    if not isinstance(obj["run"], str) or not RUN_RE.match(obj["run"]):
        return False
    if not _is_int(obj["epoch"]) or obj["epoch"] < 1:
        return False
    if obj["boundary"] not in BOUNDS:
        return False
    for field in _INT_FIELDS:
        if field in ("seq", "epoch"):
            continue
        if not _is_int(obj[field]) or obj[field] < 0:
            return False
    return True


def validate_event(obj):
    """True iff obj is an exact, in-range v5 event record."""
    if not isinstance(obj, dict) or set(obj) != _EVENT_KEYS:
        return False
    if obj["t"] != "e":
        return False
    ts = obj["ts"]
    if (not isinstance(ts, (int, float)) or isinstance(ts, bool)
            or ts != ts or ts < 0 or ts > 1e11):  # NaN / epoch-plausible guard
        return False
    if obj["cls"] not in CLASSES:
        return False
    if obj["proto"] not in PROTOS:
        return False
    port = obj["port"]
    if port is not None and (not _is_int(port) or not 1 <= port <= 65535):
        return False
    if obj["dcls"] is not None and obj["dcls"] not in DCLS:
        return False
    fp = obj["fp"]
    if fp is not None and (not isinstance(fp, str) or not FP_RE.match(fp)):
        return False
    if not _is_int(obj["n"]) or obj["n"] < 1:
        return False
    # Cross-field determinism (mirrors the DB sentinel validation of v2-R1):
    # fp only ever accompanies the `other` class; dcls only with a port.
    if obj["cls"] != "other" and fp is not None:
        return False
    if obj["dcls"] is not None and port is None:
        return False
    return True


def parse_exchange_text(text, filename_seq):
    """Validate a whole exchange file body.

    Returns None when valid, else a sanitized reason code. Rules (§7.2 /
    v2-R6 / v3-B4): the FIRST line must be exactly one header; no header
    may appear again later; every line must validate; header.seq must equal
    the filename seq. No content is ever echoed in the reason.
    """
    if not isinstance(text, str) or not text:
        return "exchange_empty"
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()  # single trailing newline is part of the format
    if not lines:
        return "exchange_empty"
    header_seen = False
    for index, line in enumerate(lines):
        try:
            obj = json.loads(line)
        except ValueError:
            return "exchange_bad_json"
        if not isinstance(obj, dict):
            return "exchange_bad_shape"
        if obj.get("t") == "h":
            if index != 0 or header_seen:
                return "exchange_header_position"
            if not validate_header(obj):
                return "exchange_header_invalid"
            if obj["seq"] != filename_seq:
                return "exchange_seq_mismatch"
            header_seen = True
            continue
        if not validate_event(obj):
            return "exchange_event_invalid"
    if not header_seen:
        return "exchange_no_header"
    return None
