"""Canonical eligibility decision (issue #33 P2, v3-B1).

ONE dependency-free stdlib module is the single source of truth for
eligibility, imported by (a) the reader, (b) CI golden tests, and (c) the
A2 acceptance probe script -- approximating eligibility with
`journalctl -p` filtering is explicitly forbidden. Application token is
authoritative; journal PRIORITY is advisory metadata used ONLY on the
tokenless-class-mismatch route and can NEVER reject an explicit
ERROR/WARN line.

Frozen decision table:
  token = ERROR/WARN           -> eligible, always (any/absent/malformed PRIORITY)
  token = INFO/DEBUG           -> drop + info_dropped++, always
  tokenless, matches class 1-7 -> eligible with that class
  tokenless, mismatch, PRIORITY parses to int 0..4
                               -> eligible -> other + fp
  tokenless, mismatch, PRIORITY missing/malformed/out-of-range
                               -> drop + nomatch_dropped++
                                  (non-missing-but-unusable also -> priority_unusable++)
"""

from .classifier import classify_entry
from .normalize import normalize_message

DROP_INFO = "info_dropped"
DROP_NOMATCH = "nomatch_dropped"

_ELIGIBLE_LEVELS = ("error", "warn")
_DROP_LEVELS = ("info", "debug")


def priority_int(raw):
    """Parse journal PRIORITY strictly: str/int in the 0..7 syslog domain,
    else None. bool is excluded (not a valid PRIORITY)."""
    if isinstance(raw, bool):
        return None
    value = None
    if isinstance(raw, int):
        value = raw
    elif isinstance(raw, str) and raw.isdigit() and len(raw) == 1:
        value = int(raw)
    if value is None or not 0 <= value <= 7:
        return None
    return value


def assess(raw_message, raw_priority):
    """Return a decision dict:
      {"disposition": "eligible"|"drop", "counter": None|DROP_* ,
       "priority_unusable": bool, "cls": str|None, "proto": str|None,
       "port": int|None, "dcls": str|None, "text": normalized str}
    `cls` None on the tokenless-mismatch eligible route means the caller
    assigns `other` + fp (fp assignment lives in the reader/aggregator so
    that the A2 probe can count eligibles without a key)."""
    text, level = normalize_message(raw_message)
    if level in _ELIGIBLE_LEVELS:
        cls, proto, port, dcls = classify_entry(text)
        if cls == "other":
            # B1: an ERROR/WARN line with no class token takes the SAME
            # other+fp fall-through route -- `cls` None tells the caller.
            cls = None
        return _eligible(cls, proto, port, dcls, text)
    if level in _DROP_LEVELS:
        return {"disposition": "drop", "counter": DROP_INFO,
                "priority_unusable": False, "cls": None, "proto": None,
                "port": None, "dcls": None, "text": text}
    cls, proto, port, dcls = classify_entry(text)
    if cls != "other":
        return _eligible(cls, proto, port, dcls, text)
    pri = priority_int(raw_priority)
    if pri is not None and 0 <= pri <= 4:
        # eligible fall-through: caller assigns `other` + fp
        return _eligible(None, proto, port, dcls, text)
    # usable-but-5..7 drops WITHOUT the flag; present-yet-unparseable/out
    # of domain marks priority_unusable (frozen B1 table).
    return {"disposition": "drop", "counter": DROP_NOMATCH,
            "priority_unusable": raw_priority is not None
            and str(raw_priority).strip() != ""
            and pri is None,
            "cls": None, "proto": None, "port": None, "dcls": None,
            "text": text}


def _eligible(cls, proto, port, dcls, text):
    return {"disposition": "eligible", "counter": None,
            "priority_unusable": False, "cls": cls, "proto": proto,
            "port": port, "dcls": dcls, "text": text}


def is_eligible(raw_message, raw_priority):
    """Convenience for the A2 acceptance probe: eligible candidate or not
    (True covers both the class-matched and the other+fp fall-through)."""
    return assess(raw_message, raw_priority)["disposition"] == "eligible"
