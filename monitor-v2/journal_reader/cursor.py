"""Opaque journal cursor validation (issue #33 P2, design v5 D5).

systemd declares the cursor FORMAT private, so the cursor is treated as an
opaque token everywhere: JSON ``__CURSOR`` extraction, ``--show-cursor``
parse output, ``committed.source.value`` / ``pending.source_end.value``
load AND store, and argv construction all run through this single
validator. The bound is generous (4096 UTF-8 bytes, >10x observed) so
correctness is never coupled to today's format; control characters are
rejected because they can never appear in a real cursor and would enable
argv/log spoofing. Cursors are always passed as direct list-form argv
elements, never shell-interpolated, never logged, and never cross the
exchange boundary (v3-B3).
"""

CURSOR_MAX_BYTES = 4096

import re

# REAL systemd framing (review #46 B1, source-verified on all three
# baselines): journalctl prints exactly `-- cursor: <opaque>\n`
# (v249 journalctl.c:2782, v255:1928, main journalctl-show.c:512).
_SHOW_CURSOR_REAL_RE = re.compile(r"^-- cursor: (\S+)$", re.MULTILINE)
# Explicitly-accepted fixture/test framing (in-process fakes only; the LIVE
# gate asserts the REAL form against the installed journalctl).
_SHOW_CURSOR_FIXTURE_RE = re.compile(r"^cursor: (\S+)$", re.MULTILINE)


def validate_cursor(value):
    """True iff `value` is a usable opaque cursor (v5-D5 grammar)."""
    if not isinstance(value, str):
        return False
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if not (1 <= len(raw) <= CURSOR_MAX_BYTES):
        return False
    for ch in value:
        cp = ord(ch)
        if cp < 0x21 or (0x7F <= cp <= 0x9F):
            return False
    return True


def parse_show_cursor(stdout_text):
    """Extract the cursor from `journalctl --show-cursor` output.

    Only the two fixed framings above are stripped -- whole line, single
    token -- and the captured value then runs through the SAME shared
    validator. Anything else (trailing text, other prefixes, multiple
    fields) yields None; the framing is strict, the token stays opaque.
    Returns None when absent or invalid; nothing is ever logged.
    """
    if not isinstance(stdout_text, str):
        return None
    for rx in (_SHOW_CURSOR_REAL_RE, _SHOW_CURSOR_FIXTURE_RE):
        match = rx.search(stdout_text)
        if match is not None:
            value = match.group(1)
            return value if validate_cursor(value) else None
    return None
