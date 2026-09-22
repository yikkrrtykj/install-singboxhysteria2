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

_SHOW_CURSOR_RE = re.compile(r"^cursor: (\S+)$", re.MULTILINE)


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

    Strict single shape '^cursor: (\\S+)$'; the captured value then runs
    through the SAME validator. Returns None when absent or invalid.
    """
    if not isinstance(stdout_text, str):
        return None
    match = _SHOW_CURSOR_RE.search(stdout_text)
    if match is None:
        return None
    value = match.group(1)
    return value if validate_cursor(value) else None
