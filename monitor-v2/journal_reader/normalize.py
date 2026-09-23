"""Message normalization before classification (issue #33 P2 §5.1).

Lossy decode -> lowercase match form -> strip leading timestamp tokens ->
detect/strip ONE leading application level token -> 4096-char cap, all
BEFORE classification. The returned text is only ever a matching INPUT:
no field of the exchange format can carry it (schema.py has no text
field), so normalization errors can never leak raw content.
"""

import re

MAX_MESSAGE_CHARS = 4096

# Leading timestamp / prefix noise forms seen across supported baselines:
# ISO-8601 (space or T, optional fraction + zone), slash dates, bracketed
# monotonic/pid prefixes. Applied repeatedly (a date AND a time may be two
# separate tokens).
_PREFIX_RES = (
    re.compile(r"\A\d{4}-\d{2}-\d{2}[ t]\d{2}:\d{2}:\d{2}(\.\d+)?(z|[+-]\d{2}:?\d{2})?\s+", re.IGNORECASE),
    re.compile(r"\A\d{4}/\d{2}/\d{2} \d{1,2}:\d{2}:\d{2}\s+"),
    re.compile(r"\A\[\s*\d{1,7}\]\s+"),
    re.compile(r"\At=\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}[tz][\d:+-]*\s+", re.IGNORECASE),
)

_LEVEL_RE = re.compile(r"\A(error|warning|warn|info|debug)(?=$|[\s:,;\[])")

_LEVEL_MAP = {"error": "error", "warn": "warn", "warning": "warn",
              "info": "info", "debug": "debug"}


def decode_message(raw):
    """MESSAGE may arrive as str (journalctl -o json) or byte forms; decode
    lossy -- replacement chars can only ever REDUCE matches, never invent
    secrets, and nothing text-shaped crosses the boundary anyway."""
    if isinstance(raw, str):
        return raw
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw).decode("utf-8", "replace")
    if isinstance(raw, list) and all(isinstance(b, int) for b in raw):
        # Some json output variants expose MESSAGE as a byte array.
        try:
            return bytes(raw).decode("utf-8", "replace")
        except (ValueError, OverflowError):
            return ""
    return ""


def normalize_message(raw):
    """Return (lowercased normalized text, level_token | None)."""
    text = decode_message(raw).lower()
    while True:
        stripped = False
        for rx in _PREFIX_RES:
            m = rx.match(text)
            if m:
                text = text[m.end():]
                stripped = True
        if not stripped:
            break
    level = None
    m = _LEVEL_RE.match(text)
    if m:
        level = _LEVEL_MAP[m.group(1)]
        text = text[m.end():].lstrip(" \t:;,")
    if len(text) > MAX_MESSAGE_CHARS:
        text = text[:MAX_MESSAGE_CHARS]
    return text, level
