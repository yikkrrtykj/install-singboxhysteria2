"""journalctl --since timestamp normalization, stdlib Python (issue #33 P2).

The installed reader must NOT import anything from tests/ (C5 / G9). This
module re-implements the canonical contract of tests/lib/journal-time.sh
(kept as the reference) and tests/test-monitor-v2-jr.sh proves record-for-
record equivalence over the whole existing compatibility corpus, including
the fail-closed set.

Contract (Ubuntu 22.04 / 24.04 / 26.04; capability-based):
  * raw RFC3339 "…Z" is NEVER handed to journalctl --since (22.04 rejects
    it): normalize to local wall-clock "%Y-%m-%d %H:%M:%S";
  * already-normalized "YYYY-MM-DD HH:MM:SS" passes through unchanged
    (idempotent) after a strict shape check;
  * Python 3.10 floor: a trailing "Z" becomes "+00:00" explicitly;
  * fail-closed: empty/unparseable raises; never a silent wrong window.
"""

from datetime import datetime, timezone

_JCTL_FORM = "%Y-%m-%d %H:%M:%S"


class JournalTimeError(ValueError):
    """Raised fail-closed on empty/unparseable input (never a guess)."""


def normalize_journalctl_since(raw):
    """Return the exact local "YYYY-MM-DD HH:MM:SS" string for --since."""
    if not isinstance(raw, str) or not raw.strip():
        raise JournalTimeError("empty timestamp")
    text = raw.strip()

    # Already-normalized journalctl form: strict-check, then pass through.
    if "T" not in text and "Z" not in text:
        try:
            datetime.strptime(text, _JCTL_FORM)
        except ValueError:
            raise JournalTimeError("not a valid timestamp") from None
        return text

    iso = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        raise JournalTimeError("not a valid RFC3339 timestamp") from None
    if dt.tzinfo is None:
        # RFC3339 without an explicit offset: canary convention is UTC.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone().strftime(_JCTL_FORM)


def now_journalctl_form(now_fn=None):
    """Capture "now" ONCE in the canonical local form (C5: never recomputed
    per poll -- the caller persists the returned string verbatim)."""
    dt = (now_fn or datetime.now)()
    if dt.tzinfo is None:
        dt = dt.astimezone()
    return dt.strftime(_JCTL_FORM)
