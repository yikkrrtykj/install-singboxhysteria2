# journal-time.sh -- journalctl time normalization (compatibility layer).
# shellcheck shell=bash
#
# Canonical implementation used by the VPS canary runbook and by
# tests/test-journal-time-compat.sh.
#
# Compatibility contract (supported baselines: Ubuntu 22.04 / 24.04 / 26.04
# LTS; capability-based, never distro-version branching):
#   * Internal canary timestamps stay RFC3339/UTC (e.g. 2026-09-14T15:51:50Z).
#   * journalctl --since NEVER receives raw "...T...Z" input: the real VPS
#     canary (Ubuntu 22.04, 2026-09-14) showed its journalctl rejects that
#     form. Normalize to local "YYYY-MM-DD HH:MM:SS" first.
#   * Python compatibility: the oldest supported baseline ships Python 3.10,
#     whose datetime.fromisoformat() does NOT accept a trailing "Z" -- the
#     offset is converted to "+00:00" explicitly instead of relying on any
#     3.11+ behavior. Standard library only.
#   * Fail-closed: empty or unparseable input prints a clear diagnostic to
#     stderr and returns rc 1; it never silently yields a wrong time window.

journal_time_normalize_jctl() { # journal_time_normalize_jctl <timestamp> -> local "YYYY-MM-DD HH:MM:SS"
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || {
        printf 'journal-time: python3 not found; cannot normalize timestamp\n' >&2
        return 1
    }
    "$pybin" - "$1" <<'PY'
import sys
from datetime import datetime, timezone

raw = sys.argv[1] if len(sys.argv) > 1 else ""
if not raw.strip():
    print("journal-time: empty timestamp", file=sys.stderr)
    sys.exit(1)

text = raw.strip()

# Already-normalized journalctl form ("YYYY-MM-DD HH:MM:SS"): passthrough
# unchanged (idempotent), after a strict shape check.
if "T" not in text and "Z" not in text:
    try:
        datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        print(f"journal-time: not a valid timestamp: {raw!r}", file=sys.stderr)
        sys.exit(1)
    print(text)
    sys.exit(0)

# RFC3339: convert a trailing "Z" to an explicit "+00:00" offset (Python 3.10
# fromisoformat() rejects "Z"; explicit offsets and fractional seconds are
# supported on every baseline).
iso = text[:-1] + "+00:00" if text[-1] in ("Z", "z") else text
try:
    dt = datetime.fromisoformat(iso)
except ValueError:
    print(f"journal-time: not a valid RFC3339 timestamp: {raw!r}", file=sys.stderr)
    sys.exit(1)
if dt.tzinfo is None:
    # RFC3339 without an explicit offset: canary convention is UTC.
    dt = dt.replace(tzinfo=timezone.utc)
# Local wall-clock form accepted by journalctl --since on all supported baselines.
print(dt.astimezone().strftime("%Y-%m-%d %H:%M:%S"))
PY
}
