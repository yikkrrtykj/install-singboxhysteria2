"""Shared persistence helpers for the Monitor web access data.

Access data (whitelist, auth hashes) lives in its own directory and is
strictly separate from the sing-box configuration: Phase C credentials are
never read or written here, and changing web access data never reloads or
restarts sing-box.
"""

from __future__ import annotations

import json
import os
import tempfile


def ensure_private_dir(path):
    """Create the data directory with 0700 on POSIX (best effort)."""
    os.makedirs(path, exist_ok=True)
    if os.name == "posix":
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass


def restrict_file_permissions(path):
    if os.name != "posix":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def atomic_write_json(path, payload):
    """Write JSON atomically (tempfile + os.replace) with 0600 on POSIX."""
    directory = os.path.dirname(path) or "."
    handle = tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory,
                                         prefix=".monitor-", suffix=".tmp",
                                         delete=False)
    try:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
        handle.close()
        os.replace(handle.name, path)
    except BaseException:
        handle.close()
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise
    restrict_file_permissions(path)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return None  # unreadable/corrupt file == defaults (fail-closed)
