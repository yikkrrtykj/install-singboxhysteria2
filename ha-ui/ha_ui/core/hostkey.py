"""SSH host-key fingerprints.

The app never trusts a system ``known_hosts`` entry implicitly: the operator
confirms the SHA-256 fingerprint shown by the server (or by their cloud panel)
and that value is stored in the non-secret ``servers.json``. A later connection
with a different key is refused before authentication, so a password is never
sent to an unconfirmed host.

Fingerprint format: OpenSSH style ``SHA256:<base64 without padding>``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re

from . import errors
from .errors import HaUiError

FINGERPRINT_RE = re.compile(r"\ASHA256:[A-Za-z0-9+/]{43}\Z")


def fingerprint_from_key_bytes(key_bytes: bytes) -> str:
    """OpenSSH-style fingerprint of the SSH wire-format public key."""
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def fingerprint_from_key(key) -> str:
    """Fingerprint a Paramiko PKey (``asbytes`` is the wire format)."""
    try:
        raw = key.asbytes()
    except Exception:
        raise HaUiError(errors.E_HOSTKEY_FORMAT, detail="key") from None
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise HaUiError(errors.E_HOSTKEY_FORMAT, detail="key")
    return fingerprint_from_key_bytes(bytes(raw))


def validate_fingerprint(value: str) -> str:
    if not isinstance(value, str) or not FINGERPRINT_RE.fullmatch(value):
        raise HaUiError(errors.E_HOSTKEY_FORMAT, detail="format")
    return value


def fingerprint_matches(expected: str, actual: str) -> bool:
    """Constant-time comparison of two validated fingerprints."""
    left = validate_fingerprint(expected)
    right = validate_fingerprint(actual)
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def ensure_trusted(expected: str | None, actual: str) -> None:
    """Raise the fixed trust error unless *actual* matches *expected*."""
    if not expected:
        raise HaUiError(errors.E_HOSTKEY_MISSING, detail="confirm-first")
    if not fingerprint_matches(expected, actual):
        # Never include either fingerprint in logs. The UI shows the actual
        # fingerprint through a dedicated, non-logged confirmation dialog.
        raise HaUiError(errors.E_HOSTKEY_MISMATCH, detail="fingerprint")
