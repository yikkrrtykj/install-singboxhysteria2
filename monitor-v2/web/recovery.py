"""Recovery access flow for the Monitor v2 web dashboard (Phase E2).

Purpose: an admin whose current address lost whitelist access (IP changed,
entry removed, DHCP churn) can bootstrap back in with the one-time recovery
key. The key is >= 128-bit random (token_urlsafe(24) ~ 192 bits), shown
exactly once at setup/rotation; the server stores a scrypt hash only.

This flow is deliberately MINIMAL -- it is the single whitelist exception
and can do exactly one thing:

    input recovery key -> server takes the REAL socket peer address ->
    add that address as a host entry (/32 or /128) to the whitelist

It can NEVER: view the dashboard, view the whitelist, add an arbitrary
target IP, delete whitelist entries, change the password, create clients,
download YAML or touch any proxy configuration. A successful recovery does
NOT create an admin session -- the response only says the IP was added and
points the user back to the normal login. Failures are rate limited.
"""

from __future__ import annotations

import secrets

from web.auth import LoginRateLimiter

RECOVERY_KEY_BYTES = 24  # token_urlsafe(24) ~= 192 bits of entropy

RECOVERY_MAX_FAILURES = 3
RECOVERY_WINDOW_SECONDS = 900.0
RECOVERY_LOCKOUT_SECONDS = 1800.0

RECOVERY_SUCCESS_MESSAGE = "IP added. Please login normally."


def generate_key():
    return secrets.token_urlsafe(RECOVERY_KEY_BYTES)


class RecoveryRateLimiter(LoginRateLimiter):
    """Stricter lockout for recovery attempts (3 failures -> 30 minutes)."""

    def __init__(self, max_failures=RECOVERY_MAX_FAILURES,
                 window_seconds=RECOVERY_WINDOW_SECONDS,
                 lockout_seconds=RECOVERY_LOCKOUT_SECONDS, **kwargs):
        LoginRateLimiter.__init__(self, max_failures=max_failures,
                                  window_seconds=window_seconds,
                                  lockout_seconds=lockout_seconds, **kwargs)
