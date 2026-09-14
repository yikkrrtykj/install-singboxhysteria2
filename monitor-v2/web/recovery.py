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
import threading
import time

from web.auth import LoginRateLimiter

RECOVERY_KEY_BYTES = 24  # token_urlsafe(24) ~= 192 bits of entropy

RECOVERY_MAX_FAILURES = 3
RECOVERY_WINDOW_SECONDS = 900.0
RECOVERY_LOCKOUT_SECONDS = 1800.0

# Process-wide verification budget. The per-IP limiter cannot bound many
# DIFFERENT sources hitting the single public endpoint simultaneously;
# these two bounds can. Numbers are deliberately modest for a 1-4 core
# VPS: scrypt (N=16384) is meant to be expensive.
RECOVERY_GLOBAL_CONCURRENCY = 2
RECOVERY_GLOBAL_WINDOW_SECONDS = 60.0
RECOVERY_GLOBAL_MAX_ATTEMPTS = 20

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


class RecoveryGlobalGuard:
    """Process-wide bound on recovery-key verification work.

    Two independent, deterministic bounds:

    * a rolling window caps TOTAL attempts (successful or not) per
      interval, across all source addresses;
    * a bounded semaphore caps how many scrypt verifications (N=16384)
      run concurrently; everything above the cap is rejected with 429
      BEFORE any scrypt work happens.

    Thread-safe: ThreadingHTTPServer serves requests on many threads.
    """

    CONCURRENCY_RETRY_SECONDS = 2

    def __init__(self, max_concurrent=RECOVERY_GLOBAL_CONCURRENCY,
                 window_seconds=RECOVERY_GLOBAL_WINDOW_SECONDS,
                 max_attempts_per_window=RECOVERY_GLOBAL_MAX_ATTEMPTS,
                 clock=time.time):
        self.max_concurrent = max_concurrent
        self.window_seconds = window_seconds
        self.max_attempts_per_window = max_attempts_per_window
        self._clock = clock
        self._slots = threading.BoundedSemaphore(max_concurrent)
        self._mutex = threading.Lock()
        self._attempts = []  # attempt timestamps inside the window

    def try_acquire(self):
        """``(acquired, retry_after_seconds)``; caller MUST release()."""
        now = self._clock()
        with self._mutex:
            horizon = now - self.window_seconds
            self._attempts = [t for t in self._attempts if t > horizon]
            if len(self._attempts) >= self.max_attempts_per_window:
                retry = int(self._attempts[0] + self.window_seconds - now) + 1
                return False, max(retry, 1)
            self._attempts.append(now)
        if not self._slots.acquire(blocking=False):
            return False, self.CONCURRENCY_RETRY_SECONDS
        return True, 0

    def release(self):
        self._slots.release()
