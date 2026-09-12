"""Admin authentication for the Monitor v2 web dashboard (Phase E2).

The IP whitelist is not a login: an allowed address still needs the admin
password. Requirements implemented here:

* passwords are NEVER stored in plaintext -- scrypt (N=16384, r=8, p=1)
  over a random 16-byte salt, verified with ``hmac.compare_digest``;
* session tokens are ``secrets.token_urlsafe(32)`` (256-bit) and live in
  memory ONLY: restarting the web process logs browsers out instead of
  persisting bearer tokens on disk;
* the session cookie is ``Secure; HttpOnly; SameSite=Strict`` (8h default
  lifetime; browsers treat localhost as trustworthy so Secure cookies work
  on the loopback canary too, and remote mode is TLS-only anyway);
* failed logins are rate limited per source IP: 5 failures inside 15
  minutes lock the address out for 15 minutes.

Nothing here is ever logged: the server logs request lines only, and the
password hash file (auth.json) holds hashes, never the password itself.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time

from web.storage import atomic_write_json, ensure_private_dir, read_json

DEFAULT_SESSION_TTL = 8 * 3600.0
MIN_PASSWORD_LENGTH = 8

SCRYPT_N = 1 << 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16

AUTH_VERSION = 1

LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW_SECONDS = 900.0
LOGIN_LOCKOUT_SECONDS = 900.0


def hash_secret(secret):
    """scrypt hash record for a secret (password / recovery key)."""
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(secret.encode("utf-8"), salt=salt,
                            n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P,
                            dklen=SCRYPT_DKLEN)
    return {
        "algorithm": "scrypt",
        "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(digest).decode("ascii"),
    }


def verify_secret(secret, record):
    """Constant-time verification against a stored hash record."""
    if not isinstance(record, dict) or not isinstance(secret, str):
        return False
    try:
        if record.get("algorithm") != "scrypt":
            return False
        salt = base64.b64decode(record["salt"])
        expected = base64.b64decode(record["hash"])
        digest = hashlib.scrypt(secret.encode("utf-8"), salt=salt,
                                n=int(record["n"]), r=int(record["r"]),
                                p=int(record["p"]), dklen=len(expected))
    except (KeyError, ValueError, TypeError):
        return False
    return hmac.compare_digest(digest, expected)


def validate_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            "password must be a string of at least %d characters"
            % MIN_PASSWORD_LENGTH)
    return password


class LoginRateLimiter:
    """Per-IP sliding-window lockout for failed logins (in memory)."""

    def __init__(self, max_failures=LOGIN_MAX_FAILURES,
                 window_seconds=LOGIN_WINDOW_SECONDS,
                 lockout_seconds=LOGIN_LOCKOUT_SECONDS, clock=time.time):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._failures = {}     # ip -> [timestamps]
        self._locked_until = {}  # ip -> timestamp

    def check(self, ip):
        """(allowed, retry_after_seconds) for a login attempt from ip."""
        now = self._clock()
        until = self._locked_until.get(ip)
        if until is not None:
            if now < until:
                return False, int(round(until - now))
            del self._locked_until[ip]
            self._failures.pop(ip, None)
        return True, 0

    def record_failure(self, ip):
        now = self._clock()
        window_start = now - self.window_seconds
        recent = [t for t in self._failures.get(ip, []) if t > window_start]
        recent.append(now)
        self._failures[ip] = recent
        if len(recent) >= self.max_failures:
            self._locked_until[ip] = now + self.lockout_seconds

    def record_success(self, ip):
        self._failures.pop(ip, None)
        self._locked_until.pop(ip, None)


class SessionStore:
    """In-memory bearer sessions; nothing token-shaped is ever persisted."""

    def __init__(self, ttl=DEFAULT_SESSION_TTL, clock=time.time):
        self.ttl = ttl
        self._clock = clock
        self._sessions = {}  # token -> {"created": ts, "expires": ts}

    def create(self):
        now = self._clock()
        token = secrets.token_urlsafe(32)
        record = {"created": now, "expires": now + self.ttl,
                  "csrf_token": secrets.token_urlsafe(32)}
        self._sessions[token] = record
        return token

    def resolve(self, token):
        record = self._sessions.get(token)
        if record is None:
            return None
        if self._clock() >= record["expires"]:
            del self._sessions[token]
            return None
        return record

    def drop(self, token):
        self._sessions.pop(token, None)

    def drop_all(self, except_token=None):
        for token in list(self._sessions):
            if token != except_token:
                del self._sessions[token]


class AuthStore:
    """auth.json persistence (hashes only) + in-memory session/rate state."""

    def __init__(self, data_dir, session_ttl=DEFAULT_SESSION_TTL,
                 clock=time.time):
        self.data_dir = data_dir
        self.path = "%s/auth.json" % data_dir
        self.sessions = SessionStore(ttl=session_ttl, clock=clock)
        self.login_limiter = LoginRateLimiter(clock=clock)
        self._password = None
        self._recovery = None
        self.load()

    # -- persistence ---------------------------------------------------------

    def load(self):
        data = read_json(self.path)
        if not isinstance(data, dict):
            return
        password = data.get("password")
        if isinstance(password, dict) and password.get("hash"):
            self._password = password
        recovery = data.get("recovery")
        if isinstance(recovery, dict) and recovery.get("hash"):
            self._recovery = recovery

    def save(self):
        ensure_private_dir(self.data_dir)
        payload = {"version": AUTH_VERSION}
        if self._password is not None:
            payload["password"] = self._password
        if self._recovery is not None:
            payload["recovery"] = self._recovery
        atomic_write_json(self.path, payload)

    # -- password ------------------------------------------------------------

    def password_configured(self):
        return self._password is not None

    def verify_password(self, password):
        if self._password is None:
            return False
        return verify_secret(password, self._password)

    def set_password(self, password, keep_session=None):
        validate_password(password)
        self._password = hash_secret(password)
        self.save()
        # A new password invalidates every OTHER session (admin may be
        # locking out a compromised browser); the caller stays logged in.
        self.sessions.drop_all(except_token=keep_session)

    # -- recovery record (hash only; the flow lives in web/recovery.py) ------

    def recovery_configured(self):
        return self._recovery is not None

    def set_recovery_key(self, key):
        self._recovery = hash_secret(key)
        self.save()

    def verify_recovery_key(self, key):
        if self._recovery is None:
            return False
        return verify_secret(key, self._recovery)
