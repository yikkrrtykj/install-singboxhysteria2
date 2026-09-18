"""Admin authentication for the Monitor v2 web dashboard (Phase E2).

The IP whitelist is not a login: an allowed address still needs the admin
password. Requirements implemented here:

* passwords are NEVER stored in plaintext -- scrypt (N=16384, r=8, p=1)
  over a random 16-byte salt, verified with ``hmac.compare_digest``;
* session tokens are ``secrets.token_urlsafe(32)`` (256-bit) and live in
  memory ONLY: restarting the web process logs browsers out instead of
  persisting bearer tokens on disk. Each session also carries its own
  CSRF token (exposed to the page via ``/api/v1/session``; every
  authenticated mutation must present it);
* a session may additionally hold a **step-up** (M0.5 / rev5 G3): a
  300-second re-authentication window that privileged mutations require.
  It too is memory-only and bound to its session -- logout, password
  change, recovery-key rotation, session expiry and web restart each make
  it vanish (``revoke_all_step_ups`` / session drop), never a disk write;
* the session cookie is always ``HttpOnly; SameSite=Strict`` with an 8h
  default lifetime. The ``Secure`` flag is MODE-SCOPED: mandatory on
  remote listeners and any TLS listener; deliberately omitted on a
  loopback HTTP listener, where browsers differ in whether they accept
  Secure cookies over plain http://localhost and nothing crosses a
  network anyway;
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
import threading
import time

from web.storage import atomic_write_json, ensure_private_dir, read_json

DEFAULT_SESSION_TTL = 8 * 3600.0
MIN_PASSWORD_LENGTH = 8

# Step-up (re-authentication) window for privileged mutations. Deliberately a
# process constant, not a per-session value: the 300s figure is a contract
# (rev5 §5.1 U-7), not a tunable.
DEFAULT_STEP_UP_TTL = 300.0

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


def _stepup_fingerprint(token, granted_at):
    """16-hex audit fingerprint for one step-up grant (M2 §12 S-A).

    sha256 over the memory-only session token and the canonical grant
    timestamp: one-way (the token is not recoverable), stable within the
    window (every mutation in the window attributes to the same fp), and
    guaranteed to rotate on the next grant because the timestamp differs.
    """
    material = "%s:%s" % (token, repr(float(granted_at)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


class LoginRateLimiter:
    """Per-IP sliding-window lockout for failed logins (in memory).

    Thread-safe: ThreadingHTTPServer may process several logins at once,
    and the failure window / lockout tables must not race.
    """

    def __init__(self, max_failures=LOGIN_MAX_FAILURES,
                 window_seconds=LOGIN_WINDOW_SECONDS,
                 lockout_seconds=LOGIN_LOCKOUT_SECONDS, clock=time.time):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._clock = clock
        self._mutex = threading.Lock()
        self._failures = {}     # ip -> [timestamps]
        self._locked_until = {}  # ip -> timestamp

    def check(self, ip):
        """(allowed, retry_after_seconds) for a login attempt from ip."""
        now = self._clock()
        with self._mutex:
            until = self._locked_until.get(ip)
            if until is not None:
                if now < until:
                    return False, int(round(until - now))
                del self._locked_until[ip]
                self._failures.pop(ip, None)
            return True, 0

    def record_failure(self, ip):
        now = self._clock()
        with self._mutex:
            window_start = now - self.window_seconds
            recent = [t for t in self._failures.get(ip, []) if t > window_start]
            recent.append(now)
            self._failures[ip] = recent
            if len(recent) >= self.max_failures:
                self._locked_until[ip] = now + self.lockout_seconds

    def record_success(self, ip):
        with self._mutex:
            self._failures.pop(ip, None)
            self._locked_until.pop(ip, None)


class SessionStore:
    """In-memory bearer sessions; nothing token-shaped is ever persisted.

    Thread-safe: concurrent logins/logouts/expiries come from different
    request threads; the sessions dict is guarded by a mutex (no reliance
    on GIL atomicity for multi-step operations).

    Each session record is::

        {"created", "expires", "csrf_token", "step_up_expires",
         "step_up_granted_at", "stepup_fp"}

    where ``step_up_expires`` is ``None`` (never re-authenticated) or an
    absolute clock value. The step-up is a property of one session: dropping
    the session drops it, and it is never persisted anywhere.

    M2 extends the in-memory step-up record with ``step_up_granted_at`` and
    ``stepup_fp`` (docs/e3-m2-web-adapter-design.md §12 S-A): the fingerprint
    is what the RPC ``actor`` carries for privileged-audit attribution. It is
    derived from the memory-only session token, never stored on disk, never
    returned to the browser, and cleared TOGETHER with the expiry by every
    revocation path (logout / password change / recovery reset / recovery
    rotate / session expiry; a web restart clears all memory state anyway).
    """

    def __init__(self, ttl=DEFAULT_SESSION_TTL, clock=time.time,
                 step_up_ttl=DEFAULT_STEP_UP_TTL):
        self.ttl = ttl
        self.step_up_ttl = step_up_ttl
        self._clock = clock
        self._mutex = threading.Lock()
        self._sessions = {}  # token -> {"created", "expires", "csrf_token"}

    def create(self):
        now = self._clock()
        token = secrets.token_urlsafe(32)
        record = {"created": now, "expires": now + self.ttl,
                  "csrf_token": secrets.token_urlsafe(32),
                  "step_up_expires": None,
                  "step_up_granted_at": None,
                  "stepup_fp": None}
        with self._mutex:
            self._sessions[token] = record
        return token

    def resolve(self, token):
        with self._mutex:
            record = self._sessions.get(token)
            if record is None:
                return None
            if self._clock() >= record["expires"]:
                del self._sessions[token]
                return None
            return record

    def drop(self, token):
        with self._mutex:
            self._sessions.pop(token, None)

    def drop_all(self, except_token=None):
        with self._mutex:
            for token in list(self._sessions):
                if token != except_token:
                    del self._sessions[token]

    # -- step-up (re-authentication) -----------------------------------------

    def grant_step_up(self, token, ttl=None):
        """Open a step-up window on ``token``; returns its expiry or None.

        None means the session does not exist (or already expired), so no
        window could be opened -- the caller must answer 401, never pretend
        a grant happened.

        M2: the grant also creates the audit fingerprint pair. Every grant
        writes a FRESH ``step_up_granted_at``, so a re-grant always rotates
        the fingerprint; within one window all mutations reuse the same fp,
        which is what makes the helper's audit trail attributable per
        step-up window.
        """
        ttl = self.step_up_ttl if ttl is None else ttl
        now = self._clock()
        with self._mutex:
            record = self._sessions.get(token)
            if record is None or now >= record["expires"]:
                return None
            record["step_up_expires"] = now + ttl
            record["step_up_granted_at"] = now
            record["stepup_fp"] = _stepup_fingerprint(token, now)
            return record["step_up_expires"]

    def step_up_active(self, token):
        """True while a valid, unexpired step-up window exists on the session."""
        now = self._clock()
        with self._mutex:
            record = self._sessions.get(token)
            if record is None or now >= record["expires"]:
                return False
            expires = record.get("step_up_expires")
            return expires is not None and now < expires

    def step_up_credentials(self, token):
        """Atomic snapshot of the step-up state: ``{"active", "fp"}``.

        ``fp`` is the audit fingerprint to send as the RPC actor's
        ``stepup_fp`` while the window is live, else ``None``. Checking
        liveness and reading the fingerprint in one locked step removes the
        gap where a revocation lands between ``step_up_active()`` and a
        separate fingerprint fetch. The fp NEVER goes back to the browser:
        its only consumer is the RPC actor payload.
        """
        now = self._clock()
        with self._mutex:
            record = self._sessions.get(token)
            if record is None or now >= record["expires"]:
                return {"active": False, "fp": None}
            expires = record.get("step_up_expires")
            if expires is None or now >= expires:
                return {"active": False, "fp": None}
            return {"active": True, "fp": record.get("stepup_fp")}

    def revoke_all_step_ups(self):
        """Drop EVERY step-up (the sessions themselves survive).

        M2: the fingerprint pair dies with the window -- a revoked window
        must not leave a reusable ``stepup_fp`` behind.
        """
        with self._mutex:
            for record in self._sessions.values():
                record["step_up_expires"] = None
                record["step_up_granted_at"] = None
                record["stepup_fp"] = None


class AuthStore:
    """auth.json persistence (hashes only) + in-memory session/rate state.

    Thread-safe and storage-first: mutations build the candidate payload,
    write it atomically, and only then publish the in-memory state under a
    mutex. A failed write therefore leaves memory and disk coherent (and
    the HTTP layer turns the exception into a 500 -- never a success).
    """

    def __init__(self, data_dir, session_ttl=DEFAULT_SESSION_TTL,
                 clock=time.time, step_up_ttl=DEFAULT_STEP_UP_TTL):
        self.data_dir = data_dir
        self.path = "%s/auth.json" % data_dir
        self.sessions = SessionStore(ttl=session_ttl, clock=clock,
                                     step_up_ttl=step_up_ttl)
        self.login_limiter = LoginRateLimiter(clock=clock)
        self._mutex = threading.RLock()
        self._password = None
        self._recovery = None
        self.load()

    # -- persistence ---------------------------------------------------------

    def load(self):
        with self._mutex:
            data = read_json(self.path)
            if not isinstance(data, dict):
                return
            password = data.get("password")
            if isinstance(password, dict) and password.get("hash"):
                self._password = password
            recovery = data.get("recovery")
            if isinstance(recovery, dict) and recovery.get("hash"):
                self._recovery = recovery

    def _payload(self, password_record=None, recovery_record=None):
        payload = {"version": AUTH_VERSION}
        password = password_record if password_record is not None \
            else self._password
        if password is not None:
            payload["password"] = password
        recovery = recovery_record if recovery_record is not None \
            else self._recovery
        if recovery is not None:
            payload["recovery"] = recovery
        return payload

    def save(self):
        with self._mutex:
            ensure_private_dir(self.data_dir)
            atomic_write_json(self.path, self._payload())

    # -- password ------------------------------------------------------------

    def password_configured(self):
        with self._mutex:
            return self._password is not None

    def verify_password(self, password):
        with self._mutex:
            record = self._password
        if record is None:
            return False
        return verify_secret(password, record)

    def set_password(self, password, keep_session=None):
        validate_password(password)
        record = hash_secret(password)
        with self._mutex:
            # storage first: a failed write raises BEFORE any in-memory
            # state changes, so HTTP callers can never observe a 200 with
            # disk left stale.
            ensure_private_dir(self.data_dir)
            atomic_write_json(self.path, self._payload(password_record=record))
            self._password = record
            # A new password invalidates every OTHER session (admin may be
            # locking out a compromised browser); the caller stays logged in.
            self.sessions.drop_all(except_token=keep_session)
            # ...but EVERY step-up dies, including the caller's own: the
            # credential the step-up was based on no longer exists, so the
            # mutation privilege is revoked immediately rather than after
            # the 300s window. The caller keeps a normal read-only session
            # and must re-authenticate before the next mutation.
            self.sessions.revoke_all_step_ups()

    # -- recovery record (hash only; the flow lives in web/recovery.py) ------

    def recovery_configured(self):
        with self._mutex:
            return self._recovery is not None

    def set_recovery_key(self, key):
        record = hash_secret(key)
        with self._mutex:
            ensure_private_dir(self.data_dir)
            atomic_write_json(self.path,
                              self._payload(recovery_record=record))
            self._recovery = record
            # Rotating (or first configuring) the recovery key changes the
            # authentication root, so every outstanding step-up is revoked:
            # the same rule as a password change, applied to the recovery
            # credential. Sessions stay logged in.
            self.sessions.revoke_all_step_ups()

    def verify_recovery_key(self, key):
        with self._mutex:
            record = self._recovery
        if record is None:
            return False
        return verify_secret(key, record)
