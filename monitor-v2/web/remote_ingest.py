"""Machine ingest plane: HMAC auth, freshness, limits, disposition.

This is the SERVER half of the frozen PR-6A wire contract (issue #67 §6/§8).
The HTTP layer (``web/server.py``) owns only the exact route dispatch and
byte framing; everything below runs AFTER

    POST framing  ->  source whitelist  ->  exact ingest dispatch

and BEFORE any browser ``_cross_origin`` / session / CSRF handling -- a
machine-auth route with no session-cookie, password or CSRF fallback, and
no other POST route shares the exception.

Ordering inside :meth:`RemoteIngest.handle` is load-bearing:

1. process-wide PRE-AUTH guard (never keyed by an attacker-supplied
   probe_id, exposes nothing, bounded);
2. header grammar (the five exact headers, canonical integer text, no
   CR/LF) -- failure is the closed authentication failure;
3. registry lookup -- unknown/disabled identity performs the SAME dummy-key
   HMAC work as a known one and exposes the SAME closed authentication
   failure (no identity enumeration oracle);
4. HMAC-SHA256 over the exact frozen signature input, CONSTANT-TIME
   comparison;
5. transport freshness: ``sent_epoch`` within server_now +/- 300 s (a
   captured old request dies here, before any storage work);
6. per-probe + authenticated-global token buckets (charged only AFTER
   successful authentication -- unauthenticated traffic can never consume a
   legitimate probe's capacity);
7. body: parse -> frozen closed sample schema (PR-6A's own validator, never
   a forked grammar) -> canonical re-encode == exact received bytes;
8. one serialized store transaction: exact receipt lookup and hash verdict,
   then NEW-tuple sample_epoch/progression/admission checks and a durable
   receipt + sample + run commit under the re-frozen three-table contract.

No secret, signature, header value or exception text is logged or persisted.
Raw bodies are never logged/echoed; validated canonical samples are evidence
rows only. Receipts contain the original hash, never the body.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
import time

from remote_probe import (INGEST_PATH, MAX_BODY_BYTES as ROUTE_MAX_BODY,
                          P6_PROTOCOL)
from remote_probe.payload import (validate_sample, valid_probe_id,
                                  valid_run, verify_signature)

from web.remote_registry import DUMMY_KEY
from web.remote_store import (RemoteStore, RemoteStoreError, RunCapacityError)
from web.remote_store import ReceiptCapacityError, StorageCapacityError

INGEST_METHOD = "POST"

# The exact route (single frozen definition: PR-6A's constants).
REMOTE_INGEST_PATH = INGEST_PATH

# The five exact wire headers (§6).
HEADER_PROBE_ID = "X-Remote-Probe-Id"
HEADER_SENT_EPOCH = "X-Remote-Probe-Sent-Epoch"
HEADER_RUN = "X-Remote-Probe-Run"
HEADER_SEQ = "X-Remote-Probe-Seq"
HEADER_SIGNATURE = "X-Remote-Probe-Signature"
INGEST_HEADERS = (HEADER_PROBE_ID, HEADER_SENT_EPOCH, HEADER_RUN,
                  HEADER_SEQ, HEADER_SIGNATURE)

# Framing (§6): HTTP/1.1 is the protocol version of the listener itself;
# the remaining route-specific gates live in the server handler. The
# route cap is the SAME 16 KiB the agent enforces on its encoded body;
# the server handler checks it BEFORE reading or parsing anything.
INGEST_MAX_BODY = ROUTE_MAX_BODY          # exact 16 KiB (16384 bytes)
CONTENT_TYPE_JSON = "application/json"
SENT_EPOCH_FRESHNESS_SECONDS = 300.0
SAMPLE_EPOCH_FUTURE_SECONDS = 300.0
SAMPLE_EPOCH_AGE_SECONDS = 7 * 86400.0 + 12 * 3600.0

# Canonical integer text: no sign, no leading zeros, digits only.
_INT_RE = re.compile(r"\A[0-9]{1,19}\Z")
SEQ_MAX = (1 << 63) - 1

# Closed response vocabulary (§11). Success is the EXACT schema PR-6A's
# disposition contract ACKs on: {"v": 1, "result": "accepted"|"duplicate"}.
SUCCESS_VERSION = 1
RESULT_ACCEPTED = "accepted"
RESULT_DUPLICATE = "duplicate"

# Closed error codes (one key, one token; never exception text).
ERR_UNAUTHORIZED = "unauthorized"            # ALL authentication failures
ERR_RATE_LIMITED = "rate_limited"            # 429, retryable
ERR_INVALID_BODY = "invalid_body"            # parse / schema / identity match
ERR_NON_CANONICAL = "non_canonical_body"     # re-encode != received bytes
ERR_SAMPLE_EPOCH_RANGE = "sample_epoch_out_of_range"
ERR_SEQUENCE_NOT_INCREASING = "sequence_not_increasing"
ERR_EPOCH_NOT_INCREASING = "sample_epoch_not_increasing"
ERR_EQUIVOCATION = "equivocation"            # same tuple, different hash
ERR_REMOTE_STORE = "remote_store_unavailable"  # 503, retryable
ERR_REMOTE_RUN_CAPACITY = "remote_run_capacity"  # 503, retryable
ERR_REMOTE_RECEIPT_CAPACITY = "remote_receipt_capacity"
ERR_REMOTE_STORAGE_CAPACITY = "remote_storage_capacity"
PROBE_REPORTING_SECONDS = 180.0  # three default 60-second generation cycles
ERR_BAD_FRAMING = "invalid_framing"         # 400: CL/Content-Type rules
ERR_PAYLOAD_TOO_LARGE = "payload_too_large"  # 413: > 16 KiB route cap
ERR_CONTENT_TYPE = "unsupported_media_type"  # 400: not application/json

# §10 token buckets (authenticated): per probe 2/s burst 120; global 20/s
# burst 240. One process-wide PRE-AUTH guard (never keyed by probe data):
# coarse, bounded, 2x the authenticated global sustained rate.
PER_PROBE_RATE = 2.0
PER_PROBE_BURST = 120
GLOBAL_RATE = 20.0
GLOBAL_BURST = 240
PREAUTH_RATE = 40.0
PREAUTH_BURST = 600

_valid_probe_id = valid_probe_id
_valid_run = valid_run


class TokenBucket:
    """A bounded token bucket over an injectable clock."""

    def __init__(self, rate, burst, clock=None):
        self.rate = float(rate)
        self.burst = float(burst)
        self.clock = clock or (lambda: time.monotonic())
        self._tokens = float(burst)
        self._updated = self.clock()
        self._lock = threading.Lock()

    def check(self):
        """(allowed, retry_after_seconds) -- deterministic, no jitter."""
        with self._lock:
            return self._check_locked()

    def _check_locked(self):
        now = self.clock()
        with_token = min(self.burst,
                         self._tokens + max(0, now - self._updated) * self.rate)
        self._updated = max(now, self._updated)
        if with_token >= 1.0:
            self._tokens = with_token - 1.0
            return True, 0.0
        self._tokens = with_token
        needed = (1.0 - with_token) / self.rate
        return False, max(1, int(needed) + (1 if needed % 1 else 0))


class IngestRateLimiter:
    """Per-probe + global authenticated buckets, created only for
    AUTHENTICATED identities and bounded to the registry maximum (plus a
    small idle-eviction margin so a churned registry cannot grow it)."""

    MAX_BUCKETS = 512                     # >= 64 identities, idle-evicted

    def __init__(self, clock=None):
        self.clock = clock or (lambda: time.monotonic())
        self._global = TokenBucket(GLOBAL_RATE, GLOBAL_BURST, self.clock)
        self._per_probe = {}
        self._lock = threading.Lock()

    def bucket(self, probe_id):
        with self._lock:
            bucket = self._per_probe.get(probe_id)
            if bucket is None:
                if len(self._per_probe) >= self.MAX_BUCKETS:
                    # Evict the oldest half: buckets hold no secrets and are
                    # rebuilt on demand, so eviction loses at most cadence.
                    for key in sorted(self._per_probe)[:self.MAX_BUCKETS // 2]:
                        del self._per_probe[key]
                bucket = TokenBucket(PER_PROBE_RATE, PER_PROBE_BURST,
                                     self.clock)
                self._per_probe[probe_id] = bucket
            return bucket

    @property
    def global_bucket(self):
        return self._global


def parse_canonical_int(text, minimum=1, maximum=SEQ_MAX):
    """Canonical base-10 integer header text -> int, or None.

    Digits only, no sign, no leading zeros (``str(int(text)) == text``),
    within the closed range. Anything else is an authentication failure.
    """
    if type(text) is not str or not _INT_RE.match(text):
        return None
    value = int(text)
    if str(value) != text or value < minimum or value > maximum:
        return None
    return value


class RemoteIngest:
    """The machine ingest plane: registry + store + limits + disposition."""

    def __init__(self, data_dir, clock=None, registry=None, store=None,
                 limiter=None):
        self.clock = clock or (lambda: time.time())
        # The registry defaults to the frozen production paths; an absent
        # config file leaves the plane DARK (not_configured -> the route
        # answers a plain 404 and core Monitor runs exactly as before).
        self.registry = registry
        if self.registry is None:
            from web.remote_registry import RemoteRegistry
            self.registry = RemoteRegistry()
        self.store = store
        self.limiter = limiter or IngestRateLimiter(
            clock=lambda: time.monotonic())
        self.preauth = TokenBucket(PREAUTH_RATE, PREAUTH_BURST,
                                   clock=lambda: time.monotonic())
        self._store_error = None
        self._state_lock = threading.RLock()
        self._capacity_failures = {}  # bounded to authenticated registry IDs
        if store is None:
            try:
                self.store = RemoteStore(data_dir, clock=self.clock).open()
            except RemoteStoreError as exc:
                # The remote plane degrades; core Monitor is untouched.
                self.store = None
                self._store_error = str(exc)

    # -- plane lifecycle -----------------------------------------------------

    def close(self):
        if self.store is not None:
            self.store.close()

    def configured(self):
        """False while the operator has not configured the remote plane at
        all (the DARK default): the route then answers a plain 404 like any
        other unknown path, so an unconfigured Monitor gains no surface."""
        state, _sub = self.registry.health()
        return state != "not_configured"

    # -- status --------------------------------------------------------------

    def status(self):
        """Closed remote-plane status (§12/§14 primitives; the HTTP read
        surface belongs to a later PR). A store failure never touches the
        History health object -- this dict is not consumed by
        ``_evidence_health_locked()`` or ``classifier_bundle()``."""
        now = float(self.clock())
        state, subcode = self.registry.health()
        store_status, times, probes = None, {}, {}
        try:
            if self.store is not None:
                store_status = self.store.status()
                times = self.store.probe_sample_times()
                with self._state_lock:
                    for probe_id in list(self._capacity_failures):
                        if self.store.capacity_code(probe_id) is None:
                            del self._capacity_failures[probe_id]
                    failures = dict(self._capacity_failures)
                self._store_error = None
            else:
                failures = {}
        except RemoteStoreError:
            self._store_error = ERR_REMOTE_STORE
            failures = {}
        for probe_id, entry in sorted(self.registry.entries.items()):
            if not entry.enabled:
                continue
            epoch = times.get(probe_id)
            code = failures.get(probe_id)
            if code is None and self.store is not None and self._store_error is None:
                try:
                    code = self.store.capacity_code(probe_id)
                except RemoteStoreError:
                    self._store_error = ERR_REMOTE_STORE
            if self._store_error is not None:
                probe_state, code = "degraded", ERR_REMOTE_STORE
            elif code:
                probe_state = "degraded"
            elif epoch is None or now - epoch > PROBE_REPORTING_SECONDS:
                probe_state, code = "source_unavailable", "probe_not_reporting"
            elif store_status and store_status["budget_pruned"]:
                probe_state, code = "degraded", "remote_budget_pruned"
            else:
                probe_state, code = "fresh", None
            probes[probe_id] = {"status": probe_state, "subcode": code,
                                "last_sample_epoch": epoch,
                                "site_label": entry.site_label,
                                "path_label": entry.path_label}
        for probe_id in self.registry.identity_problems():
            probes[probe_id] = {"status": "degraded", "subcode": "remote_config_invalid",
                                "last_sample_epoch": None, "site_label": None, "path_label": None}
        if state == "ready":
            state, subcode = "not_configured", None
            if probes:
                state = "fresh"
                for target in ("degraded", "source_unavailable"):
                    matches = [p for p in probes.values() if p["status"] == target]
                    if matches:
                        state, subcode = target, matches[0]["subcode"]
                        break
        if state != "not_configured" and self._store_error is not None:
            state, subcode = "degraded", ERR_REMOTE_STORE
        return {
            "status": state,
            "subcode": subcode,
            "probes_configured": len(self.registry.entries) + len(self.registry.identity_problems()),
            "suspended_probes": sorted(p for p, row in probes.items()
                                       if row["subcode"] in (ERR_REMOTE_RUN_CAPACITY,
                                          ERR_REMOTE_RECEIPT_CAPACITY, ERR_REMOTE_STORAGE_CAPACITY)),
            "probes": probes,
            "store": store_status,
        }

    def read_samples(self, start_epoch, end_epoch, probe_id=None, limit=256):
        """Internal retained-sample primitive for later presentation work.

        No incident/HTTP route is added. Labels are current operator assertions;
        retired mappings return no labels. Receipts are never evidence rows.
        """
        if self.store is None:
            raise RemoteStoreError("remote store unavailable")
        result = []
        for sample in self.store.read_samples(start_epoch, end_epoch, probe_id, limit):
            entry = self.registry.lookup(sample["probe_id"])
            mapped = entry is not None and entry.enabled
            result.append({"sample": sample, "mapping_retired": not mapped,
                           "site_label": entry.site_label if mapped else None,
                           "path_label": entry.path_label if mapped else None})
        return result

    # -- the one machine entry point -----------------------------------------

    def handle(self, raw_body, headers, now=None):
        """The full ingest verdict -> ``(status, payload, extra_headers)``.

        ``raw_body`` is the EXACT received byte string; ``headers`` is the
        closed five-key dict the HTTP layer extracted. This method never
        raises: every outcome is a closed status.
        """
        now = float(self.clock() if now is None else now)
        # 1. pre-auth process guard: bounded, unkeyed, identity-blind.
        allowed, retry_after = self.preauth.check()
        if not allowed:
            return self._rate_limited(retry_after)
        # 2. header grammar.
        probe_id = headers.get(HEADER_PROBE_ID)
        run = headers.get(HEADER_RUN)
        signature = headers.get(HEADER_SIGNATURE)
        sent_epoch = parse_canonical_int(headers.get(HEADER_SENT_EPOCH),
                                         minimum=0)
        seq = parse_canonical_int(headers.get(HEADER_SEQ), minimum=1)
        if not self._grammar_ok(probe_id, _valid_probe_id) \
                or not self._grammar_ok(run, _valid_run) \
                or sent_epoch is None or seq is None \
                or type(signature) is not str or not signature:
            return self._auth_failed(raw_body, probe_id, sent_epoch, run,
                                     seq, signature)
        # 3. registry lookup.
        entry = self.registry.lookup(probe_id) \
            if self.registry is not None else None
        if entry is None or not entry.enabled:
            # Unknown AND disabled identities do the same dummy-key HMAC
            # work as known ones: identical timing, identical response.
            self._dummy_work(raw_body, probe_id, sent_epoch, run, seq)
            return self._unauthorized()
        # 4. HMAC over the exact frozen input, constant-time.
        if not verify_signature(entry.key, probe_id, sent_epoch, run, seq,
                                raw_body, signature):
            return self._unauthorized()
        # 5. transport freshness: a captured request dies here.
        if abs(sent_epoch - now) > SENT_EPOCH_FRESHNESS_SECONDS:
            return self._unauthorized()
        # 6. authenticated rate limits: the per-probe bucket is charged
        #    only now -- unauthenticated traffic can never consume it.
        allowed, retry_after = self.limiter.bucket(probe_id).check()
        if allowed:
            allowed, retry_after = self.limiter.global_bucket.check()
        if not allowed:
            return self._rate_limited(retry_after)
        # 7. body: schema, identity match, exact canonical bytes.
        sample = self._parse_body(raw_body)
        if sample is None:
            return 400, {"error": ERR_INVALID_BODY}, ()
        if sample.get("probe_id") != probe_id or sample.get("run") != run \
                or sample.get("seq") != seq:
            return 400, {"error": ERR_INVALID_BODY}, ()
        from remote_probe.payload import canonical_bytes
        try:
            if canonical_bytes(sample) != raw_body:
                return 400, {"error": ERR_NON_CANONICAL}, ()
        except (TypeError, ValueError):
            return 400, {"error": ERR_NON_CANONICAL}, ()
        # 8. The store classifies receipts BEFORE applying NEW-sample bounds.
        epoch = sample.get("sample_epoch")
        # 9. store: idempotency / equivocation / continuity.
        if self.store is None:
            return 503, {"error": ERR_REMOTE_STORE}, ()
        try:
            verdict = self.store.accept(probe_id, run, seq, epoch, raw_body, now)
            if verdict in (RESULT_ACCEPTED, RESULT_DUPLICATE):
                with self._state_lock:
                    self._capacity_failures.pop(probe_id, None)
                return 200, {"v": SUCCESS_VERSION, "result": verdict}, ()
            return (400 if verdict == ERR_SAMPLE_EPOCH_RANGE else 409), {"error": verdict}, ()
        except RemoteStoreError as exc:
            if isinstance(exc, (RunCapacityError, ReceiptCapacityError, StorageCapacityError)):
                with self._state_lock:
                    self._capacity_failures[probe_id] = exc.code
                return 503, {"error": exc.code}, ()
            self._store_error = ERR_REMOTE_STORE
            return 503, {"error": ERR_REMOTE_STORE}, ()

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _grammar_ok(value, validate):
        """PR-6A's own grammar validators -- never a forked copy."""
        try:
            return validate(value)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _parse_body(raw_body):
        import json
        if type(raw_body) is not bytes or not raw_body:
            return None
        if len(raw_body) > ROUTE_MAX_BODY:
            return None
        try:
            sample = json.loads(raw_body.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        if not isinstance(sample, dict) or validate_sample(sample):
            return None
        return sample

    def _unauthorized(self):
        """THE closed authentication failure: unknown, disabled, malformed,
        bad-signature and stale-epoch all answer this exact body."""
        return 401, {"error": ERR_UNAUTHORIZED}, ()

    def _rate_limited(self, retry_after):
        return 429, {"error": ERR_RATE_LIMITED}, \
            [("Retry-After", str(max(1, int(retry_after))))]

    def _dummy_work(self, raw_body, probe_id, sent_epoch, run, seq,):
        """One real HMAC over the same frozen input with the dummy key, so
        an unknown identity costs the same as a known one."""
        if sent_epoch is None:
            sent_epoch = 0
        digest = hashlib.sha256(raw_body or b"").hexdigest()
        message = ("%s\n%s\n%s\n%s\n%d\n%s\n%d\n%s"
                   % (P6_PROTOCOL, INGEST_METHOD, INGEST_PATH,
                      probe_id if type(probe_id) is str else "",
                      sent_epoch, run if type(run) is str else "",
                      seq if seq is not None else 0,
                      digest)).encode("utf-8", errors="replace")
        hmac.new(DUMMY_KEY, message, hashlib.sha256).digest()

    def _auth_failed(self, raw_body, probe_id, sent_epoch, run, seq,
                     signature):
        """Uniform failure path for malformed headers: the same dummy HMAC
        work, then the same closed body as every other auth failure."""
        self._dummy_work(raw_body, probe_id, sent_epoch, run, seq)
        return self._unauthorized()
