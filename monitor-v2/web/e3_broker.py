"""Status broker for the sbox-cm web adapter (M2-B): TTL caches, the
status-driven breaker, and the fresh-only ``management_active`` provider.

Frozen semantics (docs/e3-m2-web-adapter-design.md §7):

* everything is thread-safe -- ThreadingHTTPServer serves each request on
  its own thread;
* status and list each SINGLE-FLIGHT their refreshes: at most one refresh
  RPC at any moment, and at most one refresh ATTEMPT per TTL window, so a
  burst of requests that all miss an expired TTL produces exactly one
  helper RPC, never a fan-out (the other threads wait on the same flight
  lock and then share the winner's outcome -- success or failure alike);
* the breaker is driven ONLY by management.status transport probes. A
  list/mutation transport failure returns its own error and never moves
  the counter; a mutation caller timeout can never poison the breaker;
* the web transport state (fresh | stale | unavailable) is ORTHOGONAL to
  ``helper.degraded``, which is only ever what a real management.status
  response said. A refresh failure may serve the stale snapshot with its
  original as_of, but it never fabricates or rewrites helper fields;
* ``management_active()`` is True iff a FRESH (within-TTL) status said so.
  A stale "active" is never trusted; TTL expired + helper unreachable
  answers False;
* a mutation is dispatched only while the breaker is ``closed``. After an
  uncertain result the status path stays available by design: an open
  breaker serves the last snapshot instead of blocking the only way to
  learn what happened (last_transaction).

No background threads: refreshes happen lazily on the request path.
"""

from __future__ import annotations

import threading

FRESH = "fresh"
STALE = "stale"
UNAVAILABLE = "unavailable"

STATUS_OP = "management.status"
LIST_OP = "client.list"
EXPORT_OP = "client.export"


class BrokerUnavailable(Exception):
    """Raised to refuse an operation without dispatching any RPC (breaker
    not closed, or no provable snapshot). The HTTP layer maps this to 503
    ``e3_unavailable``."""


def _default_clock():
    import time
    return time.monotonic()


def _default_wall():
    import time
    return time.time()


class E3Broker:
    """TTL caches + breaker + provider. The RPC client is injected so tests
    can drive every path without a socket."""

    def __init__(self, client, status_ttl=2.0, list_ttl=5.0,
                 breaker_failures=3, breaker_open_seconds=10.0,
                 clock=None, wall=None):
        self.client = client
        self.status_ttl = status_ttl
        self.list_ttl = list_ttl
        self.breaker_failures = breaker_failures
        self.breaker_open_seconds = breaker_open_seconds
        self._clock = clock or _default_clock
        self._wall = wall or _default_wall

        self._mutex = threading.Lock()
        self._status_flight = threading.Lock()
        self._list_flight = threading.Lock()

        self._status_cache = None   # {"payload", "fetched_at"} on success
        self._list_cache = None
        self._status_attempted_at = 0.0   # last refresh attempt (any outcome)
        self._list_attempted_at = 0.0
        self._failures = 0
        self._state = "closed"      # closed | open | half-open
        self._opened_at = 0.0

    # ------------------------------------------------------------ internals --
    def breaker_state(self):
        with self._mutex:
            return self._state

    def _serve(self, cache, now, ttl):
        """(transport, entry) for the current cache at time ``now``."""
        if cache is None:
            return UNAVAILABLE, None
        if now - cache["fetched_at"] < ttl:
            return FRESH, cache
        return STALE, cache

    def _result(self, transport, cache):
        if cache is None:
            return {"transport": UNAVAILABLE, "payload": None, "as_of": None,
                    "verdict_error": None}
        return {"transport": transport, "payload": cache["payload"],
                "as_of": cache.get("fetched_wall", cache["fetched_at"]),
                "verdict_error": None}

    def _verdict_error(self, verdict):
        """Result for an ``ok:false`` HELPER verdict (B1).

        The transport itself worked, so this is NOT a breaker input and the
        last-known-good cache stays untouched. The caller maps the verdict
        through the error table; ``transport`` is deliberately None because
        no snapshot was obtained."""
        error = verdict.get("error") if isinstance(verdict.get("error"),
                                                  dict) else {}
        return {"transport": None, "payload": None, "as_of": None,
                "verdict_error": {
                    "code": error.get("code") or "E_INTERNAL",
                    "stage": error.get("stage"),
                    "retriable": bool(error.get("retriable")),
                    "detail": error.get("detail")
                    or error.get("code") or "E_INTERNAL",
                    "request_id": verdict.get("request_id")}}

    # ------------------------------------------------------------ status --
    def status(self):
        """management.status via the cache. Returns
        ``{"transport", "payload", "as_of"}`` -- never raises for transport
        problems (``payload is None`` marks unavailable)."""
        now = self._clock()
        with self._mutex:
            cache = self._status_cache
            transport, _ = self._serve(cache, now, self.status_ttl)
        if transport is FRESH:
            return self._result(FRESH, cache)

        with self._status_flight:
            now = self._clock()
            with self._mutex:
                cache = self._status_cache
                transport, _ = self._serve(cache, now, self.status_ttl)
                if transport is FRESH:
                    return self._result(FRESH, cache)
                # Attempt throttle first: at most one refresh attempt per TTL
                # window, so concurrent misses share one outcome instead of
                # fanning out. (Cooldown 10s > TTL 2s, so this never starves
                # the half-open probe below.)
                if now - self._status_attempted_at < self.status_ttl:
                    return self._result(
                        STALE if cache is not None else UNAVAILABLE, cache)
                # Breaker gate: an open breaker (cooldown active) blocks all
                # attempts; an elapsed cooldown arms THE half-open probe --
                # performed by this thread, the only one inside the flight
                # lock while a probe runs.
                if self._state == "open":
                    if now - self._opened_at < self.breaker_open_seconds:
                        return self._result(
                            STALE if cache is not None else UNAVAILABLE, cache)
                    self._state = "half-open"
                elif self._state == "half-open":
                    # Defensive: unreachable while the prober holds the flight
                    # lock; if ever reached, do not add a second probe.
                    return self._result(
                        STALE if cache is not None else UNAVAILABLE, cache)
            try:
                verdict = self.client.call(STATUS_OP)
            except Exception:  # noqa: BLE001 - any transport failure counts
                now = self._clock()
                with self._mutex:
                    self._failures += 1
                    self._status_attempted_at = now
                    if self._state == "half-open" \
                            or self._failures >= self.breaker_failures:
                        self._state = "open"
                        self._opened_at = now
                return self._result(
                    STALE if cache is not None else UNAVAILABLE, cache)

            if isinstance(verdict, dict) and verdict.get("ok") is False:
                # B1-final: a HELPER verdict proves the transport itself
                # works, so it ENDS the failure streak -- reset the counter
                # and close the breaker (also un-sticking a half-open probe
                # that met a semantic answer). The last-known-good cache is
                # not touched and the caller still gets the helper's own
                # error semantics.
                with self._mutex:
                    self._failures = 0
                    self._state = "closed"
                    self._status_attempted_at = self._clock()
                return self._verdict_error(verdict)

            now = self._clock()
            with self._mutex:
                self._failures = 0
                self._status_attempted_at = now
                self._state = "closed"
                self._status_cache = {"payload": verdict, "fetched_at": now,
                                      "fetched_wall": self._wall()}
            return self._result(FRESH, self._status_cache)

    def management_active(self):
        """Fresh-only rule: True iff a within-TTL status said active.

        The cached payload is the daemon's full response envelope; the
        management fields live under ``data``."""
        now = self._clock()
        with self._mutex:
            cache = self._status_cache
        if cache is None:
            return False
        if now - cache["fetched_at"] >= self.status_ttl:
            return False  # stale active is NEVER trusted
        payload = cache["payload"]
        data = payload.get("data") if isinstance(payload, dict) else None
        return isinstance(data, dict) and data.get("management_active") is True

    def helper_degraded(self):
        """What the last real status response said about degraded, plus the
        transport state so callers cannot conflate the two (§7.5)."""
        now = self._clock()
        with self._mutex:
            cache = self._status_cache
            transport, _ = self._serve(cache, now, self.status_ttl)
        if cache is None:
            return {"degraded": False, "transport": UNAVAILABLE,
                    "observed": False}
        payload = cache["payload"]
        data = payload.get("data") if isinstance(payload, dict) else {}
        helper = data.get("helper") if isinstance(data, dict) else {}
        return {"degraded": bool(isinstance(helper, dict)
                                 and helper.get("degraded")),
                "transport": transport,
                "observed": True}

    # ------------------------------------------------------------ list --
    def list_clients(self, force=False):
        """client.list via the cache. ``force`` bypasses TTL and the attempt
        throttle (the delete preflight) but still requires a closed breaker."""
        now = self._clock()
        with self._mutex:
            cache = self._list_cache
            transport, _ = self._serve(cache, now, self.list_ttl)
            breaker = self._state
        if transport is FRESH and not force:
            return self._result(FRESH, cache)

        with self._list_flight:
            now = self._clock()
            with self._mutex:
                cache = self._list_cache
                transport, _ = self._serve(cache, now, self.list_ttl)
                breaker = self._state
                if transport is FRESH and not force:
                    return self._result(FRESH, cache)
                if breaker != "closed":
                    return self._result(
                        STALE if cache is not None else UNAVAILABLE, cache)
                if not force \
                        and now - self._list_attempted_at < self.list_ttl:
                    return self._result(
                        STALE if cache is not None else UNAVAILABLE, cache)

            try:
                verdict = self.client.call(LIST_OP)
            except Exception:  # noqa: BLE001 - never a breaker input
                with self._mutex:
                    self._list_attempted_at = self._clock()
                return self._result(
                    STALE if cache is not None else UNAVAILABLE, cache)

            if isinstance(verdict, dict) and verdict.get("ok") is False:
                # B1: helper verdict on a working transport -- no cache write
                # and no breaker input (the breaker is STATUS-driven only; a
                # list call never touches it). The caller maps the helper
                # semantics.
                with self._mutex:
                    self._list_attempted_at = self._clock()
                return self._verdict_error(verdict)

            now = self._clock()
            with self._mutex:
                self._list_attempted_at = now
                self._list_cache = {"payload": verdict, "fetched_at": now,
                                    "fetched_wall": self._wall()}
            return self._result(FRESH, self._list_cache)

    # ------------------------------------------------------------ mutations --
    def mutate(self, op, payload=None, actor=None):
        """Dispatch one mutation RPC. Refused (BrokerUnavailable, zero RPC)
        unless the breaker is closed. Transport errors propagate to the
        caller untouched -- they are this request's own outcome and never a
        breaker input."""
        with self._mutex:
            if self._state != "closed":
                raise BrokerUnavailable(
                    "breaker is %s; mutation not dispatched" % self._state)
        return self.client.call(op, payload=payload, actor=actor)

    # ------------------------------------------------------------ export --
    def export_client(self, name, actor=None):
        """Dispatch exactly ONE read-only client.export RPC (M4).

        Refused -- ZERO client.export dispatches -- unless ALL of the
        following hold (a management.status refresh to prove freshness is
        allowed and expected; the credential-carrying RPC never runs on a
        refusal):

        * the breaker is ``closed``;
        * a FRESH (within-TTL) management.status snapshot reports
        ``management_active`` true, ``helper.degraded`` false,
        ``helper.reconcile`` clean and ``lock.acquirable`` true.

        This gate is deliberately STRICTER than ``mutate``: an export hands
        credential material to the caller, so it runs only while the helper
        plane is provably healthy right now (a stale/unavailable/verdict
        answer is a refusal, never a fallback). The result is SENSITIVE: it
        is returned to this one caller for immediate delivery and NEVER
        cached, replayed or stored by the broker. Transport errors and
        helper verdicts propagate untouched -- same single-dispatch rule as
        ``mutate``; no automatic retry is ever performed here."""
        with self._mutex:
            if self._state != "closed":
                raise BrokerUnavailable(
                    "breaker is %s; export not dispatched" % self._state)
        result = self.status()
        if result.get("transport") != FRESH or result.get("payload") is None:
            raise BrokerUnavailable("no fresh management.status; export refused")
        payload = result["payload"]
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, dict):
            raise BrokerUnavailable("fresh status has no data; export refused")
        helper = data.get("helper")
        lock = data.get("lock")
        ok = (data.get("management_active") is True
              and isinstance(helper, dict)
              and helper.get("degraded") is False
              and helper.get("reconcile") == "clean"
              and isinstance(lock, dict)
              and lock.get("acquirable") is True)
        if not ok:
            raise BrokerUnavailable("management gate not satisfied; "
                                    "export refused")
        return self.client.call(EXPORT_OP, payload={"name": name},
                                actor=actor)
