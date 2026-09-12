"""Snapshot broker: one long-lived E1 collector, many web readers.

The collector MUST stay a single long-running instance. E1's continuity --
active lifecycles, banked closed totals, the replay guard -- lives in the
in-memory ``Tracker``; restarting the stream consumer per HTTP request
would silently destroy all of it. This broker therefore runs the collector
once, in a daemon thread, for the whole life of the web process.

Threading model
---------------

* consumer thread: runs ``Collector.consume()`` in bounded duration slices.
  ``consume()`` never raises: on stream failure it keeps the last state,
  flips ``stale=True`` and retries with capped backoff (E1 semantics,
  inherited unchanged by the dashboard).
* tracker access is serialized through a lock. The lock is installed as a
  proxy wrapper AROUND the tracker object -- ``collector.py`` itself stays
  unmodified and the E1 regression suite is unaffected.
* publisher thread: builds ONE decorated snapshot per poll tick (~1s),
  serializes it once and bumps a version under a condition variable.
* SSE subscribers wait on the condition variable and always receive the
  latest JSON. A browser that disconnects only ends its own generator --
  the collector never notices.
"""

from __future__ import annotations

import datetime
import json
import threading
import time

# consume() slice length: short enough for a clean shutdown, long enough
# that stream reconnection state (backoff) behaves exactly like E1's.
CONSUME_SLICE_SECONDS = 300.0

SUBSCRIBER_IDLE_WAIT = 15.0


def _iso(timestamp):
    return datetime.datetime.fromtimestamp(
        timestamp, datetime.timezone.utc).isoformat()


class _LockedTracker:
    """Serialize Tracker access between the consumer and publisher threads."""

    __slots__ = ("_tracker", "_lock")

    def __init__(self, tracker, lock):
        self._tracker = tracker
        self._lock = lock

    def apply_batch(self, batch, now):
        with self._lock:
            return self._tracker.apply_batch(batch, now)

    def snapshot(self, now):
        with self._lock:
            return self._tracker.snapshot(now)


class SnapshotBroker:
    """Owns the collector thread and the latest serialized snapshot."""

    def __init__(self, collector, poll_seconds=1.0, clock=time.time):
        self._collector = collector
        self._poll = poll_seconds
        self._clock = clock
        self._lock = threading.Lock()       # tracker access
        self._cond = threading.Condition()  # snapshot publication
        self._version = 0
        self._snapshot = None               # decorated dict (publisher only writes)
        self._snapshot_json = None          # canonical JSON string
        self._stop = threading.Event()
        self._consumer_thread = None
        self._publisher_thread = None
        self.started_at = self._clock()
        self.started_iso = _iso(self.started_at)
        # Wrap the tracker BEFORE the consumer thread starts.
        self._collector.tracker = _LockedTracker(self._collector.tracker,
                                                 self._lock)

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        self._consumer_thread = threading.Thread(
            target=self._consume_loop, name="monitor-collector", daemon=True)
        self._publisher_thread = threading.Thread(
            target=self._publish_loop, name="monitor-publisher", daemon=True)
        self._consumer_thread.start()
        self._publisher_thread.start()

    def stop(self):
        self._stop.set()
        with self._cond:
            self._cond.notify_all()

    def _consume_loop(self):
        while not self._stop.is_set():
            # never raises; stale/retry semantics live inside consume()
            self._collector.consume(duration=CONSUME_SLICE_SECONDS)

    # -- publication ---------------------------------------------------------

    def _publish_loop(self):
        while not self._stop.is_set():
            snapshot = self._collector.snapshot()
            self._decorate(snapshot)
            payload = json.dumps(snapshot, sort_keys=True)
            with self._cond:
                self._snapshot = snapshot
                self._snapshot_json = payload
                self._version += 1
                self._cond.notify_all()
            self._stop.wait(self._poll)

    def _decorate(self, snapshot):
        """Add web-level fields WITHOUT touching any E1 traffic field."""
        snapshot["monitor_started_at"] = self.started_iso
        snapshot["snapshot_generated_at"] = snapshot.get("generated_at")
        stale = bool(snapshot.get("stale"))
        snapshot["api_status"] = "STALE" if stale else "CONNECTED"
        alive = bool(self._consumer_thread is not None
                     and self._consumer_thread.is_alive())
        snapshot["web_status"] = "HEALTHY" if alive else "STALE"
        snapshot["collector_uptime_seconds"] = round(
            self._clock() - self.started_at, 3)

    # -- readers -------------------------------------------------------------

    def snapshot(self):
        with self._cond:
            return self._snapshot

    def snapshot_json(self):
        with self._cond:
            return self._version, self._snapshot_json

    def wait_for_snapshot(self, timeout=10.0):
        with self._cond:
            if self._snapshot_json is None:
                self._cond.wait_for(
                    lambda: self._snapshot_json is not None, timeout=timeout)
            return self._snapshot_json is not None

    def subscribe(self, after_version=0):
        """Yield ``(version, json)`` per published snapshot.

        Always yields the LATEST version (slow readers skip, never queue).
        Ends when the broker stops; a browser disconnect simply closes the
        generator and never touches the collector.
        """
        version = after_version
        while not self._stop.is_set():
            with self._cond:
                if self._version <= version:
                    self._cond.wait_for(
                        lambda: self._version > version or self._stop.is_set(),
                        timeout=SUBSCRIBER_IDLE_WAIT)
                if self._version <= version:
                    continue
                version = self._version
                payload = self._snapshot_json
            yield version, payload
