"""Incident runtime -- issue #33 Phase 4, PR-4B
(docs/monitor-v2-incident-runtime-p4b.md).

The classifier's ONLY runtime consumer: one dedicated daemon thread turns
persisted, already-sanitized evidence into a bounded, deduplicated,
recoverable incident lifecycle. The classifier itself stays pure (no clock,
no I/O); this module is where the clock lives, and the single-consumer
allowlist in the classify lane is the gate that keeps it the only one.

Contract (frozen, all enforced, all tested):

* **Frozen constants.** The six module constants below are the ONLY numeric
  analysis thresholds; every bucket computation goes through the
  classifier's own exported names (``BUCKET_SECONDS``,
  ``MIN_BASELINE_BUCKETS``, ``MAX_BUCKETS``) -- the runtime has no second
  threshold algorithm. (The ``+ 3.0`` / ``0.5`` courtesy bounds in ``stop``
  mirror the probe scheduler's join bound; they are not analysis
  thresholds.)
* **Lifecycle.** Activation pins a ONE-WAY floor (no v3-era backfill); five
  complete buckets after the floor enable the first analysis; only
  ``status == "incident"`` opens a row, in the SAME transaction as the
  runtime pointer, so a crash can never leave a dangling one. The open row
  updates IN PLACE: ``analysis_start_epoch`` stays frozen at open,
  ``category`` broadens only along the §8.1 lattice, and a cycle with no
  material change writes nothing. Three consecutive clean tail buckets close
  ``clean_buckets`` with ``last_signal_epoch`` kept at the last anomalous
  bucket end; a window past ``MAX_ANALYSIS_BUCKETS`` closes
  ``window_limit`` FAIL-CLOSED from the row's own accumulated values (no
  new classification). One quiet bucket before a second cluster stays ONE
  operational lifecycle: the classifier's
  ``insufficient_evidence + multiple_anomaly_clusters`` verdict updates the
  same row and never splits it.
* **Reader continuity (G8).** Every ``start()`` BREAKS continuity: a fresh
  heartbeat restarts it at the activation floor, anything else leaves it
  NULL. While running, a non-fresh heartbeat clears it and a recovery from
  NULL stamps THIS observation moment -- never earlier -- so later
  freshness can never retroactively repair settled journal negatives. The
  bundle projection is ``fresh`` only when the heartbeat is fresh AND
  continuity exists AND it begins at or before the window start.
* **Absolute containment (§11).** A cycle's defects never travel outward:
  any failure becomes one closed counter and one closed ``last_error_code``
  from the four-token vocabulary; the next cadence tick is normal. The
  broker, probe scheduler, journal ingest and web threads are never
  delayed, and this thread is a daemon like the probe scheduler's. The
  stage code is honest: read refusals are ``evidence_read_failed``,
  classifier/encoding defects ``classify_failed``, write refusals
  ``persist_failed``, and a corrupt runtime-state shape (or a defect that
  escapes every stage guard) ``runtime_state_corrupt``.
* **Crash idempotence.** Every cycle re-reads the runtime-state snapshot,
  so a restart with an open incident continues the SAME ``incident_id``
  (the pointer lives in the store, not in this object); the partial unique
  index plus single-transaction writes make a mid-close crash settle on
  either side cleanly. Activation and the initial continuity mark happen
  before the thread spawns: a store that refuses either leaves the scanner
  DARK (no thread, zero cycles, ``enabled`` false), mirroring the probe
  scheduler's failed-injection dark start.
"""

from __future__ import annotations

import math
import threading
import time

from web import incident_classifier as ic

# The six frozen constants (§2). Bucketing facts are REFERENCED from the
# classifier, never rewritten: one definition of the bucket grid.
BUCKET_SECONDS = ic.BUCKET_SECONDS
SCAN_INTERVAL_SECONDS = 30
BUCKET_GRACE_SECONDS = 15
DISCOVERY_BUCKETS = 5
CLOSE_CLEAN_BUCKETS = 3
MAX_ANALYSIS_BUCKETS = ic.MAX_BUCKETS

# The closed four-token error vocabulary (§11): no exception text, no
# paths, no stack -- the code IS the whole message.
ERROR_EVIDENCE_READ_FAILED = "evidence_read_failed"
ERROR_CLASSIFY_FAILED = "classify_failed"
ERROR_PERSIST_FAILED = "persist_failed"
ERROR_RUNTIME_STATE_CORRUPT = "runtime_state_corrupt"

PHASE_WARMUP = "warmup"
PHASE_IDLE = "idle"
PHASE_OPEN = "open"
PHASE_DEGRADED = "degraded"

# §8.1 frozen broadening lattice: edges point UP only. A same-level or
# downward verdict keeps the persisted category, so a terminal write can
# never narrow what the incident already claimed.
_CATEGORY_LATTICE = {
    ic.CATEGORY_INSUFFICIENT: frozenset((
        ic.CATEGORY_COMMON_INBOUND,
        ic.CATEGORY_HY2_UDP,
        ic.CATEGORY_REALITY_TCP,
        ic.CATEGORY_VPS_OUTBOUND,
        ic.CATEGORY_VPS_PROCESS,
    )),
    ic.CATEGORY_REALITY_TCP: frozenset((ic.CATEGORY_VPS_OUTBOUND,)),
    ic.CATEGORY_HY2_UDP: frozenset((ic.CATEGORY_VPS_OUTBOUND,)),
    ic.CATEGORY_COMMON_INBOUND: frozenset((ic.CATEGORY_VPS_OUTBOUND,)),
}

# The conservative non-fresh projection token (§9.3); the store's bundle
# gate validates it, an invalid token refuses the read fail-closed.
_READER_PROJECTION_STALE = "stale"
_READER_HB_FRESH = "fresh"

_CLOSURE_CLEAN_BUCKETS = "clean_buckets"
_CLOSURE_WINDOW_LIMIT = "window_limit"


class _CycleAbort(Exception):
    """Internal containment token: carries ONLY the closed error code."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _epoch(value):
    """The scanner-side epoch validation, mirroring the store boundary:
    exactly a plain finite non-negative int/float (never a bool)."""
    if type(value) not in (int, float) or not math.isfinite(value):
        return None
    if value < 0:
        return None
    return float(value)


def _broaden(persisted, incoming):
    """§8.1: a category may move UP along the lattice only; anything else
    (same level, downward, unknown token) keeps the persisted value."""
    if type(persisted) is not str or type(incoming) is not str:
        return persisted
    if incoming == persisted:
        return persisted
    if incoming in _CATEGORY_LATTICE.get(persisted, frozenset()):
        return incoming
    return persisted


class IncidentScanner:
    """One daemon thread driving bounded incident scan cycles.

    Every public method never raises. The scanner holds no storage state
    of its own and persists nothing directly -- the history store is the
    single sink, and the scan thread is the only writer of the runtime
    state row, so restart continuation is a read, never a repair.
    """

    def __init__(self, history,
                 scan_interval_seconds=SCAN_INTERVAL_SECONDS,
                 clock=time.time):
        self._history = history
        self._clock = clock
        self._interval = (float(scan_interval_seconds)
                          if isinstance(scan_interval_seconds, (int, float))
                          and not isinstance(scan_interval_seconds, bool)
                          and float(scan_interval_seconds) > 0
                          else SCAN_INTERVAL_SECONDS)
        self._stop = threading.Event()
        # RLock: start() holds the lock across _activate(), which caches
        # activation state under the same lock (start is the only caller).
        self._lock = threading.RLock()
        self._thread = None
        self._enabled = False
        self._cycles_completed = 0
        self._cycles_failed = 0
        self._last_error_code = None
        self._last_cycle_failed = False
        self._last_evaluated_end_epoch = None
        self._open_incident_id = None

    # -- lifecycle -----------------------------------------------------------

    def start(self):
        """Activate the one-way floor and spawn the scan thread;
        idempotent. A store that refuses activation or the initial
        continuity mark leaves the scanner DARK -- no thread, zero
        cycles -- with ``enabled`` false in ``status()``."""
        with self._lock:
            if self._thread is not None or self._stop.is_set():
                return
            if not self._activate():
                return
            self._thread = threading.Thread(
                target=self._guarded_loop, name="monitor-incidents",
                daemon=True)
            self._thread.start()

    def stop(self, join_timeout=None):
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None and thread.is_alive():
            timeout = (self._interval + 3.0) if join_timeout is None \
                else float(join_timeout)
            thread.join(timeout=max(0.5, timeout))

    def _activate(self):
        """The one-way floor plus the §9 restart-continuity break, written
        before the thread exists: fresh heartbeat -> continuity restarts AT
        the floor, anything else -> NULL. Never raises; False means the
        scanner stays dark."""
        try:
            now = self._clock()
            floor = math.ceil(now / BUCKET_SECONDS) * BUCKET_SECONDS
            if not self._history.incident_activate(floor):
                return False
            snapshot = self._read_snapshot()
            state = snapshot["state"]
            hb = self._reader_hb()
            rfs = floor if hb == _READER_HB_FRESH else None
            if not self._history.incident_runtime_mark(
                    state["last_evaluated_end_epoch"], rfs):
                return False
        except Exception:  # noqa: BLE001 -- dark-start containment
            return False
        with self._lock:
            self._enabled = True
            self._last_cycle_failed = False
            self._last_error_code = None
            end = _epoch(state.get("last_evaluated_end_epoch"))
            self._last_evaluated_end_epoch = \
                end if (end is not None and end > 0.0) else None
            open_id = state.get("open_incident_id")
            self._open_incident_id = open_id \
                if type(open_id) is int and not isinstance(open_id, bool) \
                and open_id >= 1 else None
        return True

    # -- cycle loop ----------------------------------------------------------

    def _guarded_loop(self):
        # Absolute containment line, mirroring the probe scheduler's
        # write-alongside discipline: nothing from a scan cycle may
        # travel outward on this thread's stack toward anything else in
        # the process. Runtime defects become closed counters only.
        while not self._stop.is_set():
            if self._stop.wait(self._interval):
                return
            try:
                self.run_once()
            except Exception:  # noqa: BLE001 -- runtime plane, counter only
                self._note_failure(ERROR_RUNTIME_STATE_CORRUPT)

    def run_once(self):
        """One bounded scan cycle. Never raises; a failure becomes a
        closed counter and the closed ``last_error_code`` only, and the
        next tick is a normal cycle."""
        if not self._enabled:
            return
        try:
            self._run_one_cycle()
        except _CycleAbort as abort:
            self._note_failure(abort.code)
        except Exception:  # noqa: BLE001 -- absolute containment (§11)
            self._note_failure(ERROR_RUNTIME_STATE_CORRUPT)
        else:
            self._note_success()

    def _run_one_cycle(self):
        snapshot = self._read_snapshot()
        state = snapshot["state"]
        floor = _epoch(state.get("activation_floor_epoch"))
        if floor is None or floor <= 0.0:
            return  # inert row: activation has not landed (not a failure)
        rfs = self._derive_rfs(state.get("reader_fresh_since_epoch"))
        last_end = self._last_complete_end(floor)
        if last_end is None:
            self._mark(None, rfs, state)
            return
        open_row = snapshot.get("open_incident")
        if open_row is not None and not isinstance(open_row, dict):
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        if open_row is None:
            evaluated = self._discovery_cycle(floor, last_end, rfs)
        else:
            evaluated = self._open_cycle(open_row, last_end, rfs)
        self._mark(evaluated, rfs, state)

    # -- stage: discovery (IDLE) ---------------------------------------------

    def _discovery_cycle(self, floor, last_end, rfs):
        """IDLE: analyze the last DISCOVERY_BUCKETS complete buckets;
        only an ``incident`` verdict opens a row. Returns the evaluated
        window end, or None while still warming up."""
        if last_end - floor < DISCOVERY_BUCKETS * BUCKET_SECONDS:
            return None  # warmup: not enough complete buckets to analyze
        window_start = last_end - DISCOVERY_BUCKETS * BUCKET_SECONDS
        detection = self._detect(window_start, last_end, rfs)
        classification = detection.classification
        if classification.status != ic.STATUS_INCIDENT:
            return last_end
        evidence_bits, unknown_bits = self._encode_bits(classification)
        analysis_start = (detection.first_signal_epoch
                          - ic.MIN_BASELINE_BUCKETS * BUCKET_SECONDS)
        incident_id = self._open_row(
            classification.category, analysis_start,
            detection.first_signal_epoch, detection.last_signal_epoch,
            last_end, evidence_bits, unknown_bits)
        with self._lock:
            self._open_incident_id = incident_id
        return last_end

    # -- stage: open lifecycle ------------------------------------------------

    def _open_cycle(self, row, last_end, rfs):
        """OPEN: extend the frozen window to the newest complete bucket;
        broaden in place, close on a clean tail or a window limit.
        Returns the evaluated window end, or None on a window-limit
        close (the over-long window is refused, not analyzed)."""
        window_start = _epoch(row.get("analysis_start_epoch"))
        if window_start is None:
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        count = int(round((last_end - window_start) / BUCKET_SECONDS))
        if count < 1:
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        if count > MAX_ANALYSIS_BUCKETS:
            self._close_window_limit(row)
            return None
        detection = self._detect(window_start, last_end, rfs)
        classification = detection.classification
        bits = self._encode_bits(classification)
        indices = detection.anomaly_bucket_indices
        clean_tail = all(i < count - CLOSE_CLEAN_BUCKETS for i in indices)
        last_signal = self._advance_last_signal(row, detection, indices)
        if clean_tail:
            self._close_clean(row, count, last_signal, last_end)
            return last_end
        category = _broaden(row.get("category"), classification.category)
        if self._unchanged(row, category, last_signal, bits):
            return last_end  # §8: no material change, no write
        evidence_bits, unknown_bits = bits
        try:
            landed = self._history.incident_update_window(
                row["incident_id"], category, last_signal, last_end, count,
                evidence_bits, unknown_bits)
        except Exception:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if not landed:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        return last_end

    def _close_clean(self, row, count, last_signal, last_end):
        """Three consecutive clean tail buckets: close with the row's own
        accumulated attribution (a terminal write never re-narrows), the
        evaluated end advanced to this window."""
        evidence_bits, unknown_bits = self._row_bits(row)
        try:
            landed = self._history.incident_close_window(
                row["incident_id"], row["category"], last_signal, last_end,
                count, evidence_bits, unknown_bits, _CLOSURE_CLEAN_BUCKETS)
        except Exception:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if not landed:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        with self._lock:
            self._open_incident_id = None

    def _close_window_limit(self, row):
        """The frozen window outgrew MAX_ANALYSIS_BUCKETS: fail CLOSED
        from the row's own accumulated values -- no new classification,
        no category motion (§8, §16-11). The evaluated end does NOT
        advance: this window was refused, not analyzed."""
        evidence_bits, unknown_bits = self._row_bits(row)
        last_signal = _epoch(row.get("last_signal_epoch"))
        classified_end = _epoch(row.get("last_classified_end_epoch"))
        buckets = row.get("buckets")
        if last_signal is None or classified_end is None \
                or type(buckets) is not int or isinstance(buckets, bool):
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        try:
            landed = self._history.incident_close_window(
                row["incident_id"], row["category"], last_signal,
                classified_end, buckets, evidence_bits, unknown_bits,
                _CLOSURE_WINDOW_LIMIT)
        except Exception:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if not landed:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        with self._lock:
            self._open_incident_id = None

    # -- stage helpers ---------------------------------------------------------

    def _detect(self, window_start, window_end, rfs):
        """The §9.3 conservative projection: the bundle reader status is
        fresh only when continuity exists and begins at or before the
        window start; every journal negative the classifier settles on
        then has a positively proven witness window."""
        reader_status = (_READER_HB_FRESH
                         if (rfs is not None and rfs <= window_start)
                         else _READER_PROJECTION_STALE)
        try:
            bundle = self._history.classifier_bundle(
                window_start, window_end, reader_status)
        except Exception:
            raise _CycleAbort(ERROR_EVIDENCE_READ_FAILED)
        if bundle is None:
            raise _CycleAbort(ERROR_EVIDENCE_READ_FAILED)
        try:
            return ic.detect(bundle)
        except Exception:
            raise _CycleAbort(ERROR_CLASSIFY_FAILED)

    def _encode_bits(self, classification):
        evidence_bits = ic.evidence_to_bits(classification.evidence)
        unknown_bits = ic.unknown_to_bits(classification.unknowns)
        if evidence_bits is None or unknown_bits is None:
            raise _CycleAbort(ERROR_CLASSIFY_FAILED)
        return evidence_bits, unknown_bits

    def _open_row(self, category, analysis_start, first_signal, last_signal,
                  last_end, evidence_bits, unknown_bits):
        try:
            incident_id = self._history.incident_open_window(
                category, analysis_start, first_signal, last_signal,
                last_end, DISCOVERY_BUCKETS, evidence_bits, unknown_bits)
        except Exception:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if type(incident_id) is not int or isinstance(incident_id, bool):
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        return incident_id

    def _advance_last_signal(self, row, detection, indices):
        """No new anomaly -> keep the persisted last-anomaly end; a new
        anomaly -> the later of the two (a clock skew can never move the
        signal end backward)."""
        persisted = _epoch(row.get("last_signal_epoch"))
        if persisted is None:
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        if not indices:
            return persisted
        advanced = _epoch(detection.last_signal_epoch)
        if advanced is None:
            raise _CycleAbort(ERROR_CLASSIFY_FAILED)
        return max(persisted, advanced)

    def _unchanged(self, row, category, last_signal, bits):
        evidence_bits, unknown_bits = bits
        return (category == row.get("category")
                and last_signal == _epoch(row.get("last_signal_epoch"))
                and evidence_bits == row.get("evidence_bits")
                and unknown_bits == row.get("unknown_bits"))

    def _row_bits(self, row):
        evidence_bits = row.get("evidence_bits")
        unknown_bits = row.get("unknown_bits")
        if type(evidence_bits) is not int or isinstance(evidence_bits, bool) \
                or type(unknown_bits) is not int \
                or isinstance(unknown_bits, bool):
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        return evidence_bits, unknown_bits

    def _reader_hb(self):
        """The heartbeat-derived reader token (never raises through the
        store boundary). A missing or malformed token is NOT fresh: the
        continuity derivation then clears continuity fail-closed."""
        try:
            status = self._history.journal_status()
        except Exception:
            raise _CycleAbort(ERROR_EVIDENCE_READ_FAILED)
        reader = status.get("reader") if isinstance(status, dict) else None
        token = reader.get("status") if isinstance(reader, dict) else None
        return token if type(token) is str else None

    def _derive_rfs(self, persisted):
        """§9.2 while running: a non-fresh heartbeat clears continuity; a
        recovery from NULL stamps THIS observation moment (never
        retroactive); an unbroken continuity is kept as-is."""
        hb = self._reader_hb()
        if hb != _READER_HB_FRESH:
            return None
        existing = _epoch(persisted)
        if existing is None:
            return self._clock()
        return existing

    def _last_complete_end(self, floor):
        """The newest bucket end at or below the grace-adjusted clock,
        aligned on the floor's grid; None before the first complete
        bucket after the floor."""
        now = self._clock()
        latest = floor + BUCKET_SECONDS * math.floor(
            (now - BUCKET_GRACE_SECONDS - floor) / BUCKET_SECONDS)
        if latest < floor + BUCKET_SECONDS:
            return None
        return latest

    def _mark(self, evaluated_end, rfs, state):
        """Persist the per-cycle advance: how far the window was
        evaluated (the persisted value when this cycle evaluated
        nothing) and where reader continuity currently begins. The open
        pointer is deliberately not a parameter: it only moves inside
        the open/close transactions."""
        persisted_end = _epoch(state.get("last_evaluated_end_epoch"))
        if persisted_end is None:
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        end = persisted_end if evaluated_end is None else evaluated_end
        try:
            landed = self._history.incident_runtime_mark(end, rfs)
        except Exception:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if not landed:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if evaluated_end is not None:
            with self._lock:
                self._last_evaluated_end_epoch = evaluated_end

    def _read_snapshot(self):
        try:
            snapshot = self._history.incident_runtime_snapshot()
        except Exception:
            raise _CycleAbort(ERROR_EVIDENCE_READ_FAILED)
        if not isinstance(snapshot, dict) \
                or not isinstance(snapshot.get("state"), dict):
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        return snapshot

    # -- bookkeeping -----------------------------------------------------------

    def _note_success(self):
        with self._lock:
            self._cycles_completed += 1
            self._last_cycle_failed = False
            self._last_error_code = None

    def _note_failure(self, code):
        with self._lock:
            self._cycles_failed += 1
            self._last_cycle_failed = True
            self._last_error_code = code

    # -- read surface ----------------------------------------------------------

    def status(self):
        """The closed 8-key status object (§12): no categories, no
        windows, no exception text -- counters, tokens and bools only.
        Never raises."""
        with self._lock:
            running = (self._thread is not None
                       and self._thread.is_alive()
                       and not self._stop.is_set())
            return {
                "enabled": bool(self._enabled),
                "running": running,
                "phase": self._phase(),
                "cycles_completed": int(self._cycles_completed),
                "runtime_failures": int(self._cycles_failed),
                "last_error_code": self._last_error_code,
                "last_evaluated_end_epoch": self._last_evaluated_end_epoch,
                "open_incident": self._open_incident_id is not None,
            }

    def _phase(self):
        # degraded dominates (§12): the last cycle failed with no success
        # since; a dark scanner never activated, so it reports the
        # pre-analysis phase and zero counters.
        if not self._enabled:
            return PHASE_WARMUP
        if self._last_cycle_failed:
            return PHASE_DEGRADED
        if self._open_incident_id is not None:
            return PHASE_OPEN
        if self._last_evaluated_end_epoch is None:
            return PHASE_WARMUP
        return PHASE_IDLE
