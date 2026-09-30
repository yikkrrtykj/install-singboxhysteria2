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
* **Lifecycle.** Activation pins a ONE-WAY floor (no v3-era backfill) and
  the discovery gate at the same value; five complete buckets *after the
  discovery floor* enable the first analysis; only ``status ==
  "incident"`` opens a row, in the SAME transaction as the runtime
  pointer, so a crash can never leave a dangling one. The open row updates
  IN PLACE with ONE consistent snapshot of THIS cycle's ``detect()``:
  ``analysis_start_epoch`` stays frozen at open, ``category`` is exactly
  what the current classification says (no lattice, no sticky
  attribution -- a fail-closed ``insufficient_evidence`` genuinely
  replaces an earlier ``reality_tcp_path``), and a write is skipped ONLY
  when this cycle evaluated the same complete bucket as the persisted row
  AND every snapshot field matches. A clean tail closes ``clean_buckets``
  by settling the CURRENT cycle's verdict (its category, bits, window end
  and bucket count), never the previous row's. A window past
  ``MAX_ANALYSIS_BUCKETS`` closes ``window_limit`` FAIL-CLOSED from the
  row's own last successful snapshot and then enters the ``rearm`` gate:
  automatic discovery stops until an operator re-arms it (``rearm`` is a
  normal phase, not a failure). One quiet bucket before a second cluster
  stays ONE operational lifecycle: the classifier's
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
PHASE_REARM = "rearm"
PHASE_DEGRADED = "degraded"

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


def _rearm_flag(value):
    """The §8.3 rearm gate's closed validation: exactly an int 0 or 1
    (never a bool). None means the runtime-state row is not the shape this
    module was written for -- the scanner then stays dark or fails closed
    with the closed corrupt-state code; it never guesses the gate."""
    if type(value) is int and value in (0, 1):
        return value == 1
    return None


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
        # A cache of the store's durable rearm gate (§8.3), refreshed from
        # every cycle's snapshot; the store, never this field, is authority.
        self._rearm_required = False
        # Whether the newest cycle was held back by the discovery gate
        # (§8): a restart keeps the persisted evaluation state until its
        # own first cycle says otherwise, so a dark/pre-activation scanner
        # and a re-warming one both report warmup.
        self._warmup_gated = True
        # A cache of the store's durable discovery floor (§8.2), refreshed
        # from every cycle's snapshot and moved by a close in the same
        # cycle that settled it; the store, never this field, is authority.
        self._discovery_floor_epoch = None

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
        scanner stays dark. The §8.3 gates (discovery floor, rearm) are
        READ here, never written: activation cannot un-learn a rearm
        demand, so a restart keeps whatever the store settled. R3 §5.1
        adds a shape wall (an activated state with no discovery floor is
        corrupt, so the scanner stays dark instead of falling back), and
        R3 §8.2 derives the reported phase from those gates and the grid
        position instead of assuming it."""
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
        rearm = _rearm_flag(state.get("rearm_required"))
        if rearm is None:
            return False
        activation = _epoch(state.get("activation_floor_epoch"))
        if activation is None or activation <= 0.0:
            return False  # no floor landed: dark, and never an assumed one
        discovery = _epoch(state.get("discovery_floor_epoch"))
        if not rearm and discovery is None:
            # R3 §5.1: an activated state that carries no discovery floor is
            # CORRUPT. It never falls back to the activation floor here
            # either -- the scanner stays DARK rather than re-admitting the
            # wider history the lost gate had excluded.
            return False
        with self._lock:
            self._enabled = True
            self._rearm_required = rearm
            self._last_cycle_failed = False
            self._last_error_code = None
            end = _epoch(state.get("last_evaluated_end_epoch"))
            self._last_evaluated_end_epoch = \
                end if (end is not None and end > 0.0) else None
            self._discovery_floor_epoch = discovery
            # R3 §8.2: the phase is DERIVED from the durable gate and the
            # grid position, never assumed from what a previous process
            # happened to do -- a restart in the middle of a post-clean
            # warmup reports warmup BEFORE its first cycle. rearm owns its
            # own phase (§8.3), so it is not read as warmup here.
            self._warmup_gated = not rearm and self._warming(
                discovery, self._last_complete_end(activation))
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
        gate = self._discovery_gate(state)
        rfs = self._derive_rfs(state.get("reader_fresh_since_epoch"))
        last_end = self._last_complete_end(floor)
        if last_end is None:
            with self._lock:
                self._warmup_gated = True
            self._mark(None, rfs, state)
            return
        open_row = snapshot.get("open_incident")
        if open_row is not None and not isinstance(open_row, dict):
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        if open_row is not None:
            evaluated = self._open_cycle(open_row, last_end, rfs)
        elif gate is None:
            # §8.3 rearm: the thread keeps running and continuity stays
            # honest, but nothing is classified -- an outage period that
            # outlived its frozen window must not become a new baseline.
            evaluated = None
        else:
            evaluated = self._discovery_cycle(gate, last_end, rfs)
        with self._lock:
            # R3 §8.2: the phase is DERIVED from the durable gate as it
            # stands AFTER this cycle, not from what the cycle happened to
            # write. A clean close moved the floor to its own signal end in
            # the store's transaction, so this very cycle already reports
            # warmup; a window-limit close raised rearm, which owns its own
            # phase.
            self._warmup_gated = not self._rearm_required and self._warming(
                self._discovery_floor_epoch, last_end)
        self._mark(evaluated, rfs, state)

    def _warming(self, gate, last_end):
        """ONE predicate for §8's discovery gate: automatic discovery is
        held back until the last ``DISCOVERY_BUCKETS`` window lies wholly
        at or after the durable gate. A missing gate or a grid with no
        complete bucket yet warms up fail-closed."""
        if gate is None or last_end is None:
            return True
        return last_end - DISCOVERY_BUCKETS * BUCKET_SECONDS < gate

    def _discovery_gate(self, state):
        """The discovery gate (§8's warmup floor plus the §8.3 rearm gate),
        read from the store every cycle: ``rearm_required`` stops
        automatic discovery (None), otherwise the durable
        ``discovery_floor_epoch`` bounds warmup.

        R3 §5.1: an activated state with NO discovery floor is corrupt and
        aborts the cycle. It never falls back to the one-way activation
        floor -- a state the runtime cannot prove must not re-open the
        wider history that the lost gate had excluded, which would be the
        opposite of fail-closed."""
        rearm = _rearm_flag(state.get("rearm_required"))
        if rearm is None:
            raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
        discovery_floor = _epoch(state.get("discovery_floor_epoch"))
        with self._lock:
            self._rearm_required = rearm
            if not rearm:
                if discovery_floor is None:
                    raise _CycleAbort(ERROR_RUNTIME_STATE_CORRUPT)
                self._discovery_floor_epoch = discovery_floor
        return None if rearm else discovery_floor

    # -- stage: discovery (IDLE) ---------------------------------------------

    def _discovery_cycle(self, gate, last_end, rfs):
        """IDLE: analyze the last DISCOVERY_BUCKETS complete buckets;
        only an ``incident`` verdict opens a row. Returns the evaluated
        window end, or None while still warming up -- and after a clean
        close warmup means five complete buckets AFTER the signal end, so
        the three just-closed clean buckets become this segment's trusted
        baseline before any new row can open."""
        window_start = last_end - DISCOVERY_BUCKETS * BUCKET_SECONDS
        if self._warming(gate, last_end):
            return None  # warmup: the window is not trusted yet
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
        """OPEN: extend the frozen window to the newest complete bucket and
        settle THIS cycle's verdict in place; close on a clean tail or a
        window limit. Returns the evaluated window end, or None on a
        window-limit close (the over-long window is refused, not
        analyzed)."""
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
        category = classification.category
        bits = self._encode_bits(classification)
        indices = detection.anomaly_bucket_indices
        clean_tail = all(i < count - CLOSE_CLEAN_BUCKETS for i in indices)
        last_signal = self._advance_last_signal(row, detection, indices)
        if clean_tail:
            self._close_clean(row, category, bits, last_signal,
                              last_end, count)
            return last_end
        if self._unchanged(row, category, last_signal, last_end, count, bits):
            return last_end  # §8: same bucket, same verdict, no write
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

    def _close_clean(self, row, category, bits, last_signal, last_end,
                     count):
        """Three consecutive clean tail buckets: the terminal write
        SETTLES THIS cycle's ``detect()`` -- its category and bitsets, this
        window end and bucket count -- never the previous row's (§8.2). The
        CLOSED row is therefore the consistent snapshot of the last real
        classification, and the discovery gate moves in the same store
        transaction."""
        evidence_bits, unknown_bits = bits
        try:
            landed = self._history.incident_close_window(
                row["incident_id"], category, last_signal, last_end,
                count, evidence_bits, unknown_bits, _CLOSURE_CLEAN_BUCKETS)
        except Exception:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        if not landed:
            raise _CycleAbort(ERROR_PERSIST_FAILED)
        with self._lock:
            self._open_incident_id = None
            # R3 §8.2: mirror the gate the store moved in the SAME
            # transaction, exactly as §8.3 mirrors rearm -- the closed
            # row's clean tail is the NEXT segment's baseline, so discovery
            # is held back from THIS cycle, not from the next one.
            self._discovery_floor_epoch = last_signal

    def _close_window_limit(self, row):
        """The frozen window outgrew MAX_ANALYSIS_BUCKETS: fail CLOSED from
        the row's own LAST SUCCESSFUL snapshot -- this cycle never
        classified, so there is no current verdict to settle and inventing
        one would fabricate a bucket (§8.2, §16-11). The evaluated end does
        NOT advance and the gate flips to ``rearm`` in the same store
        transaction."""
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
            # Mirror the gate the store just raised in the SAME
            # transaction, so the phase this cycle reports is already the
            # persisted one; the next cycle re-reads it from the store.
            self._rearm_required = True
            self._discovery_floor_epoch = None

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

    def _unchanged(self, row, category, last_signal, last_end, count, bits):
        """§8/§8.1: no-write is a GENERATION test, not a verdict test.
        It holds only when this cycle evaluated the same complete bucket
        the row was last classified on AND every snapshot field matches
        -- so the 30 s cadence re-scanning one bucket stays quiet, while
        a genuinely newer bucket always advances
        ``last_classified_end_epoch`` and ``buckets`` even on a
        byte-identical verdict."""
        evidence_bits, unknown_bits = bits
        return (count == row.get("buckets")
                and last_end == _epoch(row.get("last_classified_end_epoch"))
                and category == row.get("category")
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
        # rearm dominates idle (§8.3): it is a NORMAL phase -- no failure
        # counter, no error code -- that only says automatic discovery is
        # durably stopped until an operator re-arms it.
        if self._rearm_required:
            return PHASE_REARM
        if self._warmup_gated:
            return PHASE_WARMUP
        return PHASE_IDLE
