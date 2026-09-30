#!/usr/bin/env python3
"""PR-4B incident-runtime harness (issue #33 Phase 4) -- behaviour groups.

Every group returns a flat dict of BOOLEAN verdicts that the shell lane
turns into counted gates, exactly like the PR-4A classifier harness. Nothing
here prints from inside a group, and a crash is reported by the runner as a
FAIL instead of escaping green.

What this harness owns (docs/monitor-v2-incident-runtime-p4b.md §16): the
SCANNER's lifecycle, the reader-continuity protocol, the containment wall,
the incident persistence plane's own refusals, and the closed observability
surface. The classifier's verdicts are NOT re-litigated here -- that is the
classify lane's job (gate 18 of §16 is literally "the classify lane stays
green"), and this file only ever asks the classifier what the scanner would
have seen.

Two construction idioms are used deliberately:

* **canned evidence, real store** (groups lifecycle/continuity/containment):
  the scanner's evidence READ plane is swapped for a known bundle, while the
  persistence plane is a REAL schema-v4 SQLite database. That isolates the
  state machine from the reader, which the store group already proves on its
  own.
* **nothing canned** (group end_to_end): a real store published through the
  live history module, read back through the real ``classifier_bundle``
  reader, classified by the real ``detect``, written by the real scanner. A
  lifecycle that only ever worked against a stub is not the lifecycle that
  ships.

``classify_groups`` is imported on purpose: the scenario bundles and the
store builders are the shared artefacts of issue #33 Phase 4, and reusing
them means the runtime lane cannot quietly drift onto evidence the classifier
lane never reviewed. If that file changes, the classifier lane's own
fixture-match gate goes red first.
"""

from __future__ import annotations

import http.client
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "monitor-classify"))

import classify_groups as cg  # noqa: E402
from web import incident_classifier as ic  # noqa: E402
from web import incident_history as ih  # noqa: E402
from web import incident_runtime as ir  # noqa: E402

BASE = cg.BASE              # 1700000400: an exact multiple of 60
BUCKET = cg.BUCKET          # 60.0
SENTINEL = cg.LEAK_PROBES   # identity material that must never be persisted

SCEN = {entry[0]: entry[1] for entry in cg.scenarios()}

PASSWORD = "p4b-runtime-password-0"

# The frozen §2 constant table, restated as literals here (a second witness
# written by a different hand than the module).
FROZEN_CONSTANTS = {
    "BUCKET_SECONDS": 60,
    "SCAN_INTERVAL_SECONDS": 30,
    "BUCKET_GRACE_SECONDS": 15,
    "DISCOVERY_BUCKETS": 5,
    "CLOSE_CLEAN_BUCKETS": 3,
    "MAX_ANALYSIS_BUCKETS": 60,
}
FROZEN_ERRORS = ("evidence_read_failed", "classify_failed", "persist_failed",
                 "runtime_state_corrupt")
FROZEN_PHASES = ("warmup", "idle", "open", "rearm", "degraded")
FROZEN_V4_TABLES = {"meta", "timeline_samples", "device_protocol_states",
                    "network_probe_samples", "journal_runs", "journal_events",
                    "journal_ingest_audit", "journal_ingest_state",
                    "incident_windows", "incident_runtime_state"}


# -- harness plumbing --------------------------------------------------------

def _store_dir(**kw):
    """One REAL schema-v4 store over a private temp root."""
    root = tempfile.mkdtemp(prefix="p4b-ir-")
    clock = [BASE]
    exchange = os.path.join(root, "out")
    os.makedirs(exchange)
    history = ih.IncidentHistory(os.path.join(root, "diagnostics"),
                                 SENTINEL[0],
                                 clock=lambda: clock[0],
                                 journal_exchange_dir=exchange, **kw)
    history.open()
    return history, root, clock


def _drop(root):
    shutil.rmtree(root, ignore_errors=True)


class Canned:
    """The scanner's view of the store during state-machine tests.

    Only the two EVIDENCE reads are canned; every incident-plane write goes
    to the real store underneath. ``_seen`` records the reader status the
    scanner supplied for each window, which is how the §9 continuity
    projections are observed rather than assumed.
    """

    def __init__(self, real, bundle=None, reader="fresh"):
        self._real = real
        self._bundle = bundle
        self._reader = reader
        self._raise = set()
        self._refuse = set()
        self._seen = []

    def classifier_bundle(self, window_start, window_end, reader_status):
        self._seen.append((window_start, window_end, reader_status))
        if "classifier_bundle" in self._raise:
            raise RuntimeError("injected evidence read fault")
        if "classifier_bundle" in self._refuse:
            return None
        if callable(self._bundle):
            # A live-evidence fixture: the read is built for the window the
            # scanner actually asked about (see _continuing_outage).
            return self._bundle(window_start, window_end)
        return self._bundle

    def journal_status(self):
        if "journal_status" in self._raise:
            raise RuntimeError("injected heartbeat fault")
        return {"reader": {"status": self._reader}}

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        attr = getattr(self._real, name)
        if name in self._raise:
            def raiser(*args, **kwargs):
                raise RuntimeError("injected fault in %s" % name)
            return raiser
        if name in self._refuse:
            shape = {"incident_activate": False,
                     "incident_runtime_mark": False,
                     "incident_update_window": False,
                     "incident_close_window": False,
                     "incident_open_window": None,
                     "incident_runtime_snapshot": {"state": None,
                                                   "open_incident": None}}
            refusal = shape[name] if name in shape else False

            def refuser(*args, **kwargs):
                return refusal
            return refuser
        return attr


def _scanner(canned, clock):
    # A huge cadence keeps the daemon thread from ever ticking: every cycle
    # in this harness is driven explicitly through run_once().
    return ir.IncidentScanner(canned, scan_interval_seconds=3600.0,
                              clock=lambda: clock[0])


def _activate(env, floor_clock=BASE, scan_clock=BASE + 615.0):
    """Pin the floor at BASE, then stand the clock where the fixture era's
    last complete bucket ends (BASE+600), so the discovery window is
    [BASE+300, BASE+600]."""
    env["clock"][0] = floor_clock
    env["scanner"].start()
    env["clock"][0] = scan_clock


def _env(bundle=None, reader="fresh", **kw):
    history, root, clock = _store_dir(**kw)
    canned = Canned(history, bundle, reader)
    env = {"history": history, "root": root, "clock": clock, "canned": canned}
    env["scanner"] = _scanner(canned, clock)
    return env


def _close_env(env):
    try:
        env["scanner"].stop(join_timeout=0.5)
    except Exception:  # noqa: BLE001 -- teardown never decides a gate
        pass
    try:
        env["history"].close()
    except Exception:  # noqa: BLE001
        pass
    _drop(env["root"])


def _rows(history):
    cols = ih.IncidentHistory.INCIDENT_WINDOW_COLUMNS
    rows = history._conn.execute(
        "SELECT %s FROM incident_windows ORDER BY incident_id"
        % ", ".join(cols)).fetchall()
    return [dict(zip(cols, row)) for row in rows]


def _state(history):
    return history.incident_runtime_snapshot()["state"]


def _bundle_health(history):
    """The bundle's own health section -- the classifier's view of how good
    its evidence is. None if the reader itself refused."""
    bundle = history.classifier_bundle(BASE, BASE + 60.0, "fresh")
    return None if bundle is None else bundle["health"]


def _open_raw(history, category="reality_tcp_path", analysis_start=None,
              first_signal=None, last_signal=None, classified_end=None,
              buckets=5, evidence_bits=0, unknown_bits=0, state="open",
              closed_epoch=None, closure_reason=None, created=None,
              updated=None):
    """A window row written BEYOND the store boundary: exactly what a crash
    between two transactions could leave behind, and what the CHECKs and the
    partial unique index have to survive."""
    z = lambda value, default: default if value is None else value  # noqa: E731
    history._conn.execute(
        "INSERT INTO incident_windows (classifier_version, state, category,"
        " analysis_start_epoch, first_signal_epoch, last_signal_epoch,"
        " last_classified_end_epoch, closed_epoch, closure_reason, buckets,"
        " evidence_bits, unknown_bits, created_epoch, updated_epoch)"
        " VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (state, category, z(analysis_start, BASE), z(first_signal, BASE + 180),
         z(last_signal, BASE + 240), z(classified_end, BASE + 240),
         closed_epoch, closure_reason, buckets, evidence_bits, unknown_bits,
         z(created, BASE), z(updated, BASE + 1.0)))
    history._conn.commit()


def _pump_samples(history, count, start=BASE, width=0.1):
    """`count` timeline_samples rows inside [start, start+count*width)."""
    cols = ("epoch", "iso_utc", "run_id", "monitor_uptime_seconds",
            "snapshot_version", "snapshot_generated_at", "last_success_at",
            "collector_stale", "api_status", "total_active_connections",
            "reality_active_connections", "hysteria2_active_connections",
            "other_active_connections", "uplink_rate", "downlink_rate",
            "skipped_events", "duplicate_events", "identity_conflicts",
            "abandoned_on_reset")
    sql = "INSERT INTO timeline_samples (%s) VALUES (%s)" % (
        ", ".join(cols), ", ".join("?" * len(cols)))
    for index in range(count):
        history._conn.execute(sql, (start + index * width, SENTINEL[0],
                                    SENTINEL[0], 1.0, index, None, None, 0,
                                    "CONNECTED", 40, 25, 15, 0, 1.0, 2.0,
                                    0, 0, 0, 0))
    history._conn.commit()


def _bits(cls):
    return (ic.evidence_to_bits(cls.evidence),
            ic.unknown_to_bits(cls.unknowns))


def _continuing_outage():
    """A canned READ for an outage that is STILL GOING: the evidence is built
    for the window the scanner actually asks about, with the anomaly at its
    tail, so a frozen open window keeps growing instead of cleaning its own
    tail at bucket 13. The builders default to a ten-bucket ``window``
    section, so a longer span has to be told the truth about itself --
    exactly what a real reader's rows would carry.
    """
    def build(window_start, window_end):
        count = int(round((window_end - window_start) / BUCKET))
        if window_start != BASE or not 6 <= count <= ic.MAX_BUCKETS:
            return None  # refused read fails closed; never a fake verdict
        bundle = cg.reality_incident_bundle(buckets=count,
                                            drop_from=count - 3)
        bundle["window"]["end_epoch"] = float(window_end)
        return bundle
    return build


# -- group: static contract --------------------------------------------------

def group_static():
    out = {}
    import ast
    source = open(os.path.join(os.environ["MONITOR_V2_ROOT"], "web",
                               "incident_runtime.py"),
                  encoding="utf-8").read()
    tree = ast.parse(source)

    # (1) The six frozen constants, by value.
    out["constants_frozen"] = all(
        getattr(ir, name) == value for name, value in FROZEN_CONSTANTS.items())
    # (2) Bucketing facts are REFERENCED from the classifier, never rewritten:
    #     the module must not contain a second copy of the grid.
    out["bucket_grid_referenced_not_rewritten"] = (
        "BUCKET_SECONDS = ic.BUCKET_SECONDS" in source
        and "MAX_ANALYSIS_BUCKETS = ic.MAX_BUCKETS" in source)

    # (3) The numeric-literal wall (§2): the only numbers the runtime module
    #     may hold are the four remaining frozen constants, the two courtesy
    #     bounds of stop() that mirror the probe scheduler, and the 0/1
    #     validation bounds of the epoch/id checks. 60 may NOT appear: the
    #     bucket grid is a reference, so a literal 60 here would be a second
    #     algorithm.
    numbers = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            numbers.add(node.value)
    allowed = {30, 15, 5, 3, 3.0, 0.5, 0, 1, 0.0}
    out["no_second_threshold_literal"] = numbers <= allowed
    out["no_bucket_grid_literal"] = 60 not in numbers and 60.0 not in numbers

    # (4) The import closure (§3): stdlib plus the classifier, nothing else.
    #     Both shapes are pinned -- the modules reached and the names pulled
    #     out of them -- so a second consumer, or a widened stdlib use,
    #     breaks this gate instead of hiding inside one set. The classifier
    #     is imported under its shipped dotted path, which is the same
    #     literal the packaging single-consumer gate pins.
    imports = set()
    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = ("." * node.level) + (node.module or "")
            imports.add(module)
            imported_names.update("%s.%s" % (module, alias.name)
                                  for alias in node.names)
    out["import_closure_closed"] = imports == {
        "__future__", "math", "threading", "time", "web"} and imported_names \
        == {"__future__.annotations", "web.incident_classifier"}
    # (5) The closed vocabularies, restated as literals outside the module.
    out["error_vocabulary_closed"] = frozenset(
        getattr(ir, name) for name in dir(ir)
        if name.startswith("ERROR_")) == frozenset(FROZEN_ERRORS)
    out["phase_vocabulary_closed"] = frozenset(
        getattr(ir, name) for name in dir(ir)
        if name.startswith("PHASE_")) == frozenset(FROZEN_PHASES)
    out["closure_reasons_are_two"] = {ir._CLOSURE_CLEAN_BUCKETS,
                                      ir._CLOSURE_WINDOW_LIMIT} == \
        {"clean_buckets", "window_limit"}
    # (6) PR-4B R2 §8.1: the category lattice is DELETED, not merely unused.
    #     The persisted-category rule is now "write exactly what THIS
    #     detect() said", so a module-level priority table (or a helper that
    #     consults one) is a second verdict algorithm living in the runtime
    #     plane. Both the attributes and the source tokens are pinned absent:
    #     a renamed lattice would be the same bug, and the destination
    #     category's unemittability is already pinned by the store's own
    #     CHECK-boundary gates.
    out["lattice_surface_deleted"] = (
        not hasattr(ir, "_CATEGORY_LATTICE") and not hasattr(ir, "_broaden")
        and "CATEGORY_LATTICE" not in source and "_broaden" not in source)
    # (7) The same rule from the other side: the runtime module names NO
    #     category at all. Bucketing facts are referenced from the
    #     classifier; categories only ever flow in through
    #     ``classification.category``, so there is nothing here that could
    #     rank one category above another.
    out["module_names_no_category"] = not [
        name for name in dir(ir)
        if isinstance(getattr(ir, name, None), str)
        and getattr(ir, name) in ic.EMITTABLE_CATEGORIES]
    # (8) The status surface's key ORDER and count (§12): eight keys.
    env = _env(SCEN["normal_background"])
    try:
        keys = list(env["scanner"].status())
        out["status_keys_exact_and_ordered"] = keys == [
            "enabled", "running", "phase", "cycles_completed",
            "runtime_failures", "last_error_code",
            "last_evaluated_end_epoch", "open_incident"]
        out["status_dark_before_start"] = (
            env["scanner"].status()["enabled"] is False
            and env["scanner"].status()["phase"] == "warmup")
    finally:
        _close_env(env)
    return out


# -- group: the incident persistence plane ----------------------------------

def group_store():
    out = {}
    history, root, clock = _store_dir()
    try:
        conn = history._conn
        # (1) Exactly the ten v4 tables, no more.
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        out["exactly_ten_v4_tables"] = tables == FROZEN_V4_TABLES
        # (2) The frozen column sets, in order.
        window_cols = [row[1] for row in conn.execute(
            "PRAGMA table_info(incident_windows)")]
        state_cols = [row[1] for row in conn.execute(
            "PRAGMA table_info(incident_runtime_state)")]
        out["window_columns_exact"] = window_cols == list(
            ih.IncidentHistory.INCIDENT_WINDOW_COLUMNS)
        out["state_columns_exact"] = state_cols == [
            "id", "runtime_version", "activation_floor_epoch",
            "last_evaluated_end_epoch", "reader_fresh_since_epoch",
            "open_incident_id", "discovery_floor_epoch", "rearm_required"]
        # (3) No column may hold raw text, an identity or an address: the
        #     only TEXT columns in the whole plane are the three closed enums.
        types = {row[1]: row[2] for row in conn.execute(
            "PRAGMA table_info(incident_windows)")}
        out["text_columns_are_only_closed_enums"] = {
            name for name, decl in types.items()
            if decl.upper().startswith("TEXT")} == {
                "state", "category", "closure_reason"}
        forbidden = ("raw", "line", "fp", "egress_ip", "run_id", "ip",
                     "address", "device", "identity", "uuid", "payload",
                     "name", "json", "secret", "log")
        out["no_forbidden_column_names"] = not any(
            bad in [c.lower() for c in window_cols + state_cols]
            for bad in forbidden)
        # (4) The runtime-state row is born INERT and there is only ever one.
        #     PR-4B R2: inert birth also means NO discovery floor and NO
        #     rearm demand -- the gates exist only once activation lands.
        inert = conn.execute(
            "SELECT id, runtime_version, activation_floor_epoch,"
            " last_evaluated_end_epoch, reader_fresh_since_epoch,"
            " open_incident_id, discovery_floor_epoch, rearm_required"
            " FROM incident_runtime_state").fetchall()
        out["state_row_born_inert_single"] = inert == [
            (1, 1, 0.0, 0.0, None, None, None, 0)]
        try:
            # rearm_required is carried explicitly: with a NOT NULL column
            # omitted the refusal below would come from the NOT NULL
            # constraint, not from the id = 1 CHECK it means to prove.
            conn.execute("INSERT INTO incident_runtime_state (id,"
                         " runtime_version, activation_floor_epoch,"
                         " last_evaluated_end_epoch, rearm_required)"
                         " VALUES (2, 1, 0.0, 0.0, 0)")
            out["state_second_row_refused"] = False
            conn.rollback()
        except sqlite3.IntegrityError:
            out["state_second_row_refused"] = True
            conn.rollback()
        # (5) The category CHECK: six emittable classes, and
        #     destination_specific has NO slot (discriminator 13, DB half).
        categories = list(ic.EMITTABLE_CATEGORIES)
        landed = 0
        for category in categories:
            _open_raw(history, category=category, state="closed",
                      closed_epoch=BASE + 300.0, closure_reason="clean_buckets")
            landed += 1
        out["all_six_emittable_categories_persist"] = landed == 6
        out["emittable_count_is_six"] = len(categories) == 6
        try:
            _open_raw(history, category=ic.CATEGORY_DESTINATION, state="closed",
                      closed_epoch=BASE + 300.0, closure_reason="clean_buckets")
            out["destination_db_check_refuses"] = False
            conn.rollback()
        except sqlite3.IntegrityError:
            out["destination_db_check_refuses"] = True
            conn.rollback()
        # ... and the store boundary refuses it BEFORE SQL (first wall).
        rejected_before = history.incident_status()["rejected_total"]
        out["destination_boundary_refuses"] = (
            history.incident_open_window(
                ic.CATEGORY_DESTINATION, BASE, BASE + 180, BASE + 240,
                BASE + 240, 5, 0, 0) is None
            and history.incident_status()["rejected_total"]
            > rejected_before)
        out["destination_failure_code_is_closed"] = (
            history.incident_status()["last_error_code"]
            == ih.CODE_HISTORY_INCIDENT_PERSIST_FAILED)
        # (6) The closure-reason, state-pairing and epoch-order CHECKs.
        for label, kwargs in (
                ("bogus_closure_reason", dict(state="closed",
                                              closed_epoch=BASE + 300.0,
                                              closure_reason="because_i_said_so")),
                ("open_with_closed_epoch", dict(state="open",
                                                closed_epoch=BASE + 300.0)),
                ("closed_without_reason", dict(state="closed",
                                               closed_epoch=BASE + 300.0)),
                ("signal_before_analysis", dict(first_signal=BASE - 60.0,
                                                last_signal=BASE + 240.0,
                                                classified_end=BASE + 240.0)),
                ("last_before_first", dict(first_signal=BASE + 240.0,
                                           last_signal=BASE + 180.0,
                                           classified_end=BASE + 240.0)),
                ("buckets_zero", dict(buckets=0)),
                ("buckets_61", dict(buckets=61))):
            try:
                _open_raw(history, **kwargs)
                out["check_rejects_%s" % label] = False
                conn.rollback()
            except sqlite3.IntegrityError:
                out["check_rejects_%s" % label] = True
                conn.rollback()
        # (7) The partial unique index: a second OPEN row is a violation.
        _open_raw(history)
        try:
            _open_raw(history, category="vps_outbound")
            out["one_open_index_refuses_second"] = False
            conn.rollback()
        except sqlite3.IntegrityError:
            out["one_open_index_refuses_second"] = True
            conn.rollback()
        # The CHECK/index proofs above wrote rows BEYOND the boundary on
        # purpose. The boundary-API proofs that follow need the incident
        # table in a known state, so the raw rows are dropped here -- nothing
        # they proved is undone, each rejection already fired inside its own
        # transaction.
        conn.execute("DELETE FROM incident_windows")
        conn.commit()
        # The store's own clock now stands past every epoch used below: the
        # close transaction refuses a closed_epoch that PRECEDES the signal it
        # closes over, and that rule has to be satisfied, not argued with.
        clock[0] = BASE + 700.0
        # (8) The bitset width: every token of both closed vocabularies maps
        #     to its sorted position, the full union is the frozen maximum,
        #     and one bit past it is refused TWICE (encoder, then CHECK).
        evidence_tokens = sorted(ic.EVIDENCE_TOKENS)
        unknown_tokens = sorted(ic.UNKNOWN_TOKENS)
        out["vocabulary_widths_pinned"] = (
            len(evidence_tokens) == 45 and len(unknown_tokens) == 28)
        out["bits_positional_per_token"] = all(
            ic.evidence_to_bits((token,)) == (1 << position)
            for position, token in enumerate(evidence_tokens)) and all(
            ic.unknown_to_bits((token,)) == (1 << position)
            for position, token in enumerate(unknown_tokens))
        out["bits_union_is_frozen_max"] = (
            ic.evidence_to_bits(evidence_tokens) == 2 ** 45 - 1
            and ic.unknown_to_bits(unknown_tokens) == 2 ** 28 - 1)
        out["bits_encoder_refuses_unknown_token"] = (
            ic.evidence_to_bits(("not_a_token",)) is None
            and ic.unknown_to_bits(("not_a_token",)) is None
            and ic.evidence_to_bits("not-a-sequence") is None)
        out["bits_boundary_refuses_one_past"] = (
            history.incident_open_window(
                ic.CATEGORY_REALITY_TCP, BASE, BASE + 180, BASE + 240,
                BASE + 240, 5, 1 << 45, 0) is None
            and history.incident_open_window(
                ic.CATEGORY_REALITY_TCP, BASE, BASE + 180, BASE + 240,
                BASE + 240, 5, 0, 1 << 28) is None)
        for label, kwargs in (("evidence", {"evidence_bits": 1 << 45}),
                              ("unknown", {"unknown_bits": 1 << 28})):
            try:
                _open_raw(history, **kwargs)
                out["bits_db_check_refuses_one_past_%s" % label] = False
                conn.rollback()
            except sqlite3.IntegrityError:
                out["bits_db_check_refuses_one_past_%s" % label] = True
                conn.rollback()
        maxima_id = history.incident_open_window(
            ic.CATEGORY_REALITY_TCP, BASE, BASE + 180, BASE + 240, BASE + 300,
            5, 2 ** 45 - 1, 2 ** 28 - 1)
        out["bits_frozen_maxima_persist"] = (
            maxima_id is not None
            and history.incident_update_window(
                maxima_id, ic.CATEGORY_REALITY_TCP, BASE + 240, BASE + 300, 5,
                2 ** 45 - 1, 2 ** 28 - 1) is True
            and history.incident_close_window(
                maxima_id, ic.CATEGORY_REALITY_TCP, BASE + 240, BASE + 300, 5,
                2 ** 45 - 1, 2 ** 28 - 1, "clean_buckets") is True)
        # (9) Nothing identity-shaped can ride in: a row opened from evidence
        #     that CARRIES sentinels persists only bits and closed enums.
        bundle = SCEN["reality_outage"]
        cls = ic.classify(bundle)
        # The fixture has to genuinely carry identity material, or the proof
        # below would be vacuous -- so that premise is a gate of its own.
        out["fixture_carries_identity_material"] = any(
            probe in json.dumps(bundle) for probe in cg.CARRIED_LEAK_PROBES)
        identity = history.incident_open_window(
            cls.category, BASE, BASE + 180, BASE + 240, BASE + 300, 5,
            *_bits(cls))
        landed_rows = [row for row in _rows(history)
                       if row["incident_id"] == identity]
        out["identity_row_landed"] = len(landed_rows) == 1
        dumped = json.dumps(landed_rows, sort_keys=True, default=str)
        out["row_carries_no_identity_material"] = bool(landed_rows) and not any(
            probe in dumped for probe in SENTINEL)
        out["row_bits_match_the_verdict"] = bool(landed_rows) and (
            landed_rows[0]["evidence_bits"] == ic.evidence_to_bits(cls.evidence))
        # (10) The runtime-state snapshot's closed shape.
        snapshot = history.incident_runtime_snapshot()
        out["snapshot_state_keys"] = set(snapshot["state"]) == {
            "runtime_version", "activation_floor_epoch",
            "last_evaluated_end_epoch", "reader_fresh_since_epoch",
            "open_incident_id", "discovery_floor_epoch", "rearm_required"}
        out["snapshot_open_row_columns"] = (
            list(snapshot["open_incident"])
            == list(ih.IncidentHistory.INCIDENT_WINDOW_COLUMNS))
        # (11) Activation is ONE-WAY: the inert row takes the first floor it
        #      is given and every later floor is refused as a move -- a
        #      scanner restart can therefore never rewind or shift where
        #      runtime analysis may begin (no v3-era backfill).
        out["state_row_is_inert_before_activation"] = (
            _state(history)["activation_floor_epoch"] == 0.0)
        out["activate_lands_the_first_floor"] = (
            history.incident_activate(BASE) is True
            and _state(history)["activation_floor_epoch"] == float(BASE))
        out["activate_is_one_way"] = (
            history.incident_activate(BASE + 10_000.0) is True
            and _state(history)["activation_floor_epoch"] == float(BASE))
        # R2: the first activation owns THREE columns in one statement, so a
        # floor can never exist without its discovery gate (§5, §8).
        out["activate_pins_the_discovery_floor"] = (
            _state(history)["discovery_floor_epoch"] == float(BASE)
            and _state(history)["rearm_required"] == 0)
        pointer_before = _state(history)["open_incident_id"]
        out["mark_never_moves_the_pointer"] = (
            history.incident_runtime_mark(BASE + 400.0, None) is True
            and _state(history)["open_incident_id"] == pointer_before)
        out["mark_refuses_malformed"] = (
            history.incident_runtime_mark(None, None) is False
            and history.incident_runtime_mark(-1.0, None) is False
            and history.incident_runtime_mark(BASE, "not-an-epoch") is False
            and history.incident_runtime_mark(BASE, True) is False)
        # (12) Update and close address ONLY an open row, and only with a
        #      closed reason; a refusal is never a silent no-op.
        out["update_requires_open_row"] = (
            history.incident_update_window(identity, ic.CATEGORY_VPS_OUTBOUND,
                                           BASE + 240, BASE + 300, 5, 0,
                                           0) is True
            and history.incident_close_window(
                identity, ic.CATEGORY_VPS_OUTBOUND, BASE + 240, BASE + 300, 5,
                0, 0, "clean_buckets") is True
            and history.incident_update_window(
                identity, ic.CATEGORY_VPS_OUTBOUND, BASE + 240, BASE + 300, 5,
                0, 0) is False
            and history.incident_close_window(
                999_999, ic.CATEGORY_VPS_OUTBOUND, BASE + 240, BASE + 300, 5,
                0, 0, "clean_buckets") is False
            and history.incident_close_window(
                999_998, ic.CATEGORY_VPS_OUTBOUND, BASE + 240, BASE + 300, 5,
                0, 0, "nonsense") is False)
        out["close_clears_the_pointer_atomically"] = (
            _state(history)["open_incident_id"] is None)
        out["incident_status_keys_closed"] = set(history.incident_status()) == {
            "enabled", "degraded", "last_error_code", "persisted_total",
            "rejected_total"}
        # (13) The bounded internal read (§7): a section that cannot fit
        #      refuses the WHOLE bundle -- never a truncated view.
        budget = ih.CLASSIFIER_BUNDLE_ROW_BUDGET
        out["bundle_budget_is_classifier_budget"] = (
            budget == ic.MAX_RECORDS_PER_SECTION == 2000)
        _pump_samples(history, budget + 1)
        rejected = history.incident_status()["rejected_total"]
        out["bundle_over_budget_refuses_all"] = (
            history.classifier_bundle(BASE, BASE + 500.0, "fresh") is None
            and history.incident_status()["rejected_total"] > rejected)
        out["bundle_at_budget_serves"] = (
            history.classifier_bundle(BASE, BASE + budget * 0.1,
                                      "fresh") is not None)
        out["bundle_refuses_unordered_window"] = (
            history.classifier_bundle(BASE + 100.0, BASE + 100.0, "fresh")
            is None
            and history.classifier_bundle(BASE + 100.0, BASE, "fresh") is None)
        out["bundle_reader_tokens_are_two"] = (
            ih.CLASSIFIER_READER_STATUSES == ("fresh", "stale"))
        for token in ("disabled", "absent", "unreadable", "invalid", "", None,
                      0, "bogus"):
            if history.classifier_bundle(BASE, BASE + 60.0, token) is not None:
                out["bundle_refuses_non_projectable_reader_token"] = False
                break
        else:
            out["bundle_refuses_non_projectable_reader_token"] = True
        # (14) The bundle projects ONLY the columns the classifier consumes,
        #      and the timeline HTTP surface stays exactly as wide as it was.
        small, small_root, _c = _store_dir()
        try:
            small._conn.execute(
                "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
                " collector_stale, total_active_connections,"
                " reality_active_connections, hysteria2_active_connections,"
                " other_active_connections, uplink_rate, downlink_rate,"
                " skipped_events, duplicate_events, identity_conflicts,"
                " abandoned_on_reset) VALUES (?, ?, ?, 0, 40, 25, 15, 0, 1.0,"
                " 2.0, 0, 0, 0, 0)", (BASE + 1.0, SENTINEL[0], SENTINEL[0]))
            small._conn.commit()
            bundle = small.classifier_bundle(BASE, BASE + 60.0, "fresh")
            out["bundle_keys_are_eight_closed_sections"] = set(bundle) == {
                "window", "health", "reader", "samples", "device_states",
                "probe_rows", "journal_events", "audit"}
            out["bundle_sample_columns_are_store_columns"] = (
                list(bundle["samples"][0]) == list(ih.SAMPLE_COLUMNS))
            out["timeline_surface_unchanged"] = set(
                small.query_timeline(since=0.0, limit=10)) == {
                    "samples", "device_states", "probe_rows", "truncated",
                    "limit"}
        finally:
            small.close()
            _drop(small_root)
        # (15) PR-4B R2 §5/§8.3: the two gate columns are CHECKed STATE, and
        #      every close moves the gate in the SAME transaction as the row
        #      it closes. A private store keeps these raw-SQL proofs from
        #      disturbing the boundary-API sequence above.
        gate, gate_root, gate_clock = _store_dir()
        try:
            gc = gate._conn
            gate_clock[0] = BASE + 700.0  # a close may not precede its signal
            gate.incident_activate(BASE)
            for label, sql, params in (
                    ("floor_below_activation",
                     "UPDATE incident_runtime_state SET"
                     " discovery_floor_epoch = ? WHERE id = 1",
                     (BASE - 60.0,)),
                    ("rearm_not_zero_or_one",
                     "UPDATE incident_runtime_state SET rearm_required = 2"
                     " WHERE id = 1", ()),
                    # R3 §5.1: the armed shape requires a floor. An
                    # activated row may NOT lose its discovery floor --
                    # that is the state the runtime also refuses to read,
                    # because falling back to the activation floor would
                    # widen history instead of failing closed.
                    ("active_without_discovery_floor",
                     "UPDATE incident_runtime_state SET"
                     " discovery_floor_epoch = NULL WHERE id = 1", ())):
                try:
                    gc.execute(sql, params)
                    out["state_check_refuses_%s" % label] = False
                    gc.rollback()
                except sqlite3.IntegrityError:
                    out["state_check_refuses_%s" % label] = True
                    gc.rollback()
            opened = gate.incident_open_window(
                ic.CATEGORY_REALITY_TCP, BASE, BASE + 180, BASE + 240,
                BASE + 300, 5, 0, 0)
            # The pairing CHECKs below only bite with an OPEN pointer, so
            # that premise is proved rather than assumed.
            out["gate_premise_open_pointer_lands"] = (
                opened is not None
                and _state(gate)["open_incident_id"] == opened)
            try:
                gc.execute("UPDATE incident_runtime_state SET"
                           " rearm_required = 1 WHERE id = 1")
                out["state_check_refuses_rearm_while_incident_open"] = False
                gc.rollback()
            except sqlite3.IntegrityError:
                out["state_check_refuses_rearm_while_incident_open"] = True
                gc.rollback()
            # The same statement shape but with the pointer moved aside: the
            # refusal then can only come from the floor half of the CHECK
            # (rearm=1 requires a NULL discovery floor), not from the pointer.
            try:
                gc.execute("UPDATE incident_runtime_state SET"
                           " open_incident_id = NULL, rearm_required = 1,"
                           " discovery_floor_epoch = ? WHERE id = 1",
                           (BASE + 240.0,))
                out["state_check_refuses_rearm_with_discovery_floor"] = False
                gc.rollback()
            except sqlite3.IntegrityError:
                out["state_check_refuses_rearm_with_discovery_floor"] = True
                gc.rollback()
            # clean_buckets: the gate re-arms discovery AT the signal end.
            gate.incident_close_window(opened, ic.CATEGORY_REALITY_TCP,
                                       BASE + 240, BASE + 300, 5, 0, 0,
                                       "clean_buckets")
            settled = _state(gate)
            out["clean_close_moves_the_discovery_floor"] = (
                settled["open_incident_id"] is None
                and settled["discovery_floor_epoch"] == float(BASE + 240.0)
                and settled["rearm_required"] == 0)
            # window_limit: discovery is DISARMED, not re-baselined.
            second = gate.incident_open_window(
                ic.CATEGORY_HY2_UDP, BASE, BASE + 180, BASE + 240,
                BASE + 300, 5, 0, 0)
            gate.incident_close_window(second, ic.CATEGORY_HY2_UDP,
                                       BASE + 240, BASE + 300, 5, 0, 0,
                                       "window_limit")
            disarmed = _state(gate)
            out["window_limit_close_raises_rearm"] = (
                disarmed["open_incident_id"] is None
                and disarmed["discovery_floor_epoch"] is None
                and disarmed["rearm_required"] == 1)
            # ... and a later activation can never un-learn it: the one-way
            # early return leaves the gate exactly where the close left it.
            survived = gate.incident_activate(BASE + 600.0)
            after = _state(gate)
            out["rearm_survives_reactivation"] = (
                survived is True and after["rearm_required"] == 1
                and after["discovery_floor_epoch"] is None
                and after["activation_floor_epoch"] == float(BASE))
        finally:
            gate.close()
            _drop(gate_root)
        # (16) PR-4B R2 §7: the bundle's health is the COMPOSED health of the
        #      classifier's EVIDENCE planes (ordinary OR journal OR probe,
        #      same code precedence as ``health()``) and explicitly NOT the
        #      incident plane's -- otherwise the consumer's own failures would
        #      steer the classifier that is judging it. The three evidence
        #      flags are raised through the store's own per-plane recorders
        #      (the same calls a real sqlite fault runs); the incident flag is
        #      raised by a REAL boundary refusal.
        clean = {"enabled": True, "degraded": False, "last_error_code": None}
        for plane, recorder, code in (
                ("ordinary", "_record_failure", ih.CODE_WRITE_FAILED),
                ("journal", "_record_journal_failure",
                 ih.CODE_EXCHANGE_UNREADABLE),
                ("probe", "_record_probe_failure",
                 ih.CODE_PROBE_PERSIST_FAILED)):
            one, one_root, _c = _store_dir()
            try:
                out["bundle_health_clean_before_%s" % plane] = (
                    _bundle_health(one) == clean)
                getattr(one, recorder)(code)
                out["bundle_health_admits_%s" % plane] = (
                    _bundle_health(one) == {"enabled": True, "degraded": True,
                                            "last_error_code": code})
            finally:
                one.close()
                _drop(one_root)
        both, both_root, _c = _store_dir()
        try:
            # The precedence is IDENTICAL to health(): probe < journal <
            # ordinary, so a lower plane never swallows a higher code, and
            # the bundle surface is the same projection of the same state.
            both._record_probe_failure(ih.CODE_PROBE_PERSIST_FAILED)
            both._record_journal_failure(ih.CODE_EXCHANGE_UNREADABLE)
            stage_one = (_bundle_health(both)
                         == {k: both.health()[k] for k in
                             ("enabled", "degraded", "last_error_code")}
                         and _bundle_health(both)["last_error_code"]
                         == ih.CODE_EXCHANGE_UNREADABLE)
            both._record_failure(ih.CODE_WRITE_FAILED)
            out["bundle_health_code_precedence_matches_health"] = (
                stage_one and _bundle_health(both) == {
                    k: both.health()[k] for k in
                    ("enabled", "degraded", "last_error_code")}
                and _bundle_health(both)["degraded"] is True
                and _bundle_health(both)["last_error_code"]
                == ih.CODE_WRITE_FAILED)
        finally:
            both.close()
            _drop(both_root)
        neither, neither_root, _c = _store_dir()
        try:
            refused = neither.incident_open_window(
                ic.CATEGORY_DESTINATION, BASE, BASE + 180, BASE + 240,
                BASE + 300, 5, 0, 0)
            out["bundle_health_incident_refusal_lands"] = (
                refused is None and neither.incident_status()["degraded"]
                is True)
            out["bundle_health_excludes_the_incident_plane"] = (
                _bundle_health(neither) == clean
                and neither.health()["degraded"] is False)
        finally:
            neither.close()
            _drop(neither_root)
    finally:
        history.close()
        _drop(root)
    return out


# -- group: retention (§10) --------------------------------------------------

def group_retention():
    out = {}
    history, root, clock = _store_dir(retention_seconds=100.0)
    try:
        # A CLOSED window ages out by its own last-signal age; an OPEN one is
        # live operational state and never does; the continuity row is a
        # terminal authority like journal_ingest_state.
        old = BASE - 10_000.0
        closed_id = history.incident_open_window(
            ic.CATEGORY_REALITY_TCP, old, old + 180.0, old + 240.0,
            old + 240.0, 5, 0, 0)
        history.incident_close_window(closed_id, ic.CATEGORY_REALITY_TCP,
                                      old + 240.0, old + 240.0, 5, 0, 0,
                                      "clean_buckets")
        open_id = history.incident_open_window(
            ic.CATEGORY_VPS_OUTBOUND, old + 500.0, old + 680.0, old + 740.0,
            old + 740.0, 5, 0, 0)
        clock[0] = BASE + 10.0
        history._cleanup("retention-gate")
        ids = {row["incident_id"] for row in _rows(history)}
        out["closed_window_ages_out"] = closed_id not in ids
        out["open_window_never_pruned"] = open_id in ids
        out["state_row_survives_retention"] = (
            history._conn.execute("SELECT COUNT(*) FROM"
                                  " incident_runtime_state").fetchone()[0] == 1)
        out["retention_did_not_degrade_the_plane"] = (
            history.incident_status()["degraded"] is False)
        # Neither incident table participates in SIZE pruning: the prune
        # sources are the evidence timeline and nothing else.
        pruned = {table for table, _column in ih._PRUNE_SOURCES}
        out["incident_tables_are_not_size_pruned"] = not (
            pruned & {"incident_windows", "incident_runtime_state"})
        out["seven_day_contract_untouched"] = (
            ih.RETENTION_SECONDS == 7 * 86400.0
            and history._retention_seconds == 100.0)
    finally:
        history.close()
        _drop(root)
    return out


# -- group: the scanner state machine ----------------------------------------

def group_lifecycle():
    out = {}
    single = SCEN["reality_outage"]
    detection = ic.detect(single)

    # D1: three baseline buckets + a Reality drop opens EXACTLY one row.
    env = _env(single)
    try:
        _activate(env)
        # Warmup is a cycle that RUNS and decides nothing, not an absence of
        # cycles: the clock stands where the complete-bucket grid is still
        # short of DISCOVERY_BUCKETS, so only the guard itself separates this
        # cycle from a classification of an incomplete window.
        env["clock"][0] = BASE + 250.0
        env["scanner"].run_once()
        warmup_status = env["scanner"].status()
        out["warmup_makes_no_classification"] = (
            env["canned"]._seen == [] and not _rows(env["history"])
            and warmup_status["phase"] == "warmup"
            and warmup_status["last_evaluated_end_epoch"] is None)
        env["clock"][0] = BASE + 615.0
        env["scanner"].run_once()
        rows = _rows(env["history"])
        out["exactly_one_open_row"] = len(rows) == 1 and rows[0][
            "state"] == "open"
        row = rows[0] if rows else {}
        out["category_is_reality_path"] = row.get("category") == "reality_tcp_path"
        # The signal epochs come straight from the detection. §4/§5 define
        # first_signal as the first anomalous bucket's START and last_signal
        # as the last anomalous bucket's END, so one anomalous bucket gives
        # last - first == BUCKET_SECONDS: the two epochs are NOT equal at
        # open, and this lane pins the arithmetic rather than a shorthand.
        out["analysis_start_frozen_at_first_minus_three"] = (
            row.get("analysis_start_epoch")
            == detection.first_signal_epoch - 3 * BUCKET)
        out["signal_epochs_come_from_the_detection"] = (
            row.get("first_signal_epoch") == detection.first_signal_epoch
            and row.get("last_signal_epoch") == detection.last_signal_epoch)
        out["open_buckets_is_discovery_width"] = row.get("buckets") == 5
        out["row_classifier_version_pinned"] = row.get("classifier_version") == 1
        out["row_bits_are_the_verdict_bits"] = (
            row.get("evidence_bits")
            == ic.evidence_to_bits(detection.classification.evidence)
            and row.get("unknown_bits")
            == ic.unknown_to_bits(detection.classification.unknowns))
        out["pointer_and_row_land_together"] = (
            _state(env["history"])["open_incident_id"] == row.get("incident_id"))
        out["status_shows_the_open_incident"] = (
            env["scanner"].status()["phase"] == "open"
            and env["scanner"].status()["open_incident"] is True)
        # D2: once a cycle has settled the generation it evaluated, the same
        #     evidence scanned again at the SAME complete bucket writes
        #     NOTHING new. The first OPEN-period cycle is deliberately not
        #     treated as a repeat: the frozen analysis window is wider than
        #     the discovery window that opened the row, so its bucket count
        #     really moves (5 -> the frozen width) and that IS a new
        #     classification, not a duplicate write.
        env["scanner"].run_once()
        settled_row = _rows(env["history"])[0]
        updated_before = settled_row["updated_epoch"]
        out["open_period_settles_the_frozen_window_width"] = (
            settled_row["buckets"] == int(round(
                (BASE + 600.0 - settled_row["analysis_start_epoch"])
                / BUCKET)) and settled_row["buckets"] > row["buckets"])
        for _ in range(3):
            env["scanner"].run_once()
        rows = _rows(env["history"])
        out["repeat_scans_never_duplicate"] = (
            len(rows) == 1 and rows[0]["updated_epoch"] == updated_before)

        # D3 (R2 §8.1): BOTH directions write the current verdict. There is
        #     no lattice and no sticky attribution -- a broader verdict moves
        #     the row up, a narrower verdict moves it back down, and in each
        #     case the persisted category is exactly what that cycle's
        #     detect() said.
        env["canned"]._bundle = SCEN["reality_plus_generic_probe"]
        env["clock"][0] = BASE + 675.0
        env["scanner"].run_once()
        broad = _rows(env["history"])[0]
        out["broadening_updates_same_row"] = (
            len(_rows(env["history"])) == 1
            and broad["incident_id"] == row["incident_id"]
            and broad["category"] == "vps_outbound")
        env["canned"]._bundle = single
        env["clock"][0] = BASE + 735.0
        env["scanner"].run_once()
        narrowed = _rows(env["history"])[0]
        out["narrowing_rewrites_category_to_the_current_verdict"] = (
            narrowed["category"] == ic.CATEGORY_REALITY_TCP
            and narrowed["incident_id"] == row["incident_id"])

        # D4: three consecutive clean tail buckets close it. The signal end
        #     is kept exactly as it was (a close never extrapolates a signal
        #     into clean buckets), but the six snapshot columns are settled
        #     by THIS cycle's detect() (§8.2).
        last_signal_before = narrowed["last_signal_epoch"]
        env["clock"][0] = BASE + 795.0
        env["scanner"].run_once()
        closed = _rows(env["history"])[0]
        out["clean_tail_closes"] = (
            closed["state"] == "closed"
            and closed["closure_reason"] == "clean_buckets"
            and closed["closed_epoch"] == BASE + 795.0)
        out["close_keeps_last_signal"] = (
            closed["last_signal_epoch"] == last_signal_before)
        out["clean_close_settles_the_current_verdict_bits"] = (
            (closed["evidence_bits"], closed["unknown_bits"])
            == _bits(ic.detect(single).classification)
            and closed["category"] == ic.detect(
                single).classification.category)
        # This gate keeps only what it owns: the pointer and the row landed
        # together, and the row is no longer open. R2's third conjunct here
        # was `phase == "idle"`, which pinned exactly the state-face defect
        # R3 §8.4 fixes (a clean close reported idle while its own durable
        # gate was already holding discovery back), so it reads `!= "open"`
        # and the warmup claim moves to the two gates right below.
        out["close_clears_pointer_and_phase"] = (
            _state(env["history"])["open_incident_id"] is None
            and env["scanner"].status()["open_incident"] is False
            and env["scanner"].status()["phase"] != "open")
        # R3 discriminator 31: the phase is DERIVED from the durable gate as
        #     it stands AFTER the cycle, so a clean close settles warmup in
        #     the very cycle that closed. The old code inferred warmup from
        #     "this cycle analysed something", so for up to one interval the
        #     surface claimed an IDLE runtime whose discovery floor was
        #     still holding discovery back.
        state_after = _state(env["history"])
        floor_after = state_after["discovery_floor_epoch"]
        out["clean_close_immediately_reports_warmup"] = (
            env["scanner"].status()["phase"] == "warmup"
            and floor_after == closed["last_signal_epoch"]
            # The premise, proved not assumed: the new floor lies inside the
            # window this cycle classified (first_signal <= last_signal), so
            # the three just-closed clean buckets cannot already be five
            # buckets of trusted baseline.
            and env["canned"]._seen[-1][0] + 3 * BUCKET <= floor_after)
        # R3 discriminator 32: the same derivation crosses a process
        #     boundary. A scanner started inside the post-clean warmup
        #     reports warmup BEFORE its first cycle, from the floor the
        #     store already holds -- not from "nothing evaluated yet".
        restarted = _scanner(env["canned"], env["clock"])
        restarted.start()
        out["restart_in_post_clean_warmup_reports_warmup"] = (
            restarted.status()["phase"] == "warmup"
            and restarted.status()["enabled"] is True
            and restarted.status()["cycles_completed"] == 0
            and restarted.status()["open_incident"] is False)
        restarted.stop(join_timeout=0.5)
        out["no_second_row_ever"] = len(_rows(env["history"])) == 1
        # R2 §8: the three just-closed clean buckets become the NEXT
        # segment's trusted baseline, so discovery must not classify again
        # until the last-5-bucket window_start catches the new floor.
        out["clean_close_pins_the_discovery_floor"] = (
            state_after["discovery_floor_epoch"]
            == closed["last_signal_epoch"])
        reads_before = len(env["canned"]._seen)
        env["canned"]._bundle = SCEN["reality_plus_generic_probe"]
        env["clock"][0] = BASE + 855.0
        env["scanner"].run_once()
        out["post_clean_close_discovery_stays_warmup"] = (
            len(env["canned"]._seen) == reads_before
            and len(_rows(env["history"])) == 1
            and env["scanner"].status()["phase"] == "warmup")
        env["clock"][0] = BASE + 915.0
        env["scanner"].run_once()
        out["safe_warmup_then_discovery_resumes"] = (
            len(env["canned"]._seen) == reads_before + 1
            and env["scanner"].status()["phase"] != "warmup")
    finally:
        _close_env(env)

    # D5 (R2 discriminator 1): one quiet bucket then a second cluster stays
    #     ONE lifecycle -- and that lifecycle's category genuinely DROPS to
    #     the classifier's fail-closed verdict. The persistence layer has no
    #     right to keep a Reality attribution the classifier has already
    #     withdrawn.
    env = _env(single)
    try:
        _activate(env)
        env["scanner"].run_once()
        rows = _rows(env["history"])
        first_id = rows[0]["incident_id"]
        out["second_cluster_starts_from_reality_attribution"] = (
            rows[0]["category"] == ic.CATEGORY_REALITY_TCP)
        split = SCEN["two_clusters_fail_closed"]
        split_detection = ic.detect(split)
        env["canned"]._bundle = split
        env["clock"][0] = BASE + 675.0
        env["scanner"].run_once()
        rows = _rows(env["history"])
        out["second_cluster_is_not_a_second_incident"] = (
            len(rows) == 1 and rows[0]["incident_id"] == first_id)
        out["second_cluster_downgrades_the_persisted_category"] = (
            rows[0]["category"] == split_detection.classification.category
            == ic.CATEGORY_INSUFFICIENT)
        out["second_cluster_records_its_own_verdict_bits"] = (
            rows[0]["evidence_bits"]
            == ic.evidence_to_bits(split_detection.classification.evidence)
            and rows[0]["unknown_bits"]
            == ic.unknown_to_bits(split_detection.classification.unknowns))
        out["multiple_clusters_token_is_in_the_bits"] = bool(
            rows[0]["unknown_bits"]
            & (1 << sorted(ic.UNKNOWN_TOKENS).index("multiple_anomaly_clusters")))
        out["second_cluster_still_open"] = rows[0]["state"] == "open"
    finally:
        _close_env(env)

    # D6 / D7: probe-only evidence and an egress-address change are not
    #          openable or broadening witnesses.
    env = _env(SCEN["single_probe_blip"])
    try:
        _activate(env)
        env["scanner"].run_once()
        out["probe_blip_never_opens"] = (
            _rows(env["history"]) == []
            and _state(env["history"])["open_incident_id"] is None)
        out["quiet_cycle_still_advances_the_window"] = (
            _state(env["history"])["last_evaluated_end_epoch"] == BASE + 600.0)
        out["quiet_cycle_phase_is_idle"] = (
            env["scanner"].status()["phase"] == "idle")
        env["canned"]._bundle = SCEN["probe_outage_with_egress_change_only"]
        env["clock"][0] = BASE + 675.0
        env["scanner"].run_once()
        rows = _rows(env["history"])
        # A changed egress address may open at most an insufficient_evidence
        # lifecycle: it never names a destination, and it never adds a second
        # row (discriminator 7's "an address change is not a witness").
        out["egress_change_only_opens_no_destination"] = (
            len(rows) <= 1 and all(
                row["category"] != ic.CATEGORY_DESTINATION for row in rows))
    finally:
        _close_env(env)

    # D7 (R2 restated): an egress-address change is not an attribution
    #        witness. The OLD form of this gate ("the row keeps the Reality
    #        category") was the deleted lattice's semantics; under §8.1 the
    #        honest, stronger statement is that whatever the cycle's verdict
    #        is, it is NEVER destination_specific and it is exactly what
    #        detect() said.
    env = _env(single)
    try:
        _activate(env)
        env["scanner"].run_once()
        env["canned"]._bundle = SCEN["probe_outage_with_egress_change_only"]
        env["clock"][0] = BASE + 675.0
        env["scanner"].run_once()
        rows = _rows(env["history"])
        verdict = ic.detect(SCEN["probe_outage_with_egress_change_only"])
        out["egress_change_never_persists_a_destination"] = (
            len(rows) == 1
            and rows[0]["category"] != ic.CATEGORY_DESTINATION
            and rows[0]["category"] in ic.EMITTABLE_CATEGORIES
            and rows[0]["category"] == verdict.classification.category)
    finally:
        _close_env(env)

    # D9: a restart continues the SAME incident from the store's pointer.
    env = _env(single)
    try:
        _activate(env)
        env["scanner"].run_once()
        original = _rows(env["history"])[0]
        env["scanner"].stop(join_timeout=0.5)
        second = _scanner(env["canned"], env["clock"])
        second.start()
        out["restart_reads_the_pointer_not_its_memory"] = (
            second.status()["open_incident"] is True
            and second.status()["phase"] == "open")
        env["clock"][0] = BASE + 675.0
        second.run_once()
        out["restart_never_forks_a_second_row"] = (
            len(_rows(env["history"])) == 1
            and _rows(env["history"])[0]["incident_id"]
            == original["incident_id"])
        out["restart_keeps_the_frozen_analysis_start"] = (
            _rows(env["history"])[0]["analysis_start_epoch"]
            == original["analysis_start_epoch"])
    finally:
        _close_env(env)

    # D10a: a crash that left the POINTER without its row is inert state, not
    #       a dangling reference: the scanner settles on discovery.
    env = _env(single)
    try:
        _activate(env)
        env["history"]._conn.execute(
            "UPDATE incident_runtime_state SET open_incident_id = 4242"
            " WHERE id = 1")
        env["history"]._conn.commit()
        failures_before = env["scanner"].status()["runtime_failures"]
        env["scanner"].run_once()
        rows = _rows(env["history"])
        out["pointer_first_crash_is_not_a_hang"] = (
            len(rows) == 1 and rows[0]["state"] == "open"
            and _state(env["history"])["open_incident_id"]
            == rows[0]["incident_id"]
            and env["scanner"].status()["runtime_failures"] == failures_before)
    finally:
        _close_env(env)

    # D10b: a crash that left the ROW without the pointer is refused by the
    #       partial unique index, and the refusal is CONTAINED.
    env = _env(single)
    try:
        _activate(env)
        _open_raw(env["history"])
        env["scanner"].run_once()
        status = env["scanner"].status()
        out["row_first_crash_refuses_a_second_open"] = (
            len(_rows(env["history"])) == 1
            and status["runtime_failures"] == 1
            and status["last_error_code"] == "persist_failed"
            and status["phase"] == "degraded")
        out["refused_open_landed_no_pointer"] = (
            _state(env["history"])["open_incident_id"] is None)
        env["canned"]._bundle = SCEN["normal_background"]
        env["clock"][0] = BASE + 735.0
        env["scanner"].run_once()
        out["next_tick_after_a_refusal_is_a_normal_cycle"] = (
            env["scanner"].status()["last_error_code"] is None
            and env["scanner"].status()["cycles_completed"] >= 1)
    finally:
        _close_env(env)

    # D11 / R2 §8.3: a window that outgrows MAX_ANALYSIS_BUCKETS closes
    #        FAIL-CLOSED on the row's LAST SUCCESSFUL snapshot, then the
    #        durable rearm gate stops automatic discovery -- as a NORMAL
    #        phase, with no failure counter and no error code, and across a
    #        restart. Bucket 60 is really persisted; bucket 61 is not
    #        classified and not fabricated.
    env = _env(_continuing_outage())
    try:
        _activate(env)
        # The row is opened through the STORE boundary with its analysis
        # window frozen at the activation floor: that is the only honest way
        # to grow a window bucket by bucket, since any fixed fixture bundle
        # cleans its own tail long before bucket 60.
        identity = env["history"].incident_open_window(
            ic.CATEGORY_REALITY_TCP, BASE, BASE + 180.0, BASE + 240.0,
            BASE + 240.0, 4, 0, 0)
        opened_row = [row for row in _rows(env["history"])
                      if row["incident_id"] == identity][0]
        env["scanner"].run_once()
        # Settle the frozen window bucket by bucket up to the budget limit.
        env["clock"][0] = BASE + 60 * BUCKET + 15.0
        env["scanner"].run_once()
        at_limit = _rows(env["history"])[0]
        evaluated_at_limit = _state(env["history"])[
            "last_evaluated_end_epoch"]
        out["bucket_60_is_really_persisted"] = (
            at_limit["buckets"] == 60
            and at_limit["analysis_start_epoch"] == opened_row[
                "analysis_start_epoch"]
            and at_limit["last_classified_end_epoch"] == BASE + 60 * BUCKET
            and at_limit["state"] == "open")
        failures_before = env["scanner"].status()["runtime_failures"]
        reads_before = len(env["canned"]._seen)
        env["clock"][0] = BASE + 61 * BUCKET + 15.0
        env["scanner"].run_once()
        row = _rows(env["history"])[0]
        state = _state(env["history"])
        out["window_limit_closes_fail_closed"] = (
            row["state"] == "closed"
            and row["closure_reason"] == "window_limit")
        out["window_limit_keeps_the_last_successful_snapshot"] = (
            row["buckets"] == at_limit["buckets"] == 60
            and row["last_classified_end_epoch"]
            == at_limit["last_classified_end_epoch"]
            and (row["evidence_bits"], row["unknown_bits"])
            == (at_limit["evidence_bits"], at_limit["unknown_bits"])
            and row["category"] == at_limit["category"])
        out["window_limit_did_not_classify_the_overlong_window"] = (
            len(env["canned"]._seen) == reads_before
            and _state(env["history"])["last_evaluated_end_epoch"]
            == evaluated_at_limit)
        out["window_limit_is_a_lifecycle_end_not_a_failure"] = (
            env["scanner"].status()["runtime_failures"] == failures_before
            and env["scanner"].status()["last_error_code"] is None)
        out["window_limit_raises_the_persistent_rearm_gate"] = (
            state["open_incident_id"] is None
            and state["discovery_floor_epoch"] is None
            and state["rearm_required"] == 1)
        out["rearm_is_a_normal_phase_not_an_error"] = (
            env["scanner"].status()["phase"] == "rearm"
            and env["scanner"].status()["open_incident"] is False
            and env["scanner"].status()["runtime_failures"] == failures_before
            and env["scanner"].status()["last_error_code"] is None)
        # A continuing outage must not produce incident #2, and the rearm
        # cycle must not "re-warmup the last 5 buckets" behind its back.
        reads_before = len(env["canned"]._seen)
        for step in range(10):
            env["clock"][0] = (opened_row["analysis_start_epoch"]
                               + (62 + step) * BUCKET + 15.0)
            env["scanner"].run_once()
        out["rearm_stops_discovery_over_many_cycles"] = (
            len(_rows(env["history"])) == 1
            and len(env["canned"]._seen) == reads_before
            and env["scanner"].status()["phase"] == "rearm"
            and env["scanner"].status()["runtime_failures"] == failures_before)
        # The gate is durable state: a NEW scanner object on the SAME store
        # reports rearm and still opens nothing.
        env["scanner"].stop(join_timeout=0.5)
        restarted = _scanner(env["canned"], env["clock"])
        restarted.start()
        restarted.run_once()
        out["rearm_survives_restart_and_still_opens_nothing"] = (
            restarted.status()["phase"] == "rearm"
            and restarted.status()["runtime_failures"] == 0
            and len(_rows(env["history"])) == 1
            and _state(env["history"])["rearm_required"] == 1)
        restarted.stop(join_timeout=0.5)
    finally:
        _close_env(env)

    # D12: a clock jump from bucket 20 to bucket 65 must NOT fabricate
    #      bucket 60. The honest terminal write is the last classification
    #      that actually happened (bucket 20), even though the row then
    #      closes on the window limit.
    env = _env(_continuing_outage())
    try:
        _activate(env)
        identity = env["history"].incident_open_window(
            ic.CATEGORY_REALITY_TCP, BASE, BASE + 180.0, BASE + 240.0,
            BASE + 240.0, 4, 0, 0)
        env["scanner"].run_once()
        analysis_start = [row for row in _rows(env["history"])
                          if row["incident_id"] == identity][0][
            "analysis_start_epoch"]
        env["clock"][0] = analysis_start + 20 * BUCKET + 15.0
        env["scanner"].run_once()
        at_twenty = _rows(env["history"])[0]
        out["jump_premise_bucket_20_persisted"] = (
            at_twenty["buckets"] == 20
            and at_twenty["last_classified_end_epoch"]
            == analysis_start + 20 * BUCKET)
        env["clock"][0] = analysis_start + 65 * BUCKET + 15.0
        env["scanner"].run_once()
        row = _rows(env["history"])[0]
        out["jump_20_to_65_never_fabricates_bucket_60"] = (
            row["closure_reason"] == "window_limit"
            and row["buckets"] == 20
            and row["last_classified_end_epoch"] == analysis_start + 20 * BUCKET
            and row["buckets"] != 60 and row["buckets"] != 65)
    finally:
        _close_env(env)

    # D13 (R2 §8.2): the TERMINAL write settles the cycle that closed the
    #      incident, not the bits the row happened to carry before it. Here
    #      the two differ on purpose, so a close that read the old row back
    #      would be caught rather than looked past.
    env = _env(SCEN["reality_plus_generic_probe"])
    try:
        _activate(env)
        env["scanner"].run_once()
        opened = _rows(env["history"])[0]
        bits_before = (opened["evidence_bits"], opened["unknown_bits"])
        out["terminal_premise_verdicts_differ"] = bool(
            bits_before != _bits(ic.detect(single).classification))
        env["canned"]._bundle = single
        env["clock"][0] = opened["analysis_start_epoch"] + 13 * BUCKET + 15.0
        env["scanner"].run_once()
        closed = _rows(env["history"])[0]
        verdict = ic.detect(single).classification
        out["terminal_clean_close_settles_the_current_cycle"] = (
            closed["state"] == "closed"
            and closed["closure_reason"] == "clean_buckets"
            and closed["category"] == verdict.category
            and (closed["evidence_bits"], closed["unknown_bits"])
            == _bits(verdict)
            and closed["last_classified_end_epoch"]
            == opened["analysis_start_epoch"] + 13 * BUCKET
            and closed["buckets"] == 13)
        out["terminal_clean_close_did_not_reuse_the_old_bits"] = (
            (closed["evidence_bits"], closed["unknown_bits"]) != bits_before)
    finally:
        _close_env(env)
    return out


# -- group: reader negative-evidence continuity (§9, G8) ---------------------

def group_continuity():
    out = {}
    env = _env(SCEN["normal_background"], reader="fresh")
    try:
        _activate(env)
        floor = _state(env["history"])["activation_floor_epoch"]
        out["activation_continuity_starts_at_the_floor"] = (
            _state(env["history"])["reader_fresh_since_epoch"] == floor)

        # Every non-fresh heartbeat token breaks continuity.
        for token in ("stale", "invalid", "unreadable", "absent", "disabled"):
            env["canned"]._reader = token
            env["clock"][0] += 60.0
            env["scanner"].run_once()
            if _state(env["history"])["reader_fresh_since_epoch"] is not None:
                out["non_fresh_token_breaks_continuity"] = False
                break
        else:
            out["non_fresh_token_breaks_continuity"] = True

        # Recovery stamps THIS observation moment and never reaches back.
        env["canned"]._reader = "fresh"
        moment = BASE + 900.0
        env["clock"][0] = moment
        env["scanner"].run_once()
        recovered = _state(env["history"])["reader_fresh_since_epoch"]
        out["recovery_stamps_this_moment"] = (
            recovered is not None and abs(recovered - moment) < 1.0)
        out["recovery_is_never_retroactive"] = recovered > floor

        # The §9.3 projection: fresh only when continuity begins at or before
        # the window start; otherwise the conservative non-fresh token.
        seen = env["canned"]._seen
        projections = {status for _s, _e, status in seen}
        out["projection_tokens_are_only_two"] = projections <= {
            "fresh", "stale"}
        window_start = seen[-1][0]
        out["projection_is_stale_while_the_window_predates_continuity"] = (
            seen[-1][2] == ("fresh" if recovered <= window_start else "stale"))

        # G8: an unbroken continuity from NOW cannot retroactively repair a
        # journal negative the classifier already settled without it.
        env["canned"]._seen = []
        env["clock"][0] = BASE + 975.0
        env["scanner"].run_once()
        later = env["canned"]._seen[-1]
        out["g8_earlier_windows_are_not_repaired"] = (
            later[2] == "stale" and later[0] < recovered)

        # A restart with a broken heartbeat leaves continuity NULL.
        env["canned"]._reader = "stale"
        restart = _scanner(env["canned"], env["clock"])
        restart.start()
        out["restart_breaks_continuity"] = (
            _state(env["history"])["reader_fresh_since_epoch"] is None)
    finally:
        _close_env(env)

    # A fresh heartbeat at activation still restarts continuity at the floor.
    env = _env(SCEN["normal_background"], reader="fresh")
    try:
        _activate(env)
        out["restart_with_fresh_restarts_at_the_floor"] = (
            _state(env["history"])["reader_fresh_since_epoch"]
            == _state(env["history"])["activation_floor_epoch"])
    finally:
        _close_env(env)

    # A malformed heartbeat is NOT fresh: fail closed.
    env = _env(SCEN["normal_background"], reader="fresh")
    try:
        env["clock"][0] = BASE
        env["canned"]._reader = None
        env["scanner"].start()
        out["malformed_heartbeat_never_starts_continuity"] = (
            _state(env["history"])["reader_fresh_since_epoch"] is None)
    finally:
        _close_env(env)
    return out


# -- group: containment (§11, D17) -------------------------------------------

class _LyingScanner:
    """A scanner that reports things the contract does not allow."""

    def __init__(self, payload):
        self._payload = payload

    def status(self):
        return self._payload


def group_containment():
    out = {}
    from web import server as sv
    from web.access import AccessPolicy
    from web.auth import AuthStore

    # (1) Each stage of a cycle maps to exactly one closed error code. A
    #     raising read is a READ refusal; a snapshot that comes back in a
    #     shape the runtime cannot trust is corrupt state.
    stages = (
        ("classifier_bundle", "raise", "evidence_read_failed"),
        ("classifier_bundle", "refuse", "evidence_read_failed"),
        ("journal_status", "raise", "evidence_read_failed"),
        ("incident_runtime_snapshot", "raise", "evidence_read_failed"),
        ("incident_runtime_snapshot", "refuse", "runtime_state_corrupt"),
        ("incident_open_window", "raise", "persist_failed"),
        ("incident_open_window", "refuse", "persist_failed"),
        ("incident_runtime_mark", "raise", "persist_failed"),
        ("incident_runtime_mark", "refuse", "persist_failed"),
    )
    for name, mode, code in stages:
        env = _env(SCEN["reality_outage"])
        try:
            _activate(env)
            if mode == "raise":
                env["canned"]._raise.add(name)
            else:
                env["canned"]._refuse.add(name)
            env["clock"][0] = BASE + 675.0
            env["scanner"].run_once()
            status = env["scanner"].status()
            out["stage_%s_%s_is_%s" % (name, mode, code)] = (
                status["last_error_code"] == code
                and status["runtime_failures"] >= 1
                and status["phase"] == "degraded")
        finally:
            _close_env(env)

    # (2) A detect() that explodes is classify_failed, contained; the next
    #     tick recovers.
    env = _env(SCEN["reality_outage"])
    try:
        _activate(env)
        real_detect = ir.ic.detect
        real_bits = ir.ic.evidence_to_bits

        def boom(evidence):
            raise RuntimeError("synthetic classifier explosion")

        ir.ic.detect = boom
        env["scanner"].run_once()
        ir.ic.detect = real_detect
        out["exploding_detect_is_classify_failed"] = (
            env["scanner"].status()["last_error_code"] == "classify_failed")

        def refuse_bits(tokens):
            return None

        ir.ic.evidence_to_bits = refuse_bits
        env["scanner"].run_once()
        ir.ic.evidence_to_bits = real_bits
        out["unencodable_verdict_is_classify_failed"] = (
            env["scanner"].status()["last_error_code"] == "classify_failed")
        env["clock"][0] = BASE + 735.0
        env["scanner"].run_once()
        out["recovery_clears_the_closed_code"] = (
            env["scanner"].status()["last_error_code"] is None
            and env["scanner"].status()["phase"] != "degraded")
    finally:
        _close_env(env)

    # (3) A defect that escapes every stage guard still cannot leave the
    #     thread: the loop's own containment line turns it into
    #     runtime_state_corrupt.
    env = _env(SCEN["reality_outage"])
    try:
        _activate(env)
        env["canned"]._raise.add("incident_runtime_snapshot")
        env["scanner"]._run_one_cycle = lambda: (_ for _ in ()).throw(
            ValueError("escaped defect"))
        env["scanner"].run_once()
        out["escaped_defect_becomes_a_closed_code"] = (
            env["scanner"].status()["last_error_code"]
            == "runtime_state_corrupt")
    finally:
        _close_env(env)

    # (4) A store that refuses activation leaves the scanner DARK: no thread,
    #     zero cycles, enabled false -- and run_once() stays a no-op.
    class Hostile:
        def incident_activate(self, floor):
            return False

        def journal_status(self):
            return {"reader": {"status": "fresh"}}

        def incident_runtime_snapshot(self):
            return {"state": None, "open_incident": None}

    dark = ir.IncidentScanner(Hostile(), scan_interval_seconds=3600.0,
                              clock=lambda: BASE)
    dark.start()
    out["refused_activation_starts_nothing"] = (
        dark._thread is None and dark.status()["enabled"] is False)
    dark.run_once()
    out["dark_scanner_cycles_nothing"] = (
        dark.status()["cycles_completed"] == 0
        and dark.status()["runtime_failures"] == 0)

    # (4b) R3 §5.1: an ACTIVATED state row with NO discovery floor is
    #      corrupt, and "the state cannot be proved" must never mean "widen
    #      the analyzed window". This is exactly the row the store's closed
    #      shape CHECK now refuses to hold, so it can only arrive through
    #      damage -- and both read points refuse it: activation stays DARK
    #      instead of inheriting the wider activation floor, and a cycle
    #      that meets it aborts as runtime_state_corrupt WITHOUT reading a
    #      single evidence bundle.
    class Unarmed:
        def __init__(self):
            self.bundles = 0

        def incident_activate(self, floor):
            return True

        def journal_status(self):
            return {"reader": {"status": "fresh"}}

        def incident_runtime_snapshot(self):
            return {"state": {
                "runtime_version": 1,
                "activation_floor_epoch": float(BASE),
                "last_evaluated_end_epoch": float(BASE + 300.0),
                "reader_fresh_since_epoch": None,
                "open_incident_id": None,
                "discovery_floor_epoch": None,
                "rearm_required": 0},
                "open_incident": None}

        def incident_runtime_mark(self, end, rfs):
            return True

        def classifier_bundle(self, window_start, window_end, reader_status):
            self.bundles += 1
            return None

    lying = Unarmed()
    unarmed = ir.IncidentScanner(lying, scan_interval_seconds=3600.0,
                                 clock=lambda: BASE)
    unarmed.start()
    out["unprovable_state_keeps_activation_dark"] = (
        unarmed._thread is None and unarmed.status()["enabled"] is False)
    met = ir.IncidentScanner(lying, scan_interval_seconds=3600.0,
                             clock=lambda: BASE + 615.0)
    met._enabled = True
    met.run_once()
    out["active_missing_discovery_floor_is_runtime_state_corrupt"] = (
        met.status()["last_error_code"] == "runtime_state_corrupt"
        and met.status()["runtime_failures"] == 1
        and met.status()["cycles_completed"] == 0
        and met.status()["phase"] == "degraded"
        and lying.bundles == 0)

    # (5) The scanner thread is a daemon like the probe scheduler's.
    env = _env(SCEN["normal_background"])
    try:
        env["clock"][0] = BASE
        env["scanner"].start()
        out["scan_thread_is_a_daemon"] = (
            env["scanner"]._thread is not None
            and env["scanner"]._thread.daemon is True
            and env["scanner"]._thread.name == "monitor-incidents")
    finally:
        _close_env(env)

    # (6) D17: while the incident plane is failing, NOTHING ELSE in the
    #     process is delayed or degraded. The failure is REAL and lives in
    #     the store -- an over-budget evidence read the incident boundary
    #     itself refuses and records -- so this proves plane independence at
    #     the storage layer rather than against a stubbed raise.
    history, root, clock = _store_dir()
    _pump_samples(history, ih.CLASSIFIER_BUNDLE_ROW_BUDGET + 1,
                  start=BASE + 301.0)
    scanner = _scanner(history, clock)
    try:
        clock[0] = BASE
        scanner.start()
        clock[0] = BASE + 615.0
        scanner.run_once()
        scanner.run_once()
        # The health sample that decides plane independence is taken NOW: a
        # later healthy write clears the history plane's own flag, so sampling
        # after the traffic below would prove only that the flag is
        # self-healing, not that an incident failure never sets it.
        health_at_failure = history.health()
        history.on_publish(cg._snapshot(25, 15), 1)
        # A probe sample from NOW (the store's own clock): the probe
        # boundary's freshness rule is real, and a rejected sample would
        # degrade the probe plane for a harness reason, not a product one.
        probe_landed = history.record_probe_result(
            cg._probe_result(BASE + 585.0, 0), "unknown")
        timeline = history.query_timeline(since=0.0, limit=50)
        health = history.health()
        incident = history.incident_status()
        probe_plane = history.probe_status()
        journal_plane = history.journal_status()
        out["incident_failure_is_recorded_in_the_store"] = (
            incident["degraded"] is True
            and incident["last_error_code"]
            == ih.CODE_HISTORY_INCIDENT_PERSIST_FAILED)
        out["scanner_reports_the_same_closed_read_refusal"] = (
            scanner.status()["last_error_code"] == "evidence_read_failed")
        out["other_planes_keep_answering"] = (
            health["last_success_at"] is not None
            and probe_landed is True and bool(timeline["samples"]))
        out["incident_failure_never_degrades_the_history_plane"] = (
            health_at_failure["degraded"] is False
            and health["degraded"] is False and health["enabled"] is True)
        out["incident_failure_never_degrades_the_probe_plane"] = (
            probe_plane["degraded"] is False
            and probe_plane["last_error_code"] is None)
        out["incident_failure_never_degrades_the_journal_plane"] = (
            journal_plane["blocked_at"] is None)
        out["incident_failure_never_stops_the_scanner"] = (
            scanner._thread is not None and scanner._thread.is_alive())
    finally:
        scanner.stop(join_timeout=0.5)
        history.close()
        _drop(root)

    # (7) The closed projection of the status surface (§12, D19).
    out["status_keys_are_the_frozen_eight"] = (
        sv.INCIDENT_RUNTIME_STATUS_KEYS == (
            "enabled", "running", "phase", "cycles_completed",
            "runtime_failures", "last_error_code",
            "last_evaluated_end_epoch", "open_incident")
        and len(sv.INCIDENT_RUNTIME_STATUS_KEYS) == 8)
    out["phase_vocabulary_is_the_frozen_five"] = (
        sv.INCIDENT_RUNTIME_PHASE_KEYS == frozenset(FROZEN_PHASES))
    out["error_tokens_are_the_frozen_four"] = (
        sv.INCIDENT_RUNTIME_ERROR_TOKENS == frozenset(FROZEN_ERRORS))
    out["lying_phase_projects_warmup"] = (
        sv.closed_incident_phase("banana") == "warmup"
        and sv.closed_incident_phase(None) == "warmup"
        and sv.closed_incident_phase("open") == "open")
    out["lying_error_token_projects_null"] = (
        sv.closed_incident_error("stack trace here") is None
        and sv.closed_incident_error("persist_failed") == "persist_failed")

    d = tempfile.mkdtemp(prefix="p4b-ir-http-")
    access = AccessPolicy(d)
    auth = AuthStore(d, session_ttl=3600.0)
    auth.set_password(PASSWORD)
    history, root, clock = _store_dir()

    class FakeBroker:
        def snapshot(self):
            return cg._snapshot(25, 15)

    try:
        scanner = _scanner(Canned(history, SCEN["normal_background"], "fresh"),
                           clock)
        app = sv.MonitorWebApp
        wired = app(broker=FakeBroker(), access=access, static_dir=None,
                    auth=auth, incident_history=history,
                    incident_scanner=scanner)
        server = sv.build_server(wired, "127.0.0.1", 0, None)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()

        # The credential travels in a JSON body only, exactly like the
        # history lane's login: never in a URL, a query string or a header
        # any access log could echo.
        def request(method, path, cookie=None, body=None):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            headers = {}
            if cookie:
                headers["Cookie"] = cookie
            if body is not None:
                headers["Content-Type"] = "application/json"
                body = json.dumps(body)
            conn.request(method, path, body, headers)
            response = conn.getresponse()
            payload = response.read().decode("utf-8")
            set_cookie = response.getheader("Set-Cookie") or ""
            conn.close()
            return response.status, payload, set_cookie

        _status, _body, cookies = request("POST", "/api/v1/login",
                                          body={"password": PASSWORD})
        session = cookies.split(";")[0] if _status == 200 else ""
        out["harness_logged_in"] = _status == 200 and bool(session)
        status, body, _ = request("GET", "/api/v1/diagnostics/timeline",
                                 cookie=session)
        data = json.loads(body) if status == 200 else {}
        surface = data.get("incident_runtime")
        out["timeline_carries_the_incident_surface"] = (
            status == 200 and isinstance(surface, dict))
        out["surface_has_exactly_eight_keys"] = (
            isinstance(surface, dict)
            and set(surface) == set(sv.INCIDENT_RUNTIME_STATUS_KEYS))
        out["surface_domains_are_closed"] = (
            isinstance(surface, dict)
            and all(type(surface[k]) is bool for k in
                    ("enabled", "running", "open_incident"))
            and surface["phase"] in FROZEN_PHASES
            and type(surface["cycles_completed"]) is int
            and type(surface["runtime_failures"]) is int
            and surface["cycles_completed"] >= 0
            and surface["runtime_failures"] >= 0
            and (surface["last_error_code"] is None
                 or surface["last_error_code"] in FROZEN_ERRORS)
            and (surface["last_evaluated_end_epoch"] is None
                 or (type(surface["last_evaluated_end_epoch"]) in (int, float)
                     and surface["last_evaluated_end_epoch"] >= 0)))
        # No P5 route, no new query parameter, and the journal surface did
        # not widen with the new key.
        _status, _body, _ = request("GET", "/api/v1/incidents", cookie=session)
        out["no_p5_incidents_route"] = _status == 404
        status2, body2, _ = request("GET",
                                    "/api/v1/diagnostics/timeline?incident=1",
                                    cookie=session)
        out["no_new_query_parameter"] = (
            status2 == 200 and set(json.loads(body2)) == set(data))
        out["timeline_journal_surface_not_widened"] = (
            set(data) == {"history", "samples", "device_states", "probe_rows",
                          "probes", "incident_runtime", "truncated", "limit"}
            and all(set(row) == set(ih.SAMPLE_COLUMNS)
                    for row in data["samples"]))
        server.shutdown()
        server.server_close()
        scanner.stop(join_timeout=0.5)

        # A lying scanner is projected back into its closed domains.
        liar = app(broker=FakeBroker(), access=access, static_dir=None,
                   auth=auth, incident_history=history,
                   incident_scanner=_LyingScanner({
                       "enabled": "yes", "running": 1, "phase": "banana",
                       "cycles_completed": -5, "runtime_failures": "many",
                       "last_error_code": "traceback...",
                       "last_evaluated_end_epoch": float("nan"),
                       "open_incident": "true", "extra": "leak"}))
        out["lying_status_object_is_forced_closed"] = (
            liar.incident_runtime_status() == {
                "enabled": False, "running": False, "phase": "warmup",
                "cycles_completed": 0, "runtime_failures": 0,
                "last_error_code": None, "last_evaluated_end_epoch": None,
                "open_incident": False})
        # A scanner whose status() explodes is a null projection, never a 500.
        class Boom:
            def status(self):
                raise RuntimeError("scanner status exploded")

        exploding = app(broker=FakeBroker(), access=access, static_dir=None,
                        auth=auth, incident_history=history,
                        incident_scanner=Boom())
        out["exploding_status_reads_as_null_never_a_500"] = (
            exploding.incident_runtime_status() is None)
        out["unwired_scanner_reads_as_null"] = (
            app(broker=FakeBroker(), access=access, static_dir=None,
                auth=auth, incident_history=history)
            .incident_runtime_status() is None)
    finally:
        history.close()
        _drop(root)
        _drop(d)
    return out


# -- group: nothing canned (D15/D16) ----------------------------------------

def group_end_to_end():
    """The committed Reality scenario, published through the live store and
    read back through the live reader: the scanner's evidence is DATABASE
    rows here, not dicts."""
    out = {}
    # The outage shape: 3 steady buckets then Reality dials out (the same
    # construction the classify lane's store group uses and the committed
    # fixture matches).
    history, obj, counts, root = cg._build_store(buckets=5)
    clock = [BASE]
    canned_reader = None
    try:
        scanner = ir.IncidentScanner(history, scan_interval_seconds=3600.0,
                                     clock=lambda: clock[0])
        clock[0] = BASE
        scanner.start()
        floor = _state(history)["activation_floor_epoch"]
        out["grounded_activation_pins_the_floor"] = floor == BASE
        out["grounded_continuity_starts_at_the_floor"] = (
            _state(history)["reader_fresh_since_epoch"] == BASE)
        clock[0] = BASE + 320.0
        scanner.run_once()
        rows = _rows(history)
        out["reality_store_opens_exactly_one_incident"] = (
            len(rows) == 1 and rows[0]["state"] == "open")
        out["reality_incident_is_the_reality_path"] = bool(
            rows) and rows[0]["category"] == "reality_tcp_path"
        bundle = history.classifier_bundle(BASE, BASE + 300.0, "fresh")
        detected = ic.detect(bundle)
        out["grounded_evidence_is_what_the_store_holds"] = (
            bool(rows) and rows[0]["evidence_bits"]
            == ic.evidence_to_bits(detected.classification.evidence)
            and rows[0]["unknown_bits"]
            == ic.unknown_to_bits(detected.classification.unknowns))
        out["grounded_analysis_start_is_the_baseline_width"] = bool(
            rows) and rows[0]["analysis_start_epoch"] == BASE
        out["grounded_window_is_discovery_width"] = bool(
            rows) and rows[0]["buckets"] == 5
        out["grounded_reader_status_was_fresh"] = (
            detected.classification.status == "incident"
            and "journal_reader_stale" not in detected.classification.unknowns)
        scanner.run_once()
        out["grounded_repeat_scan_writes_no_second_row"] = (
            len(_rows(history)) == 1)
        scanner.stop(join_timeout=0.5)
    finally:
        history.close()
        _drop(root)

    # D15: the same machinery over quiet background opens NOTHING.
    history, obj, counts, root = cg._build_store(buckets=5, drop_from=5)
    clock = [BASE]
    try:
        scanner = ir.IncidentScanner(history, scan_interval_seconds=3600.0,
                                     clock=lambda: clock[0])
        clock[0] = BASE
        scanner.start()
        clock[0] = BASE + 320.0
        scanner.run_once()
        scanner.run_once()
        out["normal_store_opens_nothing"] = _rows(history) == []
        out["normal_store_still_evaluates"] = (
            _state(history)["last_evaluated_end_epoch"] == BASE + 300.0)
        out["normal_store_phase_is_idle"] = (
            scanner.status()["phase"] == "idle")
        out["normal_store_counted_a_cycle"] = (
            scanner.status()["cycles_completed"] == 2
            and scanner.status()["runtime_failures"] == 0)
        scanner.stop(join_timeout=0.5)
    finally:
        history.close()
        _drop(root)

    # The over-budget window is refused as evidence, so the scanner reports
    # the read refusal instead of classifying a silently truncated view.
    # Nothing is stubbed here: the rows below are the discovery window's own
    # evidence, so the refusal has to come from the live reader.
    history, root, clock = _store_dir()
    try:
        # The discovery window this clock yields is [BASE+300, BASE+600);
        # the pumped samples sit inside it and one row past the budget.
        _pump_samples(history, ih.CLASSIFIER_BUNDLE_ROW_BUDGET + 1,
                      start=BASE + 301.0)
        scanner = ir.IncidentScanner(history, scan_interval_seconds=3600.0,
                                     clock=lambda: clock[0])
        clock[0] = BASE
        scanner.start()
        clock[0] = BASE + 615.0
        scanner.run_once()
        out["over_budget_evidence_is_a_contained_read_refusal"] = (
            scanner.status()["last_error_code"] == "evidence_read_failed"
            and _rows(history) == [])
        scanner.stop(join_timeout=0.5)
    finally:
        history.close()
        _drop(root)
    return out


# -- runner ------------------------------------------------------------------

GROUPS = {"static": group_static, "store": group_store,
          "retention": group_retention, "lifecycle": group_lifecycle,
          "continuity": group_continuity, "containment": group_containment,
          "end_to_end": group_end_to_end}


def main():
    names = sys.argv[1:] or sorted(GROUPS)
    rc = 0
    for name in names:
        try:
            results = GROUPS[name]()
        except Exception as exc:  # noqa: BLE001 -- report, never die green
            import traceback
            traceback.print_exc()
            print("FAIL %s harness crashed: %s: %s"
                  % (name, type(exc).__name__, exc))
            rc = 1
            continue
        for key in sorted(results):
            if results[key] is True:
                print("PASS %s/%s" % (name, key))
            else:
                print("FAIL %s/%s" % (name, key))
                rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
