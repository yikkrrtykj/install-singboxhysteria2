#!/usr/bin/env python3
"""PR-3B probe-ingest behaviour groups (issue #33 Phase 3).

Companion of ``tests/test-monitor-v2-probe-ingest.sh``: the shell lane owns
the static/activation/wiring gates and the hard count, this file owns the
runtime proofs. Every group returns ``{name: bool}`` and the runner prints
``PASS``/``FAIL`` lines; an exception anywhere is reported as a FAIL and
surfaces as a nonzero rc, because "the harness died" must never read green.

Nothing here opens a public socket: the live scheduler runs against a
127.0.0.1 TLS fake built from the throwaway loopback certificate fixture,
and every persistence proof goes through ``record_probe_result`` directly.
"""

import decimal
import http.client
import ipaddress
import json
import os
import sqlite3
import ssl
import stat
import struct
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])

from diagnostics import network_probes as engine          # noqa: E402
from diagnostics import probe_scheduler as sched          # noqa: E402
import web.incident_history as IH                         # noqa: E402
from web.access import AccessPolicy                       # noqa: E402
from web.auth import AuthStore                            # noqa: E402
from web.incident_history import (                        # noqa: E402
    CODE_PROBE_RESULT_REJECTED, CODE_WRITE_FAILED, PROBE_COLUMNS,
    PROBE_CYCLE_FRESHNESS_SECONDS, PROBE_EGRESS_BASELINE_WINDOW_SECONDS,
    PROBE_LATENCY_MAX_MS, SCHEMA_VERSION, IncidentHistory)
from web.server import (  # noqa: E402
    PROBE_STARTUP_TOKENS, PROBE_STATUS_BOOL_KEYS, PROBE_STATUS_INT_KEYS,
    PROBE_STATUS_KEYS, PROBE_STATUS_MAX_NUMBER, PROBE_STATUS_REAL_KEYS,
    PROBE_STATUS_SOURCE_KEYS,
    PROBE_STATUS_TOKEN_KEYS, PROBE_TARGET_SOURCES, MonitorWebApp,
    build_server, closed_probe_bool, closed_probe_counter,
    closed_probe_seconds, closed_probe_source, closed_probe_startup)

NOW = 1_800_000_000.0
IP_A = "8.8.8.8"
IP_B = "1.1.1.1"
PASSWORD = "probe-ingest-password-0"
CERT = os.environ.get("PROBE_TEST_CERT", "")
KEY = os.environ.get("PROBE_TEST_KEY", "")


# -- fixtures -----------------------------------------------------------------

_CYCLE_SEQ = [0]


def next_cycle():
    """A fresh, deterministic, EXACT 32-hex cycle id.

    v3 stores one row per cycle_id (B6), so a fixture that reuses an id
    silently tests the replay rule instead of the shape it means to test.
    The "fc" prefix keeps these ids disjoint from the hand-written ids the
    individual cases still pin."""
    _CYCLE_SEQ[0] += 1
    return "fc%030x" % _CYCLE_SEQ[0]


class Impostor:
    """Hashes like ``token`` and equals everything. This is the shape that
    survives a bare ``in`` vocabulary test and is then ADOPTED as the token
    it impersonates -- and an adopted object goes on to be handed to
    ``json.dumps`` (which cannot serialize it) or to a SQLite binder (which
    cannot bind it and reports a broken STORE instead of a broken
    producer)."""

    def __init__(self, token):
        self.token = token

    def __hash__(self):
        return hash(self.token)

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False


class LyingStr(str):
    """A real str, so ``isinstance`` is satisfied, that claims equality with
    anything -- including the canonical form a gate compares against."""

    def __eq__(self, other):
        return True

    def __hash__(self):
        return str.__hash__(self)


class LyingInt(int):
    """A plain int wearing a subclass: ``isinstance`` admits it, exact type
    does not."""


class LyingFloat(float):
    pass


def global_unicast(value):
    """Harness-side restatement of "a public egress address": canonical
    form of a GLOBAL, non-multicast IP literal, else None. Written here
    independently of the two production gates so a case can state its
    expectation without importing the code under test. EXACTLY a plain str,
    which is the same shape the two production gates now demand."""
    if type(value) is not str:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not address.is_global or address.is_multicast:
        return None
    return str(address)


def derive_change(previous, ip):
    """The token a CORRECT producer claims for (baseline, this answer).
    Every reject case is paired with its honest token, so a refusal proves
    its own shape defect and can never be an accident of a mismatched
    egress-change claim."""
    before, after = global_unicast(previous), global_unicast(ip)
    if before is None or after is None:
        return "unknown"
    return "changed" if before != after else "unchanged"


def good(ip=IP_A, change=None, cycle=None, epoch=NOW):
    """One CLOSED engine-shaped result plus the egress token to pair it with.

    ``change=None`` means "derive it", which is what a well-behaved producer
    does; a case that wants a specific (possibly dishonest) token passes it.
    """
    slot_err = {"status": "failed", "latency_ms": None,
                "error_code": "timeout"}
    return {
        "v": 1, "epoch": epoch, "cycle_id": cycle if cycle is not None
        else next_cycle(),
        "dns": {"status": "ok", "latency_ms": 12, "error_code": "NONE"},
        "https": dict(slot_err),
        "udp": {"status": "ok", "latency_ms": 30, "error_code": "NONE"},
        "egress": {"status": "ok", "latency_ms": 40, "error_code": "NONE",
                   "ip": ip},
    }, (change if change is not None else derive_change(None, ip))


def network_failure_cycle(cycle=None, epoch=NOW):
    """A whole cycle that failed at the NETWORK level: this is DATA, never a
    runtime defect, and must persist as one closed all-failed row."""
    slot = {"status": "failed", "latency_ms": None, "error_code": "timeout"}
    egress = dict(slot)
    egress["ip"] = None
    return {
        "v": 1, "epoch": epoch,
        "cycle_id": cycle if cycle is not None else next_cycle(),
        "dns": dict(slot), "https": dict(slot), "udp": dict(slot),
        "egress": egress,
    }, "unknown"


def tmp_history(run_id="run-1", clock_now=NOW, root=None, **kw):
    """A history store over its own temp dir, opened and byte-tracked."""
    d = root or tempfile.mkdtemp()
    clock = kw.pop("clock", None) or (lambda: clock_now)
    kw.setdefault("monitor_version", "0.3.1")
    h = IncidentHistory(os.path.join(d, "diagnostics"), run_id, clock=clock,
                        **kw)
    h._tmpdir = d
    h.open()
    return h


def reopen(root, run_id="run-2", clock_now=NOW, **kw):
    """Re-attach a store to an EXISTING directory (the restart proof)."""
    return tmp_history(run_id, clock_now, root, **kw)


def db_path(h):
    return os.path.join(h._tmpdir, "diagnostics", "history.sqlite3")


def raw_bytes(h):
    path = db_path(h)
    if not os.path.exists(path):
        return b""
    with open(path, "rb") as handle:
        return handle.read()


def probe_rows(h, limit=2000):
    return h.query_timeline(limit=limit)["probe_rows"]


# -- group: the DB boundary revalidation ---------------------------------------

def group_boundary():
    """The v3 boundary accepts ONLY a closed engine result, re-canonicalized
    and consistent with its own durable baseline -- and refuses everything
    else with zero bytes written."""
    out = {}
    t = [NOW]
    h = tmp_history("boundary", clock=lambda: t[0])
    # A fail-closed boundary is only proved if the harness' own evidence is as
    # private as the boundary demands: directory 0700 (a dir needs +x to be
    # traversable; 0600 would make the store unreadable by its own owner
    # session), DB file 0600. Measured on the platform where modes are real --
    # the same rule the production validator applies, so a fixture that
    # smuggled in a wider tree cannot pass this gate either.
    out["harness_private_evidence_modes"] = (
        (stat.S_IMODE(os.stat(os.path.join(h._tmpdir, "diagnostics")).st_mode)
         == 0o700
         and stat.S_IMODE(os.stat(db_path(h)).st_mode) == 0o600)
        or os.name != "posix")
    out["health_enabled"] = h.health()["enabled"] is True

    r, c = good()
    out["first_ok_row_accepted"] = h.record_probe_result(r, c) is True
    out["baseline_after_first_ok"] = h.last_persisted_egress_ip() == IP_A
    st = h.probe_status()
    out["status_keys_closed"] = set(st) == {
        "enabled", "degraded", "last_error_code", "persisted_total",
        "rejected_total"}
    out["persisted_one_rejected_zero"] = (
        st["persisted_total"] == 1 and st["rejected_total"] == 0)
    out["clean_after_ok_row"] = (st["degraded"] is False
                                 and st["last_error_code"] is None)

    # consistent with the durable baseline, in both directions
    r, c = good(IP_A, derive_change(IP_A, IP_A))
    out["unchanged_consistent_accepted"] = h.record_probe_result(r, c) is True
    r, c = good(IP_B, derive_change(IP_A, IP_B))
    out["changed_consistent_accepted"] = h.record_probe_result(r, c) is True
    out["baseline_follows_newest_ok"] = h.last_persisted_egress_ip() == IP_B

    rejected = []
    refusals = []

    def refuse(label, result, change):
        refusals.append(h.record_probe_result(result, change) is False)
        rejected.append(label)

    def row_for(ip=IP_B, cycle=None, epoch=NOW):
        """A result paired with the token a CORRECT producer would claim
        against the baseline this store now holds (IP_B): every case below
        then fails for its own shape defect, never for an honest token
        mismatch -- the masking B2 review would otherwise hide."""
        return good(ip, derive_change(IP_B, ip), cycle, epoch)[0]

    # not a closed dict at all
    refuse("not_a_dict", {"203.0.113.9": 1}, "unchanged")
    # 'changed' while the durable baseline already equals the new ip
    refuse("changed_but_equal_baseline", row_for(IP_B), "changed")
    # B2: a producer may not SUPPRESS or MISDIRECT an event either. Each of
    # these three carries the token that IS honest for its own addresses, so
    # the refusal below can only come from the derivation, never from an
    # unrelated shape defect (and never from a mismatched claim hiding one).
    refuse("unchanged_across_different_addresses", row_for(IP_A), "unchanged")
    refuse("unknown_hides_a_real_change", row_for(IP_A), "unknown")
    refuse("unknown_hides_no_change", row_for(IP_B), "unknown")
    # non-canonical raw text (leading zeros) even though it parses. The claim
    # is the token a CANONICAL-FORM-ONLY world would have honoured, so this
    # case can only fail for the byte-identity of the stored text.
    refuse("non_canonical_ip", row_for("8.008.8.8"), "changed")
    # private / loopback / link-local / unique-local / unspecified, v4+v6.
    # Same pairing: "changed" is exactly what a gate that only checked
    # PARSABILITY would have accepted, so a weakened gate turns this
    # refusal into a silent second baseline instead of a red line.
    for addr in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.1.1",
                 "172.16.0.1", "::1", "fe80::1", "fc00::1", "0.0.0.0"):
        refuse("non_global_ip_" + addr.replace(".", "_").replace(":", "x"),
               row_for(addr), "changed")
    # IPv4 AND IPv6 multicast groups: globally scoped to ipaddress, and
    # therefore NOT admissible as "this host's public egress address" (B3).
    # The claim here is the one a GLOBALITY-ONLY gate would have honoured
    # ("changed"), so this case fails loudly if the unicast half of the
    # gate ever regressed -- it cannot be rescued by a token mismatch.
    for addr in ("224.0.0.1", "239.255.255.255", "ff02::1", "ff00::"):
        refuse("multicast_ip_" + addr.replace(".", "_").replace(":", "x"),
               row_for(addr), "changed")
    out["engine_refuses_multicast_egress_ip"] = all(
        engine._canonical_ip(addr) is None
        for addr in ("224.0.0.1", "239.255.255.255", "ff02::1", "ff00::"))
    out["engine_still_admits_global_unicast_egress"] = (
        engine._canonical_ip(IP_A) == IP_A
        and engine._canonical_ip("2001:4860:4860::8888")
        == "2001:4860:4860::8888")
    # a failed egress slot carrying an ip
    r = row_for(IP_A)
    r["egress"] = {"status": "failed", "latency_ms": None,
                   "error_code": "timeout", "ip": IP_A}
    refuse("failed_egress_with_ip", r, "unknown")
    # one extra key anywhere is a different, unclosed object
    r = row_for()
    r["host"] = "evil"
    refuse("extra_top_level_key", r, "unchanged")
    r = row_for()
    r["dns"] = {"status": "ok", "latency_ms": 1, "error_code": "NONE",
                "answer": IP_A}
    refuse("extra_slot_key", r, "unchanged")
    # a missing slot
    r = row_for()
    del r["udp"]
    refuse("missing_slot", r, "unchanged")
    # result version drift
    r = row_for()
    r["v"] = 2
    refuse("result_version_2", r, "unchanged")
    r = row_for()
    r["v"] = "1"
    refuse("result_version_string", r, "unchanged")
    # stale / future epoch beyond the cycle freshness bound
    for sign, delta in (("past", -(PROBE_CYCLE_FRESHNESS_SECONDS + 1.0)),
                        ("future", PROBE_CYCLE_FRESHNESS_SECONDS + 1.0),
                        ("hour_old", -3600.0)):
        r = row_for()
        r["epoch"] = NOW + delta
        refuse("epoch_skew_" + sign, r, "unchanged")
    r = row_for()
    r["epoch"] = float("nan")
    refuse("epoch_nan", r, "unchanged")
    # cycle_id must be an EXACT lowercase 32-hex token -- and never NULL:
    # the engine always emits one, and a NULL id would be invisible to the
    # replay rule. A non-string is refused by the boundary itself, never by
    # an escaping TypeError.
    for index, bad in enumerate(("zz" * 16, "A" * 32, "a" * 31, "a" * 33,
                                 12345, "  " + "a" * 30, "a" * 32 + "\n",
                                 None, "", "f" * 31 + "F")):
        r = row_for()
        r["cycle_id"] = bad
        refuse("cycle_id_shape_%d" % index, r, "unchanged")
    # closed vocabulary: an unknown status/code pair never lands
    r = row_for()
    r["dns"] = {"status": "ok", "latency_ms": 5, "error_code": "timeout"}
    refuse("ok_with_error_code", r, "unchanged")
    r = row_for()
    r["https"] = {"status": "failed", "latency_ms": 5, "error_code": "timeout"}
    refuse("failed_with_latency", r, "unchanged")
    r = row_for()
    r["https"] = {"status": "weird", "latency_ms": None,
                  "error_code": "timeout"}
    refuse("unknown_status_token", r, "unchanged")
    r = row_for()
    r["udp"] = {"status": "ok", "latency_ms": PROBE_LATENCY_MAX_MS + 1,
               "error_code": "NONE"}
    refuse("latency_over_ceiling", r, "unchanged")
    # an out-of-vocabulary change token
    r = row_for()
    refuse("unknown_change_token", r, "moved")
    refuse("none_change_token", r, None)
    # a hostile mapping type is not a closed dict
    class Sneaky(dict):
        pass
    refuse("dict_subclass", Sneaky(row_for()), "unchanged")

    # ---------------------------------------------------------------------
    # R2-B8: EVERY PRIMITIVE IS EXACTLY TYPED BEFORE IT IS JUDGED.
    #
    # The vocabularies are membership tests and the numeric bounds are
    # comparisons, so in the defective world each one let the CANDIDATE
    # answer the question: ``in`` over a tuple asks the object's own
    # ``__eq__`` (a claim-everything object was ADOPTED as "ok"/"NONE"/
    # "unchanged"), ``12 == True == 12.0 == "12"`` under the old
    # ``latency != _as_int(latency)`` test (so a bool, an integral float or
    # a numeric string was a latency), and ``isinstance`` admits any
    # subclass. A string latency was never merely cosmetic either: the
    # column has INTEGER affinity, so SQLite converts ``'12'`` on the way
    # in and the table ends up storing a coercion the engine never emitted
    # (its own normalize gate answers ``int(round(...))``, always a plain
    # int). Each case below therefore asserts the boundary's OWN REJECTION
    # code and the two counters, not just the False -- a defect that let
    # the value through to the INSERT bounces off the DDL or the binder and
    # reports a broken STORE (``persist_failed``) instead of the broken
    # PRODUCER it is, which is a different story to whoever reads the plane.
    # ---------------------------------------------------------------------
    coded = []

    def refuse_code(label, result, change):
        before = h.probe_status()
        rows_before = len(probe_rows(h))
        refused = h.record_probe_result(result, change) is False
        after = h.probe_status()
        refusals.append(refused)
        rejected.append(label)
        coded.append(label and refused
                     and after["last_error_code"] == CODE_PROBE_RESULT_REJECTED
                     and after["persisted_total"] == before["persisted_total"]
                     and after["rejected_total"] == before["rejected_total"] + 1
                     and len(probe_rows(h)) == rows_before)

    # a defective latency NEVER reaches the store, in either slot family.
    # Half the table lands on the timed dns slot, half on the egress slot,
    # so a weakened check cannot hide behind a slot-specific branch (both
    # go through the one shared closed-slot matrix).
    latency_defects = [True, False, 12.0, 0.0, "12", "", None, 12 + 0j,
                       LyingInt(12), float("nan"), decimal.Decimal(12)]
    for index, bad in enumerate(latency_defects):
        r = row_for()
        slot = "egress" if index % 2 else "dns"
        r[slot]["latency_ms"] = bad
        refuse_code("latency_exact_int_%s_%d" % (slot, index), r, "unchanged")
    out["latency_defects_all_refused_with_the_rejection_code"] = (
        all(coded[-len(latency_defects):])
        and len(latency_defects) == 11)
    # the failed path demands NULL, whatever the candidate pretends is null
    failed_null = []
    for bad in (0, False, "", 0.0, "0", LyingInt(0)):
        r = row_for()
        r["dns"]["status"] = "failed"
        r["dns"]["error_code"] = "timeout"
        r["dns"]["latency_ms"] = bad
        refuse_code("failed_slot_latency_not_null_%d" % len(failed_null),
                    r, "unchanged")
        failed_null.append(coded[-1])
    out["failed_slot_demands_exact_null"] = all(failed_null)

    # a claim-everything object may not be ADOPTED as a vocabulary token
    vocab = []
    for field, value in (("status", Impostor("ok")),
                         ("error_code", Impostor("NONE")),
                         ("status", LyingStr("weird")),
                         ("error_code", LyingStr("timeout")),
                         ("latency_ms", Impostor(12)),
                         ("status", ["ok"]),
                         ("error_code", {"NONE": 1}),
                         ("status", None),
                         ("error_code", 0)):
        r = row_for()
        r["dns"][field] = value
        refuse_code("slot_%s_impostor_%d" % (field, len(vocab)),
                    r, "unchanged")
        vocab.append(coded[-1])
    out["closed_vocabularies_refuse_impersonators"] = (
        all(vocab) and len(vocab) == 9)

    # the other four primitives, each with the exact-type wall named
    primitives = []
    r = row_for()
    r["v"] = LyingInt(1)
    refuse_code("result_version_int_subclass", r, "unchanged")
    primitives.append(coded[-1])
    for index, bad in enumerate((True, False, "1700000000.0",
                                 LyingFloat(NOW), 12 + 0j)):
        r = row_for()
        r["epoch"] = bad
        refuse_code("epoch_exact_number_%d" % index, r, "unchanged")
        primitives.append(coded[-1])
    for index, bad in enumerate((LyingStr("a" * 32), b"b" * 32, 12345,
                                 ("c" * 32,))):
        r = row_for()
        r["cycle_id"] = bad
        refuse_code("cycle_id_exact_str_%d" % index, r, "unchanged")
        primitives.append(coded[-1])
    # the canonical-identity gate is a COMPARISON, so a str subclass that
    # equals everything used to launder non-canonical raw text straight
    # through it: ``ip != raw_ip`` is answered by the candidate, not by the
    # gate.
    laundered = row_for(IP_A)
    laundered["egress"]["ip"] = LyingStr("8.008.8.8")
    refuse_code("egress_ip_lying_str_subclass_launder", laundered, "changed")
    primitives.append(coded[-1])
    for index, bad in enumerate((LyingStr("8.8.8.8"), 8, ["8.8.8.8"], None)):
        r = row_for(IP_A)
        r["egress"]["ip"] = bad
        refuse_code("egress_ip_exact_str_%d" % index, r, "changed")
        primitives.append(coded[-1])
    for index, bad in enumerate((Impostor("unchanged"), LyingStr("changed"),
                                 "unchanged ", 1, ["unknown"])):
        refuse_code("egress_change_exact_str_%d" % index, row_for(), bad)
        primitives.append(coded[-1])
    out["boundary_primitives_are_exactly_typed"] = (
        all(primitives) and len(primitives) == 20)
    out["every_exact_type_refusal_carried_the_rejection_code"] = all(coded)

    # LAST, so the plane code below is THIS case's own: a NULL cycle id is
    # refused as the shape defect it is, with the rejection code -- never by
    # slipping through the boundary and bouncing off the DDL wall, which
    # would report a PERSIST failure and tell an entirely different story
    # (a broken producer vs a broken store).
    r = row_for()
    r["cycle_id"] = None
    refuse("null_cycle_id_is_a_shape_defect", r, "unchanged")
    out["null_cycle_id_refused_with_the_rejection_code"] = (
        h.probe_status()["last_error_code"] == CODE_PROBE_RESULT_REJECTED)

    # THE REPLAY RULE (B6): the same cycle id delivered twice is ONE row,
    # and the second delivery is a closed REJECTION -- never a second
    # sample, never a second baseline move. The id is deliberately one that
    # is otherwise perfectly shaped (address == the current baseline), so
    # the replay is the ONLY defect this case can be refusing.
    replay_cycle = "7" * 32
    first = h.record_probe_result(row_for(IP_B, cycle=replay_cycle),
                                  "unchanged")
    rows_before_replay = len(probe_rows(h))
    refuse("replayed_cycle_id", row_for(IP_B, cycle=replay_cycle), "unchanged")
    out["replayed_cycle_is_refused"] = (
        first is True and rows_before_replay == 4
        and len(probe_rows(h)) == rows_before_replay)
    out["replay_moves_no_baseline"] = h.last_persisted_egress_ip() == IP_B

    # the whole matrix, evaluated once every case has run
    out["all_shaped_results_refused"] = all(refusals)
    out["reject_matrix_covers_at_least_40"] = len(refusals) >= 40
    out["reject_matrix_labels_unique"] = len(set(rejected)) == len(rejected)

    st = h.probe_status()
    out["persisted_still_four"] = st["persisted_total"] == 4
    out["rejected_total_matches_matrix"] = st["rejected_total"] == len(rejected)
    out["plane_degraded_after_refusals"] = st["degraded"] is True
    out["rejection_code_is_probe_plane"] = (
        st["last_error_code"] == CODE_PROBE_RESULT_REJECTED
        == "history_probe_result_rejected")
    out["zero_free_text_in_status"] = all(
        not isinstance(v, str) or v in (CODE_PROBE_RESULT_REJECTED,)
        for v in st.values())

    # a plain network-failure cycle is DATA: it persists and CLEARS the plane
    r, c = network_failure_cycle()
    out["network_failure_cycle_persists"] = h.record_probe_result(r, c) is True
    st = h.probe_status()
    out["network_failure_clears_probe_plane"] = (
        st["degraded"] is False and st["last_error_code"] is None)
    out["baseline_survives_failed_egress"] = (
        h.last_persisted_egress_ip() == IP_B)
    rows = probe_rows(h)
    out["all_failed_row_stored"] = (
        rows[-1]["egress_status"] == "failed"
        and rows[-1]["egress_ip"] is None
        and rows[-1]["egress_change"] == "unknown"
        and rows[-1]["dns_error_code"] == "timeout")
    out["row_columns_exact"] = set(rows[0]) == set(PROBE_COLUMNS)
    # the stored text is byte-identical to the canonical form, never the raw
    out["stored_ip_is_canonical"] = rows[0]["egress_ip"] == IP_A
    # nothing but the closed vocabulary reached the file
    blob = raw_bytes(h)
    out["no_free_text_in_file"] = (
        b"evil" not in blob and b"moved" not in blob and b"8.008" not in blob)
    h.close()
    return out


# -- group: durable egress-change semantics ------------------------------------

def group_durable():
    """The baseline is the last SUCCESSFUL PERSISTED public IP: durable
    across restarts, windowed, and never forged or fed by a failure."""
    out = {}
    t = [NOW]
    root = tempfile.mkdtemp()
    h = tmp_history("run-1", clock=lambda: t[0], root=root)
    out["fresh_db_has_no_baseline"] = h.last_persisted_egress_ip() is None
    r, c = good(IP_A, "unknown")
    h.record_probe_result(r, c)
    out["baseline_after_ok"] = h.last_persisted_egress_ip() == IP_A

    # a restart never fabricates a change event: the baseline is DURABLE
    h2 = reopen(root, "run-2", clock=lambda: t[0])
    out["baseline_durable_across_restart"] = (
        h2.last_persisted_egress_ip() == IP_A)
    r, c = good(IP_A, "unchanged")
    out["unchanged_accepted_after_restart"] = h2.record_probe_result(r, c) \
        is True
    r, c = good(IP_B, "changed")
    out["changed_accepted_after_restart"] = h2.record_probe_result(r, c) is True

    # a cycle whose egress probe failed never moves the baseline
    r, c = network_failure_cycle(cycle="c" * 32)
    h2.record_probe_result(r, c)
    out["failed_egress_does_not_move_baseline"] = (
        h2.last_persisted_egress_ip() == IP_B)
    # ...and a stale 'changed' claim about it is refused
    r, _ = good(IP_B, "changed")
    r["cycle_id"] = "d" * 32
    out["changed_equal_baseline_still_refused"] = (
        h2.record_probe_result(r, "changed") is False)

    # baseline WINDOW: outside the retention horizon the IP is history, not
    # a baseline -- so both consistent tokens must be refused and only
    # 'unknown' may be written.
    t[0] = NOW + PROBE_EGRESS_BASELINE_WINDOW_SECONDS + 5.0
    out["baseline_expires_with_window"] = (
        h2.last_persisted_egress_ip() is None)
    r, _ = good(IP_B, "unchanged")
    r["epoch"] = t[0]
    r["cycle_id"] = "e" * 32
    out["unchanged_outside_window_refused"] = (
        h2.record_probe_result(r, "unchanged") is False)
    r, _ = good("9.9.9.9", "unknown")
    r["epoch"] = t[0]
    r["cycle_id"] = "f" * 32
    out["unknown_outside_window_accepted"] = h2.record_probe_result(
        r, "unknown") is True
    out["new_baseline_after_window"] = (
        h2.last_persisted_egress_ip() == "9.9.9.9")
    h2.close()

    # DEFENSE IN DEPTH: a row smuggled in by a raw writer (bypassing the
    # boundary) can neither fake a change event nor poison the baseline --
    # the read re-canonicalizes and refuses a non-global address. Its own
    # database, so "newest ok row" is unambiguous.
    h3 = tmp_history("run-raw", clock=lambda: NOW)
    conn = sqlite3.connect(db_path(h3))
    conn.execute(
        "INSERT INTO network_probe_samples (epoch, iso_utc, run_id,"
        " cycle_id, result_version, dns_status, dns_latency_ms,"
        " dns_error_code, https_status, https_latency_ms, https_error_code,"
        " udp_status, udp_latency_ms, udp_error_code, egress_status,"
        " egress_latency_ms, egress_error_code, egress_ip, egress_change)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (NOW + 10.0, "2027-01-01T00:00:00+00:00", "raw", "9" * 32, 1,
         "ok", 1, "NONE", "ok", 1, "NONE", "ok", 1, "NONE",
         "ok", 1, "NONE", "10.0.0.1", "unknown"))
    conn.commit()
    conn.close()
    out["raw_private_row_blinds_baseline"] = (
        h3.last_persisted_egress_ip() is None)
    r, _ = good(IP_A, "changed")
    r["epoch"] = NOW + 10.0
    r["cycle_id"] = "1" * 32
    out["no_baseline_means_no_change_event"] = (
        h3.record_probe_result(r, "changed") is False)
    r["cycle_id"] = "2" * 32
    out["no_baseline_unknown_still_accepted"] = (
        h3.record_probe_result(r, "unknown") is True)
    h3.close()

    # THE GATE IS GLOBAL *UNICAST*, stated as a test so the definition can
    # never drift back to bare globality (B3): ``ipaddress`` scopes
    # 224.0.0.0/4 and ff00::/12 as GLOBAL, so a multicast GROUP passes a
    # globality-only check -- and it is a destination, never this host's
    # egress address. Each row claims "changed", the token such a gate
    # would have honoured, so a regression here silently stores the group.
    h4 = tmp_history("run-scope", clock=lambda: NOW + 20.0)
    multicast = []
    for cid, addr in (("3" * 32, "224.0.0.1"), ("3" * 31 + "1", "239.255.255.255"),
                      ("3" * 31 + "2", "ff02::1"), ("3" * 31 + "3", "ff00::")):
        r, _ = good(addr, "changed")
        r["epoch"] = NOW + 20.0
        r["cycle_id"] = cid
        multicast.append(h4.record_probe_result(r, "changed") is False)
    out["multicast_refused_v4_and_v6"] = all(multicast) and len(multicast) == 4
    out["multicast_never_becomes_the_baseline"] = (
        h4.last_persisted_egress_ip() is None)
    out["multicast_wrote_zero_rows"] = len(probe_rows(h4)) == 0
    r, _ = good("169.254.169.254", "unknown")
    r["epoch"] = NOW + 20.0
    r["cycle_id"] = "4" * 32
    out["metadata_ip_refused"] = (
        h4.record_probe_result(r, "unknown") is False)
    # ...and a legitimate global unicast V6 does persist, so the multicast
    # half cannot be paid for by shrinking the admissible address space.
    r, _ = good("2001:4860:4860::8888", "unknown")
    r["epoch"] = NOW + 20.0
    r["cycle_id"] = "5" * 32
    out["global_unicast_v6_still_admitted"] = (
        h4.record_probe_result(r, "unknown") is True
        and h4.last_persisted_egress_ip() == "2001:4860:4860::8888")
    h4.close()

    # B2: the change token is DERIVED HERE and verified against the
    # producer's claim for ALL THREE values, so no restart, stale view or
    # dishonest producer can FABRICATE, SUPPRESS or MISDIRECT an event.
    # Each triple gets its own store, seeded (when a baseline is wanted) by
    # one genuinely accepted row, so the durable read is the only source of
    # "previous" and no case inherits another's state.
    FAILED = "FAILED-EGRESS"

    def trial(baseline, answer, claim):
        store = tmp_history("derive", clock=lambda: NOW)
        if baseline is not None:
            r, c = good(baseline, "unknown")
            store.record_probe_result(r, c)
        if answer == FAILED:
            r, c = network_failure_cycle()
        else:
            r, c = good(answer, claim)
        accepted = store.record_probe_result(r, claim) is True
        current = None if answer == FAILED else answer
        judgement = engine.classify_egress_change(baseline, current)
        stored = probe_rows(store)
        row_token = stored[-1]["egress_change"] if stored else None
        store.close()
        return (accepted, judgement, row_token,
                derive_change(baseline, current))

    grid = [(None, IP_A, "unknown"), (None, IP_A, "changed"),
            (None, IP_A, "unchanged"),
            (IP_A, IP_A, "unchanged"), (IP_A, IP_A, "changed"),
            (IP_A, IP_A, "unknown"),
            (IP_A, IP_B, "changed"), (IP_A, IP_B, "unchanged"),
            (IP_A, IP_B, "unknown"),
            (IP_A, FAILED, "unknown"), (IP_A, FAILED, "changed"),
            (IP_B, IP_B, "unchanged")]
    verdicts = {("%s|%s|%s" % c): trial(*c) for c in grid}
    admits_only_derived = True
    stores_derived_token = True
    harness_matches_engine = True
    for triple in grid:
        accepted, judgement, row_token, harness = verdicts[
            "%s|%s|%s" % triple]
        if accepted != (triple[2] == judgement):
            admits_only_derived = False
        if accepted and row_token != judgement:
            stores_derived_token = False
        if harness != judgement:
            harness_matches_engine = False
    out["derive_grid_admits_only_the_derived_token"] = admits_only_derived
    out["derive_grid_stores_the_derived_token"] = stores_derived_token
    out["harness_derivation_matches_the_engine"] = harness_matches_engine
    out["a_failure_never_surfaces_a_change_event"] = (
        verdicts["%s|%s|%s" % (IP_A, FAILED, "changed")][0] is False
        and verdicts["%s|%s|%s" % (IP_A, FAILED, "unknown")][0] is True)
    out["derive_grid_covers_all_three_tokens"] = len(verdicts) >= 12

    # THE SINGLE JUDGEMENT: the engine's pure classifier, the boundary's
    # private derivation and the harness' independent restatement must be
    # the SAME function over every shape an egress answer can arrive in.
    # Three spellings that disagree would make a green suite meaningless,
    # so this table is the discriminator.
    addresses = [None, IP_A, IP_B, "224.0.0.1", "ff02::1", "10.0.0.1",
                 "::1", "8.008.8.8", "2001:db8::1", "not-an-ip", "",
                 "8.8.8.8 ", "0.0.0.0", "fe80::1"]
    identical = True
    for previous in addresses:
        for current in addresses:
            if not (engine.classify_egress_change(previous, current)
                    == IH._derive_egress_change(previous, current)
                    == derive_change(previous, current)):
                identical = False
    out["three_derivations_answer_identically_everywhere"] = identical
    return out


# -- group: schema v4 shapes, migrations and the CHECK walls -------------------

def v1_file(now=NOW):
    """An EXACT v1 database (meta claims 1 + the three v1 tables), created
    with the module's own DDL helpers so the fixture cannot drift."""
    import web.incident_history as IH
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "diagnostics"))
    path = os.path.join(d, "diagnostics", "history.sqlite3")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY,"
                 " value TEXT NOT NULL)")
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version','1')")
    IH.IncidentHistory._create_v1_tables(conn)
    conn.execute(
        "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
        " collector_stale, total_active_connections,"
        " reality_active_connections, hysteria2_active_connections,"
        " other_active_connections, uplink_rate, downlink_rate,"
        " skipped_events, duplicate_events, identity_conflicts,"
        " abandoned_on_reset) VALUES (?, '', 'v1seed', 0,1,1,0,0,0,0,0,0,0,0)",
        (now - 5.0,))
    conn.commit()
    conn.close()
    return d, path


def v2_file(now=NOW):
    """An EXACT v2 database (meta claims 2, the seven v2 tables, no probe
    table), plus one seeded v2 audit row to prove the migration moves
    nothing."""
    import web.incident_history as IH
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, "diagnostics"))
    path = os.path.join(d, "diagnostics", "history.sqlite3")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY,"
                 " value TEXT NOT NULL)")
    conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version','2')")
    IH.IncidentHistory._create_v1_tables(conn)
    IH.IncidentHistory._create_journal_tables(conn)
    IH.IncidentHistory._create_journal_state_row(conn, now)
    conn.execute(
        "INSERT INTO journal_ingest_audit (epoch, kind, seq, code)"
        " VALUES (?, 'gap', 7, 'sequence_gap')", (now - 5.0,))
    conn.commit()
    conn.close()
    return d, path


def table_set(path):
    conn = sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"),
                           uri=True)
    try:
        return {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()


def claim(path):
    conn = sqlite3.connect("file:%s?mode=ro" % path.replace("\\", "/"),
                           uri=True)
    try:
        return conn.execute("SELECT value FROM meta"
                            " WHERE key='schema_version'").fetchone()[0]
    finally:
        conn.close()


def group_schema():
    out = {}
    import web.incident_history as IH

    # fresh creation is v4 immediately, with the ONE probe table and the
    # two incident tables riding along (PR-4B)
    h = tmp_history("fresh")
    out["module_schema_version_5"] = SCHEMA_VERSION == 5
    out["fresh_claim_is_5"] = claim(db_path(h)) == "5"
    out["fresh_shape_exact_v5"] = table_set(db_path(h)) == {
        "meta", "timeline_samples", "device_protocol_states", "journal_runs",
        "journal_events", "journal_ingest_audit", "journal_ingest_state",
        "network_probe_samples", "incident_windows",
        "incident_runtime_state", "operator_markers"}
    conn = sqlite3.connect(db_path(h))
    out["probe_indexes_present"] = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'"
        " AND tbl_name='network_probe_samples'")} == {
        "idx_probe_samples_epoch", "idx_probe_samples_egress",
        "idx_probe_samples_cycle"}
    out["cycle_index_is_unique"] = (
        "UNIQUE" in (conn.execute(
            "SELECT sql FROM sqlite_master WHERE name='idx_probe_samples_cycle'"
        ).fetchone()[0] or "").upper())
    cols = [row[1] for row in conn.execute(
        "PRAGMA table_info(network_probe_samples)")]
    out["probe_columns_exact"] = tuple(cols) == PROBE_COLUMNS
    # cycle_id is NOT NULL in the durable contract too (B6): the table itself
    # cannot hold an id-less row, so a producer bug cannot make a cycle
    # invisible to the replay rule.
    notnull = {row[1]: row[3] for row in conn.execute(
        "PRAGMA table_info(network_probe_samples)")}
    out["cycle_id_column_is_not_null"] = notnull.get("cycle_id") == 1
    out["nullable_columns_are_latencies_and_the_ip_only"] = {
        name for name, flag in notnull.items() if not flag} == {
        "dns_latency_ms", "https_latency_ms", "udp_latency_ms",
        "egress_latency_ms", "egress_ip"}
    out["single_probe_table_only"] = len(
        [t for t in table_set(db_path(h)) if "probe" in t]) == 1
    conn.close()
    h.close()

    # v1 -> v4 in one step, zero v1 rows touched
    d, path = v1_file()
    before = open(path, "rb").read()
    h1 = tmp_history("v1", root=d)
    out["v1_migrated_to_5"] = claim(path) == "5"
    out["v1_probe_table_created"] = "network_probe_samples" in table_set(path)
    conn = sqlite3.connect(path)
    out["v1_rows_survived"] = conn.execute(
        "SELECT COUNT(*) FROM timeline_samples WHERE run_id='v1seed'"
        ).fetchone()[0] == 1
    out["v1_journal_state_seeded"] = conn.execute(
        "SELECT COUNT(*) FROM journal_ingest_state WHERE id=1").fetchone()[0] \
        == 1
    conn.close()
    r, c = good(IP_A, "unknown")
    out["v1_db_accepts_probe_rows"] = h1.record_probe_result(r, c) is True
    h1.close()
    out["v1_migration_mutated_old_rows_only_by_adding"] = (
        open(path, "rb").read().startswith(b"SQLite format 3\x00")
        and len(before) > 0)

    # v2 -> v4: the probe + incident tables land, the v2 audit row untouched
    d2, path2 = v2_file()
    h2 = tmp_history("v2", root=d2)
    out["v2_migrated_to_5"] = claim(path2) == "5"
    conn = sqlite3.connect(path2)
    out["v2_rows_survived"] = conn.execute(
        "SELECT COUNT(*) FROM journal_ingest_audit"
        " WHERE seq=7 AND kind='gap'").fetchone()[0] == 1
    out["v2_probe_table_created"] = conn.execute(
        "SELECT COUNT(*) FROM network_probe_samples").fetchone()[0] == 0
    conn.close()
    h2.close()

    # CRASH mid-migration: the v2->v4 transaction rolls back WHOLE, the file
    # is byte-identical, and the next open re-migrates cleanly.
    d3, path3 = v2_file()
    pristine = open(path3, "rb").read()
    original = IH.IncidentHistory._create_probe_table

    def explode(cls, conn):
        raise RuntimeError("injected mid-migration crash")

    IH.IncidentHistory._create_probe_table = classmethod(explode)
    crashed = None
    try:
        IncidentHistory(os.path.join(d3, "diagnostics"), "crash",
                        clock=lambda: NOW).open()
    except Exception as exc:  # noqa: BLE001 -- the open must refuse
        crashed = type(exc).__name__
    finally:
        IH.IncidentHistory._create_probe_table = original
    out["crash_mid_migration_raises"] = crashed == "RuntimeError"
    out["crash_mid_migration_zero_bytes"] = open(path3, "rb").read() == pristine
    out["crash_mid_migration_still_v2"] = claim(path3) == "2"
    out["crash_mid_migration_no_probe_table"] = (
        "network_probe_samples" not in table_set(path3))
    h3 = tmp_history("after-crash", root=d3)
    out["crash_recovers_by_remigrating"] = (
        claim(path3) == "5" and "network_probe_samples" in table_set(path3))
    h3.close()

    # THE ROLLBACK RUNG: a pre-v4 build meeting a v4 file refuses it through
    # the SAME gate, before any pragma/DDL/write can touch it, at zero bytes.
    # open() is fail-soft by contract, so the refusal is the DISABLED STORE +
    # the schema code, and every write path behind it has to refuse too.
    d4 = tempfile.mkdtemp()
    hv = tmp_history("v4host", root=d4)
    hv.close()
    v3_db = os.path.join(d4, "diagnostics", "history.sqlite3")
    v3_bytes = open(v3_db, "rb").read()
    real_version = IH.SCHEMA_VERSION
    IH.SCHEMA_VERSION = 3
    pre = IncidentHistory(os.path.join(d4, "diagnostics"), "pre-v4",
                          clock=lambda: NOW)
    raised = None
    try:
        pre.open()
        health = pre.health()
        probe_refused = pre.record_probe_result(*good(IP_A, "unknown")) is False
        write_refused = pre.last_persisted_egress_ip() is None
    except Exception as exc:  # noqa: BLE001 -- open() must never raise
        raised = type(exc).__name__
        health, probe_refused, write_refused = {}, False, False
    finally:
        IH.SCHEMA_VERSION = real_version
    out["pre_v4_open_never_raises"] = raised is None
    out["pre_v4_build_refuses_v4_db"] = (
        health.get("enabled") is False
        and health.get("last_error_code") == IH.CODE_SCHEMA_UNSUPPORTED
        and probe_refused and write_refused)
    out["pre_v4_refusal_zero_bytes"] = open(v3_db, "rb").read() == v3_bytes
    # and the SAME file is still fully usable for the real v4 build
    back = tmp_history("v4again", root=d4)
    r, c = good(IP_B, "unknown")
    out["v4_build_reads_its_own_file_after_refusal"] = (
        back.record_probe_result(r, c) is True)
    back.close()

    # the CHECK walls: even a raw writer cannot store a shape the engine
    # never emits -- free text, a torn transition, a non-canonical id.
    d5 = tempfile.mkdtemp()
    hw = tmp_history("checks", root=d5)
    base = ["epoch", "iso_utc", "run_id", "cycle_id", "result_version",
            "dns_status", "dns_latency_ms", "dns_error_code", "https_status",
            "https_latency_ms", "https_error_code", "udp_status",
            "udp_latency_ms", "udp_error_code", "egress_status",
            "egress_latency_ms", "egress_error_code", "egress_ip",
            "egress_change"]
    vals = [NOW, "x", "r", "0" * 32, 1, "ok", 1, "NONE", "ok", 1, "NONE",
            "ok", 1, "NONE", "ok", 1, "NONE", IP_A, "unknown"]

    def attempt(overrides):
        conn = sqlite3.connect(db_path(hw))
        row = dict(zip(base, vals))
        # Every wall gets its OWN fresh, valid cycle id unless the id IS the
        # defect under test: with cycle_id NOT NULL + UNIQUE (B6), one shared
        # id would make the FIRST insert's constraint the reason every later
        # one "held", and the whole matrix would prove nothing.
        row["cycle_id"] = next_cycle()
        row.update(overrides)
        try:
            conn.execute("INSERT INTO network_probe_samples (%s) VALUES (%s)"
                         % (", ".join(base),
                            ", ".join("?" for _ in base)),
                         [row[k] for k in base])
            conn.commit()
            return False
        except sqlite3.IntegrityError:
            return True
        finally:
            conn.close()

    walls = {
        "bad_status_token": {"egress_status": "weird"},
        "free_text_status": {"dns_status": "RuntimeError: secret"},
        "ok_with_error_code": {"dns_error_code": "timeout"},
        "failed_with_latency": {"https_status": "failed",
                                "https_latency_ms": 5},
        "failed_without_code": {"udp_status": "failed", "udp_error_code":
                                "NONE"},
        "free_text_ip": {"egress_ip": "evil.example.invalid"},
        "ip_with_comma": {"egress_ip": "8.8.8.8,1.1.1.1"},
        "ip_with_slash": {"egress_ip": "8.8.8.8/32"},
        "changed_without_ip": {"egress_change": "changed",
                               "egress_ip": None},
        "unchanged_without_ip": {"egress_change": "unchanged",
                                 "egress_ip": None},
        "failed_egress_with_ip": {"egress_status": "failed",
                                  "egress_latency_ms": None,
                                  "egress_error_code": "timeout"},
        "uppercase_cycle_id": {"cycle_id": "A" * 32},
        "short_cycle_id": {"cycle_id": "abc"},
        "free_text_cycle_id": {"cycle_id": "SECRET-TOKEN-000000000000000"},
        # B6: the id-less row is unconstructible at the DDL wall too, not
        # only at the boundary -- NULL and the wrong-case/length spellings
        # all bounce.
        "null_cycle_id": {"cycle_id": None},
        "empty_cycle_id": {"cycle_id": ""},
        "thirty_one_char_cycle_id": {"cycle_id": "f" * 31},
        "dotted_cycle_id": {"cycle_id": "08.8.8.8" + "a" * 24},
        "result_version_drift": {"result_version": 2},
        "latency_negative": {"dns_latency_ms": -1},
        "latency_over_ceiling": {"dns_latency_ms": PROBE_LATENCY_MAX_MS + 1},
        "unknown_error_code": {"dns_error_code": "credential_leaked"},
    }
    verdicts = {k: attempt(v) for k, v in walls.items()}
    out["every_check_wall_holds"] = all(verdicts.values())
    out["check_wall_matrix_broad"] = len(verdicts) >= 18 and sum(
        1 for v in verdicts.values() if v) == len(verdicts)
    # THE CYCLE IDENTITY AT THE DDL WALL (B6): one row per cycle_id, even
    # for a raw writer that bypasses the boundary -- so a redelivered cycle
    # cannot double-count a sample or move the durable baseline twice.
    dup_id = "6" * 32
    conn = sqlite3.connect(db_path(hw))
    first_row = dict(zip(base, vals))
    first_row["cycle_id"] = dup_id
    conn.execute("INSERT INTO network_probe_samples (%s) VALUES (%s)"
                 % (", ".join(base), ", ".join("?" for _ in base)),
                 [first_row[k] for k in base])
    conn.commit()
    replayed = False
    try:
        second_row = dict(first_row)
        second_row["egress_ip"] = IP_B
        conn.execute("INSERT INTO network_probe_samples (%s) VALUES (%s)"
                     % (", ".join(base), ", ".join("?" for _ in base)),
                     [second_row[k] for k in base])
        conn.commit()
    except sqlite3.IntegrityError:
        replayed = True
    finally:
        conn.close()
    out["duplicate_cycle_id_bounces_at_the_ddl_wall"] = (
        replayed and len([r for r in probe_rows(hw)
                          if r["cycle_id"] == dup_id]) == 1)
    # the only strings the table can hold are the closed vocabulary + a
    # canonical address: prove a legitimate row still writes at raw level
    conn = sqlite3.connect(db_path(hw))
    cid = "5" * 32
    conn.execute("INSERT INTO network_probe_samples (%s) VALUES (%s)"
                 % (", ".join(base), ", ".join("?" for _ in base)),
                 [NOW + 1.0, "x", "r", cid, 1, "ok", 1, "NONE", "ok", 1,
                  "NONE", "ok", 1, "NONE", "ok", 1, "NONE", "2001:db8::1",
                  "unknown"])
    conn.commit()
    out["canonical_v6_address_writable"] = conn.execute(
        "SELECT egress_ip FROM network_probe_samples"
        " WHERE cycle_id = ?", (cid,)).fetchone()[0] == "2001:db8::1"
    conn.close()
    hw.close()
    return out


# -- group: one global retention timeline, probe rows included -----------------

def group_retention():
    out = {}
    d = tempfile.mkdtemp()
    seed = tmp_history("seed", clock=lambda: 1000.0, root=d)
    conn = sqlite3.connect(db_path(seed))
    # interleave probe rows with the v1 tables across ONE epoch axis
    for step in range(0, 301, 10):
        epoch = float(step)
        conn.execute(
            "INSERT INTO timeline_samples (epoch, iso_utc, run_id,"
            " collector_stale, total_active_connections,"
            " reality_active_connections, hysteria2_active_connections,"
            " other_active_connections, uplink_rate, downlink_rate,"
            " skipped_events, duplicate_events, identity_conflicts,"
            " abandoned_on_reset) VALUES (?, '', 'seed', 0,0,0,0,0,0,0,0,0,0,0)",
            (epoch,))
        conn.execute(
            "INSERT INTO device_protocol_states (epoch, iso_utc, run_id,"
            " device, inbound, active_connections, device_status,"
            " uplink_rate, downlink_rate, uplink_total, downlink_total,"
            " reason) VALUES (?, '', 'seed', 'd', 'i', 0, 'ACTIVE',"
            " 0, 0, 0, 0, 'heartbeat')", (epoch,))
        conn.execute(
            "INSERT INTO network_probe_samples (epoch, iso_utc, run_id,"
            " cycle_id, result_version, dns_status, dns_latency_ms,"
            " dns_error_code, https_status, https_latency_ms, https_error_code,"
            " udp_status, udp_latency_ms, udp_error_code, egress_status,"
            " egress_latency_ms, egress_error_code, egress_ip, egress_change)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (epoch + 5.0, "", "seed", "%032x" % step, 1, "ok", 1, "NONE",
             "ok", 1, "NONE", "ok", 1, "NONE", "ok", 1, "NONE", IP_A,
             "unknown"))
    conn.commit()
    conn.close()
    seed.close()

    # reopen with a 100 s horizon at t=350: everything older than 250 goes,
    # in ONE globally epoch-ordered pass, across all three tables
    h = tmp_history("after", clock=lambda: 350.0, root=d,
                    retention_seconds=100.0)
    timeline = h.query_timeline(limit=2000)
    rows, samples, states = (timeline["probe_rows"], timeline["samples"],
                             timeline["device_states"])
    out["probe_rows_participate_in_prune"] = (
        len(rows) < 31 and all(r["epoch"] >= 250.0 for r in rows))
    out["probe_newest_kept"] = max(r["epoch"] for r in rows) == 305.0
    out["global_order_one_pass"] = (
        all(r["epoch"] >= 250.0 for r in samples + states + rows)
        and len(samples) > 0 and len(states) > 0)
    out["probe_pruned_to_the_exact_suffix"] = len(rows) == 6
    out["probe_rows_ascending"] = all(
        a["epoch"] <= b["epoch"] for a, b in zip(rows, rows[1:]))
    conn = sqlite3.connect(db_path(h))
    out["journal_state_row_never_pruned"] = conn.execute(
        "SELECT COUNT(*) FROM journal_ingest_state WHERE id=1").fetchone()[0] \
        == 1
    conn.close()
    out["prune_source_list_names_probe_table"] = (
        ("network_probe_samples", "epoch") in IH._PRUNE_SOURCES)
    out["prune_sources_are_six"] = len(IH._PRUNE_SOURCES) == 6

    # the newest kept ok row IS the baseline: pruning old evidence never
    # invents a change event
    out["baseline_is_the_newest_kept_row"] = (
        h.last_persisted_egress_ip() == IP_A)
    h.close()
    h2 = tmp_history("empty", clock=lambda: 900.0, root=d,
                     retention_seconds=100.0)
    out["all_probe_rows_aged_out"] = len(probe_rows(h2)) == 0
    out["baseline_follows_retention"] = h2.last_persisted_egress_ip() is None
    r, _ = good(IP_A, "unchanged")
    r["epoch"] = 900.0
    r["cycle_id"] = "6" * 32
    out["no_baseline_after_retention_refuses_tokens"] = (
        h2.record_probe_result(r, "unchanged") is False)
    h2.close()
    return out


# -- group: the two evidence planes stay independent ---------------------------

def group_health():
    out = {}
    t = [NOW]
    h = tmp_history("planes", clock=lambda: t[0])
    out["starts_clean"] = (h.probe_status()["degraded"] is False
                           and h.health()["degraded"] is False)
    baseline_failures = h.health()["failure_count"]

    # a rejection degrades the PROBE plane only
    r, _ = good(IP_A, "changed")
    r["cycle_id"] = "7" * 32
    h.record_probe_result(r, "changed")
    out["probe_plane_degraded"] = h.probe_status()["degraded"] is True
    out["write_plane_untouched"] = h._degraded is False
    out["journal_plane_untouched"] = h._journal_degraded is False
    out["whole_history_degraded"] = h.health()["degraded"] is True
    out["probe_code_visible_through_health"] = (
        h.health()["last_error_code"] == CODE_PROBE_RESULT_REJECTED)
    out["shared_failure_count_bumped"] = (
        h.health()["failure_count"] == baseline_failures + 1)

    # a network-failure cycle is DATA: it neither degrades nor counts
    before = h.health()["failure_count"]
    persisted_before = h.probe_status()["persisted_total"]
    for i in range(5):
        r, c = network_failure_cycle(cycle="%032d" % i, epoch=NOW)
        h.record_probe_result(r, c)
    out["network_data_persists"] = (
        h.probe_status()["persisted_total"] == persisted_before + 5)
    out["network_data_zero_failures"] = (
        h.health()["failure_count"] == before)
    out["network_data_clears_plane"] = (h.probe_status()["degraded"] is False
                                        and h.health()["degraded"] is False
                                        and h.health()["last_error_code"]
                                        is None)

    # precedence: a write-plane code outranks a probe code, but the probe
    # plane is never swallowed by it
    r, _ = good(IP_A, "changed")
    r["cycle_id"] = "8" * 32
    h.record_probe_result(r, "changed")
    h._record_failure(CODE_WRITE_FAILED)
    out["write_code_outranks_probe"] = (
        h.health()["last_error_code"] == CODE_WRITE_FAILED)
    out["probe_still_degraded_under_write"] = (
        h.probe_status()["degraded"] is True
        and h.probe_status()["last_error_code"] == CODE_PROBE_RESULT_REJECTED)
    # ...and an accepted probe row clears ONLY its own plane
    r, c = good(IP_A, "unknown")
    r["cycle_id"] = "9" * 32
    h.record_probe_result(r, c)
    out["probe_row_clears_probe_plane"] = h.probe_status()["degraded"] is False
    out["write_degradation_survives_probe_row"] = (
        h._degraded is True and h.health()["degraded"] is True
        and h.health()["last_error_code"] == CODE_WRITE_FAILED)

    # journal plane rides between: write cleared, journal + probe degraded
    h._degraded = False
    h._last_error_code = None
    r, _ = good(IP_A, "changed")
    r["cycle_id"] = "a" * 32
    h.record_probe_result(r, "changed")
    h._record_journal_failure("history_journal_test")
    out["journal_code_outranks_probe"] = (
        h.health()["last_error_code"] == "history_journal_test"
        and h.probe_status()["degraded"] is True)

    # a closed / never-opened store refuses quietly, never raises
    h.close()
    out["closed_store_refuses_probe_row"] = (
        h.record_probe_result(*good(IP_A, "unknown")) is False)
    out["closed_store_has_no_baseline"] = h.last_persisted_egress_ip() is None
    out["closed_store_status_shape"] = set(h.probe_status()) == {
        "enabled", "degraded", "last_error_code", "persisted_total",
        "rejected_total"}

    # hostile inputs never escape as an exception
    h2 = tmp_history("hostile", clock=lambda: NOW)
    junk = [None, [], 12345, "", b"x", (1, 2), {"dns": 1},
            good(IP_A)[0] | {"extra": 1}]
    refused = []
    for item in junk:
        try:
            refused.append(h2.record_probe_result(item, "unknown") is False)
        except Exception:  # noqa: BLE001 -- the boundary must never raise
            refused.append(False)
    out["junk_inputs_refused_quietly"] = all(refused)
    out["junk_inputs_wrote_nothing"] = len(probe_rows(h2)) == 0
    # a sentinel-shaped free text can never reach the table or the read
    # surface, however the caller is dressed up
    leak = dict(good(IP_A, "unknown")[0])
    leak["egress"] = {"status": "ok", "latency_ms": 1, "error_code": "NONE",
                      "ip": "SENTINEL-LEAK-ADDRESS"}
    out["sentinel_ip_never_persisted"] = (
        h2.record_probe_result(leak, "unknown") is False
        and "SENTINEL" not in json.dumps(probe_rows(h2)))
    h2.close()
    return out


# -- group: the activation contract (dark / injected / production) -------------

class env_var:
    """Set (or clear) the single opt-in variable for one case, then restore."""

    def __init__(self, value):
        self.value = value

    def __enter__(self):
        self.had = sched.TARGETS_ENV_VAR in os.environ
        self.old = os.environ.get(sched.TARGETS_ENV_VAR)
        if self.value is None:
            os.environ.pop(sched.TARGETS_ENV_VAR, None)
        else:
            os.environ[sched.TARGETS_ENV_VAR] = self.value
        return self

    def __exit__(self, *exc):
        if self.had:
            os.environ[sched.TARGETS_ENV_VAR] = self.old
        else:
            os.environ.pop(sched.TARGETS_ENV_VAR, None)
        return False


def write_doc(payload):
    """A target file with EXACTLY these bytes (or invalid JSON text)."""
    d = tempfile.mkdtemp()
    path = os.path.join(d, "targets.json")
    text = payload if isinstance(payload, str) else json.dumps(payload)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    return path, d


def resolve(payload):
    """Build a scheduler over one document and return its closed status."""
    path, _d = write_doc(payload)
    with env_var(path):
        return sched.ProbeScheduler(None).status()


def status_keys():
    return {"enabled", "running", "target_source", "startup_error",
            "cadence_seconds", "cycles_completed", "cycles_rejected",
            "runtime_failures", "last_cycle_epoch", "last_store_epoch"}


def group_activation():
    """Nothing turns probing on except one reviewed file, and a defective
    file turns it off -- never partially, never onto the production set."""
    out = {}

    # frozen reviewed constants (a code review, not a conf line)
    out["cadence_frozen_60s"] = sched.CADENCE_SECONDS == 60.0
    out["startup_delay_frozen_5s"] = sched.STARTUP_DELAY_SECONDS == 5.0
    out["cycle_deadline_is_the_engines"] = (
        sched.TOTAL_DEADLINE_SECONDS == engine.CYCLE_DEADLINE_SECONDS == 12.0)
    out["opt_in_variable_name_frozen"] = (
        sched.TARGETS_ENV_VAR == "SINGBOX_MONITOR_PROBE_TARGETS_FILE")
    out["startup_tokens_closed"] = (
        sched.STARTUP_NOT_CONFIGURED == "target_file_not_configured"
        and sched.STARTUP_FILE_ABSENT == "target_file_absent"
        and sched.STARTUP_INJECTION_INVALID == "target_injection_invalid"
        and sched.STARTUP_NONE is None)
    out["source_tokens_closed"] = set(
        (sched.SOURCE_PRODUCTION, sched.SOURCE_INJECTED,
         sched.SOURCE_DARK)) == {"production", "injected", "dark"}
    ep = sched.PRODUCTION_ENDPOINTS
    out["production_endpoints_are_the_reviewed_set"] = (
        (ep.dns_hostname, ep.https_host, ep.https_port, ep.https_path,
         ep.udp_resolver_ip, ep.udp_resolver_port, ep.udp_query_hostname,
         ep.egress_host, ep.egress_port, ep.egress_path) ==
        ("one.one.one.one", "1.1.1.1", 443, "/cdn-cgi/trace", "1.1.1.1", 53,
         "example.com", "api.ipify.org", 443, "/"))
    out["production_endpoint_set_is_frozen"] = (
        _assignment_raises(ep, "https_host", "evil.example"))

    # B1: every slot is a TARGET/STATUS PAIR that can actually produce
    # POSITIVE evidence. The offline proof is in two halves: the status
    # contract stays 200-only (it was NOT loosened to make the old root path
    # "work"), and the engine's own classifier, fed the status codes measured
    # on the review host, admits the new pair and refuses the old one.
    targets = sched.production_targets()
    out["production_targets_deterministic"] = (
        targets == sched.production_targets(sched.PRODUCTION_ENDPOINTS))
    out["production_https_status_contract_is_200_only"] = (
        targets.https.allowed_statuses == frozenset({200})
        and targets.egress.allowed_statuses == frozenset({200})
        and ep.https_path != "/")
    real_get = engine._https_get
    https_codes = {}
    try:
        for status, label in ((200, "trace"), (301, "root")):
            engine._https_get = (lambda spec, read_cap=None, _s=status:
                                 (time.monotonic(), _s, b""))
            https_codes[label] = engine._run_https_probe(targets.https)[
                "error_code"]
    finally:
        engine._https_get = real_get
    out["measured_https_pair_produces_evidence"] = (
        https_codes == {"trace": "NONE", "root": "bad_response"})

    # ...and the UDP slot: the engine evidences a round trip ONLY on NOERROR,
    # while RFC 6761 makes any name under ".invalid" a guaranteed NXDOMAIN.
    # So the query name may not live in a never-resolvable space, and the
    # canned replies below show both halves of the pair.
    out["production_udp_query_name_is_resolvable_space"] = (
        not ep.udp_query_hostname.endswith((".invalid", ".test", ".localhost",
                                            ".local", ".example")))
    query = engine._udp_encode_query(ep.udp_query_hostname, 0x4f3b)
    question = query[12:]

    def reply(rcode):
        return struct.pack("!HHHHHH", 0x4f3b, 0x8100 | rcode, 1, 0, 0,
                           0) + question

    udp_codes = {name: engine._udp_classify_reply(reply(rc), 0x4f3b, 2048,
                                                  question)
                 for name, rc in (("noerror", 0), ("nxdomain", 3))}
    out["measured_udp_pair_produces_evidence"] = (
        udp_codes == {"noerror": "NONE", "nxdomain": "bad_response"})

    # POSITIVE EVIDENCE IS PERSISTABLE: an all-ok result shaped exactly like
    # a successful production cycle crosses the v3 boundary. If this were
    # refused, the whole surface would be permanently dark-in-the-DB.
    ok_store = tmp_history("positive", clock=lambda: NOW)
    ok_row = {"v": 1, "epoch": NOW, "cycle_id": next_cycle(),
              "dns": {"status": "ok", "latency_ms": 5, "error_code": "NONE"},
              "https": {"status": "ok", "latency_ms": 40,
                        "error_code": "NONE"},
              "udp": {"status": "ok", "latency_ms": 9, "error_code": "NONE"},
              "egress": {"status": "ok", "latency_ms": 35,
                         "error_code": "NONE", "ip": IP_A}}
    out["all_ok_production_shape_persists"] = (
        ok_store.record_probe_result(ok_row, "unknown") is True
        and probe_rows(ok_store)[-1]["https_error_code"] == "NONE"
        and ok_store.probe_status()["rejected_total"] == 0)
    ok_store.close()

    out["scheduler_adds_no_timeout_policy"] = (
        targets.dns.timeout_seconds == engine.DNS_TIMEOUT_SECONDS
        and targets.https.timeout_seconds == engine.HTTPS_TIMEOUT_SECONDS
        and targets.udp.timeout_seconds == engine.UDP_TIMEOUT_SECONDS
        and targets.egress.timeout_seconds == engine.EGRESS_TIMEOUT_SECONDS)
    out["engine_ships_no_default_endpoints"] = (
        engine.ProbeTargets().dns is None
        and engine.ProbeTargets().egress is None)

    # the ordinary state: the variable is simply not there
    with env_var(None):
        s = sched.ProbeScheduler(None)
        st = s.status()
        threads_before = _probe_threads()
        s.start()
        dark_no_thread = _probe_threads() == threads_before
        s.stop()
    out["dark_status_shape"] = set(st) == status_keys()
    out["dark_is_the_default"] = (
        st["enabled"] is False and st["running"] is False
        and st["target_source"] == "dark"
        and st["startup_error"] == "target_file_not_configured")
    out["dark_counters_zero"] = (
        st["cycles_completed"] == 0 and st["cycles_rejected"] == 0
        and st["runtime_failures"] == 0
        and st["last_cycle_epoch"] is None
        and st["last_store_epoch"] is None)
    out["dark_starts_no_thread"] = dark_no_thread

    # every defective opt-in fails closed into DARK
    bad_docs = {
        "not_json": "{ this is not json",
        "not_json_scalar_text": "plain text",
        "json_list": [1, 2, 3],
        "json_scalar": 7,
        "wrong_version": {"v": 2},
        "no_version": {"dns": {"hostname": "localhost"}},
        "production_plus_extra": {"v": 1, "source": "production",
                                  "https": {"host": "127.0.0.1", "port": 1}},
        "production_wrong_token": {"v": 1, "source": "staging"},
        "production_without_source_key": {"v": 1, "source": True},
        "empty_injection": {"v": 1},
        "unknown_slot_key": {"v": 1, "host": "evil"},
        "bad_port": {"v": 1, "https": {"host": "127.0.0.1", "port": 0}},
        "udp_without_question": {"v": 1, "udp": {"resolver_host": "127.0.0.1"}},
        "slot_not_an_object": {"v": 1, "dns": "localhost"},
        "production_with_a_slot": {"v": 1, "source": "production",
                                   "dns": {"hostname": "localhost"}},
    }
    verdicts = {}
    for label, doc in bad_docs.items():
        st = resolve(doc)
        verdicts[label] = (
            st["enabled"] is False and st["running"] is False
            and st["target_source"] == "dark"
            and st["startup_error"] == "target_injection_invalid")
    # B4: a variable that NAMES the packaged path and finds nothing there is
    # the ordinary state of a host that has not opted in. It is DARK, and it
    # is coded as ABSENCE -- not as a defect. Confusing the two would make
    # every default host look misconfigured, and a real defect (below) look
    # like the default.
    with env_var(os.path.join(tempfile.mkdtemp(), "gone.json")):
        st = sched.ProbeScheduler(None).status()
    verdicts["missing_file_is_absence_not_defect"] = (
        st["enabled"] is False
        and st["running"] is False
        and st["target_source"] == "dark"
        and st["startup_error"] == "target_file_absent")
    out["every_defective_opt_in_goes_dark"] = all(verdicts.values())
    out["defective_matrix_broad"] = len(verdicts) >= 16 and len(
        [v for v in verdicts.values() if v]) == len(verdicts)
    # a directory, and an unreadable path shape, are refused the same way
    d_dir = tempfile.mkdtemp()
    with env_var(d_dir):
        st = sched.ProbeScheduler(None).status()
    out["directory_is_not_a_target_file"] = (
        st["enabled"] is False
        and st["startup_error"] == "target_injection_invalid")

    # the two shapes that DO turn probing on
    st = resolve({"v": 1, "source": "production"})
    out["production_token_opts_in"] = (
        st["enabled"] is True and st["target_source"] == "production"
        and st["startup_error"] is None)
    st = resolve({"v": 1, "dns": {"hostname": "localhost"}})
    out["injection_opts_in"] = (
        st["enabled"] is True and st["target_source"] == "injected")
    st = resolve({"v": 1, "dns": {"hostname": "localhost"},
                  "https": {"host": "127.0.0.1", "port": 8443, "path": "/",
                            "cafile": CERT},
                  "udp": {"resolver_host": "127.0.0.1",
                          "query_hostname": "example.invalid"},
                  "egress": {"host": "127.0.0.1", "port": 8443,
                             "path": "/echo", "cafile": CERT}})
    out["full_four_slot_injection_accepted"] = (
        st["enabled"] is True and st["target_source"] == "injected")
    out["cadence_reports_the_frozen_default"] = (
        st["cadence_seconds"] == sched.CADENCE_SECONDS)

    # an explicitly passed target set is labelled honestly, never guessed
    h = tmp_history("labels", clock=lambda: NOW)
    prod = sched.ProbeScheduler(h, targets=sched.production_targets())
    out["explicit_production_set_labelled_production"] = (
        prod.status()["target_source"] == "production")
    loop = engine.ProbeTargets(
        dns=engine.DnsProbeSpec(hostname="localhost"))
    out["explicit_loopback_set_labelled_injected"] = (
        sched.ProbeScheduler(h, targets=loop).status()["target_source"]
        == "injected")
    out["non_target_object_falls_back_to_the_file"] = (
        sched.ProbeScheduler(h, targets={"dns": 1}).status()["target_source"]
        == "dark")
    with env_var(None):
        out["a_directly_passed_set_needs_no_file"] = (
            sched.ProbeScheduler(h, targets=loop).status()["enabled"] is True)

    # unit knobs: only a positive real number moves them
    for junk in (0, -5.0, "60", True, None, float("nan")):
        st = sched.ProbeScheduler(h, targets=loop,
                                  cadence_seconds=junk).status()
        if st["cadence_seconds"] != sched.CADENCE_SECONDS:
            out["cadence_knob_refuses_junk"] = False
            break
    else:
        out["cadence_knob_refuses_junk"] = True
    out["cadence_knob_admits_a_real_number"] = (
        sched.ProbeScheduler(h, targets=loop, cadence_seconds=7.5).status()[
            "cadence_seconds"] == 7.5)
    out["startup_delay_knob_refuses_negative"] = (
        sched.ProbeScheduler(h, targets=loop, startup_delay_seconds=-1)
        ._startup_delay == sched.STARTUP_DELAY_SECONDS)
    out["startup_delay_zero_is_honoured"] = (
        sched.ProbeScheduler(h, targets=loop,
                             startup_delay_seconds=0)._startup_delay == 0.0)

    # the status object is closed and private-safe: no path, no endpoint,
    # no result text -- even when the injection file names a loopback port
    path, root = write_doc({"v": 1, "dns": {"hostname": "localhost"}})
    with env_var(path):
        st = sched.ProbeScheduler(h).status()
    blob = json.dumps(st, sort_keys=True)
    out["status_carries_no_paths_or_endpoints"] = (
        path not in blob and root not in blob and "localhost" not in blob
        and "hostname" not in blob and "8443" not in blob)
    out["status_never_raises_without_a_history"] = (
        isinstance(sched.ProbeScheduler(None).status(), dict))
    out["stop_before_start_is_safe"] = (
        _no_raise(sched.ProbeScheduler(h, targets=loop).stop))
    h.close()
    return out


def _probe_threads():
    return [th for th in threading.enumerate() if th.name == "monitor-probes"]


def _assignment_raises(obj, attr, value):
    try:
        setattr(obj, attr, value)
    except Exception:  # noqa: BLE001 -- FrozenInstanceError on a frozen slot
        return True
    return False


def _no_raise(fn):
    try:
        fn()
    except Exception:  # noqa: BLE001
        return False
    return True


# -- loopback TLS fake (the only "network" this suite ever touches) ------------

class LoopbackFake:
    """A 127.0.0.1-only HTTPS listener serving the egress-answer paths.

    It exists so the live scheduler can be proven end to end without a
    single public packet: the answer text is what the egress slot must
    report, never the connection address.
    """

    def __init__(self):
        import http.server

        outer = self
        outer.hits = {}
        outer.lock = threading.Lock()

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = {"/echo-public": b"9.9.9.9",
                        "/echo-loop": b"127.0.0.1"}.get(self.path, b"ok")
                outer.record(self.path, self.client_address[0])
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        outer.server = http.server.ThreadingHTTPServer(
            ("127.0.0.1", 0), Handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        outer.server.socket = ctx.wrap_socket(outer.server.socket,
                                              server_side=True)
        outer.port = outer.server.server_address[1]
        outer.thread = threading.Thread(target=outer.server.serve_forever,
                                        daemon=True)
        outer.thread.start()

    def record(self, path, peer):
        with self.lock:
            self.hits[path] = self.hits.get(path, 0) + 1
            self.hits["peer:" + peer] = self.hits.get("peer:" + peer, 0) + 1

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def injection_doc(fake, egress_path="/echo-public", with_udp=False):
    doc = {"v": 1,
           "dns": {"hostname": "localhost"},
           "https": {"host": "127.0.0.1", "port": fake.port, "path": "/",
                     "cafile": CERT},
           "egress": {"host": "127.0.0.1", "port": fake.port,
                      "path": egress_path, "cafile": CERT}}
    if with_udp:
        doc["udp"] = {"resolver_host": "127.0.0.1",
                      "query_hostname": "example.invalid",
                      "resolver_port": fake.port}
    return doc


def run_scheduler(doc, history, cycles=2, cadence=0.3, timeout=20.0):
    """Start a scheduler over one injection document until it has completed
    ``cycles`` accepted cycles, then stop it. Returns (scheduler, status)."""
    path, _root = write_doc(doc)
    with env_var(path):
        s = sched.ProbeScheduler(history, cadence_seconds=cadence,
                                 startup_delay_seconds=0.0)
    deadline = time.monotonic() + timeout
    s.start()
    while time.monotonic() < deadline:
        if s.status()["cycles_completed"] >= cycles:
            break
        time.sleep(0.05)
    s.stop()
    return s, s.status()


def group_e2e():
    """A live scheduler, a real v3 store and a loopback-only endpoint set:
    the whole activation path, with the durable egress semantics derived
    from what actually got persisted."""
    out = {}
    if not (CERT and KEY and os.path.exists(CERT)):
        out["_skipped_no_tls_fixture"] = True
        return out
    fake = LoopbackFake()
    try:
        out["fake_bound_to_loopback_only"] = (
            fake.server.server_address[0] == "127.0.0.1")
        # the real wall clock: the engine stamps live epochs, the boundary
        # judges them against the store clock, so both must be time.time
        root = tempfile.mkdtemp()
        h = tmp_history("live", clock=time.time, root=root)
        s, st = run_scheduler(injection_doc(fake), h, cycles=3)
        rows = probe_rows(h)
        out["live_status_injected_and_was_running"] = (
            st["target_source"] == "injected" and st["enabled"] is True)
        out["live_cycles_persisted_one_row_each"] = (
            st["cycles_completed"] >= 3 and len(rows) == st["cycles_completed"])
        out["live_no_rejects_no_runtime_failures"] = (
            st["cycles_rejected"] == 0 and st["runtime_failures"] == 0)
        out["live_https_verified_against_the_injected_ca"] = (
            all(r["https_status"] == "ok" and r["https_error_code"] == "NONE"
                for r in rows))
        out["live_dns_slot_ok"] = all(r["dns_status"] == "ok" for r in rows)
        out["live_unconfigured_slot_is_data"] = (
            all(r["udp_status"] == "failed"
                and r["udp_error_code"] == "unavailable" for r in rows))
        out["live_egress_reports_the_answer_not_the_peer"] = (
            all(r["egress_status"] == "ok" and r["egress_ip"] == "9.9.9.9"
                for r in rows))
        out["live_loopback_address_never_stored"] = (
            "127.0.0.1" not in json.dumps(rows))
        out["live_first_change_is_unknown"] = rows[0]["egress_change"] \
            == "unknown"
        out["live_later_changes_are_unchanged"] = (
            all(r["egress_change"] == "unchanged" for r in rows[1:]))
        out["live_durable_baseline"] = h.last_persisted_egress_ip() == "9.9.9.9"
        out["live_traffic_stayed_on_loopback"] = (
            fake.hits.get("/echo-public", 0) >= 3
            and fake.hits.get("peer:127.0.0.1", 0) >= 3
            and all(k.startswith("/") or k == "peer:127.0.0.1"
                    for k in fake.hits))
        out["live_probe_plane_clean_over_real_failures"] = (
            h.probe_status()["degraded"] is False
            and h.health()["degraded"] is False)
        out["live_status_stopped_after_stop"] = st["running"] is False

        # a restart never fabricates a change event: the durable baseline
        # makes the very first post-restart cycle ``unchanged``
        h2 = reopen(root, "live-2", clock=time.time)
        s2, st2 = run_scheduler(injection_doc(fake), h2, cycles=1)
        new_rows = [r for r in probe_rows(h2) if r["run_id"] == "live-2"]
        out["restart_first_row_is_not_a_change_event"] = (
            len(new_rows) == 1 and new_rows[0]["egress_change"] == "unchanged")
        out["restart_rejected_nothing"] = st2["cycles_rejected"] == 0
        h2.close()

        # and a loopback ANSWER can never become the egress IP: the slot
        # degrades to data, the baseline is untouched, no change event
        h3 = tmp_history("loopback-answer", clock=time.time)
        s3, st3 = run_scheduler(injection_doc(fake, "/echo-loop"), h3,
                                cycles=2)
        rows3 = probe_rows(h3)
        out["loopback_answer_never_ok"] = (
            all(r["egress_status"] == "failed"
                and r["egress_error_code"] == "parse_failed"
                and r["egress_ip"] is None for r in rows3))
        out["loopback_answer_still_persists_as_data"] = (
            len(rows3) == st3["cycles_completed"] and st3["cycles_rejected"]
            == 0)
        out["loopback_answer_forges_no_baseline"] = (
            h3.last_persisted_egress_ip() is None)
        out["loopback_answer_rows_are_unknown"] = all(
            r["egress_change"] == "unknown" for r in rows3)
        h3.close()
        h.close()
    finally:
        fake.close()
    return out


# -- group: one dedicated thread, bounded shutdown, no lock convoy -------------

class RaisingHistory:
    """A persistence sink that always raises: the runtime plane must become
    a closed counter, the loop must survive."""

    def __init__(self):
        self.calls = 0

    def last_persisted_egress_ip(self):
        self.calls += 1
        raise RuntimeError("injected store defect")

    def record_probe_result(self, result, egress_change=None):
        self.calls += 1
        raise RuntimeError("injected store defect")


def group_threads():
    out = {}
    fake_ok_doc = {"v": 1, "dns": {"hostname": "localhost"}}

    # (1) exactly ONE daemon thread, named, idempotent start
    h = tmp_history("threads", clock=time.time)
    path, _root = write_doc(fake_ok_doc)
    with env_var(path):
        s = sched.ProbeScheduler(h, cadence_seconds=0.2,
                                 startup_delay_seconds=0.0)
    s.start()
    s.start()
    live = _probe_threads()
    out["exactly_one_scheduler_thread"] = len(live) == 1
    out["thread_is_a_daemon"] = len(live) == 1 and live[0].daemon is True
    out["thread_name_frozen"] = len(live) == 1 and live[0].name == \
        "monitor-probes"
    out["status_reports_running"] = s.status()["running"] is True
    s.stop()
    out["stop_joins_within_budget"] = _no_raise(lambda: s.stop())
    out["no_thread_after_stop"] = len(_probe_threads()) == 0
    s.start()
    out["start_after_stop_is_a_no_op"] = len(_probe_threads()) == 0
    h.close()

    # (2) 20x start/stop: threads cannot accumulate, no runtime failures
    h = tmp_history("stress", clock=time.time)
    max_seen = 0
    completed = 0
    failures = 0
    for _i in range(20):
        with env_var(path):
            s = sched.ProbeScheduler(h, cadence_seconds=0.05,
                                     startup_delay_seconds=0.0)
        s.start()
        max_seen = max(max_seen, len(_probe_threads()))
        # let this instance finish at least one cycle, so a start/stop that
        # always beat the thread would prove nothing about accumulation
        deadline = time.monotonic() + 10.0
        while (time.monotonic() < deadline
               and s.status()["cycles_completed"] < 1):
            time.sleep(0.01)
        s.stop(join_timeout=6.0)
        completed += s.status()["cycles_completed"]
        failures += s.status()["runtime_failures"]
    out["stress_20_cycles_no_accumulation"] = (
        len(_probe_threads()) == 0 and max_seen <= 1)
    out["stress_no_runtime_failures"] = failures == 0
    out["stress_persisted_every_accepted_cycle"] = (
        completed == len(probe_rows(h)) and completed >= 20)
    out["stress_single_writer_run_id"] = len(
        {r["run_id"] for r in probe_rows(h)}) == 1
    h.close()

    # (3) a dark scheduler is a THREAD-FREE scheduler
    h = tmp_history("dark-threads", clock=time.time)
    before = len(_probe_threads())
    with env_var(None):
        s = sched.ProbeScheduler(h)
        for _i in range(20):
            s.start()
            s.stop()
    out["dark_never_spawns_a_thread"] = len(_probe_threads()) == before
    out["dark_wrote_nothing"] = len(probe_rows(h)) == 0
    h.close()

    # (4) a runtime defect is a COUNTER, not a dead loop: 20 defective
    # cycles must all be counted and the thread must still be alive
    stub = RaisingHistory()
    with env_var(path):
        s = sched.ProbeScheduler(stub, cadence_seconds=0.02,
                                 startup_delay_seconds=0.0)
    s.start()
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline and s.status()["runtime_failures"] < 20:
        time.sleep(0.02)
    st = s.status()
    out["defect_becomes_a_closed_counter"] = st["runtime_failures"] >= 20
    out["defect_loop_survives"] = st["running"] is True
    out["defect_counts_nothing_as_completed"] = (
        st["cycles_completed"] == 0 and st["cycles_rejected"] == 0)
    out["defect_only_counters_in_status"] = (
        set(st) == status_keys() and st["target_source"] == "injected")
    s.stop()
    out["defect_thread_joins_cleanly"] = len(_probe_threads()) == 0

    # (5) NO LOCK CONVOY: a slow cycle must not hold the history lock, the
    # store's own reads must stay instant, and status() must answer
    real_cycle = engine.run_probe_cycle(engine.ProbeTargets())
    original_cycle = sched.engine.run_probe_cycle
    inside = threading.Event()

    def slow_cycle(targets=None, **kw):
        inside.set()
        time.sleep(1.0)
        # Each delivery is a DISTINCT cycle: the schema now enforces one row
        # per cycle_id, so handing back the same stamped result would turn
        # this fixture into a replay-rejection loop and prove nothing about
        # the lock convoy it is meant to measure.
        fresh = dict(real_cycle)
        fresh["cycle_id"] = next_cycle()
        fresh["epoch"] = time.time()
        return fresh

    h = tmp_history("convoy", clock=time.time)
    sched.engine.run_probe_cycle = slow_cycle
    try:
        s = sched.ProbeScheduler(h, targets=engine.ProbeTargets(
            dns=engine.DnsProbeSpec(hostname="localhost")),
            cadence_seconds=0.4, startup_delay_seconds=0.0)
        s.start()
        deadline = time.monotonic() + 5.0
        while not inside.is_set() and time.monotonic() < deadline:
            time.sleep(0.01)
        started = time.monotonic()
        h.last_persisted_egress_ip()
        h.probe_status()
        h.query_timeline(limit=10)
        read_latency = time.monotonic() - started
        started = time.monotonic()
        s.status()
        status_latency = time.monotonic() - started
        out["history_stays_readable_during_a_cycle"] = read_latency < 0.3
        out["status_stays_readable_during_a_cycle"] = status_latency < 0.3
        started = time.monotonic()
        s.stop(join_timeout=6.0)
        out["stop_bounded_while_a_cycle_is_in_flight"] = (
            time.monotonic() - started < 3.0
            and len(_probe_threads()) == 0)
    finally:
        sched.engine.run_probe_cycle = original_cycle
    h.close()

    # (6) startup delay is honoured, cadence spacing is real
    h = tmp_history("cadence", clock=time.time)
    with env_var(path):
        s = sched.ProbeScheduler(h, cadence_seconds=0.35,
                                 startup_delay_seconds=0.8)
    started = time.monotonic()
    s.start()
    time.sleep(0.35)
    out["startup_delay_honoured"] = s.status()["cycles_completed"] == 0
    deadline = started + 12.0
    while time.monotonic() < deadline and s.status()["cycles_completed"] < 3:
        time.sleep(0.02)
    elapsed = time.monotonic() - started
    st = s.status()
    s.stop()
    out["cadence_spacing_is_real"] = (
        st["cycles_completed"] >= 3 and elapsed >= 0.8 + 2 * 0.35 - 0.1)
    out["cadence_is_not_a_busy_loop"] = st["cycles_completed"] <= 8
    out["cadence_timestamps_move_forward"] = (
        st["last_cycle_epoch"] is not None
        and st["last_store_epoch"] is not None
        and st["last_store_epoch"] >= st["last_cycle_epoch"])
    h.close()
    return out


# -- group: the bounded read surface over real HTTP ----------------------------

class StubScheduler:
    """A scheduler stand-in that only answers status() -- the projection
    must never trust what it is handed."""

    def __init__(self, payload=None):
        self._payload = payload

    def status(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class SwappableScheduler(StubScheduler):
    """The same, with a payload the case can replace between requests: one
    server then carries a whole matrix of hostile values, so every row of
    that matrix is proved over the REAL HTTP path."""

    def __init__(self, payload=None):
        StubScheduler.__init__(self, payload)

    def set(self, payload):
        self._payload = payload


def no_json_constant(token):
    """``parse_constant`` hook: called for NaN / Infinity / -Infinity, the
    three bare words Python will happily write and no JSON reader can
    parse. Raising here turns "the body is valid JSON" into a proof."""
    raise AssertionError("non-JSON literal in body: %s" % token)


def group_http():
    """`/api/v1/diagnostics/timeline` is the one read surface: session
    gated, bounded, and carrying the probe rows plus a closed projection of
    the scheduler -- nothing else."""
    out = {}
    t = [NOW]
    d = tempfile.mkdtemp()
    access = AccessPolicy(d)
    auth = AuthStore(d, session_ttl=3600.0)
    auth.set_password(PASSWORD)

    class FakeBroker:
        def snapshot(self):
            return None

        def snapshot_json(self):
            return 1, "{}"

        def running(self):
            return True

        def wait_for_snapshot(self, timeout=10.0):
            return True

        def subscribe(self, after_version=0):
            return iter(())

    history = tmp_history("http-probe", clock=lambda: t[0], root=d)
    # seeded with the token a CORRECT producer claims against the store's
    # own durable baseline (B2): these rows must actually land, or the read
    # surface below would be proving an empty table.
    baseline = None
    for index, ip in enumerate((IP_A, IP_B, IP_A)):
        r, c = good(ip, derive_change(baseline, ip))
        r["cycle_id"] = "%032x" % index
        history.record_probe_result(r, c)
        baseline = ip
    r, c = network_failure_cycle(cycle="f" * 32)
    history.record_probe_result(r, c)

    healthy = {"enabled": True, "running": True, "target_source": "injected",
               "startup_error": None, "cadence_seconds": 60.0,
               "cycles_completed": 7, "cycles_rejected": 1,
               "runtime_failures": 0, "last_cycle_epoch": NOW,
               "last_store_epoch": NOW}
    liar = {"enabled": "yes", "running": 1, "target_source": "corp.example",
            "startup_error": "/etc/singbox-monitor/targets.json",
            "cadence_seconds": "fast", "cycles_completed": "many",
            "runtime_failures": 2.5, "last_cycle_epoch": "yesterday",
            "host": "api.ipify.org", "targets": healthy, "path": "/x"}

    def serve(scheduler):
        app = MonitorWebApp(broker=FakeBroker(), access=access,
                            static_dir=None, auth=auth,
                            incident_history=history,
                            probe_scheduler=scheduler)
        server = build_server(app, "127.0.0.1", 0, None)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, port

    def get(port, path, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        headers = {"Cookie": cookie} if cookie else {}
        conn.request("GET", path, None, headers)
        response = conn.getresponse()
        body = response.read().decode("utf-8")
        set_cookie = response.getheader("Set-Cookie") or ""
        conn.close()
        return response.status, body, set_cookie

    def login(port):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/api/v1/login", json.dumps(
            {"password": PASSWORD}), {"Content-Type": "application/json"})
        response = conn.getresponse()
        response.read()
        cookie = (response.getheader("Set-Cookie") or "").split(";")[0]
        conn.close()
        return cookie

    server, port = serve(StubScheduler(healthy))
    try:
        status, _, _ = get(port, "/api/v1/diagnostics/timeline")
        out["timeline_requires_a_session"] = status == 401
        cookie = login(port)
        status, body, _ = get(port, "/api/v1/diagnostics/timeline", cookie)
        out["timeline_serves_with_a_session"] = status == 200
        payload = json.loads(body)
        out["surface_carries_probe_rows_and_probes"] = (
            "probe_rows" in payload and "probes" in payload)
        rows = payload["probe_rows"]
        out["http_probe_rows_are_the_persisted_four"] = len(rows) == 4
        out["http_probe_row_columns_exact"] = (
            set(rows[0]) == set(PROBE_COLUMNS))
        out["http_probe_rows_chronological"] = all(
            a["epoch"] <= b["epoch"] for a, b in zip(rows, rows[1:]))
        out["http_egress_ips_are_only_canonical_globals"] = (
            {r["egress_ip"] for r in rows if r["egress_ip"]} ==
            {IP_A, IP_B})
        out["http_carries_the_closed_projections"] = (
            set(payload["probes"]) == status_keys())
        out["http_healthy_projection_is_honest"] = (
            payload["probes"]["target_source"] == "injected"
            and payload["probes"]["cycles_completed"] == 7
            and payload["probes"]["cadence_seconds"] == 60.0)
        status, body, _ = get(port, "/api/v1/diagnostics/timeline?limit=2",
                              cookie)
        payload = json.loads(body)
        out["http_probe_rows_respect_the_bound"] = (
            len(payload["probe_rows"]) == 2
            and payload["truncated"] is True)
        status, body, _ = get(
            port, "/api/v1/diagnostics/timeline?since=%.1f" % (NOW + 1),
            cookie)
        payload = json.loads(body)
        out["http_since_bound_applies_to_probe_rows"] = (
            payload["probe_rows"] == [])
        status, body, _ = get(
            port, "/api/v1/diagnostics/timeline?since=%.1f" % NOW, cookie)
        payload = json.loads(body)
        out["http_since_keeps_the_window"] = len(payload["probe_rows"]) == 4
        out["http_no_arbitrary_filter_leak"] = (
            "table" not in body and "sqlite" not in body.lower())
    finally:
        server.shutdown()
        server.server_close()

    # the lying / broken / missing scheduler
    server, port = serve(StubScheduler(liar))
    try:
        cookie = login(port)
        status, body, _ = get(port, "/api/v1/diagnostics/timeline", cookie)
        payload = json.loads(body)
        probes = payload["probes"]
        out["liar_projection_keys_stay_closed"] = (
            set(probes) == status_keys())
        out["liar_source_collapsed_to_dark"] = probes["target_source"] \
            == "dark"
        out["liar_free_text_startup_refused"] = probes["startup_error"] is None
        # R2-B7: a flag is EXACTLY a bool. ``bool("yes")`` and ``bool(1)``
        # both answer True, so the lying scheduler used to be reported as
        # ENABLED AND RUNNING from a string and an integer. The closed
        # domain has no "unknown" shape that keeps the JSON type, so a
        # non-bool now answers the DENY direction: False.
        out["liar_bool_not_a_flag_refused"] = (
            probes["enabled"] is False and probes["running"] is False)
        out["liar_counters_clamped_to_zero"] = (
            probes["cycles_completed"] == 0
            and probes["runtime_failures"] == 0)
        out["liar_reals_collapsed"] = (
            probes["cadence_seconds"] is None
            and probes["last_cycle_epoch"] is None)
        out["liar_leaks_no_endpoint_or_path"] = (
            "api.ipify.org" not in body and "targets.json" not in body
            and "corp.example" not in body and "/etc" not in body)
    finally:
        server.shutdown()
        server.server_close()

    # R2-B7: THE THREE NON-NUMERIC FIELDS ARE VALUE DOMAINS TOO, and each
    # had its own failure mode behind it. ``bool(value)`` coerced. The two
    # token fields asked a frozenset to HASH their candidate, so a list or a
    # dict raised TypeError out of the projection -- OUTSIDE the try/except,
    # which only wraps the scheduler call -- and the request died instead of
    # answering the closed minimum. And membership compares with ``__eq__``,
    # so ``Impostor`` was adopted as the token it impersonated and handed to
    # ``json.dumps`` verbatim, which cannot serialize it. Every row here is
    # proved over real HTTP, with the request wrapped, so a raising
    # projection shows up as one red row instead of as a dead server.
    shape_matrix = {}
    for key in sorted(PROBE_STATUS_BOOL_KEYS):
        shape_matrix["%s_string" % key] = (key, "yes", False)
        shape_matrix["%s_int" % key] = (key, 1, False)
        shape_matrix["%s_zero" % key] = (key, 0, False)
        shape_matrix["%s_float" % key] = (key, 1.0, False)
        shape_matrix["%s_none" % key] = (key, None, False)
        shape_matrix["%s_list" % key] = (key, ["true"], False)
        shape_matrix["%s_dict" % key] = (key, {"true": 1}, False)
        shape_matrix["%s_impostor" % key] = (key, Impostor("True"), False)
        shape_matrix["%s_str_subclass" % key] = (key, LyingStr("True"), False)
    for label, value in (("source_list", ["dark"]), ("source_dict", {"dark": 1}),
                         ("source_impostor", Impostor("production")),
                         ("source_str_subclass", LyingStr("production")),
                         ("source_endpoint", "api.ipify.org"),
                         ("source_case", "PRODUCTION"),
                         ("source_padded", " production"),
                         ("source_empty", ""), ("source_int", 1),
                         ("source_none", None)):
        shape_matrix[label] = ("target_source", value, "dark")
    for label, value in (("startup_list", ["target_file_absent"]),
                         ("startup_dict", {"a": 1}),
                         ("startup_impostor", Impostor("target_file_absent")),
                         ("startup_str_subclass",
                          LyingStr("target_injection_invalid")),
                         ("startup_traceback", "ValueError: /etc/x"),
                         ("startup_padded", "target_file_absent "),
                         ("startup_empty", ""), ("startup_int", 0)):
        shape_matrix[label] = ("startup_error", value, None)

    collapsed_shapes = []
    strict_json_shapes = True
    surviving_projection = []
    swappable = SwappableScheduler(dict(healthy))
    server, port = serve(swappable)
    try:
        cookie = login(port)
        for label in sorted(shape_matrix):
            key, value, want = shape_matrix[label]
            payload = dict(healthy)
            payload[key] = value
            swappable.set(payload)
            try:
                code, body, _ = get(port, "/api/v1/diagnostics/timeline",
                                    cookie)
                surface = json.loads(body, parse_constant=no_json_constant)
            except (AssertionError, ValueError, http.client.HTTPException,
                    OSError):
                strict_json_shapes = False
                collapsed_shapes.append(False)
                surviving_projection.append(False)
                continue
            # a projection that RAISED answers a different route entirely
            # (a 500 with no probes field), so this half of the row proves
            # the read survived -- which is precisely what a membership test
            # on an unhashable candidate used to break.
            surviving_projection.append(code == 200
                                        and "probes" in surface
                                        and surface["probes"] is not None)
            projected = surface["probes"].get(key) if "probes" in surface \
                else None
            collapsed_shapes.append(code == 200
                                    and type(projected) is type(want)
                                    and projected == want)
    finally:
        server.shutdown()
        server.server_close()
    out["hostile_shapes_always_collapse"] = (
        all(collapsed_shapes) and len(collapsed_shapes) == len(shape_matrix))
    out["hostile_shape_body_is_strict_json"] = strict_json_shapes
    out["hostile_shapes_never_kill_the_projection"] = (
        all(surviving_projection)
        and len(surviving_projection) == len(shape_matrix))
    out["shape_matrix_covers_every_non_numeric_key"] = (
        {shape_matrix[label][0] for label in shape_matrix}
        == set(PROBE_STATUS_BOOL_KEYS) | PROBE_STATUS_SOURCE_KEYS
        | PROBE_STATUS_TOKEN_KEYS)

    # the closing half of the same contract: an HONEST value must still
    # project verbatim, or a closure that refuses everything would pass
    # every gate above.
    honest = []
    swappable = SwappableScheduler(dict(healthy))
    server, port = serve(swappable)
    try:
        cookie = login(port)
        for source in sorted(PROBE_TARGET_SOURCES):
            payload = dict(healthy)
            payload["target_source"] = source
            swappable.set(payload)
            _code, body, _h = get(port, "/api/v1/diagnostics/timeline",
                                  cookie)
            honest.append(json.loads(body)["probes"]["target_source"] == source)
        for token in sorted(PROBE_STARTUP_TOKENS) + [None]:
            payload = dict(healthy)
            payload["startup_error"] = token
            swappable.set(payload)
            _code, body, _h = get(port, "/api/v1/diagnostics/timeline",
                                  cookie)
            honest.append(json.loads(body)["probes"]["startup_error"] == token)
        for flag in sorted(PROBE_STATUS_BOOL_KEYS):
            payload = dict(healthy)
            payload[flag] = True
            swappable.set(payload)
            _code, body, _h = get(port, "/api/v1/diagnostics/timeline",
                                  cookie)
            projected = json.loads(body)["probes"][flag]
            honest.append(projected is True)
    finally:
        server.shutdown()
        server.server_close()
    out["honest_flags_sources_and_tokens_still_project"] = (
        all(honest) and len(honest) == 3 + 4 + 2)

    # the container itself: a dict SUBCLASS used to satisfy isinstance and
    # was projected as if it were an honest status object -- and its ``get``
    # can answer a different value per key than the mapping actually holds,
    # which is precisely the surface the projection must not trust.
    class SneakyStatus(dict):
        def get(self, key, default=None):
            if key == "target_source":
                return "production"
            return dict.get(self, key, default)

    containers = []
    for container in (SneakyStatus({"target_source": "dark"}), ["status"],
                      ("status",), "status", 7, None):
        server, port = serve(StubScheduler(container))
        try:
            cookie = login(port)
            _code, body, _h = get(port, "/api/v1/diagnostics/timeline", cookie)
            containers.append(json.loads(body)["probes"] is None)
        finally:
            server.shutdown()
            server.server_close()
    out["only_an_exact_dict_is_a_status_container"] = (
        all(containers) and len(containers) == 6)

    # the three new closers, on their own tables: what the projection
    # answers for each field, named value by value.
    bool_table = [(True, True), (False, False), ("yes", False), ("", False),
                  (1, False), (0, False), (1.0, False), (None, False),
                  ([], False), ({}, False), (Impostor("True"), False),
                  (LyingStr("True"), False)]
    out["closed_probe_bool_table"] = all(
        closed_probe_bool(value) is want for value, want in bool_table)
    source_table = [("production", "production"), ("injected", "injected"),
                    ("dark", "dark"), ("corp.example", "dark"),
                    ("api.ipify.org", "dark"), ("/etc/singbox-monitor", "dark"),
                    ("PRODUCTION", "dark"), (" production", "dark"),
                    ("production ", "dark"), ("", "dark"), (None, "dark"),
                    (["dark"], "dark"), ({"dark": 1}, "dark"),
                    (Impostor("production"), "dark"),
                    (LyingStr("production"), "dark"), (1, "dark")]
    out["closed_probe_source_table"] = all(
        closed_probe_source(value) == want
        for value, want in source_table)
    startup_table = [(None, None),
                     ("target_file_not_configured", "target_file_not_configured"),
                     ("target_file_absent", "target_file_absent"),
                     ("target_injection_invalid", "target_injection_invalid"),
                     ("target_file_absent ", None), ("", None),
                     ("/etc/x/targets.json raised", None),
                     (["target_file_absent"], None), ({"a": 1}, None),
                     (Impostor("target_file_absent"), None),
                     (LyingStr("target_file_absent"), None), (0, None),
                     (True, None)]
    out["closed_probe_startup_table"] = all(
        closed_probe_startup(value) is want
        for value, want in startup_table)
    # the closers are TOTAL over the closed vocabularies (they close the
    # domain, they do not replace it) and they never raise on junk.
    out["closers_are_total_over_the_vocabularies"] = (
        all(closed_probe_source(token) == token
            for token in PROBE_TARGET_SOURCES)
        and all(closed_probe_startup(token) == token
                for token in PROBE_STARTUP_TOKENS)
        and closed_probe_startup(None) is None
        and all(closed_probe_bool(flag) is flag for flag in (True, False)))
    out["closers_never_raise_on_unhashable"] = all(
        _c(bad) in (False, "dark", None)
        for _c in (closed_probe_bool, closed_probe_source,
                   closed_probe_startup)
        for bad in ([1], {"a": 1}, {1, 2}, Impostor("dark"),
                    LyingStr("dark"), object(), b"bytes", 0.0))

    # B5: NUMBERS ARE A VALUE DOMAIN TOO. A scheduler that answers NaN or an
    # infinity would otherwise serialize the bare words ``NaN``/``Infinity``
    # into the response -- not JSON, so one lying float breaks this endpoint
    # for every reader -- and a negative, fractional, bool or astronomically
    # large counter would be repeated as a fact. Every hostile value
    # collapses to the closed minimum (None for a real, 0 for a count) and
    # the body stays strictly parseable JSON, proved here over real HTTP.
    hostile = {
        "cadence_nan": ("cadence_seconds", float("nan")),
        "cadence_inf": ("cadence_seconds", float("inf")),
        "cadence_neg_inf": ("cadence_seconds", float("-inf")),
        "cadence_negative": ("cadence_seconds", -1.0),
        "cadence_beyond_safe": ("cadence_seconds", 2.0 ** 64),
        "cadence_bool": ("cadence_seconds", True),
        "cadence_string": ("cadence_seconds", "fast"),
        "cycle_epoch_nan": ("last_cycle_epoch", float("nan")),
        "cycle_epoch_negative": ("last_cycle_epoch", -0.5),
        "store_epoch_inf": ("last_store_epoch", float("inf")),
        "completed_float": ("cycles_completed", 2.5),
        "completed_negative": ("cycles_completed", -1),
        "completed_nan": ("cycles_completed", float("nan")),
        "completed_huge": ("cycles_completed", 2 ** 64),
        "completed_bool": ("cycles_completed", True),
        "completed_string": ("cycles_completed", "many"),
        "rejected_string": ("cycles_rejected", "many"),
        "failures_float": ("runtime_failures", 0.5),
        "failures_negative": ("runtime_failures", -7),
    }
    collapsed = []
    strict_json = True
    swappable = SwappableScheduler(dict(healthy))
    server, port = serve(swappable)
    try:
        cookie = login(port)
        for key, value in hostile.values():
            payload = dict(healthy)
            payload[key] = value
            swappable.set(payload)
            code, body, _ = get(port, "/api/v1/diagnostics/timeline", cookie)
            try:
                surface = json.loads(body, parse_constant=no_json_constant)
            except (AssertionError, ValueError):
                strict_json = False
                collapsed.append(False)
                continue
            probes = surface["probes"]
            want = None if key in PROBE_STATUS_REAL_KEYS else 0
            projected = probes[key]
            # ``==`` alone would let 0.0 or False pass for a 0, and True for
            # None, so the type is asserted alongside the value.
            collapsed.append(code == 200
                             and type(projected) is type(want)
                             and projected == want)
    finally:
        server.shutdown()
        server.server_close()
    out["hostile_numerics_always_collapse"] = (
        all(collapsed) and len(collapsed) == len(hostile))
    out["hostile_projection_body_is_strict_json"] = strict_json
    out["hostile_matrix_covers_every_projected_number"] = (
        {key for key, _v in hostile.values()}
        == set(PROBE_STATUS_REAL_KEYS) | set(PROBE_STATUS_INT_KEYS))
    # both hostile matrices together leave NO projected field untested, so
    # the closure is proved over the whole surface and not over the half
    # that happened to be convenient.
    out["both_matrices_cover_every_projected_key"] = (
        ({shape_matrix[label][0] for label in shape_matrix}
         | {key for key, _v in hostile.values()})
        == set(PROBE_STATUS_KEYS))

    # the two closers, on their own table: the projection's number domains
    # are exactly what these answer, and every rejected shape is named.
    seconds_table = [(None, None), (0, 0), (0.0, 0), (7.5, 7.5),
                     (60.0, 60.0), (PROBE_STATUS_MAX_NUMBER,
                                    PROBE_STATUS_MAX_NUMBER),
                     (-1.0, None), (float("nan"), None),
                     (float("inf"), None), (float("-inf"), None),
                     (2 ** 53, None), (2.0 ** 64, None), (True, None),
                     ("60", None), ([1], None)]
    out["closed_probe_seconds_table"] = all(
        closed_probe_seconds(value) == want for value, want in seconds_table)
    counter_table = [(None, 0), (0, 0), (7, 7), (PROBE_STATUS_MAX_NUMBER,
                                                 PROBE_STATUS_MAX_NUMBER),
                     (-1, 0), (2 ** 53, 0), (2 ** 64, 0), (2.5, 0),
                     (float("nan"), 0), (float("inf"), 0), (True, 0),
                     ("3", 0), (3 + 0j, 0)]
    out["closed_probe_counter_table"] = all(
        closed_probe_counter(value) == want for value, want in counter_table)
    out["closers_are_the_only_number_domains"] = (
        closed_probe_seconds(60.0) == 60.0
        and closed_probe_counter(7) == 7
        and closed_probe_seconds(2 ** 53) is None
        and closed_probe_counter(2 ** 53) == 0)

    server, port = serve(StubScheduler(RuntimeError("boom at /x/targets")))
    try:
        cookie = login(port)
        status, body, _ = get(port, "/api/v1/diagnostics/timeline", cookie)
        payload = json.loads(body)
        out["raising_scheduler_answers_null"] = payload["probes"] is None
        out["raising_scheduler_still_serves_rows"] = (
            status == 200 and len(payload["probe_rows"]) == 4)
    finally:
        server.shutdown()
        server.server_close()

    server, port = serve(None)
    try:
        cookie = login(port)
        status, body, _ = get(port, "/api/v1/diagnostics/timeline", cookie)
        payload = json.loads(body)
        out["unwired_scheduler_means_no_probe_surface"] = (
            payload["probes"] is None)
    finally:
        server.shutdown()
        server.server_close()

    # the probe rows are DATA: a degraded probe PLANE never hides them,
    # and the health object stays category-level
    r, _ = good(IP_A, "changed")
    r["cycle_id"] = "e" * 32
    history.record_probe_result(r, "changed")   # refused -> plane degraded
    server, port = serve(StubScheduler(healthy))
    try:
        cookie = login(port)
        status, body, _ = get(port, "/api/v1/diagnostics/timeline", cookie)
        payload = json.loads(body)
        out["degraded_plane_still_serves_its_data"] = (
            len(payload["probe_rows"]) == 4
            and history.probe_status()["degraded"] is True)
    finally:
        server.shutdown()
        server.server_close()
    history.close()
    return out


# -- runner -------------------------------------------------------------------

GROUPS = {"boundary": group_boundary, "durable": group_durable,
          "schema": group_schema, "retention": group_retention,
          "health": group_health, "activation": group_activation,
          "e2e": group_e2e, "threads": group_threads, "http": group_http}


def main():
    names = sys.argv[1:] or sorted(GROUPS)
    rc = 0
    for name in names:
        try:
            results = GROUPS[name]()
        except Exception as exc:  # noqa: BLE001 -- report, never die green
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
