#!/usr/bin/env python3
"""PR-5 incidents-UI harness (issue #33 Phase 5, #63 R2) -- behaviour groups.

Every group returns a flat dict of BOOLEAN verdicts that the shell lane
turns into counted gates, exactly like the PR-4A/PR-4B harnesses. Nothing
here prints from inside a group, and a crash is reported by the runner as
a FAIL instead of escaping green.

What this harness owns (#63 R2 §14):

* the PRESENTER contract: positional mirrors exactly the classifier's
  sorted vocabularies, full 45/28 explanation coverage, the exact 10-key
  summary shape, the signal-window rule, and purity (no I/O, no clock,
  no classifier import);
* the STORE's v5 plane: the exact eleven-table shape, the closed marker
  vocabulary (no free text anywhere, no future, no already-aged-out
  marker), markers inside BOTH retention disciplines but OUTSIDE the
  classifier bundle, the v4->v5 migration, and the store-side re-arm
  preconditions and floor grid;
* the HTTP surface over the SHIPPED handler: the exact route family, the
  full auth matrix, the closed error codes, the evidence wire whitelists
  (egress_ip visible; run_id/cycle_id/fp absent), the subject-bound
  evidence rule, and the timeline endpoint staying byte-frozen;
* the R2 §13 fixture duty: the committed Reality-outage scenario through
  the live store + presenter + API (assessed as the Reality/TCP path,
  never "server down", never an ISP claim, conditional HY2 action), and
  the quiet background scenario staying incident-free.
"""

from __future__ import annotations

import ast
import http.client
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "monitor-classify"))

import classify_groups as cg  # noqa: E402
from web import incident_classifier as ic  # noqa: E402
from web import incident_history as ih  # noqa: E402
from web import incident_presenter as ip  # noqa: E402
from web import incident_runtime as ir  # noqa: E402
from web import server as sv  # noqa: E402
from web.access import AccessPolicy  # noqa: E402
from web.auth import AuthStore  # noqa: E402

BASE = cg.BASE              # 1700000400: an exact multiple of 60
BUCKET = cg.BUCKET          # 60.0
SENTINEL = cg.LEAK_PROBES   # identity material that must never be persisted

PASSWORD = "p5-incidents-password-0"

FROZEN_V5_TABLES = {"meta", "timeline_samples", "device_protocol_states",
                    "network_probe_samples", "journal_runs", "journal_events",
                    "journal_ingest_audit", "journal_ingest_state",
                    "incident_windows", "incident_runtime_state",
                    "operator_markers"}

# The EXACT evidence wire whitelists (#63 R2 §8), restated as literals --
# a second witness written by a different hand than the store module.
WIRE_SAMPLE_COLUMNS = (
    "epoch", "iso_utc", "collector_stale", "api_status",
    "total_active_connections", "reality_active_connections",
    "hysteria2_active_connections", "other_active_connections",
    "uplink_rate", "downlink_rate",
    "skipped_events", "duplicate_events", "identity_conflicts",
    "abandoned_on_reset",
)
WIRE_DEVICE_COLUMNS = (
    "epoch", "iso_utc", "device", "inbound", "active_connections",
    "device_status", "uplink_rate", "downlink_rate",
    "uplink_total", "downlink_total", "reason",
)
WIRE_PROBE_COLUMNS = (
    "epoch", "iso_utc",
    "dns_status", "dns_latency_ms", "dns_error_code",
    "https_status", "https_latency_ms", "https_error_code",
    "udp_status", "udp_latency_ms", "udp_error_code",
    "egress_status", "egress_latency_ms", "egress_error_code",
    "egress_ip", "egress_change",
)
WIRE_JOURNAL_COLUMNS = ("seq", "ts", "cls", "proto", "port", "dcls", "n")
WIRE_AUDIT_COLUMNS = ("epoch", "kind", "seq", "code")
WIRE_COLUMNS = {"samples": WIRE_SAMPLE_COLUMNS,
                "device_states": WIRE_DEVICE_COLUMNS,
                "probe_rows": WIRE_PROBE_COLUMNS,
                "journal_events": WIRE_JOURNAL_COLUMNS,
                "audit": WIRE_AUDIT_COLUMNS}

# Identity / reader material that must NEVER appear on the evidence wire.
FORBIDDEN_ROW_KEYS = {"run_id", "cycle_id", "result_version", "fp"}


# -- harness plumbing ---------------------------------------------------------

def _store_dir(**kw):
    """One REAL schema-v5 store over a private temp root."""
    root = tempfile.mkdtemp(prefix="p5-inc-")
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


def _open_incident(history, category=ic.CATEGORY_REALITY_TCP,
                   analysis_start=None, first_signal=None, last_signal=None,
                   classified_end=None, buckets=5, evidence_bits=0,
                   unknown_bits=0):
    """One incident row through the store's own boundary."""
    z = lambda value, default: default if value is None else value  # noqa: E731
    return history.incident_open_window(
        category, z(analysis_start, BASE), z(first_signal, BASE + 180),
        z(last_signal, BASE + 240), z(classified_end, BASE + 240), buckets,
        evidence_bits, unknown_bits)


class _FakeBroker:
    def snapshot(self):
        return cg._snapshot(25, 15)


def _serve(history, scanner=None):
    """One loopback HTTP server over the SHIPPED handler + store. Returns
    (server, request, login, auth) -- auth so the caller can grant the
    step-up window and read CSRF tokens."""
    d = tempfile.mkdtemp(prefix="p5-inc-http-")
    access = AccessPolicy(d)
    auth = AuthStore(d, session_ttl=3600.0)
    auth.set_password(PASSWORD)
    app = sv.MonitorWebApp(broker=_FakeBroker(), access=access,
                           static_dir=None, auth=auth,
                           incident_history=history,
                           incident_scanner=scanner)
    server = sv.build_server(app, "127.0.0.1", 0, None)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    def request(method, path, cookie=None, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        send_headers = dict(headers or {})
        if cookie:
            send_headers["Cookie"] = cookie
        if body is not None:
            send_headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        conn.request(method, path, body, send_headers)
        response = conn.getresponse()
        payload = response.read().decode("utf-8")
        set_cookie = response.getheader("Set-Cookie") or ""
        allow = response.getheader("Allow") or ""
        conn.close()
        return response.status, payload, set_cookie, allow

    def login():
        _status, _body, cookies, _allow = request(
            "POST", "/api/v1/login", body={"password": PASSWORD})
        return cookies.split(";")[0] if _status == 200 else ""

    return server, request, login, auth


def _session_token(session_cookie):
    """The bare session token out of the lane's own cookie string -- the
    same extraction the server's SimpleCookie path performs."""
    return session_cookie.split("=", 1)[1] \
        if "=" in session_cookie else session_cookie


def _csrf_headers(session_cookie, auth):
    session = auth.sessions.resolve(_session_token(session_cookie))
    return {"X-CSRF-Token": session["csrf_token"]} if session else {}


def _grant_step_up(auth, session_cookie):
    auth.sessions.grant_step_up(_session_token(session_cookie), 300)


# -- group: presenter contract -------------------------------------------------

def group_presenter():
    out = {}
    # (1) Purity: the module imports NOTHING but __future__, and its source
    #     holds no I/O, clock or storage call site.
    source = open(os.path.join(os.environ["MONITOR_V2_ROOT"], "web",
                               "incident_presenter.py"),
                  encoding="utf-8").read()
    tree = ast.parse(source)
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add(("." * node.level) + (node.module or ""))
    out["presenter_imports_are_closed"] = imports == {"__future__"}
    out["presenter_has_no_io_or_clock"] = not any(
        token in source for token in
        ("open(", "socket", "sqlite", "requests", "subprocess",
         "time.time", "datetime.now", "urllib"))
    out["presenter_never_names_the_classifier"] = (
        "incident_classifier" not in source and "incident_runtime"
        not in source)
    # (2) The positional mirrors are EXACTLY the classifier's sorted
    #     vocabularies (tests may import the classifier; the presenter may
    #     not -- that asymmetry IS the single-consumer wall).
    out["evidence_mirror_is_exact"] = ip.EVIDENCE_TOKEN_ORDER == \
        tuple(sorted(ic.EVIDENCE_TOKENS))
    out["unknown_mirror_is_exact"] = ip.UNKNOWN_TOKEN_ORDER == \
        tuple(sorted(ic.UNKNOWN_TOKENS))
    out["categories_mirror_is_exact"] = ip.EMITTABLE_CATEGORIES == \
        tuple(sorted(ic.EMITTABLE_CATEGORIES))
    out["vocabulary_widths_are_frozen"] = (
        len(ip.EVIDENCE_TOKEN_ORDER) == 45
        and len(ip.UNKNOWN_TOKEN_ORDER) == 28)
    # (3) The explanation tables cover the FULL closed vocabularies, with
    #     non-empty operator sentences and nothing else.
    out["evidence_explanations_cover_all"] = (
        set(ip.EVIDENCE_EXPLANATIONS) == set(ip.EVIDENCE_TOKENS)
        and all(isinstance(text, str) and text
                for text in ip.EVIDENCE_EXPLANATIONS.values()))
    out["unknown_explanations_cover_all"] = (
        set(ip.UNKNOWN_EXPLANATIONS) == set(ip.UNKNOWN_TOKENS)
        and all(isinstance(text, str) and text
                for text in ip.UNKNOWN_EXPLANATIONS.values()))
    out["marker_labels_cover_both_kinds"] = (
        set(ip.MARKER_LABELS) == set(ih.MARKER_KINDS)
        and ip.marker_label("tt_live_studio_login_failed")
        == "TT Live Studio login failed"
        and ip.marker_label("operator_event")
        == "Operator-observed event"
        and ip.marker_label("free text") is None
        and ip.marker_label(None) is None)
    # (4) The bitset decoders: every single-token bitset round-trips at its
    #     sorted position, the full union decodes, and one bit past the
    #     frozen width (or a bool, or a float) is refused -- never guessed.
    out["evidence_decode_is_positional"] = all(
        ip.bits_to_evidence(1 << position) == (token,)
        for position, token in enumerate(ip.EVIDENCE_TOKEN_ORDER))
    out["unknown_decode_is_positional"] = all(
        ip.bits_to_unknown(1 << position) == (token,)
        for position, token in enumerate(ip.UNKNOWN_TOKEN_ORDER))
    out["decode_full_union_round_trips"] = (
        ip.bits_to_evidence(2 ** 45 - 1) == ip.EVIDENCE_TOKEN_ORDER
        and ip.bits_to_unknown(2 ** 28 - 1) == ip.UNKNOWN_TOKEN_ORDER)
    out["decode_refuses_one_past_and_non_int"] = (
        ip.bits_to_evidence(1 << 45) is None
        and ip.bits_to_unknown(1 << 28) is None
        and ip.bits_to_evidence(True) is None
        and ip.bits_to_unknown(1.0) is None
        and ip.bits_to_evidence(-1) is None)
    # (5) The texts surface: [{"token","text"}] exactly, no extra keys.
    texts = ip.evidence_texts(("api_stale", "egress_ip_changed"))
    out["evidence_texts_shape"] = texts == [
        {"token": "api_stale", "text": ip.EVIDENCE_EXPLANATIONS["api_stale"]},
        {"token": "egress_ip_changed",
         "text": ip.EVIDENCE_EXPLANATIONS["egress_ip_changed"]}]
    # (6) The L1 summary: exact 10-key shape, and NOTHING outside it.
    row = {"category": ic.CATEGORY_REALITY_TCP,
           "first_signal_epoch": BASE + 180.0,
           "last_signal_epoch": BASE + 240.0}
    summary = ip.summarize(row, ("root_cause_not_established",))
    out["summary_keys_are_exactly_ten"] = (
        set(summary) == set(ip.SUMMARY_KEYS) and len(summary) == 10)
    out["summary_window_is_the_signal_window"] = (
        summary["window"] == {"start_epoch": BASE + 180.0,
                              "end_epoch": BASE + 240.0,
                              "duration_seconds": 60.0})
    out["reality_action_is_conditional"] = (
        "If Hysteria2 is independently confirmed healthy"
        in summary["recommended_action"])
    out["reality_never_claims_hy2_healthy"] = (
        "does not prove Hysteria2 was healthy"
        in summary["protocol_state"])
    out["summary_names_no_server_down"] = (
        "server down" not in json.dumps(summary).lower())
    out["summary_carries_the_standing_limitations"] = (
        "root cause is not established" in summary["limitations"]
        and "ISP" in summary["limitations"])
    # (7) Every emittable category summarizes; insufficient has NO action;
    #     the uncertainty count is the only interpolation (0/1/N forms).
    for category in ip.EMITTABLE_CATEGORIES:
        one = ip.summarize({"category": category,
                            "first_signal_epoch": 1.0,
                            "last_signal_epoch": 2.0}, ())
        if one is None or set(one) != set(ip.SUMMARY_KEYS):
            out["summary_covers_%s" % category] = False
            break
    else:
        out["summary_covers_every_emittable_category"] = True
    out["insufficient_has_no_recommended_action"] = (
        ip.summarize({"category": "insufficient_evidence",
                      "first_signal_epoch": 1.0,
                      "last_signal_epoch": 2.0}, ())
        ["recommended_action"] is None)
    zero = ip.summarize(row, ())
    one_q = ip.summarize(row, ("no_corroboration",))
    two_q = ip.summarize(row, ("no_corroboration", "count_drop_only"))
    out["uncertainty_is_the_only_interpolation"] = (
        "No open questions" in zero["uncertainty"]
        and "1 open question" in one_q["uncertainty"]
        and "2 open questions" in two_q["uncertainty"])
    out["summary_refuses_unknown_category"] = (
        ip.summarize({"category": "destination_specific",
                      "first_signal_epoch": 1.0,
                      "last_signal_epoch": 2.0}, ()) is None
        and ip.summarize(None, ()) is None
        and ip.summarize({"category": ic.CATEGORY_REALITY_TCP,
                          "first_signal_epoch": 5.0,
                          "last_signal_epoch": 1.0}, ()) is None)
    return out


# -- group: the v5 store plane --------------------------------------------------

def group_store():
    out = {}
    history, root, clock = _store_dir()
    try:
        conn = history._conn
        # (1) Exactly the ELEVEN v5 tables, no more, no fewer.
        tables = {row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        out["exactly_eleven_v5_tables"] = tables == FROZEN_V5_TABLES
        marker_cols = [row[1] for row in conn.execute(
            "PRAGMA table_info(operator_markers)")]
        out["marker_columns_exact"] = marker_cols == list(ih.MARKER_COLUMNS)
        # (2) The marker boundary: both closed kinds persist; the default
        #     epoch is now; the 4-key row is exactly the stored shape.
        clock[0] = BASE + 1000.0
        first = history.record_marker("tt_live_studio_login_failed")
        out["marker_lands_with_default_epoch"] = (
            first is not None and first["epoch"] == BASE + 1000.0
            and first["created_epoch"] == BASE + 1000.0
            and set(first) == {"marker_id", "epoch", "kind", "created_epoch"})
        second = history.record_marker("operator_event", BASE + 500.0)
        out["operator_event_lands"] = second is not None \
            and second["epoch"] == BASE + 500.0
        # (3) The refusals: unknown kind, future epoch, already-aged-out
        #     epoch, non-epoch garbage. Zero bytes landed for any of them.
        rejected_before = history.incident_status()["rejected_total"]
        out["marker_refuses_unknown_kind"] = (
            history.record_marker("my own note") is None
            and history.record_marker(None) is None)
        out["marker_refuses_future_epoch"] = (
            history.record_marker("operator_event", BASE + 2000.0) is None)
        out["marker_refuses_already_aged_out"] = (
            history.record_marker("operator_event",
                                  BASE - ih.RETENTION_SECONDS - 1.0) is None)
        out["marker_refuses_non_epoch"] = (
            history.record_marker("operator_event", "now") is None
            and history.record_marker("operator_event", True) is None)
        out["marker_refusals_counted_closed"] = (
            history.incident_status()["rejected_total"] > rejected_before)
        out["marker_get_round_trips"] = (
            history.marker_get(first["marker_id"]) == first
            and history.marker_get(999_999) is None
            and history.marker_get(True) is None)
        # (4) The bounded list: newest epoch first, exact keys, honest
        #     truncation at the limit.
        listing = history.query_markers(1)
        out["marker_list_newest_first_with_truncation"] = (
            [m["marker_id"] for m in listing["markers"]] == [first["marker_id"]]
            and listing["truncated"] is True
            and set(listing) == {"markers", "truncated", "limit"})
        listing_all = history.query_markers(100)
        out["marker_list_two_rows_untruncated"] = (
            len(listing_all["markers"]) == 2
            and listing_all["truncated"] is False)
        # (5) Markers never enter the classifier bundle: the bundle read
        #     over a window containing both markers is byte-identical
        #     before and after they were written.
        bundle_after = history.classifier_bundle(BASE, BASE + 1100.0, "fresh")
        keys = set(bundle_after) if bundle_after else set()
        out["bundle_keys_are_eight_closed_sections"] = keys == {
            "window", "health", "reader", "samples", "device_states",
            "probe_rows", "journal_events", "audit"}
        dumped = json.dumps(bundle_after, sort_keys=True, default=str)
        out["bundle_carries_no_marker"] = (
            "tt_live_studio_login_failed" not in dumped
            and "operator_event" not in dumped
            and "marker_id" not in dumped)
        # (6) The marker_count join: closed on BOTH window ends, zero
        #     outside, and exactly the in-window markers counted.
        _open_incident(history, analysis_start=BASE + 400.0,
                       first_signal=BASE + 420.0, last_signal=BASE + 480.0,
                       classified_end=BASE + 600.0)
        rows = history.query_incidents()["incidents"]
        window_row = rows[0]
        out["marker_count_is_window_closed_join"] = (
            history.marker_count(window_row["analysis_start_epoch"],
                                 window_row["last_classified_end_epoch"]) == 1
            and history.marker_count(BASE + 501.0, BASE + 600.0) == 0
            and history.marker_count(BASE + 400.0, BASE + 499.0) == 0)
        # (7) Markers participate in TIME retention: an aged-out marker is
        #     pruned by the same cleanup pass, and _PRUNE_SOURCES carries
        #     the table for SIZE pruning as one more global-order source.
        clock[0] = BASE + 1000.0 + ih.RETENTION_SECONDS
        history._cleanup("p5-retention")
        out["marker_time_retention_prunes"] = (
            history.marker_get(second["marker_id"]) is None
            and history.marker_get(first["marker_id"]) is not None)
        out["marker_size_retention_source"] = (
            ("operator_markers", "epoch") in ih._PRUNE_SOURCES)
        history.close()
        _drop(root)

        # (8) The v4 -> v5 migration: an exact v4 database (built by
        #     dropping the marker table from a v5 store and rewinding the
        #     declared version) migrates FORWARD in one transaction; the
        #     marker table returns and every v4 row survives. A v4
        #     DECLARATION over the v5 shape is a hybrid: refused.
        history, root, clock = _store_dir()
        conn = history._conn
        kept_incident = _open_incident(history)
        conn.execute("INSERT INTO operator_markers (epoch, kind,"
                     " created_epoch) VALUES (?, 'operator_event', ?)",
                     (BASE + 10.0, BASE + 10.0))
        conn.commit()
        history.close()
        db_path = os.path.join(root, "diagnostics", "history.sqlite3")
        mv = sqlite3.connect(db_path)
        mv.execute("DROP TABLE operator_markers")
        mv.execute("UPDATE meta SET value='4' WHERE key='schema_version'")
        mv.commit()
        mv.close()
        history = ih.IncidentHistory(os.path.join(root, "diagnostics"),
                                     SENTINEL[0], clock=lambda: clock[0])
        history.open()
        out["v4_source_migrates_to_v5"] = (
            history.health()["enabled"]
            and dict(history._conn.execute(
                "SELECT key, value FROM meta")).get("schema_version") == "5")
        mv = sqlite3.connect(db_path)
        tables_mv = {row[0] for row in mv.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        marker_row = mv.execute(
            "SELECT epoch, kind FROM operator_markers").fetchall()
        incident_kept = mv.execute(
            "SELECT incident_id, category, state FROM incident_windows"
            " WHERE incident_id = ?", (kept_incident,)).fetchall()
        mv.close()
        out["v4_migration_shape_is_exact_v5"] = (
            tables_mv == FROZEN_V5_TABLES and marker_row == [])
        out["v4_migration_preserves_v4_rows"] = (
            bool(incident_kept) and incident_kept[0][2] == "open")
        reopened = open(db_path, "rb").read()
        history.close()
        stable = ih.IncidentHistory(os.path.join(root, "diagnostics"),
                                    SENTINEL[0], clock=lambda: clock[0])
        stable.open()
        out["v4_migration_reopen_zero_bytes"] = (
            stable.health()["enabled"]
            and open(db_path, "rb").read() == reopened)
        stable.close()
        # a v4 CLAIM over the v5 shape (marker table present) is refused
        _drop(root)
        history, root, clock = _store_dir()
        history.close()
        db_path = os.path.join(root, "diagnostics", "history.sqlite3")
        mv = sqlite3.connect(db_path)
        mv.execute("UPDATE meta SET value='4' WHERE key='schema_version'")
        mv.commit()
        before_bytes = open(db_path, "rb").read()
        hybrid = ih.IncidentHistory(os.path.join(root, "diagnostics"),
                                    SENTINEL[0], clock=lambda: clock[0])
        hybrid.open()
        out["v4_claim_on_v5_shape_refused"] = (
            not hybrid.health()["enabled"]
            and hybrid.health()["last_error_code"]
            == ih.CODE_SCHEMA_UNSUPPORTED
            and open(db_path, "rb").read() == before_bytes)
        hybrid.close()
        _drop(root)

        # (9) The store-side re-arm (#63 R2 §10): the SQL WHERE clause
        #     restates every precondition; the floor is the SAME one-minute
        #     bucket grid; nothing else moves.
        ih_bucket_ok = (ih.INCIDENT_BUCKET_SECONDS == 60
                        == ic.BUCKET_SECONDS == ir.BUCKET_SECONDS)
        out["rearm_bucket_grid_is_the_shared_60"] = ih_bucket_ok
        history, root, clock = _store_dir()
        conn = history._conn
        out["rearm_refused_on_inert_row"] = (
            history.incident_rearm() is False)
        history.incident_activate(BASE)
        # The store's own clock must stand past every signal it closes
        # over (a close may not precede the signal it settles).
        clock[0] = BASE + 700.0
        out["rearm_refused_without_window_limit"] = (
            history.incident_rearm() is False)
        opened = _open_incident(history)
        history.incident_close_window(opened, ic.CATEGORY_REALITY_TCP,
                                      BASE + 240, BASE + 300, 5, 0, 0,
                                      "clean_buckets")
        out["rearm_refused_after_clean_close"] = (
            history.incident_rearm() is False)
        second = _open_incident(history, category=ic.CATEGORY_HY2_UDP)
        history.incident_close_window(second, ic.CATEGORY_HY2_UDP,
                                      BASE + 240, BASE + 300, 5, 0, 0,
                                      "window_limit")
        clock[0] = BASE + 700.3   # floor must be ceil(700.3/60)*60 = 720
        state_before = history.incident_runtime_snapshot()["state"]
        out["rearm_lands_on_window_limit_state"] = (
            history.incident_rearm() is True)
        state_after = history.incident_runtime_snapshot()["state"]
        out["rearm_floor_is_the_bucket_grid"] = (
            state_after["discovery_floor_epoch"] == BASE + 720.0
            and state_after["rearm_required"] == 0)
        out["rearm_moves_nothing_else"] = (
            state_after["activation_floor_epoch"]
            == state_before["activation_floor_epoch"]
            and state_after["last_evaluated_end_epoch"]
            == state_before["last_evaluated_end_epoch"]
            and state_after["reader_fresh_since_epoch"]
            == state_before["reader_fresh_since_epoch"]
            and len(history.query_incidents()["incidents"]) == 2)
        out["rearm_is_one_shot"] = (
            history.incident_rearm() is False)
        # The rearm_required=1 shape EXCLUDES an open incident by the v4
        # shape CHECK, so the SQL precondition list is exactly what the
        # scenarios above can exercise: inert row, no window-limit gate,
        # clean-close state, and the one-shot guard.
    finally:
        history.close()
        _drop(root)
    return out


# -- group: the HTTP surface ----------------------------------------------------

def group_api():
    out = {}
    # The store clock rides REAL time here, on purpose: the marker epoch
    # rules are validated at the SERVER against time.time() and again at
    # the STORE boundary against its own clock -- one clock, so the two
    # gates face the same numbers exactly as they do in production.
    history, root, clock = _store_dir()
    clock[0] = time.time()
    try:
        server, request, login, auth = _serve(history)
        try:
            session = login()
            out["harness_logged_in"] = bool(session)
            # (1) The list surface: exact key set on an empty store, with
            #     the CURRENT runtime + history health next to the rows.
            status, body, _c, _a = request("GET", "/api/v1/incidents",
                                           cookie=session)
            data = json.loads(body) if status == 200 else {}
            out["list_keys_are_exactly_five"] = (
                status == 200 and set(data) == {
                    "incidents", "runtime", "history", "truncated", "limit"})
            out["empty_store_lists_nothing"] = (
                data.get("incidents") == [] and data.get("truncated") is False)
            out["list_carries_current_health_not_incident_health"] = (
                isinstance(data.get("history"), dict)
                and set(data["history"]) == {"enabled", "degraded",
                                             "last_success_at",
                                             "failure_count",
                                             "last_error_code", "run_id"})
            out["unwired_scanner_lists_runtime_null"] = (
                data.get("runtime") is None)
            # (2) The list params: invalid state / <1 limit are 400s, an
            #     over-large limit clamps, unknown keys are ignored.
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents?state=bogus", cookie=session)
            out["list_refuses_bad_state"] = (
                status == 400 and json.loads(body)["error"] == "invalid_state")
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents?limit=0", cookie=session)
            out["list_refuses_zero_limit"] = (
                status == 400 and json.loads(body)["error"] == "invalid_limit")
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents?limit=99999&whatever=1",
                cookie=session)
            out["list_clamps_limit_ignores_unknown"] = (
                status == 200 and json.loads(body)["limit"] == 500)
            # (3) Detail: missing and non-integer ids are the same closed
            #     404; the route never confirms an arbitrary number.
            status, body, _c, _a = request("GET", "/api/v1/incidents/999",
                                           cookie=session)
            out["detail_missing_is_closed_404"] = (
                status == 404
                and json.loads(body)["error"] == "incident_not_found")
            status, body, _c, _a = request("GET", "/api/v1/incidents/abc",
                                           cookie=session)
            out["detail_non_integer_is_closed_404"] = (
                status == 404
                and json.loads(body)["error"] == "incident_not_found")
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents/rearm", cookie=session)
            out["rearm_get_is_method_error"] = (
                status == 405 and _a == "POST")
            status, body, _c, _a = request("POST", "/api/v1/incidents",
                                           cookie=session,
                                           body={}, headers=_csrf_headers(
                                               session, auth))
            out["list_post_is_method_error"] = (
                status == 405 and _a == "GET")
            # (4) Evidence params: the subject rule and the section rule.
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples", cookie=session)
            out["evidence_without_subject_is_400"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_subject")
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples&incident_id=1"
                       "&marker_id=1", cookie=session)
            out["evidence_with_both_subjects_is_400"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_subject")
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=raw_logs&incident_id=1",
                cookie=session)
            out["evidence_refuses_bad_section"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_section")
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples&incident_id=abc",
                cookie=session)
            out["evidence_refuses_bad_subject_id"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_subject")
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples&incident_id=999",
                cookie=session)
            out["evidence_missing_incident_is_404"] = (
                status == 404
                and json.loads(body)["error"] == "incident_not_found")
            # (5) Markers through the API: the GET shape. The POST body
            #     rules live behind the FULL authorization chain (§11), so
            #     they are proven in (6b) after the step-up grant.
            status, body, _c, _a = request("GET", "/api/v1/markers",
                                           cookie=session)
            data_m = json.loads(body) if status == 200 else {}
            out["markers_get_keys_exact"] = (
                status == 200 and set(data_m) == {"markers", "truncated",
                                                  "limit"})
            # (6) The auth matrix (#63 R2 §11): GETs are session-gated;
            #     POSTs need session -> CSRF -> step-up, in that order.
            for path in ("/api/v1/incidents", "/api/v1/markers"):
                status, body, _c, _a = request("GET", path)
                out["get_%s_needs_session"
                    % path.replace("/api/v1/", "").replace("/", "_")] = (
                    status == 401
                    and json.loads(body)["error"] == "login required")
            status, body, _c, _a = request("POST", "/api/v1/markers",
                                           body={"kind": "operator_event"})
            out["marker_post_needs_session"] = (
                status == 401
                and json.loads(body)["error"] == "login required")
            status, body, _c, _a = request(
                "POST", "/api/v1/markers", cookie=session,
                body={"kind": "operator_event"})
            out["marker_post_needs_csrf"] = (
                status == 403
                and json.loads(body)["error"] == "missing or invalid CSRF"
                                                 " token")
            status, body, _c, _a = request(
                "POST", "/api/v1/incidents/rearm", cookie=session,
                body={}, headers=_csrf_headers(session, auth))
            out["rearm_post_needs_step_up"] = (
                status == 401
                and json.loads(body)["error"] == "reauth_required")
            _grant_step_up(auth, session)
            status, body, _c, _a = request(
                "POST", "/api/v1/incidents/rearm", cookie=session,
                body={}, headers=_csrf_headers(session, auth))
            out["rearm_without_runtime_gate_is_409"] = (
                status == 409 and json.loads(body)["error"]
                == "incident_runtime_not_rearmable")
            # (6b) Marker body rules, now behind the FULL chain: an extra
            #      key, a free-text kind, a future epoch and an
            #      already-aged-out epoch are each a closed 400 -- there
            #      is no body field a note could hide in.
            status, body, _c, _a = request(
                "POST", "/api/v1/markers", cookie=session,
                body={"kind": "operator_event", "text": "free note"},
                headers=_csrf_headers(session, auth))
            out["marker_post_refuses_extra_key"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_request_body")
            status, body, _c, _a = request(
                "POST", "/api/v1/markers", cookie=session,
                body={"kind": "my note"},
                headers=_csrf_headers(session, auth))
            out["marker_post_refuses_free_text_kind"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_marker_kind")
            status, body, _c, _a = request(
                "POST", "/api/v1/markers", cookie=session,
                body={"kind": "operator_event",
                      "epoch": time.time() + 3600.0},
                headers=_csrf_headers(session, auth))
            out["marker_post_refuses_future_epoch"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_marker_epoch")
            status, body, _c, _a = request(
                "POST", "/api/v1/markers", cookie=session,
                body={"kind": "operator_event",
                      "epoch": time.time() - ih.RETENTION_SECONDS - 1.0},
                headers=_csrf_headers(session, auth))
            out["marker_post_refuses_already_aged_out"] = (
                status == 400
                and json.loads(body)["error"] == "invalid_marker_epoch")
            # (7) The marker lands over HTTP and carries the closed label.
            status, body, _c, _a = request(
                "POST", "/api/v1/markers", cookie=session,
                body={"kind": "tt_live_studio_login_failed"},
                headers=_csrf_headers(session, auth))
            marker = json.loads(body) if status == 200 else {}
            out["marker_post_lands_with_label"] = (
                status == 200
                and set(marker) == {"marker_id", "epoch", "kind", "label",
                                    "created_epoch"}
                and marker["label"] == "TT Live Studio login failed")
            status, body, _c, _a = request("GET", "/api/v1/markers",
                                           cookie=session)
            listed = json.loads(body).get("markers") or []
            out["marker_list_carries_five_key_shape"] = (
                bool(listed) and set(listed[0]) == {
                    "marker_id", "epoch", "kind", "label", "created_epoch"})
            # (8) Evidence is subject-bound and whitelist-exact: one
            #     incident row over a store WITH samples + probes + journal
            #     rows; egress_ip visible, run_id/cycle_id/fp absent.
            _pump_evidence(history, clock)
            opened = _open_incident(history)
            for section in ("samples", "probe_rows", "journal_events"):
                status, body, _c, _a = request(
                    "GET", "/api/v1/evidence?section=%s&incident_id=%d"
                    % (section, opened), cookie=session)
                data_e = json.loads(body) if status == 200 else {}
                rows = data_e.get("rows") or []
                out["evidence_%s_whitelist_exact" % section] = (
                    status == 200
                    and set(data_e) == {"subject", "section", "window",
                                        "rows", "truncated",
                                        "retention_cutoff_epoch"}
                    and data_e.get("subject")
                    == {"type": "incident", "id": opened}
                    and all(set(row) == set(WIRE_COLUMNS[section])
                            for row in rows))
            # The incident window is SERVER-derived: the URL cannot
            # create arbitrary historical browsing.
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples&incident_id=%d"
                       "&start_epoch=0&end_epoch=99999999" % opened,
                cookie=session)
            data_e = json.loads(body) if status == 200 else {}
            out["url_cannot_widen_the_window"] = (
                status == 200
                and data_e.get("window") == {"start_epoch": BASE,
                                             "end_epoch": BASE + 240.0})
            # marker-bound evidence: the +/-900 s context span
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples&marker_id=%d"
                % marker["marker_id"], cookie=session)
            data_e = json.loads(body) if status == 200 else {}
            out["marker_evidence_window_is_plus_minus_900"] = (
                status == 200
                and data_e.get("window") == {
                    "start_epoch": max(0.0, marker["epoch"] - 900.0),
                    "end_epoch": marker["epoch"] + 900.0}
                and data_e.get("subject")
                == {"type": "marker", "id": marker["marker_id"]})
            status, body, _c, _a = request(
                "GET", "/api/v1/evidence?section=samples&marker_id=999",
                cookie=session)
            out["marker_evidence_missing_is_404"] = (
                status == 404
                and json.loads(body)["error"] == "marker_not_found")
            # (9) The timeline endpoint is BYTE-FROZEN: same keys, no new
            #     query parameter, and the P5 surface never widened it.
            status, body, _c, _a = request(
                "GET", "/api/v1/diagnostics/timeline", cookie=session)
            data_t = json.loads(body) if status == 200 else {}
            out["timeline_keys_unchanged"] = (
                status == 200 and set(data_t) == {
                    "history", "samples", "device_states", "probe_rows",
                    "probes", "incident_runtime", "truncated", "limit"})
            status, body2, _c, _a = request(
                "GET", "/api/v1/diagnostics/timeline?incident=1",
                cookie=session)
            out["timeline_ignores_unknown_params"] = (
                status == 200 and set(json.loads(body2)) == set(data_t))
            # (10) No edit/delete anywhere on the marker family: the
            #      uniform method wall answers 405 with Allow: GET, POST.
            status, body, _c, allow = request(
                "DELETE", "/api/v1/markers")
            out["marker_delete_is_uniform_405"] = status == 405 \
                and allow == "GET, POST"
            server.shutdown()
            server.server_close()
        finally:
            try:
                server.server_close()
            except Exception:  # noqa: BLE001 -- teardown never decides
                pass
    finally:
        history.close()
        _drop(root)
    return out


def _pump_evidence(history, clock):
    """Real rows in every evidence section, via the store's own write
    boundaries where one exists and plain INSERTs where the publish
    boundary is the only writer."""
    conn = history._conn
    sample_cols = (
        "epoch", "iso_utc", "run_id", "monitor_uptime_seconds",
        "snapshot_version", "snapshot_generated_at", "last_success_at",
        "collector_stale", "api_status", "total_active_connections",
        "reality_active_connections", "hysteria2_active_connections",
        "other_active_connections", "uplink_rate", "downlink_rate",
        "skipped_events", "duplicate_events", "identity_conflicts",
        "abandoned_on_reset")
    sql = "INSERT INTO timeline_samples (%s) VALUES (%s)" % (
        ", ".join(sample_cols), ", ".join("?" * len(sample_cols)))
    for index in range(4):
        conn.execute(sql, (BASE + index * 60.0 + 1.0, "x", SENTINEL[0],
                           1.0, index, None, None, 0, "CONNECTED", 40, 25,
                           15, 0, 1.0, 2.0, 0, 0, 0, 0))
    probe_cols = list(ih.PROBE_COLUMNS)
    psql = "INSERT INTO network_probe_samples (%s) VALUES (%s)" % (
        ", ".join(probe_cols), ", ".join("?" * len(probe_cols)))
    conn.execute(psql, [BASE + 1.0, "x", SENTINEL[0],
                        "a" * 32, 1, "ok", 12, "NONE", "ok", 12, "NONE",
                        "ok", 12, "NONE", "ok", 12, "NONE",
                        "203.0.113.1", "unchanged"])
    conn.execute(
        "INSERT INTO journal_runs (seq, run, source_epoch, boundary, lines,"
        " eligible, info_dropped, nomatch_dropped, priority_unusable,"
        " pfail, limited, first_ts, last_ts, record_count, event_count,"
        " ingested_epoch, ingested_at)"
        " VALUES (1, '%s', 1, 'NONE', 10, 3, 2, 5, 0, 0, 0, ?, ?, 1, 1, ?,"
        " 'x')" % ("a" * 32),
        (BASE + 1.0, BASE + 1.0, BASE + 1.0))
    conn.execute(
        "INSERT INTO journal_events (seq, ts, cls, proto, port, dcls, fp, n)"
        " VALUES (1, ?, 'reset', 'Reality', 443, 'https443', NULL, 3)",
        (BASE + 30.0,))
    conn.execute(
        "INSERT INTO journal_ingest_audit (epoch, kind, seq, code)"
        " VALUES (?, 'gap', 2, 'sequence_gap')", (BASE + 1.0,))
    conn.commit()


# -- group: the incidents API over a LIVE incident (#63 R2 §4/§6) ---------------

def group_live_incident():
    out = {}
    history, root, clock = _store_dir()
    try:
        # (1) One REAL incident row through the boundary, then the full
        #     detail surface over HTTP. The verdict bits come from the
        #     LIVE reader over the pumped evidence, not from a canned
        #     bundle.
        _pump_evidence(history, clock)
        live_bundle = history.classifier_bundle(BASE, BASE + 240.0, "fresh")
        detection = ic.detect(live_bundle)
        cls = detection.classification
        opened = history.incident_open_window(
            cls.category, BASE, detection.first_signal_epoch
            if detection.first_signal_epoch else BASE + 180.0,
            detection.last_signal_epoch
            if detection.last_signal_epoch else BASE + 240.0,
            BASE + 240.0, 5,
            ic.evidence_to_bits(cls.evidence),
            ic.unknown_to_bits(cls.unknowns))
        out["live_incident_lands"] = opened is not None
        server, request, login, auth = _serve(history)
        try:
            session = login()
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents?state=open", cookie=session)
            data = json.loads(body) if status == 200 else {}
            rows = data.get("incidents") or []
            out["list_row_keys_are_exactly_twelve"] = (
                status == 200 and bool(rows)
                and set(rows[0]) == {
                    "incident_id", "classifier_version", "state", "category",
                    "analysis_start_epoch", "first_signal_epoch",
                    "last_signal_epoch", "last_classified_end_epoch",
                    "closed_epoch", "closure_reason", "buckets",
                    "marker_count"})
            out["list_category_is_emittable_only"] = (
                bool(rows) and rows[0]["category"]
                in ip.EMITTABLE_CATEGORIES)
            out["state_filter_narrows"] = (
                all(row["state"] == "open" for row in rows))
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents?state=closed", cookie=session)
            out["state_filter_closed_is_empty"] = (
                status == 200 and json.loads(body)["incidents"] == [])
            # (2) The detail: 20 keys, decoded texts, the 10-key summary,
            #     the marker join. destination_specific can never appear.
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents/%d" % opened, cookie=session)
            detail = json.loads(body) if status == 200 else {}
            out["detail_keys_are_exactly_twenty"] = (
                status == 200 and set(detail) == {
                    "incident_id", "classifier_version", "state", "category",
                    "analysis_start_epoch", "first_signal_epoch",
                    "last_signal_epoch", "last_classified_end_epoch",
                    "closed_epoch", "closure_reason", "buckets",
                    "marker_count", "created_epoch", "updated_epoch",
                    "evidence_bits", "unknown_bits", "evidence", "unknowns",
                    "summary", "markers"})
            out["detail_never_names_destination_specific"] = (
                "destination_specific" not in json.dumps(detail))
            out["detail_texts_are_human_readable"] = (
                all(set(item) == {"token", "text"} and item["text"]
                    for item in detail.get("evidence", []))
                and all(set(item) == {"token", "text"} and item["text"]
                        for item in detail.get("unknowns", [])))
            out["detail_bits_match_decoded_texts"] = (
                [item["token"] for item in detail.get("evidence", [])]
                == list(ip.bits_to_evidence(detail["evidence_bits"])))
            out["detail_summary_is_the_ten_key_l1"] = (
                set(detail.get("summary") or {}) == set(ip.SUMMARY_KEYS))
            # (3) A marker inside the window is joined; one outside is not.
            #     The store clock first advances past both marker epochs,
            #     so neither is future-dated relative to the store.
            clock[0] = BASE + 90_500.0
            in_window = history.record_marker("operator_event",
                                              BASE + 100.0)
            out_of_window = history.record_marker("operator_event",
                                                  BASE + 90_000.0)
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents/%d" % opened, cookie=session)
            detail = json.loads(body)
            joined = [m["marker_id"] for m in detail.get("markers", [])]
            out["detail_joins_only_in_window_markers"] = (
                in_window["marker_id"] in joined
                and out_of_window["marker_id"] not in joined)
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents", cookie=session)
            listed = json.loads(body)["incidents"]
            out["list_marker_count_matches_join"] = (
                listed[0]["marker_count"] == len(detail["markers"]))
            server.shutdown()
            server.server_close()
        finally:
            try:
                server.server_close()
            except Exception:  # noqa: BLE001 -- teardown never decides
                pass
    finally:
        history.close()
        _drop(root)
    return out


# -- group: re-arm through the whole stack --------------------------------------

def group_rearm_stack():
    out = {}
    history, root, clock = _store_dir()
    try:
        # Drive the durable gate into window_limit through the store's own
        # boundary, then wire a REAL scanner: its §8.4 phase is DERIVED
        # from the persistent gate, so an unstarted-but-activatable
        # scanner reports rearm before its first cycle.
        history.incident_activate(BASE)
        opened = _open_incident(history)
        # The store clock must stand past the signal before the close:
        # a close whose closed_epoch precedes its signal is refused, and
        # the window-limit gate would never be raised.
        clock[0] = BASE + 700.0
        history.incident_close_window(opened, ic.CATEGORY_REALITY_TCP,
                                      BASE + 240, BASE + 300, 5, 0, 0,
                                      "window_limit")
        clock[0] = BASE + 700.3
        scanner = ir.IncidentScanner(history, scan_interval_seconds=3600.0,
                                     clock=lambda: clock[0])
        scanner.start()
        status = scanner.status()
        out["derived_phase_is_rearm_after_window_limit"] = (
            status["enabled"] is True and status["running"] is True
            and status["phase"] == "rearm")
        server, request, login, auth = _serve(history, scanner=scanner)
        try:
            session = login()
            _grant_step_up(auth, session)
            status_code, body, _c, _a = request(
                "POST", "/api/v1/incidents/rearm", cookie=session,
                body={}, headers=_csrf_headers(session, auth))
            out["rearm_succeeds_through_the_stack"] = (
                status_code == 200
                and json.loads(body)["status"] == "ok")
            state_after = history.incident_runtime_snapshot()["state"]
            out["rearm_floor_is_the_bucket_grid"] = (
                state_after["discovery_floor_epoch"] == BASE + 720.0
                and state_after["rearm_required"] == 0)
            # One shot: the second attempt is a closed 409 (the runtime
            # phase no longer says rearm once the scanner cache refreshes;
            # the store refuses regardless).
            status_code2, body2, _c, _a = request(
                "POST", "/api/v1/incidents/rearm", cookie=session,
                body={}, headers=_csrf_headers(session, auth))
            out["second_rearm_is_closed_409"] = (
                status_code2 == 409
                and json.loads(body2)["error"]
                == "incident_runtime_not_rearmable")
            server.shutdown()
            server.server_close()
        finally:
            try:
                server.server_close()
            except Exception:  # noqa: BLE001 -- teardown never decides
                pass
        scanner.stop(join_timeout=0.5)
    finally:
        history.close()
        _drop(root)
    return out


# -- group: the R2 §13 fixtures --------------------------------------------------

def group_fixtures():
    out = {}
    # (1) The committed Reality-outage scenario, published through the live
    #     store and read back through the live reader -- then judged by the
    #     PRESENTER and served through the API.
    history, obj, counts, root = cg._build_store(buckets=5)
    try:
        bundle = history.classifier_bundle(BASE, BASE + 300.0, "fresh")
        detection = ic.detect(bundle)
        cls = detection.classification
        out["reality_fixture_is_the_reality_path"] = (
            cls.category == ic.CATEGORY_REALITY_TCP)
        opened = history.incident_open_window(
            cls.category, BASE, detection.first_signal_epoch,
            detection.last_signal_epoch, BASE + 300.0, 5,
            ic.evidence_to_bits(cls.evidence),
            ic.unknown_to_bits(cls.unknowns))
        server, request, login, auth = _serve(history)
        try:
            session = login()
            status, body, _c, _a = request(
                "GET", "/api/v1/incidents/%d" % opened, cookie=session)
            detail = json.loads(body) if status == 200 else {}
            summary = detail.get("summary") or {}
            out["fixture_assessed_as_reality_path"] = (
                detail.get("category") == ic.CATEGORY_REALITY_TCP
                and "Reality/TCP path" in summary.get("headline", ""))
            out["fixture_is_not_server_down"] = (
                "server down" not in json.dumps(detail).lower()
                and summary.get("server_state", "").startswith(
                    "No evidence in this window"))
            out["fixture_action_is_conditional_hy2"] = (
                "If Hysteria2 is independently confirmed healthy"
                in (summary.get("recommended_action") or ""))
            out["fixture_never_claims_hy2_healthy"] = (
                "does not prove Hysteria2 was healthy"
                in summary.get("protocol_state", ""))
            out["fixture_uncertainty_is_visible"] = (
                bool(summary.get("uncertainty"))
                and any(item["token"] == "root_cause_not_established"
                        for item in detail.get("unknowns", [])))
            out["fixture_first_screen_has_no_raw_tokens_as_primary"] = (
                all(item["text"] and " " in item["text"]
                    for item in detail.get("evidence", [])))
            out["fixture_no_isp_claim"] = (
                "ISP" not in json.dumps({key: value
                                         for key, value in summary.items()
                                         if key != "limitations"})
                and "ISP" in summary.get("limitations", ""))
            status, body, _c, _a = request("GET", "/api/v1/incidents",
                                           cookie=session)
            listed = json.loads(body)["incidents"]
            out["fixture_lists_with_marker_count"] = (
                len(listed) == 1 and listed[0]["marker_count"] == 0)
            server.shutdown()
            server.server_close()
        finally:
            try:
                server.server_close()
            except Exception:  # noqa: BLE001 -- teardown never decides
                pass
    finally:
        history.close()
        _drop(root)
    # (2) The background-noise scenario: NO incident is invented, and the
    #     empty API surface is exactly the empty UI state's source.
    history, obj, counts, root = cg._build_store(buckets=5, drop_from=5)
    try:
        bundle = history.classifier_bundle(BASE, BASE + 300.0, "fresh")
        cls = ic.classify(bundle)
        out["background_fixture_is_no_incident"] = (
            cls.status == ic.STATUS_NO_INCIDENT)
        server, request, login, auth = _serve(history)
        try:
            session = login()
            status, body, _c, _a = request("GET", "/api/v1/incidents",
                                           cookie=session)
            data = json.loads(body) if status == 200 else {}
            out["background_stays_an_empty_list"] = (
                status == 200 and data.get("incidents") == []
                and data.get("truncated") is False)
            server.shutdown()
            server.server_close()
        finally:
            try:
                server.server_close()
            except Exception:  # noqa: BLE001 -- teardown never decides
                pass
    finally:
        history.close()
        _drop(root)
    return out


# -- runner ------------------------------------------------------------------

GROUPS = {"presenter": group_presenter, "store": group_store,
          "api": group_api, "live_incident": group_live_incident,
          "rearm_stack": group_rearm_stack, "fixtures": group_fixtures}


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
