#!/usr/bin/env python3
"""PR-4A classifier harness (issue #33 Phase 4) -- behaviour groups.

Every group returns a flat dict of BOOLEAN verdicts that the shell lane
turns into counted gates. Nothing here prints from inside a group, and a
crash is reported by the runner as a FAIL instead of escaping green: a
harness that dies quietly is worse than one that fails honestly.

The two committed fixtures (tests/monitor-classify/fixtures/*.json) are the
INPUTS of the anchor scenarios -- the generated bundle is compared against
the file, so a fixture that drifts from the code it describes fails the lane
rather than quietly testing something else.

The store group is the grounding half: it builds a REAL schema-v3 database
through web/incident_history.py, publishes samples, persists probe cycles
and ingests contract-shaped journal exchange files, then reads those rows
back and classifies them. A classifier that only ever sees hand-made
dicts is a classifier that has never met the store it claims to read.
"""

from __future__ import annotations

import copy
import json
import os
import random
import shutil
import sys
import tempfile

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])

from web import incident_classifier as cl  # noqa: E402

BUCKET = cl.BUCKET_SECONDS
BASE = 1700000400                     # an exact multiple of 60
FIXTURE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "fixtures")

# Strings that must NEVER appear anywhere in a Classification: they live in
# columns the classifier is allowed to RECEIVE but not to READ -- the stored
# timestamp text, the run identity, the device names, an egress address and a
# message fingerprint.
LEAK_PROBES = (
    "SENTINEL-SECRET-0123456789abcdef",
    "office-laptop-alpha",
    "home-phone-beta",
    "203.0.113.19",
    "0011223344556677",
)
# The probes every scenario bundle carries by construction (an egress
# address only rides a cycle that reports a change).
CARRIED_LEAK_PROBES = (LEAK_PROBES[0], LEAK_PROBES[1], LEAK_PROBES[2],
                       LEAK_PROBES[4])

DEVICE_NAMES = (LEAK_PROBES[1], LEAK_PROBES[2])


# -- row builders ------------------------------------------------------------

def sample_row(t, total, reality, hy2, other, api="CONNECTED",
               collector_stale=0):
    return {
        "epoch": float(t),
        "iso_utc": LEAK_PROBES[0],
        "run_id": LEAK_PROBES[0],
        "monitor_uptime_seconds": 100.0,
        "snapshot_version": 7,
        "snapshot_generated_at": None,
        "last_success_at": None,
        "collector_stale": collector_stale,
        "api_status": api,
        "total_active_connections": total,
        "reality_active_connections": reality,
        "hysteria2_active_connections": hy2,
        "other_active_connections": other,
        "uplink_rate": 1.0,
        "downlink_rate": 2.0,
        "skipped_events": 0,
        "duplicate_events": 0,
        "identity_conflicts": 0,
        "abandoned_on_reset": 0,
    }


def device_row(t, device, active, inbound="vless-in", reason="change"):
    return {
        "epoch": float(t),
        "iso_utc": LEAK_PROBES[0],
        "run_id": LEAK_PROBES[0],
        "device": device,
        "inbound": inbound,
        "active_connections": active,
        "device_status": "online",
        "uplink_rate": 1.0,
        "downlink_rate": 1.0,
        "uplink_total": 10.0,
        "downlink_total": 10.0,
        "reason": reason,
    }


def probe_row(t, dns="ok", https="ok", udp="ok", egress="ok",
              egress_change="unchanged", egress_ip=None):
    """One closed engine result flattened into one stored row. The
    status/error-code pairing is the stored invariant, so a hand-made row
    that breaks it is a caller defect the classifier must refuse."""
    codes = {"dns": dns, "https": https, "udp": udp, "egress": egress}
    fallback = {"dns": "dns_failed", "https": "timeout", "udp": "timeout",
                "egress": "connect_failed"}
    row = {
        "epoch": float(t),
        "iso_utc": LEAK_PROBES[0],
        "run_id": LEAK_PROBES[0],
        "cycle_id": LEAK_PROBES[0],
        "result_version": 1,
        "egress_ip": egress_ip,
        "egress_change": egress_change,
    }
    for slot, status in codes.items():
        row["%s_status" % slot] = status
        row["%s_latency_ms" % slot] = 12 if status == "ok" else None
        row["%s_error_code" % slot] = ("NONE" if status == "ok"
                                       else fallback[slot])
    if egress_change == "changed":
        # A change token is only ever emitted with a working egress probe,
        # and the address rides a column the classifier never reads.
        row["egress_status"] = "ok"
        row["egress_error_code"] = "NONE"
        row["egress_latency_ms"] = 12
        row["egress_ip"] = LEAK_PROBES[3]
    elif egress != "ok":
        row["egress_ip"] = None
    return row


def journal_row(t, cls, proto, dcls, port, n=1):
    return {
        "seq": 1,
        "ts": float(t),
        "cls": cls,
        "proto": proto,
        "port": port,
        "dcls": dcls,
        "fp": LEAK_PROBES[4] if cls == "other" else None,
        "n": n,
    }


def audit_row(t, kind, code):
    return {"epoch": float(t), "kind": kind, "seq": 3, "code": code}


def bundle(samples=(), device_states=(), probe_rows=(), journal_events=(),
           audit=(), reader="fresh", degraded=False, last_error_code=None,
           enabled=True, buckets=10, start=BASE):
    return {
        "window": {"start_epoch": float(start),
                   "end_epoch": float(start + buckets * BUCKET)},
        "samples": list(samples),
        "device_states": list(device_states),
        "probe_rows": list(probe_rows),
        "journal_events": list(journal_events),
        "audit": list(audit),
        "health": {"enabled": enabled, "degraded": degraded,
                   "last_error_code": last_error_code},
        "reader": {"status": reader},
    }


def traffic(buckets, reality=25, hy2=15, other=0, api="CONNECTED",
            collector_stale=0, from_index=0, to_index=None):
    """Twelve 5 s samples per bucket (the real publication cadence) with a
    steady client mix."""
    out = []
    end = buckets if to_index is None else to_index
    total = reality + hy2 + other
    for index in range(from_index, end):
        for step in range(12):
            t = BASE + index * BUCKET + step * 5
            out.append(sample_row(t, total, reality, hy2, other, api=api,
                                  collector_stale=collector_stale))
    return out


def probes(buckets, slots=None, at=None, egress_change_at=None,
           from_index=0):
    """One probe cycle per 60 s bucket (the frozen cadence). ``slots``
    applies to the buckets named in ``at`` (default: every bucket from
    ``from_index`` on), which is how a single-cycle blip is expressed."""
    slots = slots or {}
    targets = set(range(from_index, buckets)) if at is None else set(at)
    out = []
    for index in range(from_index, buckets):
        active = index in targets
        row = probe_row(
            BASE + index * BUCKET + 30,
            dns=slots.get("dns", "ok") if active else "ok",
            https=slots.get("https", "ok") if active else "ok",
            udp=slots.get("udp", "ok") if active else "ok",
            egress=slots.get("egress", "ok") if active else "ok",
            egress_change=("changed" if egress_change_at is not None
                           and index == egress_change_at else "unchanged"))
        out.append(row)
    return out


def background_journal(buckets):
    """The ordinary noise floor: EOF/cancel and reset chatter, a trickle of
    everything else, on all three protocol attributions. Every one of these
    keys sits BELOW the burst floor, so a window of nothing but background
    noise is never an incident."""
    out = []
    for index in range(buckets):
        t = BASE + index * BUCKET + 10
        out.append(journal_row(t, "eof_cancel", "OTHER", "NONE", 0, n=4))
        out.append(journal_row(t + 1, "reset", "OTHER", "NONE", 0, n=3))
        out.append(journal_row(t + 2, "reset", "Hysteria2", "quic", 443, n=2))
        out.append(journal_row(t + 3, "eof_cancel", "Reality", "NONE", 0,
                               n=1))
        # One hashed-destination row per bucket: this is the only place the
        # fingerprint column is ever populated, so the echo gates below are
        # testing real material rather than an empty string set.
        out.append(journal_row(t + 4, "other", "OTHER", "NONE", 0, n=1))
    return out


def devices(buckets, active_by_index):
    """Two named devices, one row per device per bucket."""
    out = []
    for index, active in enumerate(active_by_index):
        for name in DEVICE_NAMES:
            out.append(device_row(BASE + index * BUCKET + 20, name, active))
    return out


# -- scenario bundles --------------------------------------------------------

def reality_incident_bundle(buckets=10, drop_from=3, reality_target=1,
                            probe_slots=None, probe_at=None,
                            egress_change_at=None, extra_journal=(),
                            reader="fresh", audit=(), degraded=False,
                            last_error_code=None, include_probes=True,
                            include_devices=True, reality_errors=8,
                            steady=False):
    """The 2026-09-22 anchor shape: Reality dial timeouts on 443 while HY2
    clients stay up, over the standing background noise."""
    samples = []
    for index in range(buckets):
        reality = 25 if (steady or index < drop_from) else reality_target
        for step in range(12):
            t = BASE + index * BUCKET + step * 5
            samples.append(sample_row(t, reality + 15, reality, 15, 0))
    journal = background_journal(buckets)
    if reality_errors:
        for index in range(buckets):
            if index >= drop_from:
                t = BASE + index * BUCKET + 25
                journal.append(journal_row(t, "dial_timeout", "Reality",
                                           "https443", 443,
                                           n=reality_errors))
    journal.extend(extra_journal)
    device_states = devices(
        buckets, [40 if (steady or index < drop_from)
                  else reality_target + 15 for index in range(buckets)]) \
        if include_devices else []
    probe_rows = probes(buckets, probe_slots, probe_at,
                        egress_change_at) if include_probes else []
    return bundle(samples=samples, device_states=device_states,
                  probe_rows=probe_rows, journal_events=journal,
                  audit=list(audit), reader=reader, degraded=degraded,
                  last_error_code=last_error_code)


def hy2_incident_bundle(buckets=10):
    samples = []
    for index in range(buckets):
        hy2 = 15 if index < 3 else 1
        for step in range(12):
            t = BASE + index * BUCKET + step * 5
            samples.append(sample_row(t, 25 + hy2, 25, hy2, 0))
    journal = background_journal(buckets)
    for index in range(buckets):
        if index >= 3:
            t = BASE + index * BUCKET + 25
            journal.append(journal_row(t, "quic_error", "Hysteria2", "quic",
                                       443, n=8))
            journal.append(journal_row(t + 1, "reset", "Hysteria2", "quic",
                                       443, n=6))
    return bundle(samples=samples, probe_rows=probes(buckets),
                  journal_events=journal,
                  device_states=devices(buckets, [40, 40, 40, 2, 2, 2, 2,
                                                  2, 2, 2]))


def both_paths_bundle(buckets=10):
    samples = []
    for index in range(buckets):
        reality = 25 if index < 3 else 1
        hy2 = 15 if index < 3 else 1
        for step in range(12):
            t = BASE + index * BUCKET + step * 5
            samples.append(sample_row(t, reality + hy2, reality, hy2, 0))
    journal = background_journal(buckets)
    for index in range(buckets):
        if index >= 3:
            t = BASE + index * BUCKET + 25
            journal.append(journal_row(t, "dial_timeout", "Reality",
                                       "https443", 443, n=7))
            journal.append(journal_row(t + 1, "quic_error", "Hysteria2",
                                       "quic", 443, n=7))
    return bundle(samples=samples, probe_rows=probes(buckets),
                  journal_events=journal,
                  device_states=devices(buckets, [40, 40, 40, 2, 2, 2, 2,
                                                  2, 2, 2]))


def api_down_bundle(buckets=10):
    """The sing-box API goes stale: counts stop moving, half of every
    bucket says STALE, and no network plane disagrees."""
    samples = []
    for index in range(buckets):
        stale = index >= 3
        for step in range(12):
            t = BASE + index * BUCKET + step * 5
            samples.append(sample_row(
                t, 40, 25, 15, 0, api="STALE" if stale else "CONNECTED",
                collector_stale=1 if stale else 0))
    return bundle(samples=samples, probe_rows=probes(buckets),
                  journal_events=background_journal(buckets),
                  device_states=devices(buckets, [40] * buckets))


def coverage_gap_bundle(buckets=10):
    """The Monitor stopped publishing entirely in the second half."""
    samples = traffic(buckets, to_index=6)
    return bundle(samples=samples, probe_rows=probes(buckets),
                  journal_events=background_journal(buckets),
                  device_states=devices(buckets, [40] * buckets))


def destination_bundle(buckets=10, dcls="dot853", port=853, per_bucket=2,
                       from_index=3, to_index=None, extra=()):
    """One destination fails repeatedly while both transports and the VPS's
    own outbound stay healthy."""
    end = buckets if to_index is None else to_index
    journal = background_journal(buckets)
    for index in range(from_index, end):
        for step in range(per_bucket):
            journal.append(journal_row(BASE + index * BUCKET + 20 + step,
                                       "dial_timeout", "OTHER", dcls, port,
                                       n=6))
    for row in extra:
        journal.append(row)
    return bundle(samples=traffic(buckets), probe_rows=probes(buckets),
                  journal_events=journal,
                  device_states=devices(buckets, [40] * buckets))


def drop_only_bundle(buckets=10):
    """Connections fall by half with nothing else in evidence: no journal
    burst, no probe failure, no process signal."""
    samples = []
    for index in range(buckets):
        reality = 25 if index < 4 else 8
        for step in range(12):
            t = BASE + index * BUCKET + step * 5
            samples.append(sample_row(t, reality + 15, reality, 15, 0))
    return bundle(samples=samples, probe_rows=probes(buckets),
                  journal_events=background_journal(buckets),
                  device_states=devices(buckets, [40, 40, 40, 40, 23, 23,
                                                  23, 23, 23, 23]))


def unattributed_burst_rows(buckets, from_index=3):
    """OTHER-protocol errors with NO destination class: real journal
    evidence the vocabulary cannot place on any path or target."""
    out = []
    for index in range(from_index, buckets):
        out.append(journal_row(BASE + index * BUCKET + 35, "reset", "OTHER",
                               "NONE", 0, n=9))
    return out


# -- the behaviour table -----------------------------------------------------

def scenarios():
    """(name, bundle, expected status, expected category, required evidence,
    forbidden evidence, required unknowns) for every behaviour gate."""
    reality = reality_incident_bundle()
    normal = reality_incident_bundle(steady=True, reality_errors=0)
    out = [
        # The required positive anchor, stated exactly as the spec demands:
        # Reality-only errors + HY2 quiet + the VPS's own TCP probes healthy.
        ("reality_outage", reality, "incident", "reality_tcp_path",
         ("count_drop_reality", "journal_burst_reality",
          "probe_generic_tcp_healthy"),
         ("journal_burst_hysteria2", "journal_burst_other_generic",
          "probe_failed_dns", "probe_failed_https", "probe_failed_egress"),
         ("root_cause_not_established",),
         ("attribution_ambiguous", "transport_negatives_unproven",
          "unattributed_evidence_present", "journal_evidence_incomplete")),
        # The required negative control: ordinary background EOF/reset noise
        # over steady traffic is NOT an incident.
        ("normal_background", normal, "no_incident", "NONE",
         ("no_anomaly", "journal_cls_eof_cancel", "journal_cls_reset"),
         ("journal_burst_reality", "journal_burst_hysteria2",
          "journal_burst_other_generic", "count_drop_reality",
          "api_stale", "sample_coverage_gap"), (),
         ("attribution_ambiguous", "count_drop_only")),
        # The required upgrade: generic HTTPS probe evidence outranks a
        # path-specific candidate, because the VPS itself cannot get out.
        ("reality_plus_generic_probe",
         reality_incident_bundle(probe_slots={"https": "failed"}),
         "incident", "vps_outbound",
         ("probe_failed_https", "journal_burst_reality",
          "count_drop_reality"),
         ("probe_generic_tcp_healthy",),
         ("root_cause_not_established",), ()),
        # The same upgrade from the journal plane alone: OTHER-protocol
        # errors on plain web ports are broader than one transport.
        ("reality_plus_generic_journal",
         reality_incident_bundle(extra_journal=[
             journal_row(BASE + 4 * BUCKET + 40, "dial_timeout", "OTHER",
                         "https443", 443, n=9),
             journal_row(BASE + 5 * BUCKET + 40, "dial_timeout", "OTHER",
                         "https443", 443, n=9)]),
         "incident", "vps_outbound",
         ("journal_burst_other_generic", "journal_burst_reality"),
         ("probe_failed_https",), (), ()),
        ("hy2_outage", hy2_incident_bundle(), "incident",
         "hysteria2_udp_path",
         ("count_drop_hysteria2", "journal_burst_hysteria2"),
         ("journal_burst_reality", "journal_burst_other_generic"), (), ()),
        ("both_paths", both_paths_bundle(), "incident",
         "common_inbound_client_office",
         ("journal_burst_reality", "journal_burst_hysteria2",
          "count_drop_reality", "count_drop_hysteria2"),
         ("journal_burst_other_generic",), (), ()),
        ("api_down", api_down_bundle(), "incident", "vps_process_or_api",
         ("api_stale", "collector_stale"),
         ("journal_burst_reality", "journal_burst_hysteria2",
          "probe_failed_https"), (), ()),
        ("coverage_gap", coverage_gap_bundle(), "incident",
         "vps_process_or_api", ("sample_coverage_gap",),
         ("journal_burst_reality", "probe_failed_dns"), (), ()),
        ("history_degraded",
         reality_incident_bundle(steady=True, reality_errors=0,
                                 degraded=True,
                                 last_error_code="history_write_failed"),
         "incident", "vps_process_or_api", ("history_degraded",),
         ("journal_burst_reality",), (), ()),
        # Two planes each show a real fault: naming either one as THE cause
        # would be a claim the evidence does not support.
        ("process_and_network_conflict",
         reality_incident_bundle(degraded=True,
                                 last_error_code="history_write_failed"),
         "incident", "insufficient_evidence",
         ("history_degraded", "journal_burst_reality", "count_drop_reality"),
         (), ("process_and_network_evidence_conflict",), ()),
        # The forbidden inference: a bare count drop with no corroboration.
        ("drop_only_no_corroboration", drop_only_bundle(), "no_incident",
         "NONE", ("count_drop_reality",), ("journal_burst_reality",),
         ("count_drop_only", "no_corroboration"), ()),
        ("single_probe_blip",
         reality_incident_bundle(steady=True, reality_errors=0,
                                 probe_slots={"https": "failed"},
                                 probe_at=[4], egress_change_at=4),
         "no_incident", "NONE",
         ("no_anomaly", "probe_generic_tcp_healthy", "egress_ip_changed"),
         ("probe_failed_https",), (), ()),
        ("probe_outage_without_clients",
         bundle(samples=traffic(10),
                probe_rows=probes(10, {"dns": "failed", "https": "failed",
                                       "egress": "failed"}),
                journal_events=background_journal(10),
                device_states=devices(10, [40] * 10)),
         "incident", "vps_outbound",
         ("probe_failed_dns", "probe_failed_https", "probe_failed_egress"),
         ("probe_generic_tcp_healthy",), (), ()),
        # The UDP slot proves UDP reachability, not WHICH tunnel owns it:
        # sustained UDP failure alone is evidence without an attribution.
        ("udp_probe_only",
         reality_incident_bundle(steady=True, reality_errors=0,
                                 probe_slots={"udp": "failed"}),
         "incident", "insufficient_evidence", ("probe_failed_udp",),
         ("journal_burst_reality", "journal_burst_hysteria2",
          "probe_failed_https"), ("attribution_ambiguous",), ()),
        ("reality_plus_udp_probe",
         reality_incident_bundle(probe_slots={"udp": "failed"}),
         "incident", "reality_tcp_path",
         ("probe_failed_udp", "journal_burst_reality"),
         ("journal_burst_hysteria2",),
         ("root_cause_not_established",), ()),
        ("destination_proof", destination_bundle(), "incident",
         "destination_specific", ("journal_burst_destination",),
         ("journal_burst_reality", "journal_burst_hysteria2",
          "journal_burst_other_generic"), ("root_cause_not_established",),
         ()),
        # The required fail-closed: one blip of a target signature is not
        # target-specific proof, so no destination may be named.
        ("destination_single_bucket",
         destination_bundle(from_index=4, to_index=5), "incident",
         "insufficient_evidence", ("journal_burst_destination",), (),
         ("no_target_specific_proof",), ()),
        ("destination_two_targets",
         destination_bundle(extra=[
             journal_row(BASE + 4 * BUCKET + 45, "dial_timeout", "OTHER",
                         "smtpish", 465, n=6),
             journal_row(BASE + 6 * BUCKET + 45, "dial_timeout", "OTHER",
                         "smtpish", 465, n=6)]),
         "incident", "insufficient_evidence", ("journal_burst_destination",),
         (), ("multiple_destinations",), ()),
        # Path attributions rest on "the other path is quiet": with the
        # journal view incomplete and no healthy TCP probe, that negative is
        # unprovable and the classifier must refuse to name a transport.
        ("transport_negatives_unproven",
         reality_incident_bundle(reader="stale", include_probes=False),
         "incident", "insufficient_evidence",
         ("journal_burst_reality", "count_drop_reality"),
         (), ("transport_negatives_unproven", "probe_evidence_absent",
              "journal_evidence_incomplete"), ()),
        ("unattributed_alongside_reality",
         reality_incident_bundle(
             extra_journal=unattributed_burst_rows(10)),
         "incident", "reality_tcp_path",
         ("journal_burst_reality", "journal_burst_unattributed"),
         ("journal_burst_hysteria2",),
         ("root_cause_not_established", "unattributed_evidence_present"), ()),
        # A continuity gap is evidence the journal cannot prove a negative;
        # it is named, and the healthy TCP probes still carry the
        # attribution.
        ("journal_continuity_gap",
         reality_incident_bundle(
             audit=[audit_row(BASE + 5 * BUCKET + 30, "gap", "sequence_gap")]),
         "incident", "reality_tcp_path",
         ("journal_continuity_gap", "journal_burst_reality",
          "probe_generic_tcp_healthy"),
         (), ("journal_evidence_incomplete", "root_cause_not_established"),
         ()),
        # Nothing at all in the window, on a host where the reader was never
        # provisioned: absence of input is not evidence of a fault and not
        # evidence of health either.
        ("empty_bundle", bundle(reader="disabled"), "indeterminate",
         "insufficient_evidence",
         (), ("no_anomaly", "journal_burst_reality", "count_drop_reality",
              "sample_coverage_gap"),
         ("baseline_evidence_absent", "probe_evidence_absent",
          "journal_evidence_absent"), ()),
        ("short_window", bundle(samples=traffic(2), probe_rows=probes(2),
                                journal_events=background_journal(2),
                                device_states=devices(2, [40, 40]),
                                buckets=2),
         "indeterminate", "insufficient_evidence", (),
         ("no_anomaly", "count_drop_reality"), ("baseline_evidence_absent",),
         ()),
    ]
    return out


def scenario_bundle(name):
    for entry in scenarios():
        if entry[0] == name:
            return entry[1]
    raise KeyError(name)


# -- hostile inputs ----------------------------------------------------------

def _mutate_key(obj):
    obj["connections"] = []          # a section that does not exist


def _mutate_free_text(obj):
    obj["journal_events"][0]["cls"] = "REALITY: failed to dial dest"


def _mutate_bool_count(obj):
    obj["samples"][0]["total_active_connections"] = True


def _mutate_nan_epoch(obj):
    obj["samples"][0]["epoch"] = float("nan")


def _mutate_outside(obj):
    obj["samples"][0]["epoch"] = BASE - 3600


def _mutate_unaligned(obj):
    obj["window"]["start_epoch"] += 13.5


def _mutate_long_window(obj):
    obj["window"]["end_epoch"] = obj["window"]["start_epoch"] + 7200.0


def _mutate_missing_section(obj):
    del obj["reader"]


def _mutate_health_text(obj):
    obj["health"]["last_error_code"] = "password=Hunter2"


def _mutate_probe_pair(obj):
    obj["probe_rows"][0]["https_status"] = "ok"
    obj["probe_rows"][0]["https_error_code"] = "timeout"


def _mutate_dcls_pair(obj):
    for row in obj["journal_events"]:
        if row["dcls"] == "NONE":
            row["port"] = 443
            break


def _mutate_too_many(obj):
    obj["samples"] = obj["samples"] * 200


def _mutate_row_not_dict(obj):
    obj["audit"] = ["not-a-row"]


def _mutate_reader_text(obj):
    obj["reader"]["status"] = "ok-ish"


def _mutate_extra_column(obj):
    obj["samples"][0]["raw_log_line"] = "auth failed for user root"


def _mutate_negative_count(obj):
    obj["samples"][0]["reality_active_connections"] = -4


def _mutate_bad_port(obj):
    for row in obj["journal_events"]:
        if row["dcls"] != "NONE":
            row["port"] = 70000
            return


def _mutate_bad_egress_change(obj):
    obj["probe_rows"][0]["egress_change"] = "yes"


def _mutate_zero_n(obj):
    obj["journal_events"][0]["n"] = 0


HOSTILES = (
    ("unknown_section", _mutate_key, ("evidence_shape_rejected",)),
    ("free_text_cls", _mutate_free_text,
     ("evidence_rejected_journal_events",)),
    ("bool_as_count", _mutate_bool_count, ("evidence_rejected_samples",)),
    ("nan_epoch", _mutate_nan_epoch, ("evidence_rejected_samples",)),
    ("outside_window", _mutate_outside,
     ("evidence_outside_window", "evidence_rejected_samples")),
    ("unaligned_window", _mutate_unaligned, ("evidence_rejected_window",)),
    ("over_long_window", _mutate_long_window, ("evidence_rejected_window",)),
    ("missing_section", _mutate_missing_section,
     ("evidence_rejected_reader",)),
    ("credential_like_health_code", _mutate_health_text,
     ("evidence_rejected_health",)),
    ("probe_ok_with_code", _mutate_probe_pair,
     ("evidence_rejected_probe_rows",)),
    ("dcls_none_with_port", _mutate_dcls_pair,
     ("evidence_rejected_journal_events",)),
    ("oversized_section", _mutate_too_many, ("evidence_rejected_samples",)),
    ("row_not_a_dict", _mutate_row_not_dict, ("evidence_rejected_audit",)),
    ("reader_free_text", _mutate_reader_text, ("evidence_rejected_reader",)),
    ("extra_column_carries_text", _mutate_extra_column,
     ("evidence_rejected_samples",)),
    ("negative_count", _mutate_negative_count,
     ("evidence_rejected_samples",)),
    ("port_out_of_range", _mutate_bad_port,
     ("evidence_rejected_journal_events",)),
    ("egress_change_free_text", _mutate_bad_egress_change,
     ("evidence_rejected_probe_rows",)),
    ("zero_event_count", _mutate_zero_n,
     ("evidence_rejected_journal_events",)),
)


def hostile_case(name, mutate):
    """One mutation of the healthy fixture, plus a snapshot taken AFTER the
    mutation: classify() must leave the caller's bundle byte-identical."""
    obj = reality_incident_bundle()
    mutate(obj)
    return obj, repr(obj)


# -- group: behaviour table --------------------------------------------------

def group_scenarios():
    out = {}
    for entry in scenarios():
        name, obj, status, category = entry[0], entry[1], entry[2], entry[3]
        required, forbidden, unknowns_required = entry[4], entry[5], entry[6]
        unknowns_forbidden = entry[7] if len(entry) > 7 else ()
        result = cl.classify(obj)
        evidence = set(result.evidence)
        unknowns = set(result.unknowns)
        out["%s:status" % name] = result.status == status
        out["%s:category" % name] = result.category == category
        out["%s:no_refusal" % name] = not any(
            token.startswith("evidence_rejected_")
            or token in ("evidence_shape_rejected", "evidence_outside_window")
            for token in unknowns)
        for token in required:
            out["%s:evidence:%s" % (name, token)] = token in evidence
        for token in forbidden:
            out["%s:not_evidence:%s" % (name, token)] = token not in evidence
        for token in unknowns_required:
            out["%s:unknown:%s" % (name, token)] = token in unknowns
        for token in unknowns_forbidden:
            out["%s:not_unknown:%s" % (name, token)] = token not in unknowns
        if status == "no_incident":
            out["%s:empty_category" % name] = category == "NONE"
        if status == "incident":
            # An answer that names a fault also names the one thing it does
            # not claim: a cause.
            out["%s:names_root_unknown" % name] = (
                "root_cause_not_established" in unknowns)
    out["table_rows_are_well_formed"] = all(
        len(entry) in (7, 8) and isinstance(entry[1], dict)
        and all(isinstance(entry[i], tuple) for i in (4, 5, 6))
        and entry[2] in cl.STATUSES
        and (entry[3] in cl.CATEGORIES or entry[3] == "NONE")
        for entry in scenarios())
    return out


# -- group: refusals ---------------------------------------------------------

def group_hostiles():
    out = {}
    for name, mutate, expected in HOSTILES:
        obj, snapshot = hostile_case(name, mutate)
        result = cl.classify(obj)
        out["%s:indeterminate" % name] = (
            result.status == "indeterminate"
            and result.category == "insufficient_evidence")
        out["%s:never_incident" % name] = result.status != "incident"
        out["%s:exact_tokens" % name] = result.unknowns == tuple(
            sorted(set(expected)))
        out["%s:no_evidence_invented" % name] = result.evidence == ()
        # repr, not ==: a NaN epoch is a legitimate hostile input
        # and NaN never compares equal to itself.
        out["%s:input_unchanged" % name] = repr(obj) == snapshot
        out["%s:names_the_rejected_section" % name] = any(
            token.startswith("evidence_rejected_")
            or token == "evidence_shape_rejected"
            for token in result.unknowns)
    out["refusal_tokens_are_vocabulary"] = all(
        token in cl.UNKNOWN_TOKENS
        for _, _, tokens in HOSTILES for token in tokens)
    out["healthy_bundle_is_not_refused"] = cl._refusals(
        reality_incident_bundle()) == ()
    return out


def tampered(**over):
    """A well-formed bundle with one section replaced wholesale."""
    obj = bundle()
    obj.update(over)
    return obj


# -- group: closure, determinism, purity -------------------------------------

def _all_bundles():
    out = [entry[1] for entry in scenarios()]
    for name, mutate, _expected in HOSTILES:
        out.append(hostile_case(name, mutate)[0])
    return out


def group_invariants():
    out = {}
    bundles = _all_bundles()
    closed = open_results = paired = incident_names_unknown = True
    for obj in bundles:
        result = cl.classify(obj)
        if not isinstance(result, cl.Classification):
            open_results = False
            continue
        if not set(result.evidence) <= cl.EVIDENCE_TOKENS:
            closed = False
        if not set(result.unknowns) <= cl.UNKNOWN_TOKENS:
            closed = False
        if result.status not in cl.STATUSES:
            open_results = False
        valid = ((result.status == "no_incident"
                  and result.category == "NONE")
                 or (result.status in ("incident", "indeterminate")
                     and result.category in cl.CATEGORIES))
        if not valid:
            paired = False
        if result.status == "incident" and not result.unknowns:
            incident_names_unknown = False
    out["tokens_are_closed"] = closed
    out["typed_result_always"] = open_results
    out["status_category_paired"] = paired
    out["incident_never_silent_on_unknowns"] = incident_names_unknown
    untouched = True
    for obj in bundles:
        snapshot = repr(obj)
        cl.classify(obj)
        if repr(obj) != snapshot:
            untouched = False
    out["classification_mutates_no_input"] = untouched
    out["tokens_sorted_and_deduped"] = all(
        list(result.evidence) == sorted(set(result.evidence))
        and list(result.unknowns) == sorted(set(result.unknowns))
        for result in (cl.classify(obj) for obj in bundles))

    # Determinism: no input ordering may move the answer.
    anchored = scenario_bundle("reality_outage")
    first = cl.classify(anchored).to_dict()
    rng = random.Random(20260929)
    shuffled_same = True
    for _ in range(20):
        obj = copy.deepcopy(anchored)
        for section in cl.LIST_SECTIONS:
            rng.shuffle(obj[section])
        if cl.classify(obj).to_dict() != first:
            shuffled_same = False
    out["shuffle_invariant"] = shuffled_same
    out["repeat_invariant"] = all(
        cl.classify(anchored).to_dict() == first for _ in range(5))
    key_order_same = True
    for _ in range(5):
        obj = copy.deepcopy(anchored)
        rebuilt = {}
        for key in rng.sample(sorted(obj), len(obj)):
            rebuilt[key] = obj[key]
        if cl.classify(rebuilt).to_dict() != first:
            key_order_same = False
    out["section_order_invariant"] = key_order_same

    # The same behaviour table reached through a reordered bundle: the
    # verdict, not only the dict, must not move.
    table_stable = True
    for entry in scenarios():
        obj = copy.deepcopy(entry[1])
        for section in cl.LIST_SECTIONS:
            rng.shuffle(obj[section])
        result = cl.classify(obj)
        if result.status != entry[2] or result.category != entry[3]:
            table_stable = False
    out["verdicts_survive_shuffling"] = table_stable

    # Concurrency: with no clock and no module state, eight threads sharing
    # the module must answer exactly as one call does -- and interleaving
    # different bundles must not let one call see another's evidence.
    import threading
    concurrent = []
    sequential = {entry[0]: cl.classify(entry[1]).to_dict()
                  for entry in scenarios()}

    def hammer():
        for entry in scenarios():
            concurrent.append((entry[0], cl.classify(entry[1]).to_dict()))

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    out["threads_answer_identically"] = (
        len(concurrent) == 8 * len(scenarios())
        and all(name in sequential and payload == sequential[name]
                for name, payload in concurrent))

    # The function never raises, whatever it is handed.
    hostile_inputs = [None, 0, "", [], {}, b"bytes", object(), (1, 2),
                      {"window": None}, {"window": {"start_epoch": 1}},
                      tampered(samples="x"),
                      tampered(window={"start_epoch": 1, "end_epoch": 2}),
                      tampered(probe_rows=[{}]), tampered(audit=[{}]),
                      tampered(journal_events=[{"ts": BASE + 1}]),
                      tampered(device_states=[{"epoch": BASE + 1}]),
                      tampered(samples=[{"epoch": BASE + 1}]),
                      tampered(reader={"status": "fresh", "extra": 1}),
                      tampered(health={"enabled": True, "degraded": False,
                                       "last_error_code": "x"})]
    never_raises = True
    for value in hostile_inputs:
        try:
            result = cl.classify(value)
        except Exception:  # noqa: BLE001 -- the gate IS the absence
            never_raises = False
        else:
            if not isinstance(result, cl.Classification):
                never_raises = False
    out["never_raises_on_hostile_input"] = never_raises
    out["hostile_input_fails_closed"] = all(
        cl.classify(value).status == "indeterminate"
        for value in hostile_inputs)

    # A fuzzed bundle is refused or answered, never a crash and never an
    # open-ended object.
    fuzz_closed = True
    rng2 = random.Random(4242)
    for _ in range(400):
        obj = copy.deepcopy(anchored)
        section = rng2.choice(list(cl.EVIDENCE_SECTIONS))
        if section in cl.LIST_SECTIONS:
            rows = obj[section]
            if rows:
                index = rng2.randrange(len(rows))
                row = rows[index]
                if rng2.random() < 0.5 and isinstance(row, dict) and row:
                    key = rng2.choice(sorted(row))
                    row[key] = rng2.choice([None, True, "x", -1, [], {},
                                            float("nan"), float("inf"), 0])
                else:
                    obj[section] = rng2.choice([[], None, "x", 5, [None]])
        else:
            obj[section] = rng2.choice([None, {}, {"x": 1}, "y",
                                        {"status": "x"}])
        if rng2.random() < 0.2:
            del obj[rng2.choice(list(cl.EVIDENCE_SECTIONS))]
        try:
            result = cl.classify(obj)
        except Exception:  # noqa: BLE001 -- the gate IS the absence
            fuzz_closed = False
            continue
        if (not set(result.evidence) <= cl.EVIDENCE_TOKENS
                or not set(result.unknowns) <= cl.UNKNOWN_TOKENS
                or result.status not in cl.STATUSES):
            fuzz_closed = False
    out["fuzz_never_escapes_vocabulary"] = fuzz_closed
    out["bounds_are_reviewed_numbers"] = (
        cl.MAX_BUCKETS == 60 and cl.MAX_RECORDS_PER_SECTION == 2000
        and cl.BUCKET_SECONDS == 60.0)
    return out


# -- group: privacy ----------------------------------------------------------

def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            for found in _strings(item):
                yield found
    elif isinstance(value, (list, tuple)):
        for item in value:
            for found in _strings(item):
                yield found


ALLOWED_STRINGS = (frozenset(cl.EVIDENCE_TOKENS) | frozenset(cl.UNKNOWN_TOKENS)
                   | frozenset(cl.CATEGORIES) | frozenset(cl.STATUSES)
                   | frozenset({"NONE"})
                   | frozenset(("version", "status", "category",
                                 "window_start", "window_end", "buckets",
                                 "evidence", "unknowns")))


def group_privacy():
    out = {}
    leaked = set()
    unclosed = set()
    carried = set()
    for obj in _all_bundles():
        result = cl.classify(obj)
        payload = json.dumps(result.to_dict(), sort_keys=True)
        for probe in LEAK_PROBES:
            if probe in payload:
                leaked.add(probe)
            if probe in json.dumps(obj):
                carried.add(probe)
        for token in _strings(result.to_dict()):
            if token not in ALLOWED_STRINGS:
                unclosed.add(token)
    # The gate only means something if the inputs really carried the
    # material: a bundle set that never contained a sentinel could never
    # prove that none of them escaped.
    out["inputs_carry_every_leak_probe"] = carried == set(LEAK_PROBES)
    out["no_leak_probe_survives"] = not leaked
    out["serialized_strings_are_tokens"] = not unclosed
    # The columns that carry them are RECEIVED and never READ: the consumed
    # subsets must exclude them, in every section. (A device name IS read --
    # as an opaque counting key for "how many devices are quiet" -- and the
    # closed result surface below is what proves it can never be echoed.)
    forbidden_reads = {"iso_utc", "run_id", "inbound", "fp",
                       "egress_ip", "cycle_id", "dns_latency_ms",
                       "https_latency_ms", "udp_latency_ms",
                       "egress_latency_ms", "seq", "result_version",
                       "monitor_uptime_seconds", "snapshot_version",
                       "uplink_rate", "downlink_rate", "last_success_at"}
    consumed = (set(cl.SAMPLE_FIELDS) | set(cl.DEVICE_FIELDS)
                | set(cl.PROBE_FIELDS) | set(cl.JOURNAL_FIELDS)
                | set(cl.AUDIT_FIELDS))
    out["identity_columns_never_consumed"] = not (consumed & forbidden_reads)
    out["device_column_is_counting_only"] = set(cl.DEVICE_FIELDS) == {
        "epoch", "device", "active_connections", "reason"}
    out["result_surface_has_no_slot_for_an_identity"] = all(
        set(cl.classify(obj).to_dict()) == {
            "version", "status", "category", "window_start", "window_end",
            "buckets", "evidence", "unknowns"} for obj in _all_bundles())
    # The module's own hygiene: pure stdlib, no clock, no I/O, no state.
    out["module_is_pure"] = _module_pure()
    return out


def _module_pure():
    import ast
    path = os.path.join(os.environ["MONITOR_V2_ROOT"], "web",
                        "incident_classifier.py")
    source = open(path, encoding="utf-8").read()
    tree = ast.parse(source)
    allowed = {"__future__", "dataclasses"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(a.name.split(".")[0] not in allowed for a in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            if (node.module or "").split(".")[0] not in allowed:
                return False
    # With the import surface closed to two stdlib modules there is no
    # clock, no I/O and no network primitive to reach for; these are the
    # belt-and-braces greps on top of that.
    for token in ("open(", "print(", "logging.", "sqlite3", "socket",
                  "subprocess", "os.environ", "time.time"):
        if token in source:
            return False
    # No module-level state machine: nothing may re-bind a name from inside
    # a function, and no annotation/augmented assignment may introduce a
    # mutable holder a second call could observe. (The threading proof in the
    # invariants group is the behavioural half of this claim.)
    for node in tree.body:
        if isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            return False
    for node in ast.walk(tree):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            return False
    names = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    if not {"classify", "_analyse", "_refusals", "_seal"} <= names:
        return False
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "Classification":
            if not any(isinstance(d, ast.Call) and "frozen"
                       in {k.arg for k in d.keywords}
                       for d in node.decorator_list):
                return False
    return True


# -- group: vocabulary mirrors -------------------------------------------------

def group_mirrors():
    out = {}
    import web.incident_history as ih
    out["journal_classes_mirror"] = set(cl.JOURNAL_CLASSES) == set(
        ih.JOURNAL_CLASSES)
    out["journal_protos_mirror"] = set(cl.JOURNAL_PROTOS) == set(
        ih.JOURNAL_PROTOS)
    out["journal_dcls_mirror"] = set(cl.JOURNAL_DCLS) == set(ih.JOURNAL_DCLS)
    out["audit_kinds_mirror"] = set(cl.JOURNAL_AUDIT_KINDS) == set(
        ih.JOURNAL_AUDIT_KINDS)
    out["audit_codes_mirror"] = set(cl.JOURNAL_AUDIT_CODES) == set(
        ih.JOURNAL_AUDIT_CODES)
    out["probe_statuses_mirror"] = set(cl.PROBE_STATUSES) == set(
        ih.PROBE_STATUSES)
    out["probe_error_codes_mirror"] = set(cl.PROBE_ERROR_CODES) == set(
        ih.PROBE_ERROR_CODES)
    out["probe_change_values_mirror"] = set(cl.PROBE_CHANGE_VALUES) == set(
        ih.PROBE_CHANGE_VALUES)
    out["history_error_codes_mirror"] = set(cl.HISTORY_ERROR_CODES) == {
        code for name in dir(ih) if name.startswith("CODE_")
        for code in [getattr(ih, name)] if isinstance(code, str)}
    out["device_reasons_mirror"] = set(cl.DEVICE_REASONS) == {
        ih.REASON_CHANGE, ih.REASON_HEARTBEAT}
    out["api_statuses_mirror"] = set(cl.API_STATUSES) == {"CONNECTED",
                                                          "STALE"}
    out["sample_columns_mirror"] = set(cl.SAMPLE_ROW_COLUMNS) == set(
        ih.SAMPLE_COLUMNS)
    out["device_columns_mirror"] = set(cl.DEVICE_ROW_COLUMNS) == set(
        ih.DEVICE_STATE_COLUMNS)
    out["probe_columns_mirror"] = set(cl.PROBE_ROW_COLUMNS) == set(
        ih.PROBE_COLUMNS)
    out["row_shapes_are_subsets_of_the_store"] = all(
        set(needed) <= set(columns) for needed, columns in (
            (cl.SAMPLE_FIELDS, ih.SAMPLE_COLUMNS),
            (cl.DEVICE_FIELDS, ih.DEVICE_STATE_COLUMNS),
            (cl.PROBE_FIELDS, ih.PROBE_COLUMNS),
            (cl.JOURNAL_FIELDS, cl.JOURNAL_EVENT_ROW_COLUMNS),
            (cl.AUDIT_FIELDS, cl.AUDIT_ROW_COLUMNS)))
    out["probe_slots_mirror"] = set(cl.PROBE_SLOTS) == {
        "dns", "https", "udp", "egress"}
    out["generic_slots_are_a_subset"] = set(cl.GENERIC_PROBE_SLOTS) < set(
        cl.PROBE_SLOTS)
    out["generic_dcls_are_a_subset"] = set(cl.GENERIC_TCP_DCLS) < set(
        cl.JOURNAL_DCLS)
    out["categories_are_the_reviewed_seven"] = (
        len(cl.CATEGORIES) == 7 and len(set(cl.CATEGORIES)) == 7
        and cl.CATEGORY_NONE not in cl.CATEGORIES)
    out["derived_tokens_come_from_vocabularies"] = (
        {"journal_cls_" + n for n in cl.JOURNAL_CLASSES} <= cl.EVIDENCE_TOKENS
        and {"journal_audit_" + c for c in cl.JOURNAL_AUDIT_CODES}
        <= cl.EVIDENCE_TOKENS
        and {"evidence_rejected_" + s for s in cl.EVIDENCE_SECTIONS}
        <= cl.UNKNOWN_TOKENS)
    out["engine_probe_codes_agree"] = _engine_agrees()
    return out


def _engine_agrees():
    from diagnostics import network_probes as engine
    return (set(cl.PROBE_ERROR_CODES) == set(engine.ERROR_CODES)
            and set(cl.PROBE_STATUSES) == {engine.STATUS_OK,
                                           engine.STATUS_FAILED}
            and set(cl.PROBE_SLOTS) == set(engine.PROBE_SLOTS))


# -- group: the real store ---------------------------------------------------

IP_A = "8.8.8.8"
JR_RUN = "0123456789abcdef0123456789abcdef"


def _snapshot(reality, hy2, api_status="CONNECTED", stale=0):
    def protocols(reality_count, hy2_count):
        return {"vless-in": {"active_connections": reality_count,
                             "inbound_type": "vless",
                             "uplink_rate": 1.0, "downlink_rate": 2.0,
                             "uplink_total": 10.0, "downlink_total": 20.0},
                "hy2-in": {"active_connections": hy2_count,
                           "inbound_type": "hysteria2",
                           "uplink_rate": 1.0, "downlink_rate": 2.0,
                           "uplink_total": 10.0, "downlink_total": 20.0}}
    return {"devices": {DEVICE_NAMES[0]: {"status": "online",
                                         "uplink_rate": 1.0,
                                         "downlink_rate": 2.0,
                                         "protocols": protocols(reality // 2,
                                                                hy2 // 2)},
                       DEVICE_NAMES[1]: {"status": "online",
                                         "uplink_rate": 1.0,
                                         "downlink_rate": 2.0,
                                         "protocols": protocols(
                                             reality - reality // 2,
                                             hy2 - hy2 // 2)}},
            "api_status": api_status, "stale": stale,
            "active_connections": reality + hy2,
            "collector_uptime_seconds": 500.0,
            "generated_at": "2026-09-29T00:00:00Z",
            "last_success_at": "2026-09-29T00:00:00Z",
            "skipped_events": 0, "duplicate_events": 0,
            "identity_conflicts": 0, "abandoned_on_reset": 0}


def _probe_result(epoch, index, slots=None):
    slots = slots or {}

    def slot(ok, code, latency, ip=None):
        out = {"status": "ok" if ok else "failed",
               "latency_ms": latency if ok else None,
               "error_code": "NONE" if ok else code}
        if ip is not None:
            out["ip"] = ip
        return out

    ok = {}
    for name in ("dns", "https", "udp", "egress"):
        ok[name] = slot(True, "NONE", 12, IP_A if name == "egress" else None)
    failing = {"dns": ("dns_failed",), "https": ("timeout",),
               "udp": ("timeout",), "egress": ("connect_failed",)}
    for name in slots:
        ok[name] = slot(False, failing[name][0], None)
    return {"v": 1, "epoch": epoch,
            "cycle_id": "%032x" % (index + 1),
            "dns": ok["dns"], "https": ok["https"], "udp": ok["udp"],
            "egress": ok["egress"]}


def _ev_lines(seq, records):
    header = {"t": "h", "v": 1, "cv": 1, "seq": seq, "run": JR_RUN,
              "epoch": 1, "boundary": "NONE", "lines": len(records) + 1,
              "eligible": len(records), "info_dropped": 0,
              "nomatch_dropped": 0, "priority_unusable": 0, "pfail": 0,
              "limited": 0}
    lines = [json.dumps(header, sort_keys=True)]
    for record in records:
        lines.append(json.dumps(record, sort_keys=True))
    return "\n".join(lines) + "\n"


def _ev_record(ts, cls, proto, dcls, port, n=1):
    """A contract-shaped exchange record: the wire form keeps NULL where the
    DB keeps its 0/NONE sentinels."""
    return {"t": "e", "ts": ts, "cls": cls, "proto": proto,
            "port": port, "dcls": dcls,
            "fp": LEAK_PROBES[4] if cls == "other" else None, "n": n}


def _build_store(with_probes=True, hb=True, gap=False, drop_from=3,
                 buckets=10):
    """One real schema-v3 store, published through the live history module.

    Returns (history, bundle, counts). The caller closes the history."""
    import web.incident_history as ih
    from journal_reader import schema as jr_schema
    root = tempfile.mkdtemp(prefix="cls-store-")
    diag = os.path.join(root, "diagnostics")
    out = os.path.join(root, "out")
    os.makedirs(out)
    clock = [BASE]
    history = ih.IncidentHistory(diag, LEAK_PROBES[0],
                                clock=lambda: clock[0],
                                journal_exchange_dir=out)
    history.open()
    journal_records = []
    for index in range(buckets):
        reality = 25 if index < drop_from else 1
        clock[0] = BASE + index * BUCKET + 1
        for step in range(12):
            clock[0] = BASE + index * BUCKET + step * 5
            history.on_publish(_snapshot(reality, 15), step + 1)
        noise = [_ev_record(BASE + index * BUCKET + 10, "eof_cancel",
                             "OTHER", None, None, 4),
                 _ev_record(BASE + index * BUCKET + 11, "reset", "OTHER",
                            None, None, 3),
                 _ev_record(BASE + index * BUCKET + 12, "reset",
                            "Hysteria2", "quic", 443, 2),
                 _ev_record(BASE + index * BUCKET + 13, "eof_cancel",
                            "Reality", None, None, 1),
                 _ev_record(BASE + index * BUCKET + 14, "other", "OTHER",
                            None, None, 1)]
        burst = []
        if index >= drop_from:
            burst = [_ev_record(BASE + index * BUCKET + 25, "dial_timeout",
                                "Reality", "https443", 443, 8)]
        seq = index + 1
        if gap and index == 5:
            seq += 1          # file 6 never arrives: a real sequence gap
        with open(os.path.join(out, "ev-%d.jsonl" % seq), "w",
                  newline="\n") as handle:
            handle.write(_ev_lines(seq, noise + burst))
        journal_records.extend(noise + burst)
        if with_probes:
            epoch = BASE + index * BUCKET + 30
            clock[0] = epoch
            first = index == 0
            result = _probe_result(epoch, index)
            history.record_probe_result(
                result, "unknown" if first else "unchanged")
    clock[0] = BASE + buckets * BUCKET - 20
    if hb:
        with open(os.path.join(out, "hb"), "w", newline="\n") as handle:
            handle.write(json.dumps({"seq": buckets + (1 if gap else 0),
                                     "ts": clock[0]}))
    history.ingest_journal_events()
    timeline = history.query_timeline(since=BASE, limit=ih.QUERY_LIMIT_MAX)
    rows = history._conn.execute(
        "SELECT seq, ts, cls, proto, port, dcls, fp, n FROM journal_events"
        " ORDER BY seq, ts").fetchall()
    events = [dict(zip(("seq", "ts", "cls", "proto", "port", "dcls", "fp",
                        "n"), row)) for row in rows]
    audit_rows = history._conn.execute(
        "SELECT epoch, kind, seq, code FROM journal_ingest_audit"
        " ORDER BY epoch").fetchall()
    audits = [dict(zip(("epoch", "kind", "seq", "code"), row))
              for row in audit_rows]
    reader = history.journal_status()["reader"]["status"]
    health = history.health()
    obj = bundle(samples=timeline["samples"],
                 device_states=timeline["device_states"],
                 probe_rows=timeline["probe_rows"], journal_events=events,
                 audit=audits, reader=reader,
                 degraded=bool(health["degraded"]),
                 last_error_code=health["last_error_code"],
                 enabled=bool(health["enabled"]), buckets=buckets)
    counts = {"sample_rows": len(timeline["samples"]),
              "probe_rows": len(timeline["probe_rows"]),
              "journal_rows": len(events),
              "audit_rows": len(audits),
              "schema_version": ih.SCHEMA_VERSION,
              "jr_valid": all(jr_schema.validate_event(r)
                              for r in journal_records)}
    return history, obj, counts, root


def _pragma_columns(history, table):
    return [row[1] for row in
            history._conn.execute("PRAGMA table_info(%s)" % table)]


def group_store():
    out = {}
    import web.incident_history as ih
    history, obj, counts, root = _build_store()
    try:
        out["store_opens_on_schema_v3"] = (
            ih.SCHEMA_VERSION == 3 and counts["schema_version"] == 3
            and counts["sample_rows"] > 0)
        out["store_probe_rows_persist"] = counts["probe_rows"] >= 8
        out["store_journal_rows_ingest"] = counts["journal_rows"] >= 40
        out["store_exchange_records_are_valid"] = counts["jr_valid"]
        out["store_rows_pass_the_shape_wall"] = cl._refusals(obj) == ()
        out["store_reader_is_fresh"] = obj["reader"]["status"] == "fresh"
        result = cl.classify(obj)
        out["store_reality_incident"] = (
            result.status == "incident"
            and result.category == "reality_tcp_path")
        out["store_bundle_carries_leak_probes"] = all(
            probe in json.dumps(obj) for probe in CARRIED_LEAK_PROBES)
        out["store_result_echoes_nothing"] = not any(
            probe in json.dumps(result.to_dict(), sort_keys=True)
            for probe in LEAK_PROBES)
        out["store_reality_evidence"] = set(result.evidence) >= {
            "count_drop_reality", "journal_burst_reality",
            "probe_generic_tcp_healthy"}
        out["store_never_names_hy2"] = (
            "journal_burst_hysteria2" not in result.evidence)
        out["store_names_the_root_unknown"] = (
            "root_cause_not_established" in result.unknowns)
        out["pragma_sample_columns"] = set(_pragma_columns(
            history, "timeline_samples")) == set(cl.SAMPLE_ROW_COLUMNS)
        out["pragma_device_columns"] = set(_pragma_columns(
            history, "device_protocol_states")) == set(cl.DEVICE_ROW_COLUMNS)
        out["pragma_probe_columns"] = set(_pragma_columns(
            history, "network_probe_samples")) == set(cl.PROBE_ROW_COLUMNS)
        out["pragma_journal_columns"] = set(_pragma_columns(
            history, "journal_events")) == set(cl.JOURNAL_EVENT_ROW_COLUMNS)
        out["pragma_audit_columns"] = set(_pragma_columns(
            history, "journal_ingest_audit")) == set(cl.AUDIT_ROW_COLUMNS)
        # The store's own sentinels are what the classifier reads: a
        # destination-less row arrives as port 0 / dcls NONE, never NULL.
        stored = [row for row in obj["journal_events"] if row["dcls"] == "NONE"]
        out["store_sentinels_are_the_db_form"] = bool(stored) and all(
            row["port"] == 0 for row in stored)
        out["store_real_rows_carry_no_free_text"] = all(
            row["cls"] in set(cl.JOURNAL_CLASSES)
            and row["proto"] in set(cl.JOURNAL_PROTOS)
            and row["dcls"] in set(cl.JOURNAL_DCLS)
            for row in obj["journal_events"])
    finally:
        history.close()
        shutil.rmtree(root, ignore_errors=True)

    # A continuity gap the store itself recorded is evidence, and the
    # healthy TCP probes still carry the attribution.
    history, obj, counts, root = _build_store(gap=True)
    try:
        result = cl.classify(obj)
        out["store_gap_audit_lands"] = counts["audit_rows"] >= 1
        out["store_gap_is_named"] = "journal_continuity_gap" in result.evidence
        out["store_gap_still_attributes"] = (
            result.status == "incident"
            and result.category == "reality_tcp_path")
        out["store_gap_incompleteness_unknown"] = (
            "journal_evidence_incomplete" in result.unknowns)
    finally:
        history.close()
        shutil.rmtree(root, ignore_errors=True)

    # With no probe plane and no live reader heartbeat, the same rows cannot
    # support a transport name: the grounded store reproduces the refusal.
    history, obj, _counts, root = _build_store(with_probes=False, hb=False)
    try:
        result = cl.classify(obj)
        out["store_no_planes_refuses_attribution"] = (
            result.status == "incident"
            and result.category == "insufficient_evidence"
            and "transport_negatives_unproven" in result.unknowns)
    finally:
        history.close()
        shutil.rmtree(root, ignore_errors=True)

    # Background noise through the real store is still not an incident.
    history, obj, _counts, root = _build_store(drop_from=10)
    try:
        result = cl.classify(obj)
        out["store_background_stays_quiet"] = (
            result.status == "no_incident"
            and result.category == "NONE"
            and "no_anomaly" in result.evidence)
    finally:
        history.close()
        shutil.rmtree(root, ignore_errors=True)
    return out


# -- group: committed fixtures -----------------------------------------------

FIXTURES = (("incident-reality-outage.json", "reality_outage"),
            ("incident-normal-background.json", "normal_background"))


def group_fixtures():
    out = {}
    for filename, name in FIXTURES:
        path = os.path.join(FIXTURE_DIR, filename)
        exists = os.path.isfile(path)
        out["%s:fixture_present" % name] = exists
        if not exists:
            out["%s:matches_generated_bundle" % name] = False
            out["%s:classifies_as_expected" % name] = False
            continue
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        loaded = json.loads(text)
        entry = [e for e in scenarios() if e[0] == name][0]
        out["%s:matches_generated_bundle" % name] = loaded == entry[1]
        result = cl.classify(loaded)
        out["%s:classifies_as_expected" % name] = (
            result.status == entry[2] and result.category == entry[3])
        out["%s:no_refusal" % name] = cl._refusals(loaded) == ()
        # The committed text is store-shaped: every row carries exactly the
        # v3 columns the store group reads out of a live database, including
        # the ones the classifier may RECEIVE but never READ. That is what
        # makes the echo gate below worth running instead of vacuously true.
        out["%s:input_carries_leak_probes" % name] = all(
            probe in text for probe in CARRIED_LEAK_PROBES)
        out["%s:result_echoes_nothing" % name] = not any(
            probe in json.dumps(result.to_dict(), sort_keys=True)
            for probe in LEAK_PROBES)
    out["fixtures_are_two"] = len(FIXTURES) == 2
    out["fixtures_are_scenario_inputs"] = all(
        any(entry[0] == name for entry in scenarios())
        for _file, name in FIXTURES)
    return out


# -- runner ------------------------------------------------------------------

GROUPS = {"mirrors": group_mirrors, "scenarios": group_scenarios,
          "hostiles": group_hostiles, "invariants": group_invariants,
          "privacy": group_privacy, "store": group_store,
          "fixtures": group_fixtures}


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
