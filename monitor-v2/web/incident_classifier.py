"""Deterministic incident classifier -- issue #33 Phase 4, PR-4A (DARK).

A pure function over ALREADY-SANITIZED, ALREADY-BOUNDED evidence: one closed
evidence bundle in, one frozen typed ``Classification`` out, every field a
token from a reviewed closed vocabulary.

Contract (docs/monitor-v2-incident-classifier-p4a.md):

* **Pure and dark.** Standard library only (the ``dataclasses`` module), no
  clock, no state, no I/O, no imports from ``web/``, ``diagnostics/`` or
  ``journal_reader/``. Nothing in the runtime imports this module in PR-4A:
  no route, no scheduler, no service loop, no schema, no deployment surface
  touches it.
* **Schema-v3 truth only.** The accepted record shapes are the columns the
  live store actually projects -- ``timeline_samples``,
  ``device_protocol_states``, ``network_probe_samples``, ``journal_events``
  and ``journal_ingest_audit`` -- and nothing else. The value vocabularies
  are mirrored from ``web/incident_history.py``; the classify lane asserts
  every mirror against the live module, so a mirror cannot rot into a silent
  lie. No per-edge table, no Reality-target table and no net-counter table is
  assumed, because none exists.
* **No free text, ever.** Only whitelisted keys with closed value domains are
  accepted, so a raw log line, an address, a fingerprint or a credential
  cannot enter even from a buggy caller -- and cannot leave either, because
  the output holds vocabulary tokens and numbers only. The classifier says
  WHERE the evidence points, never WHY: no root-cause sentence, no ISP
  inference, and correlation is never reported as causation.
* **Bounded and deterministic.** One call covers at most ``MAX_BUCKETS``
  aligned 60 s buckets, each section at most ``MAX_RECORDS_PER_SECTION``
  records; both output tuples are sorted and deduplicated, so no input
  ordering can change the result.
* **Fail closed.** A malformed or out-of-window bundle produces the
  conservative ``indeterminate`` / ``insufficient_evidence`` result with
  closed refusal tokens; the function never raises. An attribution is
  refused unless the negatives it relies on are positively proven: a bare
  connection-count drop is never an incident, and
  ``destination_specific`` needs target-specific proof.
"""

from __future__ import annotations

from dataclasses import dataclass

CLASSIFIER_VERSION = 1

# -- bounds ------------------------------------------------------------------

BUCKET_SECONDS = 60.0
MAX_BUCKETS = 60                     # one hour of evidence per call
MAX_RECORDS_PER_SECTION = 2000       # mirrors QUERY_LIMIT_MAX
MIN_BASELINE_BUCKETS = 3             # reference buckets before a candidate
MIN_SAMPLES_PER_BUCKET = 6           # a 60 s window at the 5 s sample beat

# -- detection thresholds (reviewed constants, never runtime knobs) ----------

COUNT_DROP_RATIO = 0.5               # the bucket must fall to <=50% of ...
COUNT_DROP_MIN_BASELINE = 5.0        # ... a baseline that is non-trivial,
COUNT_DROP_MIN_ABSOLUTE = 3.0        # ... and by at least this many clients
API_STALE_BUCKET_FRACTION = 0.5      # share of a bucket's samples naming the ...
                                     # API stale before that is a signal
ALL_DEVICES_QUIET_MIN = 2            # devices needed to call "all quiet"
JOURNAL_BURST_MIN_COUNT = 5          # absolute floor above background ...
JOURNAL_BURST_MULTIPLIER = 3.0       # ... and a multiple of its own baseline
PROBE_FAIL_MIN_BUCKETS = 2           # anti-flap: one failed cycle is a blip
PROBE_HEALTH_MIN_BUCKETS = 2         # positive proof generic TCP is healthy
DESTINATION_MIN_BUCKETS = 2          # a target signature must recur, not blink

# -- closed category vocabulary (fixed by the PR-4A spec) --------------------

CATEGORY_VPS_PROCESS = "vps_process_or_api"
CATEGORY_VPS_OUTBOUND = "vps_outbound"
CATEGORY_REALITY_TCP = "reality_tcp_path"
CATEGORY_HY2_UDP = "hysteria2_udp_path"
CATEGORY_COMMON_INBOUND = "common_inbound_client_office"
CATEGORY_DESTINATION = "destination_specific"
CATEGORY_INSUFFICIENT = "insufficient_evidence"

CATEGORIES = (CATEGORY_VPS_PROCESS, CATEGORY_VPS_OUTBOUND,
              CATEGORY_REALITY_TCP, CATEGORY_HY2_UDP,
              CATEGORY_COMMON_INBOUND, CATEGORY_DESTINATION,
              CATEGORY_INSUFFICIENT)
# The sentinel style this repository already uses ('NONE' in the journal and
# probe vocabularies): a verdict that is not an incident carries no
# attribution at all rather than an invented one.
CATEGORY_NONE = "NONE"

STATUS_INCIDENT = "incident"
STATUS_NO_INCIDENT = "no_incident"
STATUS_INDETERMINATE = "indeterminate"
STATUSES = (STATUS_INCIDENT, STATUS_NO_INCIDENT, STATUS_INDETERMINATE)

# -- mirrored closed vocabularies (equality-gated against the live store) ----

# Mirror of the schema-v3 journal CHECK vocabularies in
# web/incident_history.py (JOURNAL_CLASSES / JOURNAL_PROTOS / JOURNAL_DCLS /
# JOURNAL_AUDIT_KINDS / JOURNAL_AUDIT_CODES).
JOURNAL_CLASSES = ("dns", "dial_timeout", "reset", "net_unreachable",
                   "tls_handshake", "quic_error", "eof_cancel", "other")
JOURNAL_PROTOS = ("Reality", "Hysteria2", "OTHER")
JOURNAL_DCLS = ("NONE", "https443", "http80", "quic", "dns53", "dot853",
                "smtpish", "other")
JOURNAL_AUDIT_KINDS = ("gap", "rejected")
JOURNAL_AUDIT_CODES = ("sequence_gap", "exchange_bad_json",
                       "exchange_bad_name", "exchange_bad_shape",
                       "exchange_empty", "exchange_event_invalid",
                       "exchange_header_invalid",
                       "exchange_header_position", "exchange_no_header",
                       "exchange_not_regular", "exchange_seq_mismatch",
                       "exchange_too_large", "exchange_unreadable")
# Mirror of the closed probe vocabularies (PROBE_STATUSES / PROBE_ERROR_CODES
# / PROBE_CHANGE_VALUES).
PROBE_STATUSES = ("ok", "failed")
PROBE_ERROR_CODES = ("NONE", "timeout", "dns_failed", "connect_failed",
                     "tls_failed", "bad_response", "protocol_failed",
                     "parse_failed", "unavailable")
PROBE_CHANGE_VALUES = ("unchanged", "changed", "unknown")
PROBE_SLOTS = ("dns", "https", "udp", "egress")
# The slots that say "the VPS can reach the internet over TCP at all": a
# failure here is generic, not a transport the clients own.
GENERIC_PROBE_SLOTS = ("dns", "https", "egress")
# Mirror of the sanitized history health codes (the CODE_* constants).
HISTORY_ERROR_CODES = ("history_dir_unsafe", "history_db_unsafe",
                       "history_open_failed", "history_schema_unsupported",
                       "history_write_failed", "history_retention_failed",
                       "history_read_failed", "history_ingest_apply_failed",
                       "history_probe_persist_failed",
                       "history_probe_result_rejected",
                       "history_journal_exchange_unreadable")
# Mirror of the reader availability tokens (_journal_reader_hb_status), of
# the snapshot health field the projection carries, and of the device-row
# reason wall in the v1 schema.
READER_STATUSES = ("disabled", "absent", "unreadable", "invalid",
                   "stale", "fresh")
API_STATUSES = ("CONNECTED", "STALE")
DEVICE_REASONS = ("change", "heartbeat")

# The journal destination classes that mean "plain web over TCP": errors on
# those destinations are generic TCP evidence, not one target's signature.
GENERIC_TCP_DCLS = ("https443", "http80")

# -- accepted row shapes: the REAL persisted columns, and what is read -------

SAMPLE_ROW_COLUMNS = (
    "epoch", "iso_utc", "run_id",
    "monitor_uptime_seconds", "snapshot_version", "snapshot_generated_at",
    "last_success_at", "collector_stale", "api_status",
    "total_active_connections", "reality_active_connections",
    "hysteria2_active_connections", "other_active_connections",
    "uplink_rate", "downlink_rate",
    "skipped_events", "duplicate_events", "identity_conflicts",
    "abandoned_on_reset",
)
DEVICE_ROW_COLUMNS = (
    "epoch", "iso_utc", "run_id", "device", "inbound",
    "active_connections", "device_status",
    "uplink_rate", "downlink_rate", "uplink_total", "downlink_total",
    "reason",
)
PROBE_ROW_COLUMNS = (
    "epoch", "iso_utc", "run_id", "cycle_id", "result_version",
    "dns_status", "dns_latency_ms", "dns_error_code",
    "https_status", "https_latency_ms", "https_error_code",
    "udp_status", "udp_latency_ms", "udp_error_code",
    "egress_status", "egress_latency_ms", "egress_error_code", "egress_ip",
    "egress_change",
)
JOURNAL_EVENT_ROW_COLUMNS = ("seq", "ts", "cls", "proto", "port", "dcls",
                             "fp", "n")
AUDIT_ROW_COLUMNS = ("epoch", "kind", "seq", "code")

# The subset actually CONSUMED. Latency numbers, the egress IP, the message
# fingerprint and the inbound tag carry no classification meaning, so they
# are never read; a device name is an opaque counting key and never emitted.
SAMPLE_FIELDS = ("epoch", "collector_stale", "api_status",
                 "total_active_connections", "reality_active_connections",
                 "hysteria2_active_connections", "other_active_connections")
SAMPLE_COUNT_FIELDS = ("total_active_connections",
                       "reality_active_connections",
                       "hysteria2_active_connections",
                       "other_active_connections")
DEVICE_FIELDS = ("epoch", "device", "active_connections", "reason")
PROBE_FIELDS = ("epoch", "dns_status", "dns_error_code", "https_status",
                "https_error_code", "udp_status", "udp_error_code",
                "egress_status", "egress_error_code", "egress_change")
JOURNAL_FIELDS = ("ts", "cls", "proto", "port", "dcls", "n")
AUDIT_FIELDS = ("epoch", "kind", "code")
HEALTH_FIELDS = ("enabled", "degraded", "last_error_code")
READER_FIELDS = ("status",)
WINDOW_FIELDS = ("start_epoch", "end_epoch")

LIST_SECTIONS = ("samples", "device_states", "probe_rows", "journal_events",
                 "audit")
DICT_SECTIONS = ("window", "health", "reader")
EVIDENCE_SECTIONS = LIST_SECTIONS + DICT_SECTIONS

# -- closed output vocabularies ----------------------------------------------

BASE_EVIDENCE_TOKENS = (
    "no_anomaly",
    "count_drop_total", "count_drop_reality", "count_drop_hysteria2",
    "count_drop_other", "all_devices_quiet",
    "journal_burst_reality", "journal_burst_hysteria2",
    "journal_burst_other_generic", "journal_burst_destination",
    "journal_burst_unattributed",
    "probe_failed_dns", "probe_failed_https", "probe_failed_udp",
    "probe_failed_egress", "probe_generic_tcp_healthy", "egress_ip_changed",
    "api_stale", "collector_stale", "sample_coverage_gap",
    "history_degraded", "journal_continuity_gap", "journal_rejected_batch",
)
BASE_UNKNOWN_TOKENS = (
    "no_corroboration", "count_drop_only", "attribution_ambiguous",
    "baseline_evidence_absent", "transport_negatives_unproven",
    "probe_evidence_absent", "journal_evidence_absent",
    "journal_evidence_incomplete", "no_target_specific_proof",
    "multiple_destinations", "process_and_network_evidence_conflict",
    "unattributed_evidence_present",
    "evidence_shape_rejected", "evidence_outside_window",
    # The standing unknown of every incident this classifier reports: the
    # evidence says WHERE it hurts, never WHY. Naming a cause is out of
    # scope by construction, not by omission.
    "root_cause_not_established",
)
# Derived from closed vocabularies only, so the sets cannot grow silently:
# one token per journal failure class, one per closed ingest-audit code, one
# per rejected evidence section.
_CLS_EVIDENCE_TOKENS = tuple("journal_cls_" + name for name in JOURNAL_CLASSES)
_AUDIT_EVIDENCE_TOKENS = tuple("journal_audit_" + code
                               for code in JOURNAL_AUDIT_CODES)
_SECTION_UNKNOWN_TOKENS = tuple("evidence_rejected_" + name
                                for name in EVIDENCE_SECTIONS)

EVIDENCE_TOKENS = frozenset(BASE_EVIDENCE_TOKENS + _CLS_EVIDENCE_TOKENS
                            + _AUDIT_EVIDENCE_TOKENS)
UNKNOWN_TOKENS = frozenset(BASE_UNKNOWN_TOKENS + _SECTION_UNKNOWN_TOKENS)

# Which anomaly families may corroborate one another. The connection counts
# and the device rows BOTH come from the sing-box API view, so they are one
# family and can never corroborate each other: what is needed is journal,
# probe or process evidence.
CORROBORATING_FAMILIES = ("journal", "probe", "process")

_JOURNAL_CLASS_TOKENS = frozenset(JOURNAL_CLASSES)
_JOURNAL_PROTO_TOKENS = frozenset(JOURNAL_PROTOS)
_JOURNAL_DCLS_TOKENS = frozenset(JOURNAL_DCLS)
_AUDIT_KIND_TOKENS = frozenset(JOURNAL_AUDIT_KINDS)
_AUDIT_CODE_TOKENS = frozenset(JOURNAL_AUDIT_CODES)
_PROBE_STATUS_TOKENS = frozenset(PROBE_STATUSES)
_PROBE_CODE_TOKENS = frozenset(PROBE_ERROR_CODES)
_PROBE_CHANGE_TOKENS = frozenset(PROBE_CHANGE_VALUES)
_HISTORY_TOKENS = frozenset(HISTORY_ERROR_CODES)
_READER_TOKENS = frozenset(READER_STATUSES)
_API_TOKENS = frozenset(API_STATUSES)
_DEVICE_REASON_TOKENS = frozenset(DEVICE_REASONS)

_REJECTED_SHAPE = "shape"
_REJECTED_OUTSIDE = "outside"


@dataclass(frozen=True)
class Classification:
    """The closed typed result: every string is a vocabulary token."""

    version: int
    status: str
    category: str
    window_start: float
    window_end: float
    buckets: int
    evidence: tuple
    unknowns: tuple

    def to_dict(self):
        return {"version": self.version, "status": self.status,
                "category": self.category,
                "window_start": self.window_start,
                "window_end": self.window_end,
                "buckets": self.buckets,
                "evidence": list(self.evidence),
                "unknowns": list(self.unknowns)}


def classify(evidence):
    """Classify one bounded evidence bundle. Never raises, never blocks."""
    refusals = _refusals(evidence)
    if refusals:
        start, end, count = _echo_window(evidence)
        return _seal(STATUS_INDETERMINATE, CATEGORY_INSUFFICIENT, start, end,
                     count, (), refusals)
    window = evidence["window"]
    start = float(window["start_epoch"])
    end = float(window["end_epoch"])
    count = int(round((end - start) / BUCKET_SECONDS))
    return _analyse(evidence, start, count)


# -- input refusal: closed tokens only, never exception text ------------------


def _refusals(evidence):
    if not isinstance(evidence, dict):
        return ("evidence_shape_rejected",)
    if not set(evidence) <= set(EVIDENCE_SECTIONS):
        return ("evidence_shape_rejected",)
    reasons = set()
    if not _valid_window(evidence.get("window")):
        # The window is the ruler every other section is measured with. When
        # it is unusable the rows are not thereby malformed -- they are
        # unmeasurable -- so the refusal names the window and nothing else.
        return ("evidence_rejected_window",)
    start = float(evidence["window"]["start_epoch"])
    end = float(evidence["window"]["end_epoch"])
    for section in DICT_SECTIONS[1:]:
        if not _valid_dict_section(section, evidence.get(section)):
            reasons.add("evidence_rejected_" + section)
    for section in LIST_SECTIONS:
        rows = evidence.get(section)
        if not isinstance(rows, (list, tuple)) or \
                len(rows) > MAX_RECORDS_PER_SECTION:
            reasons.add("evidence_rejected_" + section)
            continue
        outside = False
        for row in rows:
            reason = _row_reason(section, row, start, end)
            if reason == _REJECTED_OUTSIDE:
                outside = True
                break
            if reason:
                reasons.add("evidence_rejected_" + section)
                break
        if outside:
            reasons.update(("evidence_outside_window",
                            "evidence_rejected_" + section))
    return tuple(sorted(reasons))


def _valid_window(window):
    if not isinstance(window, dict) or set(window) != set(WINDOW_FIELDS):
        return False
    start = window["start_epoch"]
    end = window["end_epoch"]
    if not _is_real(start) or not _is_real(end):
        return False
    if start < 0.0 or end <= start:
        return False
    if _unaligned(start) or _unaligned(end):
        return False
    span = float(end) - float(start)
    return BUCKET_SECONDS <= span <= MAX_BUCKETS * BUCKET_SECONDS


def _echo_window(evidence):
    if isinstance(evidence, dict) and _valid_window(evidence.get("window")):
        window = evidence["window"]
        start = float(window["start_epoch"])
        end = float(window["end_epoch"])
        return start, end, int(round((end - start) / BUCKET_SECONDS))
    return 0.0, 0.0, 0


def _valid_dict_section(section, obj):
    fields = HEALTH_FIELDS if section == "health" else READER_FIELDS
    if not isinstance(obj, dict) or set(obj) != set(fields):
        return False
    if section == "reader":
        status = obj["status"]
        return isinstance(status, str) and status in _READER_TOKENS
    if not isinstance(obj["enabled"], bool) or \
            not isinstance(obj["degraded"], bool):
        return False
    code = obj["last_error_code"]
    return code is None or (isinstance(code, str) and code in _HISTORY_TOKENS)


def _row_reason(section, row, start, end):
    """'' when the row is usable, else a refusal marker."""
    if not isinstance(row, dict):
        return _REJECTED_SHAPE
    if section == "samples":
        return (_row_keys(row, SAMPLE_ROW_COLUMNS, SAMPLE_FIELDS)
                or _row_time(row, "epoch", start, end)
                or _row_flags(row, ("collector_stale",))
                or _row_counts(row, SAMPLE_COUNT_FIELDS)
                or _row_api(row))
    if section == "device_states":
        return (_row_keys(row, DEVICE_ROW_COLUMNS, DEVICE_FIELDS)
                or _row_time(row, "epoch", start, end)
                or _row_counts(row, ("active_connections",))
                or _row_one_of(row, "reason", _DEVICE_REASON_TOKENS))
    if section == "probe_rows":
        return (_row_keys(row, PROBE_ROW_COLUMNS, PROBE_FIELDS)
                or _row_time(row, "epoch", start, end)
                or _row_probes(row))
    if section == "journal_events":
        return (_row_keys(row, JOURNAL_EVENT_ROW_COLUMNS, JOURNAL_FIELDS)
                or _row_time(row, "ts", start, end)
                or _row_journal(row))
    if section == "audit":
        return (_row_keys(row, AUDIT_ROW_COLUMNS, AUDIT_FIELDS)
                or _row_time(row, "epoch", start, end)
                or _row_one_of(row, "kind", _AUDIT_KIND_TOKENS)
                or _row_one_of(row, "code", _AUDIT_CODE_TOKENS))
    return _REJECTED_SHAPE


def _row_keys(row, full_columns, needed):
    keys = set(row)
    if not keys <= set(full_columns):
        return _REJECTED_SHAPE
    if not set(needed) <= keys:
        return _REJECTED_SHAPE
    return ""


def _row_time(row, key, start, end):
    value = row[key]
    if not _is_real(value):
        return _REJECTED_SHAPE
    stamp = float(value)
    if stamp < start or stamp >= end:
        return _REJECTED_OUTSIDE
    return ""


def _row_flags(row, keys):
    for key in keys:
        if not _is_int(row[key]) or row[key] not in (0, 1):
            return _REJECTED_SHAPE
    return ""


def _row_counts(row, keys):
    for key in keys:
        if not _is_int(row[key]) or row[key] < 0:
            return _REJECTED_SHAPE
    return ""


def _row_one_of(row, key, vocabulary):
    value = row[key]
    if not isinstance(value, str) or value not in vocabulary:
        return _REJECTED_SHAPE
    return ""


def _row_api(row):
    status = row["api_status"]
    if status is None:
        return ""
    if isinstance(status, str) and status in _API_TOKENS:
        return ""
    return _REJECTED_SHAPE


def _row_probes(row):
    for slot in PROBE_SLOTS:
        status = row["%s_status" % slot]
        code = row["%s_error_code" % slot]
        if not isinstance(status, str) or status not in _PROBE_STATUS_TOKENS:
            return _REJECTED_SHAPE
        if not isinstance(code, str) or code not in _PROBE_CODE_TOKENS:
            return _REJECTED_SHAPE
        # The stored row's own invariant, re-proved here: an ok slot carries
        # NO error code and a failed slot carries something else.
        if (status == "ok") != (code == "NONE"):
            return _REJECTED_SHAPE
    change = row["egress_change"]
    if not isinstance(change, str) or change not in _PROBE_CHANGE_TOKENS:
        return _REJECTED_SHAPE
    return ""


def _row_journal(row):
    if not _is_int(row["port"]) or not 0 <= row["port"] <= 65535:
        return _REJECTED_SHAPE
    if (_row_one_of(row, "cls", _JOURNAL_CLASS_TOKENS)
            or _row_one_of(row, "proto", _JOURNAL_PROTO_TOKENS)
            or _row_one_of(row, "dcls", _JOURNAL_DCLS_TOKENS)):
        return _REJECTED_SHAPE
    # The v2-R1 sentinel pairing the DB CHECK enforces: 'NONE' is a wire
    # null, so it may not carry a port, and a destination class may not be
    # named without one.
    if row["dcls"] == "NONE":
        if row["port"] != 0:
            return _REJECTED_SHAPE
    elif row["port"] < 1:
        return _REJECTED_SHAPE
    if not _is_int(row["n"]) or row["n"] < 1:
        return _REJECTED_SHAPE
    return ""


def _is_real(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")):
        return False
    return True


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _unaligned(value):
    return float(value) % BUCKET_SECONDS != 0.0


# -- aggregation -------------------------------------------------------------


def _analyse(evidence, start, buckets):
    samples = [_sample_stats(rows) for rows in _bucketed(
        evidence["samples"], "epoch", start, buckets)]
    devices = [_device_stats(rows) for rows in _bucketed(
        evidence["device_states"], "epoch", start, buckets)]
    probes = [_probe_stats(rows) for rows in _bucketed(
        evidence["probe_rows"], "epoch", start, buckets)]
    journal = [_journal_stats(rows) for rows in _bucketed(
        evidence["journal_events"], "ts", start, buckets)]
    audit = _audit_view(_bucketed(evidence["audit"], "epoch", start, buckets))

    seen, unknown = _observations(samples, probes, journal, audit)
    window_end = start + buckets * BUCKET_SECONDS
    probe_seen = bool(evidence["probe_rows"])
    journal_seen = bool(evidence["journal_events"])
    # A window of samples that is entirely empty says "this caller handed me
    # nothing", not "the Monitor was down": absence of input is never
    # evidence of a fault, so it must not fabricate a coverage gap.
    window_has_samples = any(stats["rows"] for stats in samples)

    if buckets <= MIN_BASELINE_BUCKETS:
        # Too short to hold a candidate bucket: nothing here is provable,
        # and an unprovable window is never an incident.
        unknown.add("baseline_evidence_absent")
        return _seal(STATUS_INDETERMINATE, CATEGORY_INSUFFICIENT, start,
                     window_end, buckets, seen, unknown)

    reference = _baseline(samples, journal, buckets)
    if not reference["usable"]:
        unknown.add("baseline_evidence_absent")
    slot_fail = _probe_failures(probes)
    generic_healthy = _generic_tcp_healthy(probes)
    if generic_healthy:
        seen.add("probe_generic_tcp_healthy")
    journal_state = _journal_view_state(evidence["reader"]["status"], audit)
    negatives_provable = (journal_state == "complete" or generic_healthy)
    if journal_state == "incomplete":
        unknown.add("journal_evidence_incomplete")
    elif journal_state == "absent":
        unknown.add("journal_evidence_absent")
    degraded = bool(evidence["health"]["degraded"])

    candidates = []
    for index in range(MIN_BASELINE_BUCKETS, buckets):
        anomaly = _bucket_anomaly(index, samples, devices, journal, reference,
                                  slot_fail, degraded, window_has_samples)
        if anomaly is not None:
            candidates.append(anomaly)
    if not candidates:
        # "Nothing anomalous" is only a finding when there was something to
        # look at: with no count baseline and no independent plane the
        # honest answer is that this window cannot answer the question.
        if reference["usable"] and (probe_seen or journal_seen):
            seen.add("no_anomaly")
            return _seal(STATUS_NO_INCIDENT, CATEGORY_NONE, start, window_end,
                         buckets, seen, unknown)
        return _seal(STATUS_INDETERMINATE, CATEGORY_INSUFFICIENT, start,
                     window_end, buckets, seen, unknown)

    flags = _collect(candidates, seen)
    families = set()
    for anomaly in candidates:
        families.update(anomaly["families"])
    if not families & set(CORROBORATING_FAMILIES):
        # Exactly the case the spec forbids from becoming an incident: the
        # API view moved and nothing independent agrees with it.
        unknown.update(("count_drop_only", "no_corroboration"))
        return _seal(STATUS_NO_INCIDENT, CATEGORY_NONE, start, window_end,
                     buckets, seen, unknown)

    return _attribute(flags, seen, unknown, start, window_end, buckets,
                      probe_seen, negatives_provable)


def _bucketed(rows, key, start, buckets):
    out = [[] for _ in range(buckets)]
    for row in rows:
        index = int((float(row[key]) - start) // BUCKET_SECONDS)
        if 0 <= index < buckets:
            out[index].append(row)
    return out


def _sample_stats(rows):
    means = {name: [] for name in SAMPLE_COUNT_FIELDS}
    stale = 0
    collector_stale = 0
    for row in rows:
        means["total_active_connections"].append(
            row["total_active_connections"])
        means["reality_active_connections"].append(
            row["reality_active_connections"])
        means["hysteria2_active_connections"].append(
            row["hysteria2_active_connections"])
        means["other_active_connections"].append(
            row["other_active_connections"])
        if row["api_status"] == "STALE":
            stale += 1
        if row["collector_stale"]:
            collector_stale += 1
    return {"rows": len(rows),
            "means": {name: _mean(values) for name, values in means.items()},
            "stale": stale, "collector_stale": collector_stale}


def _device_stats(rows):
    latest = {}
    for row in rows:
        latest[row["device"]] = row["active_connections"]
    seen = len(latest)
    quiet = sum(1 for value in latest.values() if value == 0)
    return {"seen": seen,
            "all_quiet": seen >= ALL_DEVICES_QUIET_MIN and quiet == seen}


def _probe_stats(rows):
    slots = {slot: {"ok": 0, "failed": 0} for slot in PROBE_SLOTS}
    changed = 0
    for row in rows:
        for slot in PROBE_SLOTS:
            if row["%s_status" % slot] == "ok":
                slots[slot]["ok"] += 1
            else:
                slots[slot]["failed"] += 1
        if row["egress_change"] == "changed":
            changed += 1
    return {"rows": len(rows), "slots": slots, "changed": changed}


def _journal_stats(rows):
    keys = {}
    classes = {}
    for row in rows:
        key = (row["cls"], row["proto"], row["dcls"], row["port"])
        keys[key] = keys.get(key, 0) + row["n"]
        classes[row["cls"]] = classes.get(row["cls"], 0) + row["n"]
    return {"keys": keys, "classes": classes}


def _audit_view(bucket_rows):
    view = {"gap": False, "rejected": False, "codes": set()}
    for rows in bucket_rows:
        for row in rows:
            view["codes"].add(row["code"])
            if row["kind"] == "gap":
                view["gap"] = True
            else:
                view["rejected"] = True
    return view


def _baseline(samples, journal, buckets):
    """Reference means for the connection classes and a per-key burst
    threshold for every journal key that appears anywhere in the window."""
    usable = sum(1 for index in range(MIN_BASELINE_BUCKETS)
                 if samples[index]["rows"] >= MIN_SAMPLES_PER_BUCKET)
    means = {}
    for name in SAMPLE_COUNT_FIELDS:
        values = [samples[index]["means"][name]
                  for index in range(MIN_BASELINE_BUCKETS)
                  if samples[index]["rows"] >= MIN_SAMPLES_PER_BUCKET]
        means[name] = _mean(values) if values else None
    keys = set()
    for index in range(buckets):
        keys.update(journal[index]["keys"])
    thresholds = {}
    for key in keys:
        history = [journal[index]["keys"].get(key, 0)
                   for index in range(MIN_BASELINE_BUCKETS)]
        thresholds[key] = max(JOURNAL_BURST_MIN_COUNT,
                              JOURNAL_BURST_MULTIPLIER * _median(history))
    return {"means": means, "usable": usable >= MIN_BASELINE_BUCKETS,
            "thresholds": thresholds}


def _probe_failures(probes):
    """Per-slot, per-bucket failure marks with the anti-flap rule applied:
    a slot must fail in PROBE_FAIL_MIN_BUCKETS consecutive buckets, and then
    every bucket of that run is marked."""
    buckets = len(probes)
    marks = {slot: [False] * buckets for slot in PROBE_SLOTS}
    for slot in PROBE_SLOTS:
        run = []
        for index in range(buckets):
            stats = probes[index]["slots"][slot]
            if stats["failed"] and not stats["ok"]:
                run.append(index)
                continue
            if len(run) >= PROBE_FAIL_MIN_BUCKETS:
                for mark in run:
                    marks[slot][mark] = True
            run = []
        if len(run) >= PROBE_FAIL_MIN_BUCKETS:
            for mark in run:
                marks[slot][mark] = True
    return marks


def _generic_tcp_healthy(probes):
    healthy = 0
    for stats in probes:
        if all(stats["slots"][slot]["ok"] > 0
               and not stats["slots"][slot]["failed"]
               for slot in GENERIC_PROBE_SLOTS):
            healthy += 1
    return healthy >= PROBE_HEALTH_MIN_BUCKETS


def _journal_view_state(reader_status, audit):
    """'complete' only when the reader is fresh AND nothing was lost or
    refused inside the window. A gap means the journal cannot prove a
    negative; a reader that never ran means there is no journal view at all.
    'I could not look' is never treated as 'I looked and found nothing'."""
    if audit["gap"] or audit["rejected"]:
        return "incomplete"
    if reader_status == "fresh":
        return "complete"
    if reader_status in ("stale", "invalid", "unreadable"):
        return "incomplete"
    return "absent"


def _bucket_anomaly(index, samples, devices, journal, reference, slot_fail,
                    degraded, window_has_samples):
    marks = {"connections": set(), "device": set(), "journal": set(),
             "probe": set(), "process": set()}
    stats = samples[index]
    if window_has_samples and stats["rows"] < MIN_SAMPLES_PER_BUCKET:
        marks["process"].add("sample_coverage_gap")
    floor = max(1, int(stats["rows"] * API_STALE_BUCKET_FRACTION))
    if stats["rows"] and stats["stale"] >= floor:
        marks["process"].add("api_stale")
    if stats["rows"] and stats["collector_stale"] >= floor:
        marks["process"].add("collector_stale")
    if degraded:
        marks["process"].add("history_degraded")

    if reference["usable"] and stats["rows"] >= MIN_SAMPLES_PER_BUCKET:
        # A bucket with too few samples proves only that the Monitor was
        # not publishing (a process signal), never that clients dropped.
        for name in SAMPLE_COUNT_FIELDS:
            base = reference["means"][name]
            value = stats["means"][name]
            if (base is not None and base >= COUNT_DROP_MIN_BASELINE
                    and base - value >= COUNT_DROP_MIN_ABSOLUTE
                    and value <= base * (1.0 - COUNT_DROP_RATIO)):
                marks["connections"].add(name)
    if devices[index]["all_quiet"]:
        marks["device"].add("all_devices_quiet")

    for key, count in journal[index]["keys"].items():
        threshold = reference["thresholds"].get(key)
        if threshold is not None and count >= threshold:
            marks["journal"].add(key)

    for slot in PROBE_SLOTS:
        if slot_fail[slot][index]:
            marks["probe"].add(slot)

    families = set()
    if marks["process"]:
        families.add("process")
    if marks["connections"] or marks["device"]:
        families.add("connections")
    if marks["journal"]:
        families.add("journal")
    if marks["probe"]:
        families.add("probe")
    if not families:
        return None
    return {"families": families, "marks": marks}


def _observations(samples, probes, journal, audit):
    """What the window shows even when nothing is anomalous, so a quiet
    verdict still carries its own evidence and its own unknowns."""
    seen = set()
    unknown = set()
    classes = set()
    for stats in journal:
        classes.update(stats["classes"])
    for name in sorted(classes):
        seen.add("journal_cls_" + name)
    for code in sorted(audit["codes"]):
        seen.add("journal_audit_" + code)
    if audit["gap"]:
        seen.add("journal_continuity_gap")
    if audit["rejected"]:
        seen.add("journal_rejected_batch")
    if any(stats["rows"] and stats["stale"] for stats in samples):
        seen.add("api_stale")
    if any(stats["changed"] for stats in probes):
        seen.add("egress_ip_changed")
    if not any(stats["rows"] for stats in samples):
        unknown.add("baseline_evidence_absent")
    if not any(stats["rows"] for stats in probes):
        unknown.add("probe_evidence_absent")
    return seen, unknown


# -- attribution -------------------------------------------------------------


_DROP_TOKENS = {"total_active_connections": "count_drop_total",
                "reality_active_connections": "count_drop_reality",
                "hysteria2_active_connections": "count_drop_hysteria2",
                "other_active_connections": "count_drop_other"}


def _collect(candidates, seen):
    """Record what every candidate bucket actually shows, then fold the
    marks into the attribution facts. Split from the verdict on purpose:
    the OBSERVATIONS belong to the window even when the classifier refuses
    to attribute it, so a fail-closed answer still says what it saw."""
    reality = hy2 = generic = process = unattributed = False
    destination = {}
    for anomaly in candidates:
        marks = anomaly["marks"]
        pairs = set()
        for name in marks["connections"]:
            seen.add(_DROP_TOKENS[name])
        if marks["device"]:
            seen.add("all_devices_quiet")
        for token in marks["process"]:
            seen.add(token)
            process = True
        for slot in marks["probe"]:
            seen.add("probe_failed_" + slot)
            if slot in GENERIC_PROBE_SLOTS:
                generic = True
        for key in marks["journal"]:
            _cls, proto, dcls, port = key
            if proto == "Reality":
                reality = True
                seen.add("journal_burst_reality")
            elif proto == "Hysteria2":
                hy2 = True
                seen.add("journal_burst_hysteria2")
            elif proto == "OTHER" and dcls in GENERIC_TCP_DCLS:
                generic = True
                seen.add("journal_burst_other_generic")
            elif proto == "OTHER" and dcls != "NONE":
                pairs.add((dcls, port))
                seen.add("journal_burst_destination")
            else:
                unattributed = True
                seen.add("journal_burst_unattributed")
        # One candidate bucket is ONE vote per destination, however many
        # failure classes arrived in it: target-specific proof needs a
        # signature that RECURS across buckets, not a single busy bucket.
        for pair in pairs:
            destination[pair] = destination.get(pair, 0) + 1
    return {"reality": reality, "hy2": hy2, "generic": generic,
            "process": process, "unattributed": unattributed,
            "destination": destination}


def _attribute(flags, seen, unknown, start, window_end, buckets, probe_seen,
               negatives_provable):
    reality = flags["reality"]
    hy2 = flags["hy2"]
    generic = flags["generic"]
    process = flags["process"]
    destination = flags["destination"]

    network = reality or hy2 or generic or bool(destination)
    if process and network:
        # Two independent planes each show a real fault. Naming either one
        # as THE cause would be a claim the evidence does not support.
        unknown.add("process_and_network_evidence_conflict")
        return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start, window_end,
                     buckets, seen, unknown)
    if process:
        return _seal(STATUS_INCIDENT, CATEGORY_VPS_PROCESS, start, window_end,
                     buckets, seen, unknown)
    if generic:
        # The VPS's own TCP reachability, or generic HTTPS/OTHER-protocol
        # journal errors, is BROADER than any one transport: it upgrades a
        # path-specific candidate to vps_outbound.
        return _seal(STATUS_INCIDENT, CATEGORY_VPS_OUTBOUND, start,
                     window_end, buckets, seen, unknown)
    if destination and not reality and not hy2:
        if len(destination) > 1:
            unknown.add("multiple_destinations")
            return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start,
                         window_end, buckets, seen, unknown)
        if max(destination.values()) < DESTINATION_MIN_BUCKETS:
            # A target signature that blinks once is not proof: fail closed
            # rather than name a destination.
            unknown.add("no_target_specific_proof")
            return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start,
                         window_end, buckets, seen, unknown)
        return _guarded(CATEGORY_DESTINATION, flags["unattributed"], seen,
                        unknown, start, window_end, buckets,
                        negatives_provable, probe_seen)
    if reality and not hy2:
        return _guarded(CATEGORY_REALITY_TCP, flags["unattributed"], seen,
                        unknown, start, window_end, buckets,
                        negatives_provable, probe_seen)
    if hy2 and not reality:
        return _guarded(CATEGORY_HY2_UDP, flags["unattributed"], seen, unknown,
                        start, window_end, buckets, negatives_provable,
                        probe_seen)
    if reality and hy2:
        return _guarded(CATEGORY_COMMON_INBOUND, flags["unattributed"], seen,
                        unknown, start, window_end, buckets,
                        negatives_provable, probe_seen)
    if destination:
        unknown.add("no_target_specific_proof")
    unknown.add("attribution_ambiguous")
    return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start, window_end,
                 buckets, seen, unknown)


def _guarded(category, unattributed, seen, unknown, start, window_end, buckets,
             negatives_provable, probe_seen):
    """Emit a path or destination attribution only when the negatives it
    relies on are provable; otherwise fail closed with the reason named.
    Journal errors nothing can place are named even on the emitting path, so
    a positive attribution never reads as complete understanding."""
    if unattributed:
        unknown.add("unattributed_evidence_present")
    if not negatives_provable:
        unknown.add("transport_negatives_unproven")
        return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start, window_end,
                     buckets, seen, unknown)
    if not probe_seen:
        unknown.add("probe_evidence_absent")
    return _seal(STATUS_INCIDENT, category, start, window_end, buckets, seen,
                 unknown)


# -- helpers -----------------------------------------------------------------


def _mean(values):
    if not values:
        return 0.0
    return float(sum(values)) / float(len(values))


def _median(values):
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (float(ordered[mid - 1]) + float(ordered[mid])) / 2.0


def _seal(status, category, window_start, window_end, buckets, evidence,
          unknowns):
    """The closure wall: nothing outside a reviewed vocabulary can leave, and
    the status/category pairing is enforced. A violation degrades to the
    conservative indeterminate result instead of emitting an unclosed object
    that the next layer would have to trust."""
    pairing_valid = ((status == STATUS_NO_INCIDENT
                      and category == CATEGORY_NONE)
                     or (status in (STATUS_INCIDENT, STATUS_INDETERMINATE)
                         and category in CATEGORIES))
    if status not in STATUSES or not pairing_valid:
        return Classification(CLASSIFIER_VERSION, STATUS_INDETERMINATE,
                             CATEGORY_INSUFFICIENT, float(window_start),
                             float(window_end), int(buckets), (),
                             ("attribution_ambiguous",))
    tokens = set(evidence)
    blanks = set(unknowns)
    if not tokens <= EVIDENCE_TOKENS or not blanks <= UNKNOWN_TOKENS:
        return Classification(CLASSIFIER_VERSION, STATUS_INDETERMINATE,
                             CATEGORY_INSUFFICIENT, float(window_start),
                             float(window_end), int(buckets), (),
                             ("attribution_ambiguous",))
    if status == STATUS_INCIDENT:
        # The standing unknown of EVERY incident this classifier reports:
        # the evidence says WHERE it hurts, never WHY. Naming a cause is out
        # of scope by construction, not by omission.
        blanks.add("root_cause_not_established")
    return Classification(CLASSIFIER_VERSION, status, category,
                          float(window_start), float(window_end),
                          int(buckets), tuple(sorted(tokens)),
                          tuple(sorted(blanks)))
