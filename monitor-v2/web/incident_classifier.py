"""Deterministic incident classifier -- issue #33 Phase 4, PR-4A + PR-4B.

A pure function over ALREADY-SANITIZED, ALREADY-BOUNDED evidence: one closed
evidence bundle in, one frozen typed ``Classification`` out, every field a
token from a reviewed closed vocabulary.

Contract (docs/monitor-v2-incident-classifier-p4a.md,
docs/monitor-v2-incident-runtime-p4b.md):

* **Pure.** Standard library only (the ``dataclasses`` module), no
  clock, no state, no I/O, and no import of any sibling package -- not the
  web surface, not the probe engine, not the journal reader. In PR-4B exactly
  one runtime module consumes this package -- ``web/incident_runtime.py``,
  through ``detect()`` -- and the single-consumer allowlist in the classify
  lane is the gate that keeps it that way.
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
  refused unless the negatives it relies on are positively proven IN THE
  SAME BUCKETS as the anomaly: a bare connection-count drop is never an
  incident, ``destination_specific`` is in the vocabulary but is never
  emitted because v3 stores no destination identity, a probe failure whose
  only independent witness is another probe on the same two external
  endpoints does not name ``vps_outbound``, degraded diagnostics says only
  that the evidence plane is degraded, and two anomaly clusters separated by
  a quiet bucket are refused rather than folded into one combined verdict.
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
ALL_DEVICES_QUIET_MIN = 2            # (device, inbound) PAIRS needed to call
                                     # the window quiet
JOURNAL_BURST_MIN_COUNT = 5          # absolute floor above background ...
JOURNAL_BURST_MULTIPLIER = 3.0       # ... and a multiple of its own baseline
PROBE_FAIL_MIN_BUCKETS = 2           # anti-flap: one failed cycle is a blip
PROBE_HEALTH_MIN_BUCKETS = 2         # positive proof generic TCP is healthy

# A cluster is a maximal run of adjacent anomalous buckets. Two runs that a
# quiet bucket separates are two DIFFERENT episodes, and one verdict cannot
# describe both, so the window fails closed instead of folding them together.
CLUSTER_ADJACENCY_BUCKETS = 1

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
# `destination_specific` is in the vocabulary and is NEVER emitted. Schema v3
# projects a destination only as (dcls, port) -- a class and a port, not an
# identity -- so nothing in the accepted evidence can single out one target:
# https443:443 is "the web", not "that site". The category stays named so the
# gap is a stated fact rather than a silently forgotten word, and _seal()
# refuses it structurally, so no later edit can leak it out by accident.
EMITTABLE_CATEGORIES = tuple(name for name in CATEGORIES
                             if name != CATEGORY_DESTINATION)
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
# A "failed" slot is only network-significant when the engine reached the
# network and was refused: timeout, dns_failed and connect_failed. Everything
# else is the PROBE being unable to adjudicate, and the engine's own error
# mapping says so: tls_failed is what any
# ssl.SSLError maps to, SSLCertVerificationError included, so a leaf's
# certificate or TLS configuration reports exactly like a broken path;
# protocol_failed is what an answer that is not ours reports -- an
# http.client.HTTPException, a UDP reply under 12 bytes, a transaction-id or
# question-binding mismatch. bad_response and parse_failed are the same family,
# and unavailable is the dark/unconfigured state itself. Reading any of these as
# an outage would turn "I could not adjudicate the answer" into "the VPS is
# broken", so they prove nothing about the path and are named as an unusable
# plane instead.
PROBE_NETWORK_CODES = ("timeout", "dns_failed", "connect_failed")
PROBE_SOURCE_CODES = ("bad_response", "parse_failed", "unavailable",
                      "protocol_failed", "tls_failed")
PROBE_CHANGE_VALUES = ("unchanged", "changed", "unknown")
PROBE_SLOTS = ("dns", "https", "udp", "egress")
# The slots that say "the VPS can reach the internet over TCP at all": a
# failure here is generic, not a transport the clients own. Note that they
# are not three independent witnesses -- dns and https both aim at the
# Cloudflare leaf and egress at ipify -- so a single endpoint outage looks
# exactly like a VPS outbound failure. See _attribute().
GENERIC_PROBE_SLOTS = ("dns", "https", "egress")
# Mirror of the sanitized history health codes (the CODE_* constants).
HISTORY_ERROR_CODES = ("history_dir_unsafe", "history_db_unsafe",
                       "history_open_failed", "history_schema_unsupported",
                       "history_write_failed", "history_retention_failed",
                       "history_read_failed", "history_ingest_apply_failed",
                       "history_probe_persist_failed",
                       "history_probe_result_rejected",
                       "history_journal_exchange_unreadable")
# Mirror of the reader availability tokens (the heartbeat-name status
# derivation in the history store), of
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

# The subset actually CONSUMED. Latency numbers, the egress IP and the message
# fingerprint carry no classification meaning, so they are never read. The two
# naming columns ARE read, and only as opaque counting keys: `device` because
# quiet is a statement about machines, and `inbound` because
# `device_protocol_states` is keyed (device, inbound, epoch), so reading a
# device's total without it would merge two inbounds into one answer. Neither
# can be emitted: the result surface has no slot for a string that is not a
# vocabulary token, and the privacy gate proves it of both.
SAMPLE_FIELDS = ("epoch", "collector_stale", "api_status",
                 "total_active_connections", "reality_active_connections",
                 "hysteria2_active_connections", "other_active_connections")
SAMPLE_COUNT_FIELDS = ("total_active_connections",
                       "reality_active_connections",
                       "hysteria2_active_connections",
                       "other_active_connections")
DEVICE_FIELDS = ("epoch", "device", "inbound", "active_connections", "reason")
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
    "probe_failed_egress", "probe_source_unavailable",
    "probe_generic_tcp_healthy", "egress_ip_changed",
    "api_stale", "collector_stale", "sample_coverage_gap",
    "history_degraded", "journal_continuity_gap", "journal_rejected_batch",
)
BASE_UNKNOWN_TOKENS = (
    "no_corroboration", "count_drop_only", "attribution_ambiguous",
    "baseline_evidence_absent", "transport_negatives_unproven",
    "contemporaneous_negatives_unproven", "probe_evidence_absent",
    "probe_evidence_unusable", "probe_endpoint_confounded",
    "multiple_anomaly_clusters",
    "journal_evidence_absent", "journal_evidence_incomplete",
    "no_target_specific_proof",
    "multiple_destinations", "process_and_network_evidence_conflict",
    "device_states_are_change_only",
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
_PROBE_NETWORK_TOKENS = frozenset(PROBE_NETWORK_CODES)
_PROBE_SOURCE_TOKENS = frozenset(PROBE_SOURCE_CODES)
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


@dataclass(frozen=True)
class Detection:
    """The PR-4B metadata surface: the SAME verdict classify() returns, plus
    WHERE inside the window the anomalous buckets sat. Every metadata field
    is derived from the candidate indices _analyse already computed, so
    detect(evidence).classification is identical to classify(evidence) by
    construction -- there is no second analysis path and no second threshold
    anywhere in this module, and the runtime that consumes this surface
    inherits that. Positions are bucket indices into the analysed window;
    the epoch fields are the bucket boundaries of the first and last
    anomalous bucket, or None when the verdict carries no anomaly (a refused
    bundle, a quiet window, or an unprovable one)."""

    classification: Classification
    anomaly_bucket_indices: tuple
    first_signal_epoch: float
    last_signal_epoch: float


def classify(evidence):
    """Classify one bounded evidence bundle. Never raises, never blocks."""
    return detect(evidence).classification


def detect(evidence):
    """classify() plus the anomalous-bucket positions behind the verdict.

    Never raises, never blocks, reads nothing but the bundle: the metadata
    is a pure restatement of _analyse's own candidate list, so
    detect(e).classification is identical to classify(e) by construction."""
    refusals = _refusals(evidence)
    if refusals:
        start, end, count = _echo_window(evidence)
        classification = _seal(STATUS_INDETERMINATE, CATEGORY_INSUFFICIENT,
                               start, end, count, (), refusals)
        return Detection(classification, (), None, None)
    window = evidence["window"]
    start = float(window["start_epoch"])
    end = float(window["end_epoch"])
    count = int(round((end - start) / BUCKET_SECONDS))
    classification, indices = _analyse_with_meta(evidence, start, count)
    if not indices:
        return Detection(classification, (), None, None)
    first = start + indices[0] * BUCKET_SECONDS
    last = start + (indices[-1] + 1) * BUCKET_SECONDS
    return Detection(classification, tuple(indices), first, last)


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
    """The classify() view of the analysis: the verdict only. Kept as a thin
    wrapper so the classification and its metadata can never drift apart --
    there is exactly one analysis path in this module, and _analyse_with_meta
    is it."""
    classification, _indices = _analyse_with_meta(evidence, start, buckets)
    return classification


def _analyse_with_meta(evidence, start, buckets):
    """THE single analysis path, shared by classify() and detect(): the
    verdict plus the sorted indices of the buckets that carried the anomaly.
    Indices come from the candidate list this function already computed, so
    detect(e).classification == classify(e) holds by construction, not by
    re-derivation. An empty tuple means the window carried no anomaly
    (too short, nothing anomalous, or a verdict that is not an incident)."""
    samples = [_sample_stats(rows) for rows in _bucketed(
        evidence["samples"], "epoch", start, buckets)]
    device_rows = _bucketed(evidence["device_states"], "epoch", start, buckets)
    pairs_known = {(row["device"], row["inbound"])
                   for rows in device_rows for row in rows}
    devices = [_device_stats(rows, pairs_known) for rows in device_rows]
    probes = [_probe_stats(rows) for rows in _bucketed(
        evidence["probe_rows"], "epoch", start, buckets)]
    journal = [_journal_stats(rows) for rows in _bucketed(
        evidence["journal_events"], "ts", start, buckets)]
    audit = _audit_view(_bucketed(evidence["audit"], "epoch", start, buckets))

    degraded = bool(evidence["health"]["degraded"])
    seen, unknown = _observations(samples, probes, journal, audit, degraded)
    window_end = start + buckets * BUCKET_SECONDS
    window_indices = set(range(buckets))
    probe_seen = bool(evidence["probe_rows"])
    journal_seen = bool(evidence["journal_events"])
    # A window of samples that is entirely empty says "this caller handed me
    # nothing", not "the Monitor was down": absence of input is never
    # evidence of a fault, so it must not fabricate a coverage gap.
    window_has_samples = any(stats["rows"] for stats in samples)

    def note_health(indices):
        if _generic_tcp_healthy(probes, indices):
            seen.add("probe_generic_tcp_healthy")
            return True
        return False

    if buckets <= MIN_BASELINE_BUCKETS:
        # Too short to hold a candidate bucket: nothing here is provable,
        # and an unprovable window is never an incident.
        unknown.add("baseline_evidence_absent")
        return _seal(STATUS_INDETERMINATE, CATEGORY_INSUFFICIENT, start,
                     window_end, buckets, seen, unknown), ()

    reference = _baseline(samples, journal, buckets)
    if not reference["usable"]:
        unknown.add("baseline_evidence_absent")
    probe_marks = _probe_failures(probes)
    # Whether the JOURNAL can prove a negative at all is a property of the
    # window -- a gap or an unreadable reader is a gap wherever it is found.
    # Whether the PROBE plane vouches for the outbound path is a property of
    # the minutes being judged, so it is only ever computed per cluster.
    journal_state = _journal_view_state(evidence["reader"]["status"], audit)
    journal_provable = journal_state == "complete"
    if journal_state == "incomplete":
        unknown.add("journal_evidence_incomplete")
    elif journal_state == "absent":
        unknown.add("journal_evidence_absent")

    candidates = []
    for index in range(MIN_BASELINE_BUCKETS, buckets):
        anomaly = _bucket_anomaly(index, samples, devices, journal, reference,
                                  probe_marks, window_has_samples)
        if anomaly is not None:
            anomaly["index"] = index
            candidates.append(anomaly)
    if not candidates:
        # "Nothing anomalous" is only a finding when there was something to
        # look at: with no count baseline and no independent plane the
        # honest answer is that this window cannot answer the question.
        note_health(window_indices)
        if reference["usable"] and (probe_seen or journal_seen):
            seen.add("no_anomaly")
            return _seal(STATUS_NO_INCIDENT, CATEGORY_NONE, start, window_end,
                         buckets, seen, unknown), ()
        return _seal(STATUS_INDETERMINATE, CATEGORY_INSUFFICIENT, start,
                     window_end, buckets, seen, unknown), ()

    families = set()
    for anomaly in candidates:
        families.update(anomaly["families"])
    if not families & set(CORROBORATING_FAMILIES):
        # Exactly the case the spec forbids from becoming an incident: the
        # API view moved and nothing independent agrees with it.
        _collect(candidates, seen, unknown)
        note_health(window_indices)
        unknown.update(("count_drop_only", "no_corroboration"))
        return _seal(STATUS_NO_INCIDENT, CATEGORY_NONE, start, window_end,
                     buckets, seen, unknown), ()

    clusters = _clusters(anomaly["index"] for anomaly in candidates)
    if len(clusters) > 1:
        # Two episodes with a quiet bucket between them. One verdict cannot
        # describe both, and merging them would attach the second episode's
        # evidence to the first episode's attribution, so the window is
        # refused as a whole instead of folded.
        _collect(candidates, seen, unknown)
        note_health(window_indices)
        unknown.add("multiple_anomaly_clusters")
        return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start, window_end,
                     buckets, seen, unknown), tuple(
                         sorted(a["index"] for a in candidates))

    indices = set(clusters[0])
    flags = _collect(candidates, seen, unknown)
    generic_healthy = note_health(indices)
    api_healthy = _api_healthy(samples, indices)
    negatives_provable = (journal_provable or generic_healthy)
    return _attribute(flags, seen, unknown, start, window_end, buckets,
                      probe_seen, negatives_provable, generic_healthy,
                      api_healthy), tuple(sorted(indices))


def _clusters(indices):
    """Maximal runs of adjacent anomalous buckets: separated runs are
    separate episodes and are never folded into one verdict."""
    runs = []
    for index in sorted(indices):
        if runs and index == runs[-1][-1] + CLUSTER_ADJACENCY_BUCKETS:
            runs[-1].append(index)
        else:
            runs.append([index])
    return runs


def _api_healthy(samples, indices):
    """Positive proof the API view was ANSWERING, over exactly the buckets
    being judged. An absent or stale sample row cannot count as health, and
    health measured in the baseline cannot vouch for the incident."""
    if not indices:
        return False
    for index in indices:
        stats = samples[index]
        if not stats["rows"] or stats["stale"] or stats["collector_stale"]:
            return False
    return True


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


def _device_stats(rows, pairs_known):
    """Aggregate `device_protocol_states` the way the table is actually keyed:
    (device, inbound, epoch). One device holds a row PER INBOUND, so
    vmix-01/vless-in=0 and vmix-01/hy2-in=3 are two facts about one machine and
    neither overwrites the other. Within a bucket the latest row per pair wins,
    and a tie on epoch is broken toward the LARGER count: two rows that disagree
    about the same instant cannot support the negative claim "this pair is
    empty", and the answer must not depend on which row happened to be read last.

    The table is a change/heartbeat log, not a snapshot, so a pair with no row in
    this bucket did not report zero -- it did not report. `pairs_known` is every
    pair the window saw at all, and quiet therefore requires each of them to have
    ANSWERED, with zero, in this bucket: an unreported pair blocks the claim
    instead of silently counting as quiet."""
    latest = {}
    for row in rows:
        pair = (row["device"], row["inbound"])
        current = latest.get(pair)
        if current is None or (row["epoch"], row["active_connections"]) > (
                current["epoch"], current["active_connections"]):
            latest[pair] = row
    seen = set(latest)
    quiet = {pair for pair, row in latest.items()
             if row["active_connections"] == 0}
    return {"seen": len(seen),
            "all_quiet": (len(seen) >= ALL_DEVICES_QUIET_MIN
                          and seen == set(pairs_known)
                          and quiet == seen)}


def _probe_stats(rows):
    """Per-slot tallies split by what a failure PROVES. 'network' is the
    engine reaching the network and being refused; 'unusable' is a refused or
    unparseable endpoint answer, or the dark/unconfigured state. Only
    'network' can ever speak for the path."""
    slots = {slot: {"ok": 0, "network": 0, "unusable": 0}
             for slot in PROBE_SLOTS}
    changed = 0
    for row in rows:
        for slot in PROBE_SLOTS:
            if row["%s_status" % slot] == "ok":
                slots[slot]["ok"] += 1
            elif row["%s_error_code" % slot] in _PROBE_NETWORK_TOKENS:
                slots[slot]["network"] += 1
            else:
                slots[slot]["unusable"] += 1
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
    """Per-slot, per-bucket FAULT marks with the anti-flap rule applied: a slot
    must FAIL FOR THE NETWORK in PROBE_FAIL_MIN_BUCKETS consecutive buckets,
    and then every bucket of that run is marked.

    Unusable slots are deliberately NOT marked here: an unavailable or
    unparseable endpoint answer is the absence of a witness, not a fault, so
    it can only ever weaken a claim. It is read straight from the per-bucket
    tallies by `_generic_tcp_healthy` and `_observations`, which is the only
    place an absent witness belongs."""
    buckets = len(probes)
    marks = {slot: [False] * buckets for slot in PROBE_SLOTS}
    for slot in PROBE_SLOTS:
        run = []
        for index in range(buckets):
            stats = probes[index]["slots"][slot]
            if stats["network"] and not stats["ok"]:
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


def _generic_tcp_healthy(probes, indices):
    """Positive proof that the VPS reaches the internet over generic TCP,
    counted ONLY over `indices`. Health measured in the quiet baseline buckets
    is deliberately not admitted: 'it worked before' cannot vouch for the
    minutes that are already hurting, and only contemporaneous health is a
    witness that the outbound path was fine WHILE the clients were dropping."""
    healthy = 0
    for index in indices:
        stats = probes[index]
        if all(stats["slots"][slot]["ok"] > 0
               and not stats["slots"][slot]["network"]
               and not stats["slots"][slot]["unusable"]
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


def _bucket_anomaly(index, samples, devices, journal, reference, probe_marks,
                    window_has_samples):
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
        if probe_marks[slot][index]:
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


def _observations(samples, probes, journal, audit, degraded):
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
    # Degraded diagnostics is a statement about THIS classifier's own evidence
    # plane, never about the client's incident: it is named here so a quiet
    # verdict says which plane was shaky, and it votes for nothing.
    if degraded:
        seen.add("history_degraded")
    if any(stats["slots"][slot]["unusable"]
           for stats in probes for slot in PROBE_SLOTS):
        seen.add("probe_source_unavailable")
        unknown.add("probe_evidence_unusable")
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


def _collect(candidates, seen, unknown):
    """Record what every candidate bucket actually shows, then fold the
    marks into the attribution facts. Split from the verdict on purpose:
    the OBSERVATIONS belong to the window even when the classifier refuses
    to attribute it, so a fail-closed answer still says what it saw.

    Faults (what is failing) and impacts (whose clients dropped) are kept
    apart: a Reality failure that also emptied the HY2 counter is not a
    Reality-only incident, and only the impact facts can say that."""
    reality = hy2 = generic_journal = generic_probe = False
    process = unattributed = False
    reality_impact = hy2_impact = False
    destination = set()
    for anomaly in candidates:
        marks = anomaly["marks"]
        pairs = set()
        for name in marks["connections"]:
            seen.add(_DROP_TOKENS[name])
            # Impact is read from a transport's OWN counter. The total is the
            # sum of the parts, so a Reality-only collapse necessarily drops
            # it too -- treating count_drop_total as HY2 impact would turn one
            # path's outage into proof that the other path also lost clients.
            if name == "reality_active_connections":
                reality_impact = True
            if name == "hysteria2_active_connections":
                hy2_impact = True
        if marks["device"]:
            # Every (device, inbound) pair this window knows about answered zero
            # in this bucket. That is context, not impact: the pair set is only
            # what this window happened to see, the table is change/heartbeat
            # sparse, and a device's other inbound can hold the clients. Naming
            # it must not say "both transports lost clients", so it sets no
            # impact bit and no conclusion rests on it.
            seen.add("all_devices_quiet")
            unknown.add("device_states_are_change_only")
        for token in marks["process"]:
            seen.add(token)
            process = True
        for slot in marks["probe"]:
            seen.add("probe_failed_" + slot)
            if slot in GENERIC_PROBE_SLOTS:
                generic_probe = True
        for key in marks["journal"]:
            _cls, proto, dcls, port = key
            if proto == "Reality":
                reality = True
                seen.add("journal_burst_reality")
            elif proto == "Hysteria2":
                hy2 = True
                seen.add("journal_burst_hysteria2")
            elif proto == "OTHER" and dcls in GENERIC_TCP_DCLS:
                generic_journal = True
                seen.add("journal_burst_other_generic")
            elif proto == "OTHER" and dcls != "NONE":
                pairs.add((dcls, port))
                seen.add("journal_burst_destination")
            else:
                unattributed = True
                seen.add("journal_burst_unattributed")
        destination.update(pairs)
    return {"reality": reality, "hy2": hy2,
            "generic_journal": generic_journal,
            "generic_probe": generic_probe, "process": process,
            "unattributed": unattributed, "reality_impact": reality_impact,
            "hy2_impact": hy2_impact, "destination": destination}


def _attribute(flags, seen, unknown, start, window_end, buckets, probe_seen,
               negatives_provable, generic_healthy, api_healthy):
    reality = flags["reality"]
    hy2 = flags["hy2"]
    generic_journal = flags["generic_journal"]
    generic_probe = flags["generic_probe"]
    process = flags["process"]
    destination = flags["destination"]
    shared_impact = flags["reality_impact"] and flags["hy2_impact"]

    network = (reality or hy2 or generic_journal or generic_probe
               or bool(destination) or shared_impact)
    if process and network:
        # Two independent planes each show a real fault. Naming either one
        # as THE cause would be a claim the evidence does not support.
        unknown.add("process_and_network_evidence_conflict")
        return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start, window_end,
                     buckets, seen, unknown)
    if process:
        return _seal(STATUS_INCIDENT, CATEGORY_VPS_PROCESS, start, window_end,
                     buckets, seen, unknown)
    if destination:
        # v3 stores a destination as a CLASS and a port, never an identity, so
        # this evidence is named and then set aside: it can widen a verdict to
        # vps_outbound below, it cannot narrow one to a target.
        unknown.add("no_target_specific_proof")
        if len(destination) > 1:
            unknown.add("multiple_destinations")
        if not (reality or hy2 or generic_journal or generic_probe
                or shared_impact):
            return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start,
                         window_end, buckets, seen, unknown)
    if generic_journal or generic_probe:
        # Generic TCP reachability, or generic HTTPS/OTHER-protocol journal
        # errors, is BROADER than any one transport: it upgrades a
        # path-specific candidate to vps_outbound.
        if generic_probe and not generic_journal:
            # dns and https both aim at the Cloudflare leaf and egress at
            # ipify, so all three failing together is ALSO what a single
            # endpoint outage looks like. It names vps_outbound only when a
            # plane OUTSIDE the probe scheduler agrees in the same buckets:
            # a path-specific journal error, or impact on a transport's own
            # client counts. A changed egress IP is not that second plane --
            # it is the same scheduler's own row, and `changed` means ipify
            # ANSWERED, so it is network context rather than corroboration.
            if not (reality or hy2 or flags["reality_impact"]
                    or flags["hy2_impact"]):
                unknown.add("probe_endpoint_confounded")
                return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start,
                             window_end, buckets, seen, unknown)
        return _seal(STATUS_INCIDENT, CATEGORY_VPS_OUTBOUND, start,
                     window_end, buckets, seen, unknown)
    if shared_impact or (reality and hy2):
        # Both transports hurt at once, so no single transport explains it.
        # Naming the shared path needs IMPACT on both paths in these same
        # buckets and POSITIVE contemporaneous proof that the VPS's own
        # outbound probes and API view were healthy while it was happening;
        # baseline health is not admitted as that proof.
        if not shared_impact:
            unknown.add("attribution_ambiguous")
            return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start,
                         window_end, buckets, seen, unknown)
        if not (generic_healthy and api_healthy):
            unknown.add("contemporaneous_negatives_unproven")
            return _seal(STATUS_INCIDENT, CATEGORY_INSUFFICIENT, start,
                         window_end, buckets, seen, unknown)
        return _guarded(CATEGORY_COMMON_INBOUND, flags["unattributed"], seen,
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
                         and category in EMITTABLE_CATEGORIES))
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
