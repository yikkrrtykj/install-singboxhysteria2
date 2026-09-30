"""Pure incident presentation -- issue #33 Phase 5 (PR-5, #63 R2 §5).

The read-side twin of the classifier's closed vocabularies: it turns the
PERSISTED closed forms (categories, positional bitsets, marker kinds) into
operator-readable English. Everything here is presentation logic and
nothing else:

* **Pure.** No I/O, no clock, no database, no network, and no import of
  the classifier or the runtime module (the P4B single-consumer wall
  stays exactly two files wide). The vocabulary mirrors below are
  literals, equality-gated against the live classifier by the incidents
  lane -- the same no-import, duplicate-shapes discipline the history
  module uses for the journal and probe vocabularies.
* **Closed.** Every text is a frozen template keyed by a closed enum; the
  only value ever interpolated into a sentence is the unknown-token COUNT
  (an integer). No free generation, no percent/score, no "most likely"
  wording: ``root_cause_not_established`` never becomes a cause claim.
* **Windows.** The summary's ``window`` is the SIGNAL window
  (first_signal -> last_signal). The analysis window
  (analysis_start -> last_classified_end) is evidence bookkeeping and is
  never presented as incident duration.
"""

from __future__ import annotations

# -- closed marker vocabulary (#63 R2 §3) --------------------------------------

MARKER_KINDS = ("tt_live_studio_login_failed", "operator_event")

MARKER_LABELS = {
    "tt_live_studio_login_failed": "TT Live Studio login failed",
    "operator_event": "Operator-observed event",
}


def marker_label(kind):
    """The closed server label for a marker kind, or None outside it."""
    if type(kind) is not str:  # noqa: E721 -- exact type, repo discipline
        return None
    return MARKER_LABELS.get(kind)


# -- mirrored closed vocabularies (positional; equality-gated by the lane) ------

EMITTABLE_CATEGORIES = (
    "common_inbound_client_office", "hysteria2_udp_path",
    "insufficient_evidence", "reality_tcp_path", "vps_outbound",
    "vps_process_or_api")

JOURNAL_CLASSES = ("dns", "dial_timeout", "reset", "net_unreachable",
                   "tls_handshake", "quic_error", "eof_cancel", "other")
JOURNAL_AUDIT_CODES = ("sequence_gap", "exchange_bad_json",
                       "exchange_bad_name", "exchange_bad_shape",
                       "exchange_empty", "exchange_event_invalid",
                       "exchange_header_invalid",
                       "exchange_header_position", "exchange_no_header",
                       "exchange_not_regular", "exchange_seq_mismatch",
                       "exchange_too_large", "exchange_unreadable")
EVIDENCE_SECTIONS = ("samples", "device_states", "probe_rows",
                     "journal_events", "audit", "window", "health", "reader")

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
    "root_cause_not_established",
)

EVIDENCE_TOKENS = frozenset(
    BASE_EVIDENCE_TOKENS
    + tuple("journal_cls_" + name for name in JOURNAL_CLASSES)
    + tuple("journal_audit_" + code for code in JOURNAL_AUDIT_CODES))
UNKNOWN_TOKENS = frozenset(
    BASE_UNKNOWN_TOKENS
    + tuple("evidence_rejected_" + name for name in EVIDENCE_SECTIONS))

# Bit i of a stored bitset is token i of the SORTED closed vocabulary --
# exactly the classifier's own positional rule. The lane asserts this
# ordering against the live module, so a mirror cannot rot into a lie.
EVIDENCE_TOKEN_ORDER = tuple(sorted(EVIDENCE_TOKENS))
UNKNOWN_TOKEN_ORDER = tuple(sorted(UNKNOWN_TOKENS))


def bits_to_evidence(value):
    """Decode a stored evidence bitset to its sorted token tuple, or None
    when the integer is not a bitset over the frozen 45-token width."""
    if type(value) is not int or isinstance(value, bool) \
            or value < 0 or value >= (1 << len(EVIDENCE_TOKEN_ORDER)):
        return None
    return tuple(token for position, token in enumerate(EVIDENCE_TOKEN_ORDER)
                 if (value >> position) & 1)


def bits_to_unknown(value):
    """Decode a stored unknown bitset (frozen 28-token width), or None."""
    if type(value) is not int or isinstance(value, bool) \
            or value < 0 or value >= (1 << len(UNKNOWN_TOKEN_ORDER)):
        return None
    return tuple(token for position, token in enumerate(UNKNOWN_TOKEN_ORDER)
                 if (value >> position) & 1)


# -- operator-readable explanations (one per token; closed, judgment-level) -----

EVIDENCE_EXPLANATIONS = {
    "no_anomaly":
        "Analysed buckets in this window showed no anomaly signal.",
    "count_drop_total":
        "The total active-connection count fell far below its own baseline.",
    "count_drop_reality":
        "Reality active connections fell far below their baseline.",
    "count_drop_hysteria2":
        "Hysteria2 active connections fell far below their baseline.",
    "count_drop_other":
        "Other inbounds' active connections fell far below their baseline.",
    "all_devices_quiet":
        "Every observed device/inbound pair went quiet in the same buckets.",
    "journal_burst_reality":
        "Reality-classed sing-box error records spiked above their baseline.",
    "journal_burst_hysteria2":
        "Hysteria2-classed sing-box error records spiked above their baseline.",
    "journal_burst_other_generic":
        "Generic (non-protocol) sing-box error records spiked above baseline.",
    "journal_burst_destination":
        "Destination-classed sing-box error records spiked above their "
        "baseline.",
    "journal_burst_unattributed":
        "sing-box error records spiked, but their closed classes cannot be "
        "attributed to one protocol family.",
    "probe_failed_dns":
        "The server-side DNS probe failed.",
    "probe_failed_https":
        "The server-side HTTPS probe failed.",
    "probe_failed_udp":
        "The server-side UDP probe failed.",
    "probe_failed_egress":
        "The server-side public-egress probe failed.",
    "probe_source_unavailable":
        "A probe could not adjudicate its own answer, so that plane proves "
        "nothing about the network.",
    "probe_generic_tcp_healthy":
        "A generic TCP/HTTPS probe succeeded against its configured endpoint "
        "in these buckets; one successful probe does not prove general "
        "Internet reachability.",
    "egress_ip_changed":
        "The server's public egress IP changed.",
    "api_stale":
        "The sing-box service API was reported stale by the collector.",
    "collector_stale":
        "The collector marked its own snapshot stale.",
    "sample_coverage_gap":
        "Some buckets in this window hold too few samples to judge.",
    "history_degraded":
        "The evidence store reported its own degradation during this window.",
    "journal_continuity_gap":
        "The journal ingest recorded a sequence gap.",
    "journal_rejected_batch":
        "A journal batch was terminally rejected by the ingest contract.",
    "journal_cls_dns":
        "sing-box error records of the DNS class were present.",
    "journal_cls_dial_timeout":
        "sing-box dial-timeout error records were present.",
    "journal_cls_reset":
        "sing-box connection-reset error records were present.",
    "journal_cls_net_unreachable":
        "sing-box network-unreachable error records were present.",
    "journal_cls_tls_handshake":
        "sing-box TLS-handshake error records were present.",
    "journal_cls_quic_error":
        "sing-box QUIC-class error records were present.",
    "journal_cls_eof_cancel":
        "sing-box EOF/cancellation error records were present.",
    "journal_cls_other":
        "sing-box error records outside the named classes were present.",
    "journal_audit_sequence_gap":
        "The journal ingest audit recorded a missing sequence interval.",
    "journal_audit_exchange_bad_json":
        "The journal ingest rejected a reader file (invalid JSON).",
    "journal_audit_exchange_bad_name":
        "The journal ingest rejected a reader file (invalid file name).",
    "journal_audit_exchange_bad_shape":
        "The journal ingest rejected a reader file (invalid shape).",
    "journal_audit_exchange_empty":
        "The journal ingest rejected an empty reader file.",
    "journal_audit_exchange_event_invalid":
        "The journal ingest rejected a reader file (an event failed validation).",
    "journal_audit_exchange_header_invalid":
        "The journal ingest rejected a reader file (invalid header).",
    "journal_audit_exchange_header_position":
        "The journal ingest rejected a reader file (misplaced header).",
    "journal_audit_exchange_no_header":
        "The journal ingest rejected a reader file (no header).",
    "journal_audit_exchange_not_regular":
        "The journal ingest refused a non-regular reader file.",
    "journal_audit_exchange_seq_mismatch":
        "The journal ingest rejected a reader file (sequence mismatch).",
    "journal_audit_exchange_too_large":
        "The journal ingest rejected an oversized reader file.",
    "journal_audit_exchange_unreadable":
        "The journal ingest could not read a reader file.",
}

UNKNOWN_EXPLANATIONS = {
    "no_corroboration":
        "No independent evidence family corroborated the anomaly.",
    "count_drop_only":
        "The only signal was a connection-count drop, which alone cannot "
        "name a fault domain.",
    "attribution_ambiguous":
        "The evidence points in more than one direction; no single "
        "attribution is supported.",
    "baseline_evidence_absent":
        "There is not enough baseline evidence to judge the anomaly against.",
    "transport_negatives_unproven":
        "The evidence cannot prove transport-level causes were absent.",
    "contemporaneous_negatives_unproven":
        "Negative checks were not proven in the same buckets as the anomaly.",
    "probe_evidence_absent":
        "No probe evidence covers this window.",
    "probe_evidence_unusable":
        "Probe evidence exists but cannot adjudicate this window.",
    "probe_endpoint_confounded":
        "The probes share external endpoints, so one endpoint outage can "
        "look like a VPS outbound failure.",
    "multiple_anomaly_clusters":
        "The window holds more than one separated anomaly episode; no single "
        "verdict can describe both.",
    "journal_evidence_absent":
        "No journal evidence covers this window.",
    "journal_evidence_incomplete":
        "Journal evidence covers this window only partially.",
    "no_target_specific_proof":
        "No evidence can single out one specific destination.",
    "multiple_destinations":
        "Errors span several destination classes, so no single destination "
        "fits.",
    "process_and_network_evidence_conflict":
        "Process and network evidence disagree; neither attribution is "
        "supported.",
    "device_states_are_change_only":
        "Device rows in this window are ordinary change records, not "
        "failure proof.",
    "unattributed_evidence_present":
        "Evidence is present that no closed rule can attribute.",
    "evidence_shape_rejected":
        "The evidence bundle was malformed and was refused.",
    "evidence_outside_window":
        "Evidence outside the analysed window was refused.",
    "root_cause_not_established":
        "The evidence says where it hurt, not why; the root cause is not "
        "established.",
    "evidence_rejected_samples":
        "The samples section of the evidence was refused.",
    "evidence_rejected_device_states":
        "The device-states section of the evidence was refused.",
    "evidence_rejected_probe_rows":
        "The probe-rows section of the evidence was refused.",
    "evidence_rejected_journal_events":
        "The journal-events section of the evidence was refused.",
    "evidence_rejected_audit":
        "The ingest-audit section of the evidence was refused.",
    "evidence_rejected_window":
        "The evidence window itself was unusable.",
    "evidence_rejected_health":
        "The evidence health section was refused.",
    "evidence_rejected_reader":
        "The evidence reader-freshness section was refused.",
}


def evidence_texts(tokens):
    """[{"token", "text"}] for a decoded evidence tuple; a token without a
    frozen explanation is a presentation defect and is DROPPED, never
    paraphrased (the lane pins the explanation table to full coverage)."""
    out = []
    for token in tokens or ():
        text = EVIDENCE_EXPLANATIONS.get(token)
        if text is not None:
            out.append({"token": token, "text": text})
    return out


def unknown_texts(tokens):
    """[{"token", "text"}] for a decoded unknown tuple (same discipline)."""
    out = []
    for token in tokens or ():
        text = UNKNOWN_EXPLANATIONS.get(token)
        if text is not None:
            out.append({"token": token, "text": text})
    return out


# -- category presentation contract (#63 R2 §6) ---------------------------------

CATEGORY_LABELS = {
    "reality_tcp_path": "Reality/TCP path",
    "hysteria2_udp_path": "Hysteria2/UDP path",
    "vps_outbound": "VPS outbound",
    "vps_process_or_api": "sing-box process / API",
    "common_inbound_client_office": "Common inbound / client-office",
    "insufficient_evidence": "Insufficient evidence",
}

# The per-category L1 templates. Every field is a frozen sentence; the
# conditional wording of the two protocol actions and the explicit
# can't-distinguish wording of the common-path action are reviewer-frozen
# (#63 R2 §6), and insufficient_evidence carries NO action at all.
_SUMMARY_TABLE = {
    "reality_tcp_path": {
        "headline": "Reality/TCP path incident",
        "impact": "Reality traffic degraded during the signal window.",
        "protocol_state": "Assessed fault domain: the Reality/TCP path. "
                          "This evidence does not prove Hysteria2 was healthy.",
        "server_state": "No evidence in this window attributes the fault to "
                        "the sing-box process or its control API.",
        "affected_scope": "Server-side evidence cannot tell which clients or "
                          "networks were affected.",
        "assessment": "The evidence-based fault domain is the Reality/TCP path.",
        "recommended_action": "If Hysteria2 is independently confirmed "
                              "healthy, prefer it while the Reality/TCP path "
                              "is investigated.",
    },
    "hysteria2_udp_path": {
        "headline": "Hysteria2/UDP path incident",
        "impact": "Hysteria2 traffic degraded during the signal window.",
        "protocol_state": "Assessed fault domain: the Hysteria2/UDP path. "
                          "This evidence does not prove Reality was healthy.",
        "server_state": "No evidence in this window attributes the fault to "
                        "the sing-box process or its control API.",
        "affected_scope": "Server-side evidence cannot tell which clients or "
                          "networks were affected.",
        "assessment": "The evidence-based fault domain is the Hysteria2/UDP "
                      "path.",
        "recommended_action": "If Reality is independently confirmed healthy, "
                              "prefer it while the Hysteria2/UDP path is "
                              "investigated.",
    },
    "vps_outbound": {
        "headline": "VPS outbound connectivity incident",
        "impact": "The server lost reachability to parts of the internet "
                  "during the signal window.",
        "protocol_state": "Assessed fault domain: VPS outbound connectivity "
                          "(DNS/HTTPS/UDP/egress), upstream of both proxy "
                          "protocols.",
        "server_state": "No evidence in this window attributes the fault to "
                        "the sing-box process or its control API.",
        "affected_scope": "Server-side evidence cannot tell which clients or "
                          "networks were affected.",
        "assessment": "The evidence-based fault domain is VPS outbound "
                      "connectivity.",
        "recommended_action": "Inspect the outbound DNS/HTTPS/UDP probe rows "
                              "below and the public-egress context; if the "
                              "egress IP changed, check the provider network "
                              "state before changing sing-box.",
    },
    "vps_process_or_api": {
        "headline": "sing-box process / control API incident",
        "impact": "The sing-box process or its service API showed failure "
                  "evidence during the signal window.",
        "protocol_state": "Assessed fault domain: the control plane and "
                          "process health, not one proxy path.",
        "server_state": "This window was attributed to the sing-box process / "
                        "service API domain.",
        "affected_scope": "Server-side evidence cannot tell which clients or "
                          "networks were affected.",
        "assessment": "The evidence-based fault domain is the sing-box "
                      "process / service API.",
        "recommended_action": "Inspect the process and control-API evidence "
                              "below (API status, connection counts, error "
                              "classes). Do not assume a restart without "
                              "restart evidence.",
    },
    "common_inbound_client_office": {
        "headline": "Common inbound / client-office path incident",
        "impact": "The shared inbound path observed for the clients showed "
                  "failure evidence during the signal window.",
        "protocol_state": "Assessed fault domain: the common inbound / "
                          "client-office domain shared by the affected paths.",
        "server_state": "No evidence in this window attributes the fault to "
                        "the sing-box process or its control API.",
        "affected_scope": "Server-side evidence cannot tell which clients or "
                          "networks were affected.",
        "assessment": "The evidence-based fault domain is the common inbound "
                      "/ client-office path.",
        "recommended_action": "Inspect the shared-domain evidence below. The "
                              "current evidence cannot distinguish which "
                              "component of that domain caused this window.",
    },
    "insufficient_evidence": {
        "headline": "Unclassified incident window (insufficient evidence)",
        "impact": "An anomaly window was recorded, but the retained evidence "
                  "cannot say what it affected.",
        "protocol_state": "No protocol or path attribution is supported by "
                          "this evidence.",
        "server_state": "No server-side fault can be claimed or excluded from "
                        "this evidence.",
        "affected_scope": "Server-side evidence cannot tell which clients or "
                          "networks were affected.",
        "assessment": "The evidence supports no fault domain: insufficient "
                      "evidence.",
        "recommended_action": None,
    },
}

# Shared, frozen: what this presentation can NEVER claim. The store holds
# only SPARSE device state (change/heartbeat rows), so it cannot
# authoritatively determine which logical clients were affected, and it
# holds no ISP ownership/path mapping; no process-restart or
# resource-exhaustion history is persisted either (the P4A/P4B evidence
# plane carries no PID/NRestarts/FD/conntrack series), and no specific
# destination can be named.
_LIMITATIONS = ("Correlation is not causation: the root cause is not "
                "established. Server-side sparse device state cannot "
                "authoritatively determine which logical clients were "
                "affected, and it cannot infer ISP ownership or path "
                "identity; nor does it name a specific destination. No "
                "process-restart or resource-exhaustion history is "
                "recorded that could support such a claim.")

SUMMARY_KEYS = ("headline", "window", "impact", "protocol_state",
                "server_state", "affected_scope", "assessment",
                "recommended_action", "uncertainty", "limitations")


def summarize(incident, unknown_tokens):
    """The deterministic L1 summary over ONE persisted incident row.

    ``incident`` is the closed INCIDENT_WINDOW_COLUMNS dict; the summary
    window is the SIGNAL window (first_signal -> last_signal), never the
    analysis window. The only interpolation anywhere in L1 is the
    unknown-token count. Unknown category/state is refused (None), never
    invented."""
    if not isinstance(incident, dict):
        return None
    category = incident.get("category")
    template = _SUMMARY_TABLE.get(category) if category is not None else None
    if template is None:
        return None
    first = incident.get("first_signal_epoch")
    last = incident.get("last_signal_epoch")
    if type(first) not in (int, float) or type(last) not in (int, float) \
            or last < first:  # noqa: E721 -- exact types, repo discipline
        return None
    count = len(tuple(unknown_tokens or ()))
    if count == 0:
        uncertainty = "No open questions were recorded for this verdict."
    elif count == 1:
        uncertainty = "The evidence records 1 open question; see the reasons " \
                      "below."
    else:
        uncertainty = ("The evidence records %d open questions; see the "
                       "reasons below." % count)
    return {
        "headline": template["headline"],
        "window": {
            "start_epoch": first,
            "end_epoch": last,
            "duration_seconds": last - first,
        },
        "impact": template["impact"],
        "protocol_state": template["protocol_state"],
        "server_state": template["server_state"],
        "affected_scope": template["affected_scope"],
        "assessment": template["assessment"],
        "recommended_action": template["recommended_action"],
        "uncertainty": uncertainty,
        "limitations": _LIMITATIONS,
    }
