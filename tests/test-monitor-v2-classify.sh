#!/usr/bin/env bash
# Monitor 0.4.x -- PR-4A deterministic incident classifier (issue #33
# Phase 4) suite.
#
# PR-1 to PR-3B made evidence durable: samples, device states, journal
# events and probe results are all in one schema-v3 store now. PR-4A is the
# first phase that READS that evidence and answers a question -- and the
# answer is only worth having if it is honest. This lane owns the four
# properties the review contract demands proof of, in the order a reviewer
# should check them:
#
#   1. A SINGLE REVIEWED CONSUMER. The classifier is still a pure function,
#      but PR-4B wires it into the runtime through exactly one reviewed
#      consumer: web/incident_runtime.py (the IncidentScanner). The darkness
#      gate becomes a closed allowlist pinning that single file -- no second
#      consumer, no other surface: no route, schema, deploy, systemd,
#      scheduler or collector path may reference the module, and the shipped
#      VERSION / MONITOR_WEB_VERSION / SCHEMA_VERSION are exactly the values
#      this PR froze. The lane proves the wiring is exactly the reviewed
#      wiring rather than trusting a promise.
#   2. A CLOSED VOCABULARY, PINNED AS LITERALS HERE. Seven categories, three
#      statuses, forty-five evidence tokens, twenty-eight unknown tokens, the
#      six categories the sealing wall actually admits, and the two halves of
#      the probe failure split. They are re-stated in this shell file -- a
#      second, independent witness -- because a contract only the module and
#      its own test agree on is not a contract: renaming a token to make a
#      scenario pass has to break two files written by different hands.
#   3. THE COMMITTED FIXTURES DECIDE CORRECTLY *AND MOVE*. A fixture that
#      always classified the same way regardless of its content would satisfy
#      a naive expectation gate forever, so the lane mutates the Reality
#      fixture four ways and requires four different, named answers: the
#      Reality/Hysteria2 swap must follow the evidence, deleting the journal
#      burst must collapse the incident into a count-drop refusal, adding
#      generic OTHER-over-443 evidence must upgrade to vps_outbound, and
#      withdrawing the proof of the negatives must refuse attribution. That
#      is the spec's own set of discriminations, run against the files that
#      ship.
#   4. BEHAVIOUR, at scale, in tests/monitor-classify/classify_groups.py:
#      vocabulary mirrors asserted against the LIVE store module and the live
#      probe engine, a 43-scenario decision table whose rows are the review
#      counterexamples (an unreachable destination category, degraded
#      diagnostics that proves nothing, a probe code that is not a network
#      fact, one endpoint outage posing as an outbound failure, impact read
#      per transport, a device table keyed per (device, inbound) that cannot
#      grant impact at all, contemporaneous negatives, two episodes in one
#      window),
#      nineteen hostile refusals, determinism/purity/closure invariants, a
#      privacy wall that feeds real sentinel material through every section,
#      and a group that builds a REAL schema-v4 database, reads the rows back
#      out of SQLite and classifies those.
#
# Everything here is pure Python over a pure-stdlib module: no network, no
# privileges, no gate that needs Linux. The dev host and CI must therefore
# agree exactly, and the hard count below is the proof that they did.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export CLASSIFY_FIXTURE_DIR="$HERE/monitor-classify/fixtures"

PASS=0
FAIL=0
# PR-4A round 4 -- 665 checks, measured on the dev host and to be re-measured
# on Linux CI. The move from 582 is gates that were written, never a count that
# was waved through, and the breakdown is part of the record:
# PR-4B adds exactly 5 checks, all inside S3's invariants group, and nothing
# previously counted moved (665 -> 670): detect_matches_classify_everywhere,
# detection_metadata_tracks_incidence, detection_epochs_are_bucket_arithmetic,
# detect_never_raises_on_hostile_input, detect_mutates_no_input. They pin the
# PR-4B contract that detect() is classify() plus pure bucket-position
# metadata over the SAME single analysis path.
#   S0 static + darkness gates              13   unchanged in count; gate (3)
#        is PR-4B's intentional DARK-gate rework -- the zero-importer demand
#        is now a closed single-consumer allowlist naming web/incident_runtime.py
#        -- and gate (6) is PR-4B-restated: the live store now builds the ten
#        v4 tables (the eight v3 evidence tables plus the two incident tables)
#        and pins SCHEMA_VERSION == 4. The 0.5.0 VERSION pins are PR-4B's own,
#        the same single-consumer allowlist is pinned again in the packaging
#        lane, and the release this lane guards is Monitor 0.5.0 on history
#        schema v4.
#   S1 closed vocabulary, pinned literal    12   unchanged in count, but two
#        of those literals moved: the unknown vocabulary gained
#        device_states_are_change_only (27 -> 28) and the probe failure split
#        moved tls_failed and protocol_failed across the wall. Both are
#        round-4 semantics restated outside the module on purpose.
#   S2 committed fixtures decide and move   17   (+8, every one of them a
#        window the PRE-round-4 module answers differently: a genuinely quiet
#        per-(device, inbound) table that must name no impact; one device's
#        other inbound holding clients, which must make the table NOT quiet;
#        the same rows traversed in the opposite order, answering identically;
#        a pair answering 3 and 0 at ONE epoch, pinned in BOTH arrival orders
#        because the reader promises none and the tie must not be decided by
#        whichever row happened to be written last; tls_failed and
#        protocol_failed on the generic slots, once each; and a probe outage
#        whose only extra witness is a changed egress address)
#   S3 behaviour groups (classify_groups)  628   (623 + 5 PR-4B detect()
#        invariants, documented above); mirrors 24 (+0: two existing
#        gates were strengthened, and engine_probe_codes_agree now reads the
#        engine's OWN ssl/http/UDP mapping instead of trusting this file's
#        prose), scenarios 419 (+75: 36 rows became 43 -- four device-table
#        windows, the reversed-order disagreement that makes the tie-break
#        direction live in both directions, and the two moved probe codes,
#        each with its control),
#        hostiles 116 unchanged, invariants 16 -> 21 (PR-4B: the five detect()
#        invariants documented above), privacy 7, store 25,
#        fixtures 14, plus the harness rc and the fixtures-unchanged proof
EXPECTED_PASS=670
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
map_verdicts() { # <file> -> count every PASS/FAIL verdict line it holds
    while IFS= read -r line; do
        case "$line" in
            PASS\ *) pass "${line#PASS }" ;;
            FAIL\ *) fail "${line#FAIL }" ;;
            *) [ -n "$line" ] && printf '  ? %s\n' "$line" ;;
        esac
    done < "$1"
}

if [ -z "$PY" ]; then
    printf '  python3 unavailable -- this suite is a hard gate on CI\n'
    printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$((FAIL + 1))"
    exit 1
fi

CLASSIFIER="$ROOT/monitor-v2/web/incident_classifier.py"
HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
SERVER_PY="$ROOT/monitor-v2/web/server.py"
WEBAPP="$ROOT/monitor-v2/webapp.py"
COLLECTOR="$ROOT/monitor-v2/collector.py"
HARNESS="$HERE/monitor-classify/classify_groups.py"
FIX_REAL="$CLASSIFY_FIXTURE_DIR/incident-reality-outage.json"
FIX_NORMAL="$CLASSIFY_FIXTURE_DIR/incident-normal-background.json"
WORKFLOW="$ROOT/.github/workflows/tests.yml"
# Every shipped module the classifier may be wired through, checked by name
# before it is grepped: a missing file would turn a "no reference found"
# into a vacuous pass.
for surface in "$SERVER_PY" "$WEBAPP" "$HIST_PY" "$COLLECTOR"; do
    [ -f "$surface" ] || fail "surface file missing: $surface"
done

section "S0: static + darkness gates"

if "$PY" -m py_compile "$CLASSIFIER" "$HIST_PY" "$SERVER_PY" "$WEBAPP" \
    "$HARNESS" 2>"$TMP/py.err"; then
    pass "py_compile: classifier + history + server + webapp + harness"
else
    fail "py_compile: $(cat "$TMP/py.err")"
fi

# (1) The classifier's whole dependency set is two stdlib modules. This is
# the import list, not a grep: a comment may name a module, an `import`
# statement may not.
if "$PY" - "$CLASSIFIER" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
imports = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        imports.update(alias.name for alias in node.names)
    elif isinstance(node, ast.ImportFrom):
        imports.add(node.module or "")
assert imports == {"__future__", "dataclasses"}, \
    "classifier imports %r" % (sorted(imports),)
EOF
then
    pass "the classifier imports nothing but __future__ and dataclasses"
else
    fail "the classifier grew a dependency"
fi

# (2) Purity is a call-site property, so the AST judges call sites. open()
# stands for every kind of I/O -- a clock reading, a socket, a database
# handle all have to be reached through a name this list covers -- and the
# reflection primitives are listed because a classifier that can name an
# attribute at runtime can also read a column the contract forbids.
if "$PY" - "$CLASSIFIER" <<'EOF'
import ast, sys
FORBIDDEN = {"open", "print", "eval", "exec", "input", "__import__",
             "globals", "locals", "vars", "dir", "getattr", "setattr",
             "delattr", "exit", "quit", "breakpoint",
             "now", "today", "utcnow", "monotonic", "time", "sleep"}
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
hits = []
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        name = getattr(node.func, "id", None) or getattr(node.func, "attr",
                                                          None)
        if name in FORBIDDEN:
            hits.append((node.lineno, name))
assert not hits, "impure call sites: %r" % (hits,)
EOF
then
    pass "the classifier has no I/O, clock, reflection or output call site"
else
    fail "the classifier is no longer a pure function"
fi

# (3) PR-4B ends the darkness with EXACTLY ONE reviewed runtime consumer:
# web/incident_runtime.py (the IncidentScanner). The proof is still a search
# of the whole shipped tree for the module name -- but the assertion is now
# a closed allowlist pinning that single file, not a demand for zero
# importers: a second consumer, or a different one, breaks the single-
# consumer contract exactly as surely as an unreviewed first one would.
IMPORTERS="$(grep -rl 'incident_classifier' --include='*.py' \
    "$ROOT/monitor-v2" 2>/dev/null | grep -v 'web/incident_classifier.py' || true)"
assert_eq "$ROOT/monitor-v2/web/incident_runtime.py" "$IMPORTERS" \
    "exactly one runtime consumer imports the classifier: web/incident_runtime.py (closed allowlist)"
if grep -q 'incident_classif' "$SERVER_PY" "$WEBAPP" "$HIST_PY" "$COLLECTOR"; then
    fail "a server, webapp, history or collector surface names the classifier"
else
    pass "no route, status surface, store or collector path references it"
fi
# (4) The classifier reads the store's SHAPES, never the store: one SQL
# keyword anywhere in the file would mean a second, unbudgeted read path.
if grep -qiE 'sqlite|SELECT |INSERT |CREATE TABLE|executescript' "$CLASSIFIER"; then
    fail "the classifier contains a storage or SQL reference"
else
    pass "the classifier is a function over projections, not a reader"
fi
if grep -rq 'incident_classif' "$ROOT/monitor-v2/deploy" 2>/dev/null; then
    fail "a deploy surface references the classifier"
else
    pass "deploy/ is untouched by PR-4A"
fi
# (5) The frozen release identity this PR ships. PR-4B lands the incident
# runtime, so the release it guards is Monitor 0.8.0 on history schema v5.
assert_eq '0.8.0' "$(cat "$ROOT/monitor-v2/VERSION")" \
    "VERSION is 0.8.0 (the incident remote-evidence release)"
if grep -q 'MONITOR_WEB_VERSION = "0.8.0"' "$SERVER_PY"; then
    pass "MONITOR_WEB_VERSION is 0.8.0"
else
    fail "MONITOR_WEB_VERSION moved off 0.8.0"
fi
# (6) Not a declaration check but a live one: build the database the module
# actually creates and name the tables it actually made. PR-4B migrates the
# store to v4, so the classifier now sees ten tables: the eight v3 evidence
# tables it was written against -- still the whole vocabulary it may name,
# still with no per-edge, Reality-target or net-counter table -- plus the two
# incident tables the incident plane owns. The classifier still never reads
# the new tables: gate (4) proves there is no SQL in the file, and PR-4B's
# packaging gate pins exactly one runtime consumer for the module.
if "$PY" - <<'EOF'
import os, shutil, sqlite3, sys, tempfile
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
import web.incident_history as ih
assert ih.SCHEMA_VERSION == 5, "the schema moved off v5: PR-5 owns v5"
root = tempfile.mkdtemp()
h = ih.IncidentHistory(os.path.join(root, "diagnostics"), "c" * 32,
                       monitor_version="classify-lane")
h.open()
assert h.health()["enabled"], h.health()
h.close()
made = {row[0] for row in sqlite3.connect(
    os.path.join(root, "diagnostics", "history.sqlite3")).execute(
    "SELECT name FROM sqlite_master WHERE type='table'")}
assert made == {"meta", "timeline_samples", "device_protocol_states",
                "journal_runs", "journal_events", "journal_ingest_audit",
                "journal_ingest_state", "network_probe_samples",
                "incident_windows", "incident_runtime_state",
                "operator_markers"}, \
    "the live store created %r" % (sorted(made),)
shutil.rmtree(root, ignore_errors=True)
EOF
then
    pass "a live store builds exactly the eleven v5 tables (eight evidence + two incident + markers)"
else
    fail "the live store shape differs from the one the classifier mirrors"
fi
# (6a) The whole closed-surface claim rests on the output type having nowhere
# to put a sentence, an address or a device. PR-4A may not add a field either,
# because a widened result is a widened contract -- so the field list is
# pinned HERE, next to the darkness gates that keep the module uncalled.
if "$PY" - <<'EOF'
import os, sys
from dataclasses import fields
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
names = [f.name for f in fields(cl.Classification)]
assert names == ["version", "status", "category", "window_start",
                 "window_end", "buckets", "evidence", "unknowns"], names
assert cl.Classification.__dataclass_params__.frozen,     "the result object became mutable"
EOF
then
    pass "the result surface has nowhere to put an identity, address or sentence"
else
    fail "PR-4A widened the closed result surface"
fi
# (7) CI registration: a lane that is not run is a lane that is green.
if grep -q 'bash -n tests/test-monitor-v2-classify.sh' "$WORKFLOW" \
    && grep -q 'bash tests/test-monitor-v2-classify.sh' "$WORKFLOW"; then
    pass "suite is registered in CI (bash -n + monitor-regression)"
else
    fail "suite is NOT registered in tests.yml"
fi
# (8) The fixtures are committed artefacts with real content, not stubs the
# harness could regenerate: if they were thin, every expectation gate above
# would be testing a toy.
if [ -s "$FIX_REAL" ] && [ -s "$FIX_NORMAL" ] \
    && "$PY" - "$FIX_REAL" "$FIX_NORMAL" <<'EOF'
import json, os, sys
for path in sys.argv[1:]:
    obj = json.load(open(path, encoding="utf-8"))
    assert sorted(obj) == sorted(["window", "samples", "device_states",
                                  "probe_rows", "journal_events", "audit",
                                  "health", "reader"]), sorted(obj)
    assert len(obj["samples"]) >= 100 and len(obj["journal_events"]) >= 40
    assert len(obj["probe_rows"]) >= 10 and len(obj["device_states"]) >= 15
    assert len(open(path, encoding="utf-8").read()) > 40000
EOF
then
    pass "both fixtures are committed, full-sectioned and non-trivial"
else
    fail "a committed fixture is missing, thin or wrongly shaped"
fi

section "S1: the closed vocabulary is pinned as literals"

# The lists below are the contract, re-stated in the language a reviewer
# reads. A token that only exists inside the module is a token that can be
# renamed in one file.
"$PY" - >"$TMP/vocab.out" 2>"$TMP/vocab.err" <<'EOF'
import os
import re
import sys
from dataclasses import fields

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl

CATEGORIES = ["common_inbound_client_office", "destination_specific",
              "hysteria2_udp_path", "insufficient_evidence",
              "reality_tcp_path", "vps_outbound", "vps_process_or_api"]
STATUSES = ["incident", "indeterminate", "no_incident"]
EVIDENCE = """
all_devices_quiet api_stale collector_stale count_drop_hysteria2
count_drop_other count_drop_reality count_drop_total egress_ip_changed
history_degraded journal_audit_exchange_bad_json
journal_audit_exchange_bad_name journal_audit_exchange_bad_shape
journal_audit_exchange_empty journal_audit_exchange_event_invalid
journal_audit_exchange_header_invalid journal_audit_exchange_header_position
journal_audit_exchange_no_header journal_audit_exchange_not_regular
journal_audit_exchange_seq_mismatch journal_audit_exchange_too_large
journal_audit_exchange_unreadable journal_audit_sequence_gap
journal_burst_destination journal_burst_hysteria2
journal_burst_other_generic journal_burst_reality journal_burst_unattributed
journal_cls_dial_timeout journal_cls_dns journal_cls_eof_cancel
journal_cls_net_unreachable journal_cls_other journal_cls_quic_error
journal_cls_reset journal_cls_tls_handshake journal_continuity_gap
journal_rejected_batch no_anomaly probe_failed_dns probe_failed_egress
probe_failed_https probe_failed_udp probe_generic_tcp_healthy
probe_source_unavailable sample_coverage_gap""".split()
UNKNOWNS = """
attribution_ambiguous baseline_evidence_absent
contemporaneous_negatives_unproven count_drop_only
device_states_are_change_only
evidence_outside_window evidence_rejected_audit
evidence_rejected_device_states evidence_rejected_health
evidence_rejected_journal_events evidence_rejected_probe_rows
evidence_rejected_reader evidence_rejected_samples evidence_rejected_window
evidence_shape_rejected journal_evidence_absent journal_evidence_incomplete
multiple_anomaly_clusters
multiple_destinations no_corroboration no_target_specific_proof
probe_endpoint_confounded probe_evidence_absent probe_evidence_unusable
process_and_network_evidence_conflict
root_cause_not_established transport_negatives_unproven
unattributed_evidence_present""".split()


def verdict(name, ok):
    print("%s vocab/%s" % ("PASS" if ok else "FAIL", name))


verdict("categories_are_the_reviewed_seven",
        sorted(cl.CATEGORIES) == CATEGORIES and len(cl.CATEGORIES) == 7)
verdict("none_is_a_status_value_not_a_cause",
        cl.CATEGORY_NONE == "NONE" and cl.CATEGORY_NONE not in cl.CATEGORIES
        and cl.CATEGORY_INSUFFICIENT in cl.CATEGORIES)
verdict("statuses_are_the_closed_three", sorted(cl.STATUSES) == STATUSES)
verdict("evidence_tokens_are_the_pinned_forty_five",
        sorted(cl.EVIDENCE_TOKENS) == sorted(EVIDENCE)
        and len(cl.EVIDENCE_TOKENS) == 45)
verdict("unknown_tokens_are_the_pinned_twenty_eight",
        sorted(cl.UNKNOWN_TOKENS) == sorted(UNKNOWNS)
        and len(cl.UNKNOWN_TOKENS) == 28)
# The two planes must not overlap: a token that is both an observation and a
# denial would let one string mean two things in the same report.
verdict("the_two_vocabularies_are_disjoint",
        not (set(cl.EVIDENCE_TOKENS) & set(cl.UNKNOWN_TOKENS)))
# The result object is closed: a future field would have to be added to this
# list too, which is the point -- an identity column cannot arrive quietly.
verdict("result_surface_is_closed_and_typed",
        [f.name for f in fields(cl.Classification)]
        == ["version", "status", "category", "window_start", "window_end",
            "buckets", "evidence", "unknowns"])
# Snake-case-only ascii, bounded in length: the tokens reach a UI one day,
# and a token that looks like a sentence is where a root cause starts being
# invented.
verdict("every_token_is_a_bare_snake_case_identifier",
        all(re.fullmatch(r"[a-z][a-z0-9_]*", t) and len(t) <= 44
            for t in list(cl.EVIDENCE_TOKENS) + list(cl.UNKNOWN_TOKENS)))
# The two standing refusals the review contract is about: an incident is
# never a cause, and a destination is never a guess.
verdict("correlation_is_never_reported_as_causation",
        "root_cause_not_established" in cl.UNKNOWN_TOKENS
        and "no_target_specific_proof" in cl.UNKNOWN_TOKENS
        and cl.CATEGORY_DESTINATION in cl.CATEGORIES)
# Two of those sentences are mechanisms, not promises. Schema v3 projects a
# destination as (dcls, port) -- a class and a port, never an identity -- so
# the list the sealing wall admits is the reviewed seven WITHOUT
# destination_specific, and a category outside it cannot leave a result. A
# 'failed' probe slot is either a fact about the network or the absence of a
# witness, and only the first may speak for the path. The engine is the
# authority on which is which: it maps ANY ssl.SSLError -- a certificate
# refusal included -- to tls_failed, and an http.client.HTTPException or a UDP
# reply that is too short, has the wrong id or answers somebody else's question
# to protocol_failed. Both are the probe failing to adjudicate an answer, so
# they sit on the source side of this wall with bad_response and parse_failed.
EMITTABLE = ["common_inbound_client_office", "hysteria2_udp_path",
             "insufficient_evidence", "reality_tcp_path", "vps_outbound",
             "vps_process_or_api"]
NETWORK_CODES = ["connect_failed", "dns_failed", "timeout"]
SOURCE_CODES = ["bad_response", "parse_failed", "protocol_failed",
                "tls_failed", "unavailable"]
verdict("the_unemittable_category_is_pinned_out_of_the_answer",
        sorted(cl.EMITTABLE_CATEGORIES) == EMITTABLE
        and set(cl.CATEGORIES) - set(cl.EMITTABLE_CATEGORIES)
        == set([cl.CATEGORY_DESTINATION]))
verdict("probe_failure_codes_are_split_by_what_they_prove",
        sorted(cl.PROBE_NETWORK_CODES) == NETWORK_CODES
        and sorted(cl.PROBE_SOURCE_CODES) == SOURCE_CODES
        and set(cl.PROBE_NETWORK_CODES) | set(cl.PROBE_SOURCE_CODES)
        | set(["NONE"]) == set(cl.PROBE_ERROR_CODES))
# The store's identity-bearing columns. This is the PR-1 privacy rule
# re-stated where the classifier can read it: "not read" is a property of the
# code, and this is the list the code is checked against by the harness's own
# AST gate. Exactly one of these names may appear in an accepted field list
# at all -- `device`, as an opaque counting key and nothing else -- and none
# of them may ever reach the result surface. The device field list carries one
# more key than that one: `inbound`, because (device, inbound, epoch) is the
# key the table is really built on. It is not an identity column, it is read
# for nothing but grouping, and the sentinel below proves it cannot be echoed.
IDENTITY_COLUMNS = ["iso_utc", "run_id", "device", "egress_ip", "fp",
                    "cycle_id", "snapshot_generated_at", "last_success_at"]
READ_FIELDS = (set(cl.SAMPLE_FIELDS) | set(cl.DEVICE_FIELDS)
               | set(cl.PROBE_FIELDS) | set(cl.JOURNAL_FIELDS)
               | set(cl.AUDIT_FIELDS))
verdict("identity_bearing_names_are_a_closed_tuple",
        sorted(IDENTITY_COLUMNS) == [
            "cycle_id", "device", "egress_ip", "fp", "iso_utc",
            "last_success_at", "run_id", "snapshot_generated_at"]
        and set(IDENTITY_COLUMNS) & READ_FIELDS == {"device"}
        and cl.DEVICE_FIELDS == ("epoch", "device", "inbound",
                                 "active_connections", "reason")
        and not set(IDENTITY_COLUMNS) & (set(cl.EVIDENCE_TOKENS)
                                         | set(cl.UNKNOWN_TOKENS)))
EOF
if [ -s "$TMP/vocab.err" ]; then
    fail "the vocabulary probe crashed: $(cat "$TMP/vocab.err")"
fi
map_verdicts "$TMP/vocab.out"

section "S2: the committed fixtures decide correctly -- and move"

# (1) The anchor: the 2026-09-22 shape. Reality dial timeouts on 443 while
# Hysteria2 clients stay up and the VPS's own outbound is healthy.
if "$PY" - "$FIX_REAL" <<'EOF'
import json, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
r = cl.classify(json.load(open(sys.argv[1], encoding="utf-8")))
assert r.status == "incident", r.status
assert r.category == "reality_tcp_path", r.category
assert {"count_drop_reality", "journal_burst_reality",
        "probe_generic_tcp_healthy"} <= set(r.evidence), r.evidence
assert "journal_burst_hysteria2" not in r.evidence, r.evidence
assert "root_cause_not_established" in r.unknowns, r.unknowns
EOF
then
    pass "the Reality fixture answers reality_tcp_path, sealed as non-causal"
else
    fail "the Reality fixture no longer answers reality_tcp_path"
fi

# (2) The negative control: the same background noise, nothing dropping.
if "$PY" - "$FIX_NORMAL" <<'EOF'
import json, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
r = cl.classify(json.load(open(sys.argv[1], encoding="utf-8")))
assert r.status == "no_incident", r.status
assert r.category == "NONE", r.category
assert "no_anomaly" in r.evidence, r.evidence
assert {"journal_cls_eof_cancel", "journal_cls_reset"} <= set(r.evidence)
assert not set(r.evidence) & {"journal_burst_reality",
                              "journal_burst_hysteria2",
                              "journal_burst_other_generic",
                              "journal_burst_destination"}, r.evidence
EOF
then
    pass "the normal-background control stays quiet despite the noise floor"
else
    fail "the negative control reports an incident"
fi

# (3) Determinism on the committed artefacts, including under reordering.
# Three repeats and one shuffled pass must hash identically.
STABLE="$("$PY" - "$FIX_REAL" "$FIX_NORMAL" <<'EOF'
import hashlib, json, os, random, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl

def line(obj):
    return json.dumps(cl.classify(obj).to_dict(), sort_keys=True)

runs = []
for _ in range(3):
    runs.append("".join(line(json.load(open(p, encoding="utf-8")))
                        for p in sys.argv[1:]))
shuffled = []
for path in sys.argv[1:]:
    obj = json.load(open(path, encoding="utf-8"))
    rng = random.Random(7)
    for key in ("samples", "device_states", "probe_rows", "journal_events",
                "audit"):
        rng.shuffle(obj[key])
    shuffled.append(line(obj))
runs.append("".join(shuffled))
digests = {hashlib.sha256(r.encode()).hexdigest() for r in runs}
print("STABLE" if len(digests) == 1 else "UNSTABLE")
EOF
)"
assert_eq "$STABLE" "STABLE" \
    "the fixture answers repeat identically and ignore input ordering"

# (4)-(7) The four mutations. Each names the evidence axis it moves and the
# answer it must produce, so the lane proves the classifier READS the
# fixture rather than recognising its filename.
mutate() { # <python body over `obj`> -> "status category unknowns"
    "$PY" - "$FIX_REAL" <<EOF
import copy, json, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
obj = copy.deepcopy(json.load(open(sys.argv[1], encoding="utf-8")))
$1
r = cl.classify(obj)
print("%s %s %s" % (r.status, r.category, ",".join(sorted(r.unknowns))))
EOF
}
assert_eq "incident hysteria2_udp_path root_cause_not_established" \
    "$(mutate '
for row in obj["journal_events"]:
    if row["proto"] == "Reality" and row["cls"] == "dial_timeout":
        row["proto"] = "Hysteria2"
for row in obj["samples"]:
    row["reality_active_connections"], row["hysteria2_active_connections"] = (
        row["hysteria2_active_connections"], row["reality_active_connections"])
')" \
    "swapping every Reality signal for Hysteria2 moves the answer with it"
assert_eq "no_incident NONE count_drop_only,no_corroboration" \
    "$(mutate '
obj["journal_events"] = [r for r in obj["journal_events"]
                         if not (r["proto"] == "Reality"
                                 and r["cls"] == "dial_timeout")]
')" \
    "deleting the journal burst collapses it: a count drop alone is never an incident"
assert_eq "incident vps_outbound root_cause_not_established" \
    "$(mutate '
base = int(obj["window"]["start_epoch"])
for index in (4, 5):
    obj["journal_events"].append({"seq": 900 + index,
                                  "ts": float(base + index * 60 + 40),
                                  "cls": "dial_timeout", "proto": "OTHER",
                                  "port": 443, "dcls": "https443",
                                  "fp": None, "n": 9})
')" \
    "generic OTHER-over-443 evidence beside the Reality burst upgrades to vps_outbound"
assert_eq "incident insufficient_evidence journal_evidence_incomplete,probe_evidence_absent,root_cause_not_established,transport_negatives_unproven" \
    "$(mutate '
obj["reader"] = {"status": "unreadable"}
obj["probe_rows"] = []
')" \
    "when the negatives stop being provable the same evidence refuses attribution"

# (7a)-(7f) The round-4 refusals, restated on the committed artefact rather
# than in the harness. Each one is a fixture the PRE-round-4 module answers
# differently, so these are discriminators and not decorations.
quiet_rows() { # <hy2 answer> -> a per-(device, inbound) table for every bucket
    "$PY" - "$FIX_REAL" "$1" <<'EOF'
import copy, json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
hy2 = int(sys.argv[2])
template = obj["device_states"][0]
base = int(obj["window"]["start_epoch"])
devices = sorted({row["device"] for row in obj["device_states"]})
rows = []
for index in range(10):
    for device in devices:
        pairs = [("hy2-in", hy2 if index >= 3 else 20),
                 ("vless-in", 0 if index >= 3 else 20)]
        for inbound, active in pairs:
            row = copy.deepcopy(template)
            row.update({"epoch": float(base + index * 60 + 20),
                        "device": device, "inbound": inbound,
                        "active_connections": active})
            rows.append(row)
print(json.dumps(rows))
EOF
}
import_rows() { # <rows json> -> "status category unknowns" for that device table
    "$PY" - "$FIX_REAL" "$1" <<'EOF'
import json, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
obj = json.load(open(sys.argv[1], encoding="utf-8"))
obj["device_states"] = json.loads(sys.argv[2])
r = cl.classify(obj)
print("%s %s %s" % (r.status, r.category, ",".join(sorted(r.unknowns))))
EOF
}
QUIET_ZERO="$(quiet_rows 0)"
QUIET_HOLD="$(quiet_rows 3)"
assert_eq "incident reality_tcp_path device_states_are_change_only,root_cause_not_established" \
    "$(import_rows "$QUIET_ZERO")" \
    "a genuinely quiet device table is context: it names no impact and no shared path"
assert_eq "incident reality_tcp_path root_cause_not_established" \
    "$(import_rows "$QUIET_HOLD")" \
    "one device's other inbound holding clients is read per (device, inbound), not per device"
assert_eq "incident reality_tcp_path root_cause_not_established" \
    "$("$PY" - "$FIX_REAL" "$QUIET_HOLD" <<'EOF'
import json, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
obj = json.load(open(sys.argv[1], encoding="utf-8"))
rows = json.loads(sys.argv[2])
reversed_rows = []
for index in range(10):
    chunk = rows[index * 4:(index + 1) * 4]
    reversed_rows = reversed_rows + chunk[::-1]
obj["device_states"] = reversed_rows
r = cl.classify(obj)
print("%s %s %s" % (r.status, r.category, ",".join(sorted(r.unknowns))))
EOF
)" \
    "the same device rows traversed in the opposite order answer exactly the same"
tie_rows() { # <first>,<second> -> two rows per (device, inbound) at ONE epoch
    "$PY" - "$FIX_REAL" "$1" <<'EOF'
import copy, json, sys
obj = json.load(open(sys.argv[1], encoding="utf-8"))
order = [int(value) for value in sys.argv[2].split(",")]
template = obj["device_states"][0]
base = int(obj["window"]["start_epoch"])
devices = sorted({row["device"] for row in obj["device_states"]})
rows = []
for index in range(10):
    for device in devices:
        for inbound in ("hy2-in", "vless-in"):
            for value in (order if index >= 3 else [20, 20]):
                row = copy.deepcopy(template)
                row.update({"epoch": float(base + index * 60 + 20),
                            "device": device, "inbound": inbound,
                            "active_connections": value})
                rows.append(row)
print(json.dumps(rows))
EOF
}
assert_eq "incident reality_tcp_path root_cause_not_established" \
    "$(import_rows "$(tie_rows 3,0)")" \
    "one (device, inbound) answering 3 and 0 at the same instant is not quiet"
assert_eq "incident reality_tcp_path root_cause_not_established" \
    "$(import_rows "$(tie_rows 0,3)")" \
    "the same instant read in the other order answers the same: no row is last"
for CODE in tls_failed protocol_failed; do
assert_eq "incident reality_tcp_path probe_evidence_unusable,root_cause_not_established" \
    "$(mutate "
base = int(obj['window']['start_epoch'])
for row in obj['probe_rows']:
    if row['epoch'] >= base + 3 * 60:
        for slot in ('dns', 'https', 'egress'):
            row['%s_status' % slot] = 'failed'
            row['%s_error_code' % slot] = '$CODE'
            row['%s_latency_ms' % slot] = None
")" \
    "a generic slot that fails with $CODE is the probe failing to adjudicate, not a path that is down"
done
assert_eq "incident insufficient_evidence probe_endpoint_confounded,root_cause_not_established" \
    "$(mutate '
base = int(obj["window"]["start_epoch"])
for row in obj["samples"]:
    row["reality_active_connections"] = 25
    row["total_active_connections"] = 40
obj["journal_events"] = [r for r in obj["journal_events"]
                         if not (r["proto"] == "Reality"
                                 and r["cls"] == "dial_timeout")]
for row in obj["probe_rows"]:
    index = int((row["epoch"] - base) // 60)
    if index >= 4:
        for slot in ("dns", "https"):
            row[slot + "_status"] = "failed"
            row[slot + "_error_code"] = "timeout"
            row[slot + "_latency_ms"] = None
    if index == 4:
        row["egress_change"] = "changed"
')" \
    "a changed egress address is the same scheduler answering, not a second witness"

# (8) Privacy on the committed artefacts: the fixtures carry real sentinel
# material in the columns the classifier may receive but never read, plus the
# two it reads as counting keys, so a result that repeats any of it is a leak,
# not a style problem.
if "$PY" - "$FIX_REAL" "$FIX_NORMAL" <<'EOF'
import json, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
PROBES = ("SENTINEL-SECRET-0123456789abcdef", "office-laptop-alpha",
          "home-phone-beta", "203.0.113.19", "0011223344556677", "vless-in")
for path in sys.argv[1:]:
    text = open(path, encoding="utf-8").read()
    carried = [p for p in PROBES if p in text]
    assert len(carried) >= 5, "fixture %s carries no identity material" % path
    out = json.dumps(cl.classify(json.loads(text)).to_dict(), sort_keys=True)
    for probe in PROBES:
        assert probe not in out, "fixture %s leaked %s" % (path, probe)
    assert "@" not in out and "=" not in out, out
EOF
then
    pass "neither fixture's result echoes a device, inbound tag, address or fp"
else
    fail "a classifier result echoed identity material from its input"
fi

# (9) The never-raises wall on inputs no validator would bless.
if "$PY" <<'EOF'
import os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from web import incident_classifier as cl
for bad in (None, 0, "", [], {}, {"window": None}, {"window": {}},
            [[]], {"samples": [None]}, "not-a-bundle"):
    r = cl.classify(bad)
    assert r.status == "indeterminate", (bad, r.status)
    assert r.category == "insufficient_evidence", (bad, r.category)
    assert set(r.unknowns) <= set(cl.UNKNOWN_TOKENS), r.unknowns
    assert set(r.evidence) <= set(cl.EVIDENCE_TOKENS), r.evidence
EOF
then
    pass "garbage input answers indeterminate in closed tokens, never a raise"
else
    fail "the classifier raised or improvised on a malformed bundle"
fi

section "S3: behaviour groups (mirrors, decision table, hostiles, store)"

FIXTURE_HASH_BEFORE="$(cat "$FIX_REAL" "$FIX_NORMAL" | sha256sum | cut -d' ' -f1)"
"$PY" "$HARNESS" >"$TMP/groups.log" 2>&1
RC=$?
map_verdicts "$TMP/groups.log"
if [ "$RC" -ne 0 ]; then
    fail "classify_groups.py exited rc=$RC (a crashing harness is itself a gate)"
    tail -20 "$TMP/groups.log"
else
    pass "classify_groups.py exited 0 over all seven groups"
fi
# "Matches the generated bundle" is only a real gate if the harness cannot
# generate: running the full suite must leave the committed bytes untouched.
assert_eq "$FIXTURE_HASH_BEFORE" \
    "$(cat "$FIX_REAL" "$FIX_NORMAL" | sha256sum | cut -d' ' -f1)" \
    "a full harness run left both committed fixtures byte-identical"

section "RESULT"
printf 'checks: %d passed, %d failed (expected %d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '== PR-4A classifier suite: FAILED ==\n'
    exit 1
fi
printf '== PR-4A classifier suite: GREEN ==\n'
exit 0
