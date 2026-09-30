#!/usr/bin/env bash
# Monitor 0.6.0 -- PR-5 incidents UI / operator-readable diagnostics
# (issue #33 Phase 5, #63 R2) suite.
#
# PR-4B left the persisted incident lifecycle with exactly one runtime
# consumer and a closed 8-key timeline projection. PR-5 is the operator
# surface over that same plane, under the R2 re-freeze (#63):
#
#   1. THE RELEASE IDENTITY moved to 0.6.0 / schema v5: the eleven-table
#      store gains ONLY operator_markers, and the release pins are
#      restated by this lane and the hist/runtime lanes together.
#   2. THE PRESENTER WALL. web/incident_presenter.py is pure presentation:
#      no I/O, no clock, no classifier/runtime import, positional mirrors
#      of the 45/28 vocabularies with FULL explanation coverage, the exact
#      10-key L1 summary, and closed marker labels.
#   3. THE WIRE. Five route paths exactly; the list/detail/evidence
#      projections are key-set-exact; evidence is SUBJECT-BOUND (the
#      server derives the window; a URL cannot widen it); egress_ip is
#      visible while run_id/cycle_id/fp never are; markers are closed-enum
#      (NO free-text field, no future, no already-aged-out epoch) and
#      never enter the classifier bundle; rearm requires a RUNNING scanner
#      in phase=rearm and moves exactly two durable values on the shared
#      one-minute bucket grid; timeline stays byte-frozen.
#   4. THE FIXTURES (R2 §13) are exercised, not cited: the committed
#      Reality-outage store is published, read through the live reader,
#      summarized by the presenter and served over the shipped handler
#      (Reality/TCP-path assessment, never "server down", conditional HY2
#      action, uncertainty visible), and the quiet background store stays
#      an empty list.
#
# No mutation testing in this round (#63 R2 §15): these gates are
# preventive, and the lane measures its own count each run.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export CLASSIFY_FIXTURE_DIR="$HERE/monitor-classify/fixtures"

PASS=0
FAIL=0
# PR-5 R1 (#63 R2 §15): 139 checks, measured on the dev host (Windows,
# Python 3.14) and re-measured on Linux CI. Breakdown:
#   S0 static + wiring gates            17   py_compile over server + history
#        + presenter + webapp + harness; the release identity (VERSION /
#        MONITOR_WEB_VERSION 0.6.0 / SCHEMA_VERSION 5); the route family's
#        five frozen literals (the explicit retirement-replacement of P4B's
#        darkness gate); the timeline one-incident-key wall; the
#        classifier/runtime import wall over server+history+presenter; the
#        presenter purity wall (no I/O, no clock, no DB); the marker
#        table's no-free-text wall; both CI registrations; the UI lane's
#        incidents duty.
#   S1 behaviour groups                 122  = 121 harness verdicts plus the
#        harness rc gate plus the cross-lane fixture-immutability proof:
#        presenter 25 (import closure, positional mirrors == the sorted
#        classifier vocabularies, 45/28 explanation coverage, marker
#        labels, decode positionality + one-past refusals, exact 10-key
#        summary, signal-window rule, per-category coverage, conditional
#        Reality/HY2 wording, no server-down/ISP claims, insufficient has
#        no action, uncertainty the only interpolation, unknown-category
#        refusal),
#        store 32 (eleven-table shape, marker columns, boundary accept /
#        refuse matrix incl. future + aged-out + non-epoch, bounded list +
#        truncation, bundle excludes markers, marker_count closed join,
#        time + size retention membership, v4->v5 migration + v4-claim
#        hybrid refusal + zero-byte re-open, rearm store preconditions +
#        bucket-grid floor + moves-nothing-else + one-shot),
#        api 34 (list keys/params/errors, detail 404s, method closure,
#        evidence subject/section rules, marker GET/POST body rules behind
#        the full auth chain, auth matrix incl. step-up, rearm 409 without
#        the runtime gate, evidence whitelists + server-derived window,
#        marker +/-900 window, timeline byte-frozen, uniform 405 wall),
#        live_incident 12 (list 12-key rows, emittable-only category,
#        state filter, detail 20 keys, no destination_specific, decoded
#        texts match bits, 10-key summary, in-window marker join,
#        list marker_count parity),
#        rearm_stack 5 (derived phase=rearm over a REAL scanner, full-stack
#        rearm success, bucket-grid floor, one-shot 409),
#        fixtures 13 (R2 §13: reality fixture through live store + reader
#        + presenter + API -- Reality/TCP assessment, never server-down,
#        conditional HY2 action, HY2 not proven healthy, uncertainty +
#        root-cause limitation visible, no ISP claim, first screen without
#        raw tokens as primary, list parity; background stays no-incident
#        and an empty list).
EXPECTED_PASS=139
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$1', got '$2')"; fi; }
map_verdicts() {
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

SERVER_PY="$ROOT/monitor-v2/web/server.py"
HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
PRESENTER="$ROOT/monitor-v2/web/incident_presenter.py"
WEBAPP="$ROOT/monitor-v2/webapp.py"
HARNESS="$HERE/monitor-incidents/incident_ui_groups.py"
UI_LANE="$ROOT/tests/test-monitor-v2-ui.cjs"
WORKFLOW="$ROOT/.github/workflows/tests.yml"
FIX_REAL="$CLASSIFY_FIXTURE_DIR/incident-reality-outage.json"
FIX_NORMAL="$CLASSIFY_FIXTURE_DIR/incident-normal-background.json"
for required in "$SERVER_PY" "$HIST_PY" "$PRESENTER" "$WEBAPP" "$HARNESS" \
    "$UI_LANE" "$WORKFLOW" "$FIX_REAL" "$FIX_NORMAL"; do
    [ -f "$required" ] || fail "lane input missing: $required"
done

section "S0: static + wiring gates"

if "$PY" -m py_compile "$SERVER_PY" "$HIST_PY" "$PRESENTER" "$WEBAPP" \
    "$HARNESS" 2>"$TMP/py.err"; then
    pass "py_compile: server + history + presenter + webapp + harness"
else
    fail "py_compile: $(cat "$TMP/py.err")"
fi

# (1) The release identity PR-5 froze: Monitor 0.6.0 on history schema v5.
assert_eq '0.6.0' "$(cat "$ROOT/monitor-v2/VERSION")" \
    "VERSION is 0.6.0 (the incidents-UI release)"
if grep -q 'MONITOR_WEB_VERSION = "0.6.0"' "$SERVER_PY"; then
    pass "MONITOR_WEB_VERSION is 0.6.0"
else
    fail "MONITOR_WEB_VERSION moved off 0.6.0"
fi
if grep -q '^SCHEMA_VERSION = 5$' "$HIST_PY"; then
    pass "history SCHEMA_VERSION is 5"
else
    fail "history SCHEMA_VERSION moved off 5"
fi

# (2) The route family is EXACTLY the five reviewed paths -- the explicit
#     retirement of P4B's darkness gate, replaced by presence of each
#     frozen route (set-exactness over the family is proven live by the
#     harness's 404/method-error answers).
for route in '"/api/v1/incidents"' '"/api/v1/incidents/rearm"' \
    '"/api/v1/evidence"' '"/api/v1/markers"'; do
    if grep -qF "$route" "$SERVER_PY"; then
        pass "route literal present: $route"
    else
        fail "route literal missing: $route"
    fi
done
if grep -q 'startswith("/api/v1/incidents/")' "$SERVER_PY"; then
    pass "detail subroute family present: /api/v1/incidents/<id>"
else
    fail "detail subroute family missing"
fi

# (3) Timeline stays byte-frozen: the incidents family added no second
#     status surface to it.
assert_eq '1' "$(grep -c '"incident_runtime":' "$SERVER_PY")" \
    "the timeline body still carries exactly one incident key"

# (4) The single-consumer wall: server/history/presenter never import the
#     classifier or the runtime; the presenter is pure presentation.
if grep -qE 'import.*incident_classifier|import.*incident_runtime' \
        "$SERVER_PY" "$HIST_PY" "$PRESENTER"; then
    fail "a P5 module imports the classifier or the runtime"
else
    pass "server/history/presenter never import the classifier or runtime"
fi
if grep -qE 'sqlite|open\(|socket|subprocess|urllib|requests|time\.time' \
        "$PRESENTER"; then
    fail "the presenter has an I/O, clock or storage call site"
else
    pass "the presenter is pure presentation (no I/O, no clock, no DB)"
fi

# (5) The marker table has NO free-text column: the only TEXT is the
#     closed two-kind enum column.
if grep -q 'kind TEXT NOT NULL' "$HIST_PY" \
        && ! grep -qE 'CREATE TABLE operator_markers.*text' "$HIST_PY"; then
    pass "operator_markers carries no free-text column"
else
    fail "operator_markers shape drifted toward free text"
fi

# (6) CI registration and the UI lane's P5 duty.
if grep -q 'bash -n tests/test-monitor-v2-incidents.sh' "$WORKFLOW"; then
    pass "tests.yml syntax-checks this lane"
else
    fail "tests.yml does not bash -n this lane"
fi
if grep -q 'run: bash tests/test-monitor-v2-incidents.sh' "$WORKFLOW"; then
    pass "tests.yml runs this lane in the Monitor regression job"
else
    fail "tests.yml never runs this lane"
fi
if grep -q 'incidents' "$UI_LANE"; then
    pass "the UI lane exercises the incidents view"
else
    fail "the UI lane was not extended to the incidents view"
fi

section "S1: behaviour groups (presenter, store, API, live incident, rearm, fixtures)"

# The two committed classify fixtures are shared property data, not this
# lane's to edit: a full harness run must leave their bytes identical.
FIXTURE_HASH_BEFORE="$(cat "$FIX_REAL" "$FIX_NORMAL" | sha256sum | cut -d' ' -f1)"
"$PY" "$HARNESS" >"$TMP/groups.log" 2>&1
RC=$?
map_verdicts "$TMP/groups.log"
if [ "$RC" -ne 0 ]; then
    fail "incident_ui_groups.py exited rc=$RC (a crashing harness is itself a gate)"
    tail -25 "$TMP/groups.log"
else
    pass "incident_ui_groups.py exited 0 over all six groups"
fi
assert_eq "$FIXTURE_HASH_BEFORE" \
    "$(cat "$FIX_REAL" "$FIX_NORMAL" | sha256sum | cut -d' ' -f1)" \
    "a full harness run left both committed classify fixtures byte-identical"

section "RESULT"
printf 'checks: %d passed, %d failed (expected %d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '== PR-5 incidents suite: FAILED ==\n'
    exit 1
fi
printf '== PR-5 incidents suite: GREEN ==\n'
exit 0
