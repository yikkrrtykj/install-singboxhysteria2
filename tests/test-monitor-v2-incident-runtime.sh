#!/usr/bin/env bash
# Monitor 0.5.0 -- PR-4B incident runtime (issue #33 Phase 4) suite.
#
# PR-4A made the classifier a pure function that no runtime called. PR-4B
# wires it into the Monitor process through exactly one reviewed consumer,
# gives it a durable home in schema v4, and keeps every promise the classifier
# makes about honesty. This lane owns the four properties that wiring has to
# prove, in the order a reviewer should check them:
#
#   1. THE WIRING IS EXACTLY THE REVIEWED WIRING. The scanner is constructed
#      once, in webapp.py, and is stopped BEFORE the history store closes --
#      an in-flight scan cycle must never meet a closed store. The release
#      identity is pinned at Monitor 0.5.0 / MONITOR_WEB_VERSION 0.5.0 /
#      history SCHEMA_VERSION 4, and the contract document that froze them is
#      present with all thirty-four discriminators listed (R1's nineteen,
#      R2's eleven and R3's four).
#   2. THE SURFACE DID NOT WIDEN. The timeline endpoint gains EXACTLY ONE
#      key (the closed eight-key ``incident_runtime`` object), and the
#      incident runtime module holds no SQL, no file, no socket and no
#      process call site: it reads through the store's bounded reader and
#      writes through the store's boundary only. (The old "no P5 route"
#      gate stood in this lane and was explicitly RETIRED by PR-5, #63 R2
#      §13 -- the route family is now owned, and set-exactness-gated, by
#      tests/test-monitor-v2-incidents.sh. Every other gate here is
#      untouched.)
#   3. BEHAVIOUR, at the level a reviewer cannot fake: tests/
#      monitor-incident-runtime/runtime_groups.py drives the real
#      IncidentScanner over a real schema-v4 SQLite store and asserts the
#      frozen lifecycle -- one row per incident, the analysis window frozen at
#      ``first_signal - 3*BUCKET``, the persisted six columns as the ONE
#      CONSISTENT SNAPSHOT of the most recent successful ``detect()`` (which
#      may move the category either way, because the persistence layer has no
#      opinion to defend), a three-clean-bucket tail settled from THAT cycle,
#      the sixty-bucket cap really persisted at 60 and closed fail-closed at
#      61 without fabricating a bucket, the durable ``rearm`` gate that a
#      window-limit close raises and a restart cannot forget, restart
#      continuation from the stored pointer, crash orders on both sides of
#      the transaction, the bitset walls at 45 and 28 bits,
#      ``destination_specific`` refused twice over, reader-continuity recovery
#      that is never retroactive, the composed evidence-plane health that the
#      incident plane itself can never pollute, and every stage failure
#      landing in one closed four-token vocabulary while the other planes of
#      the same process keep answering.
#   4. NOTHING CANONICALISED ITSELF: the end-to-end group cans NOTHING. It
#      publishes the committed Reality-outage scenario into a live store,
#      reads the evidence back out of SQLite through the live bounded reader,
#      and lets the shipped classifier decide -- and the same machinery over
#      the quiet fixture opens no row at all.
#
# Everything here is pure Python over stdlib plus SQLite, with a loopback-only
# HTTP server: no network, no privileges, no gate that needs Linux. The dev
# host and CI must therefore agree exactly, and the hard count below is the
# proof that they did.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export CLASSIFY_FIXTURE_DIR="$HERE/monitor-classify/fixtures"

PASS=0
FAIL=0
# PR-4B R3 -- 224 checks, measured on the dev host and to be re-measured on
# Linux CI. The breakdown is part of the record, and so is the reason every
# section moved: R1 measured 188 (14 + 174); R2 re-froze the verdict
# snapshot and the discovery/rearm gate (219 = 14 + 205, 203 verdicts); R3
# fixes the two review blockers -- the derived phase (§8.4) and the closed
# state shape (§5.1). Its five gates are all ADDED: store 69 -> 70 (+1, the
# armed row may not lose its discovery floor), lifecycle 54 -> 56 (+2, the
# clean close reports warmup in the cycle that closed and a restart inside
# the post-clean warmup reports warmup before its first cycle), containment
# 38 -> 40 (+2, an unprovable shape keeps activation dark and aborts a
# running cycle as runtime_state_corrupt without reading one bundle). None
# was renamed and no expectation was loosened, with ONE declared exception:
# lifecycle/close_clears_pointer_and_phase asserted phase == "idle" on the
# closing cycle, which is precisely the behaviour blocker A identifies as
# wrong, so its third conjunct is restated as phase != "open". The gate's
# count is not new and its pointer/row halves are untouched; R3's own warmup
# claim rides on the two added lifecycle gates. static 14 -> 12 (-2 in
# R2, the four broadening-lattice gates deleted with the lattice itself and
# two category-surface gates added in their place), retention 6 -> 6,
# continuity 10 -> 10, end_to_end 14 -> 14: 208 verdicts plus the harness rc
# gate plus the fixture-immutability proof.
# PR-5 (#63 R2 §13/§14): 224 -> 222, by RETIREMENT only, never by
# loosening: (a) S0 static 14 -> 13 -- the "no P5 route exists" static wall
# is the one gate the R2 contract retires (the route family is now
# set-exactness-gated by the incidents lane); (b) containment 40 -> 39 --
# the live "P5 route answers 404" verdict is the same retirement point
# served over HTTP. The release-identity witnesses are RESTATED in place
# (VERSION 0.7.0 / MONITOR_WEB_VERSION 0.7.0 / SCHEMA_VERSION 5 -- the
# store gains ONLY operator_markers) and no expectation was otherwise
# weakened; the timeline one-key wall, all 34 contract discriminators and
# every behaviour verdict keep their exact prior shape.
#   S0 static + wiring gates             13   the release identity (VERSION /
#        MONITOR_WEB_VERSION / SCHEMA_VERSION), one scanner construction site
#        and the stop-before-close teardown order, the exactly-one-new-key
#        surface wall, the runtime module's SQL-free and I/O-free call-site
#        walls, and the contract document's THIRTY-FOUR discriminator list
#        (R1's nineteen plus R2's eleven plus R3's four; a gate that went
#        missing with a lattice that went deleted could otherwise hide
#        behind a spec that stopped mentioning it). All static, all
#        platform-independent.
#   S1 behaviour groups (runtime_groups) 209  = 207 harness verdicts plus the
#        harness rc gate plus the cross-lane fixture-immutability proof:
#        static 12 (the six frozen constants by value, the bucket grid
#        REFERENCED not rewritten, the numeric-literal wall that forbids a
#        second copy of 60, the import closure, the closed error/phase/
#        closure vocabularies with rearm in the phase set, the deleted
#        lattice's SURFACE (no _CATEGORY_LATTICE/_broaden attribute and no
#        module attribute holding an emittable category string), the eight-key
#        ordered status surface, dark before start),
#        store 69 (exactly ten v4 tables and their exact column sets, the
#        three TEXT columns as the only closed enums, no raw/identity column
#        anywhere, the inert single state row now eight columns born with a
#        NULL discovery floor and rearm 0, the six emittable categories
#        persisting while destination_specific is refused at the boundary AND
#        by CHECK, twelve CHECK rejections -- the five new ones being a floor
#        below the activation floor, a rearm outside {0,1}, rearm=1 paired
#        with an open pointer or with a discovery floor, and R3's armed row
#        (activation landed, rearm 0) losing its discovery floor, the shape
#        the reader also refuses -- the one-open
#        partial index, the 45/28-bit positional round-trip with one-past
#        refused twice, no identity material reaching a row, activation
#        pinning BOTH floors one-way, a mark that never moves the pointer,
#        update/close requiring an open row and a closed reason, the close
#        moving pointer/floor/rearm in the SAME transaction for both closure
#        reasons and rearm surviving reactivation, the composed bundle health
#        -- clean before each of the three evidence planes, admitting each of
#        them, error-code precedence identical to health(), and the incident
#        plane's own degradation EXCLUDED -- the per-section 2000-row budget
#        refusing the WHOLE bundle, and the timeline projection staying
#        exactly as wide as it was),
#        retention 6 (a closed window ages out by its own signal age, an open
#        one never does, the continuity row survives, neither incident table
#        takes part in size pruning, the seven-day contract untouched),
#        lifecycle 54 (D1-D7 plus D9-D13: exactly one open row, the frozen
#        analysis start, signal epochs from the detection, repeat scans of the
#        SAME bucket writing nothing while a NEWER complete bucket advances
#        the classified end, the category moving to the current verdict in
#        BOTH directions (narrowing rewrites), the clean tail closing on
#        THAT cycle's snapshot rather than the row's old bits, the discovery
#        floor pinned at the closed incident's last signal with warmup holding
#        until five post-signal buckets and discovery then resuming -- and
#        that warmup is the DERIVED phase (§8.4), reported by the closing
#        cycle itself and by a scanner restarted inside it before any cycle,
#        pointer/row landing together and both crash orders, restart
#        continuing the same incident, a probe-only blip and a changed egress
#        address opening and broadening nothing, bucket 60 really persisted
#        and bucket 61 closing fail-closed on the last SUCCESSFUL snapshot
#        without classifying the over-long window, the 20->65 clock jump
#        never fabricating bucket 60, and the durable rearm gate: a normal
#        phase, no failure counter, discovery stopped over ten further
#        cycles of continuing outage, and the same answer after a restart),
#        continuity 10 (fresh/stale only on the projection, activation
#        starting continuity at the floor, every non-fresh token breaking it,
#        recovery stamping THIS moment and never repairing an earlier window,
#        a restart breaking continuity, a malformed heartbeat never starting
#        it),
#        containment 40 (nine stage/mode fault injections each mapping to
#        exactly one closed code, an exploding detect, an unencodable verdict,
#        a defect escaping every guard, a refused activation leaving the
#        scanner dark, R3's unprovable state shape (§5.1) keeping the scanner
#        dark at start AND ending a running cycle in runtime_state_corrupt
#        without reading a single evidence bundle (the failure to fall back to
#        the wider activation floor is the gate), the daemon thread,
#        plane independence on the SAME store
#        while the incident plane is failing, the lying-status projection
#        forced back into its closed domains, an exploding scanner reading as
#        null rather than a 500, and live loopback HTTP over the shipped
#        handler: eight surface keys, closed domains, 404 on the P5 route, no
#        new query parameter, the journal surface not widened),
#        end_to_end 14 (the committed outage scenario through the live store:
#        exactly one reality_tcp_path row with the discovery-width window and
#        the row's bits equal to the live reader's own verdict; the quiet
#        scenario opening nothing while still evaluating; an over-budget
#        evidence window refused as a contained read error).
EXPECTED_PASS=222
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
# NOTE on argument order: this lane's assert_eq is (want, got, label), the
# packaging lane's convention. The message is written to match, so a failure
# line can never blame the wrong side.
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$1', got '$2')"; fi; }
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

RUNTIME="$ROOT/monitor-v2/web/incident_runtime.py"
CLASSIFIER="$ROOT/monitor-v2/web/incident_classifier.py"
HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
SERVER_PY="$ROOT/monitor-v2/web/server.py"
WEBAPP="$ROOT/monitor-v2/webapp.py"
COLLECTOR="$ROOT/monitor-v2/collector.py"
HARNESS="$HERE/monitor-incident-runtime/runtime_groups.py"
DOC="$ROOT/docs/monitor-v2-incident-runtime-p4b.md"
FIX_REAL="$CLASSIFY_FIXTURE_DIR/incident-reality-outage.json"
FIX_NORMAL="$CLASSIFY_FIXTURE_DIR/incident-normal-background.json"
WORKFLOW="$ROOT/.github/workflows/tests.yml"
# Every file this lane greps is checked for existence first: a "no reference
# found" over a missing file is a vacuous pass, and a vacuous pass is worse
# than no gate at all.
for required in "$RUNTIME" "$CLASSIFIER" "$HIST_PY" "$SERVER_PY" "$WEBAPP" \
    "$COLLECTOR" "$HARNESS" "$DOC" "$WORKFLOW"; do
    [ -f "$required" ] || fail "lane input missing: $required"
done

section "S0: static + wiring gates"

if "$PY" -m py_compile "$RUNTIME" "$CLASSIFIER" "$HIST_PY" "$SERVER_PY" \
    "$WEBAPP" "$HARNESS" 2>"$TMP/py.err"; then
    pass "py_compile: runtime + classifier + history + server + webapp + harness"
else
    fail "py_compile: $(cat "$TMP/py.err")"
fi

# (1) The release identity PR-5 restated. Three witnesses, three files: the
#     VERSION this lane guards, the web build it ships, the schema it writes.
assert_eq '0.7.0' "$(cat "$ROOT/monitor-v2/VERSION")" \
    "VERSION is 0.7.0 (the remote-probe ingest release)"
if grep -q 'MONITOR_WEB_VERSION = "0.7.0"' "$SERVER_PY"; then
    pass "MONITOR_WEB_VERSION is 0.7.0"
else
    fail "MONITOR_WEB_VERSION moved off 0.7.0"
fi
if grep -q '^SCHEMA_VERSION = 5$' "$HIST_PY"; then
    pass "history SCHEMA_VERSION is 5"
else
    fail "history SCHEMA_VERSION moved off 5"
fi

# (2) ONE construction site, in the entrypoint. The class name appears in
#     server.py only as prose about the closed surface; the CONSTRUCTOR call
#     is what wires a thread, and there is exactly one.
CONSTRUCTORS="$(grep -rl 'IncidentScanner(' --include='*.py' "$ROOT/monitor-v2" \
    2>/dev/null | grep -v 'web/incident_runtime.py' || true)"
assert_eq "$ROOT/monitor-v2/webapp.py" "$CONSTRUCTORS" \
    "exactly one module constructs the scanner: webapp.py (closed allowlist)"
assert_eq '1' "$(grep -c 'IncidentScanner(' "$WEBAPP")" \
    "the entrypoint constructs the scanner exactly once"

# (3) Teardown ORDER: the scanner goes down before the store closes. Line
#     numbers over the shipped file, not a comment about intent -- a reversed
#     pair is exactly one edit away and would let a scan cycle meet a closed
#     store.
STOP_LINE="$(grep -n '^        scanner.stop()$' "$WEBAPP" | head -1 | cut -d: -f1)"
CLOSE_LINE="$(grep -n '^        history.close()$' "$WEBAPP" | head -1 | cut -d: -f1)"
if [ -n "$STOP_LINE" ] && [ -n "$CLOSE_LINE" ] && \
        [ "$STOP_LINE" -lt "$CLOSE_LINE" ]; then
    pass "shutdown order is scanner.stop() (line $STOP_LINE) before history.close() (line $CLOSE_LINE)"
else
    fail "the scanner is not stopped before the history store closes (stop='$STOP_LINE' close='$CLOSE_LINE')"
fi

# (4) The surface did not widen: the timeline gains exactly ONE key. (The
#     old "no P5 route exists" wall that shared this number is RETIRED by
#     PR-5 -- see the header; its replacement lives in the incidents lane.)
assert_eq '1' "$(grep -c '"incident_runtime":' "$SERVER_PY")" \
    "the timeline body gains exactly one incident key (no second status surface)"

# (5) The runtime module touches NOTHING but the store's own bounded
#     interfaces. SQL would mean a second, unbudgeted read path; a file,
#     socket or process call would mean evidence the contract never reviewed.
if grep -qiE 'sqlite|SELECT |INSERT |CREATE TABLE|executescript' "$RUNTIME"; then
    fail "the incident runtime contains a storage or SQL reference"
else
    pass "the runtime reads only through the store's bounded classifier reader"
fi
if grep -qE 'open\(|socket|subprocess|urllib|os\.|requests' "$RUNTIME"; then
    fail "the incident runtime has a file, socket or process call site"
else
    pass "the incident runtime touches no filesystem, network or subprocess"
fi

# (6) The frozen contract is present and complete: all THIRTY-FOUR
#     discriminators are listed in the document this lane implements, so a
#     gate that went missing cannot hide behind a spec that stopped
#     mentioning it.
DISC_COUNT="$(sed -n '/^## 16\./,/^## 17\./p' "$DOC" | grep -cE '^[0-9]+\. ')"
assert_eq '34' "$DISC_COUNT" \
    "the P4B contract document lists all thirty-four discriminators"

# (7) This lane is registered in CI where the other Monitor behaviour lanes
#     run: a suite nobody executes is a suite that cannot fail.
if grep -q 'bash -n tests/test-monitor-v2-incident-runtime.sh' "$WORKFLOW"; then
    pass "tests.yml syntax-checks this lane"
else
    fail "tests.yml does not bash -n this lane"
fi
if grep -q 'run: bash tests/test-monitor-v2-incident-runtime.sh' "$WORKFLOW"; then
    pass "tests.yml runs this lane in the Monitor regression job"
else
    fail "tests.yml never runs this lane"
fi

section "S1: behaviour groups (wiring, lifecycle, persistence, containment)"

# The two committed fixtures are shared property data, not this lane's to
# edit. Importing classify_groups is deliberate -- the same scenario rows the
# classifier lane decides on are the evidence this lane feeds the runtime --
# so a full run here must leave those bytes exactly as they are.
FIXTURE_HASH_BEFORE="$(cat "$FIX_REAL" "$FIX_NORMAL" | sha256sum | cut -d' ' -f1)"
"$PY" "$HARNESS" >"$TMP/groups.log" 2>&1
RC=$?
map_verdicts "$TMP/groups.log"
if [ "$RC" -ne 0 ]; then
    fail "runtime_groups.py exited rc=$RC (a crashing harness is itself a gate)"
    tail -25 "$TMP/groups.log"
else
    pass "runtime_groups.py exited 0 over all seven groups"
fi
assert_eq "$FIXTURE_HASH_BEFORE" \
    "$(cat "$FIX_REAL" "$FIX_NORMAL" | sha256sum | cut -d' ' -f1)" \
    "a full harness run left both committed classify fixtures byte-identical"

section "RESULT"
printf 'checks: %d passed, %d failed (expected %d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '== PR-4B incident runtime suite: FAILED ==\n'
    exit 1
fi
printf '== PR-4B incident runtime suite: GREEN ==\n'
exit 0
