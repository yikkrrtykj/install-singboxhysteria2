#!/usr/bin/env bash
# Monitor 0.3.x -- PR-3B probe activation + ingest (issue #33 Phase 3) suite.
#
# PR-3A shipped the engine; PR-3B switches it on in exactly one narrow way
# and makes the result durable. This lane owns the four things the review
# contract demands proof of:
#
#   1. the CLOSED SHAPES match across the module boundary. web/ may not
#      import diagnostics/, so the history store mirrors the engine
#      vocabulary and the web surface mirrors the scheduler's status object;
#      every mirror is asserted against the LIVE value here, so a mirror
#      cannot rot into a silent lie (the same discipline PR-2B uses for the
#      journal contract).
#   2. the boundary, durability, schema, retention, health-plane, activation,
#      live-loopback and threading behaviour, in
#      tests/monitor-probes/probe_ingest_groups.py: a reject matrix of more
#      than forty counterexamples (B1-B6 included),
#      the durable egress baseline (restart + window + raw-writer defense +
#      the three-token egress-change derivation grid),
#      fresh/v1->v3/v2->v3 atomicity with an injected mid-migration crash and
#      the pre-v3-build refusal that is the RUNTIME half of the rollback
#      contract, one globally epoch-ordered prune, the two evidence planes
#      staying independent, a live scheduler against a 127.0.0.1-only TLS
#      fake, and 20x start/stop thread discipline with a slow-cycle lock test.
#   3. the rollback schema gate at FUNCTION level, on a real fixture: both
#      readers are read-only, every unknown shape refuses, and a refusal
#      mutates ZERO bytes. The end-to-end `install-monitor.sh rollback`
#      refusal rides the packaging lane's full deploy fixture.
#   4. CI hygiene: no shipped deploy surface can switch probing on by
#      omission, and the suite's network surface is loopback-only BY
#      CONSTRUCTION -- the behaviour groups run behind an audit-layer guard
#      that refuses every public connect, send, lookup and bind, so a leak
#      fails the lane instead of generating traffic.
#
# POSIX-only assertions run for real on Linux (the CI gate) and stay vacuous
# where the platform has no permission model, exactly like the hist suite.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export PROBE_TEST_CERT="$HERE/monitor-probes/tls-test-cert.pem"
export PROBE_TEST_KEY="$HERE/monitor-probes/tls-test-key.pem"

PASS=0
FAIL=0
# PR-3B functional-review head -- 307 checks, measured on the dev host and
# to be re-measured on Linux CI. The R1 round (B1-B6) added the
# counterexample regressions; the R2 round (B7-B8) closed the two remaining
# value-domain holes, so each section moved deliberately:
#   S0 static + mirror gates               8  (+2: gates (6) and (7) make the
#        EXACT-TYPE discipline structural -- no isinstance/bool/_as_int in
#        any probe judgement -- and pin latency to one shared exact-int wall)
#   S1 rollback gate wiring                6   (unchanged)
#   S2 rollback gate decisions on files   21   (unchanged)
#   S3 packaged opt-in path                15   (unchanged)
#   S4 network guard self-test              7   (unchanged)
#   S5 behaviour groups under the guard   250  (+17, all B7-B8 regressions:
#        boundary 35 +5 (exact-type latency/vocabulary/primitive matrices,
#        each asserting the REJECTION code and both counters), http 42 +12
#        (36-row hostile shape matrix with its own raise/leak proofs, the
#        honest-token table, the exact-dict container, three closer tables,
#        two coverage gates);
#        durable 25, schema 31, retention 12, health 21, e2e 21, threads 25)
EXPECTED_PASS=307
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }

if [ -z "$PY" ]; then
    printf '  python3 unavailable -- this suite is a hard gate on CI\n'
    printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$((FAIL + 1))"
    exit 1
fi

HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
SCHED="$ROOT/monitor-v2/diagnostics/probe_scheduler.py"
SERVER_PY="$ROOT/monitor-v2/web/server.py"
WEBAPP="$ROOT/monitor-v2/webapp.py"
ENGINE="$ROOT/monitor-v2/diagnostics/network_probes.py"
HARNESS="$HERE/monitor-probes/probe_ingest_groups.py"
GUARD="$HERE/monitor-probes/no_public_network.py"
LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"
INSTALL="$ROOT/monitor-v2/deploy/install-monitor.sh"

section "S0: static + mirror gates"

if "$PY" -m py_compile "$HIST_PY" "$SERVER_PY" "$WEBAPP" "$SCHED" \
    "$ENGINE" "$HARNESS" "$GUARD" 2>"$TMP/py.err"; then
    pass "py_compile: history + server + webapp + scheduler + engine + harness + guard"
else
    fail "py_compile: $(cat "$TMP/py.err")"
fi

# (1) the DB boundary mirrors the engine's closed vocabulary EXACTLY
if "$PY" - <<'EOF'
import os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from diagnostics import network_probes as engine
import web.incident_history as ih
assert set(ih.PROBE_ERROR_CODES) == set(engine.ERROR_CODES), \
    "error-code mirror drifted"
assert set(ih.PROBE_STATUSES) == {engine.STATUS_OK, engine.STATUS_FAILED}
assert set(ih.PROBE_CHANGE_VALUES) == {"unchanged", "changed", "unknown"}
assert ih.PROBE_RESULT_VERSION == engine.RESULT_VERSION
assert set(ih._PROBE_RESULT_KEYS) == set(engine.RESULT_KEYS)
assert set(ih._PROBE_CYCLE_KEYS) == {"status", "latency_ms", "error_code"}
assert set(ih._PROBE_EGRESS_KEYS) == set(ih._PROBE_CYCLE_KEYS) | {"ip"}
EOF
then
    pass "history mirrors the engine vocabulary and closed key sets exactly"
else
    fail "the probe vocabulary mirror drifted from the engine"
fi

# (2) the IP gate is ONE rule, mirrored not imported: the two bodies must be
# identical ASTs (docstrings and the function's own name stripped), or the DB
# could disagree with the engine about what a public address is.
if "$PY" - <<'EOF'
import ast, inspect, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from diagnostics import network_probes as engine
import web.incident_history as ih

def shape(fn):
    fdef = ast.parse(inspect.getsource(fn)).body[0]
    first = fdef.body[0]
    if (isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)):
        fdef.body.pop(0)          # prose may differ; logic may not
    fdef.name = "gate"
    return ast.unparse(fdef)

assert shape(engine._canonical_ip) == shape(ih._canonical_global_ip), \
    "%r != %r" % (shape(engine._canonical_ip), shape(ih._canonical_global_ip))
EOF
then
    pass "the boundary's global-IP gate is an identical AST mirror of the engine's"
else
    fail "the two IP gates drifted: the DB can now disagree with the engine"
fi

# (3) latency ceiling: above any real cycle, below an unbounded integer
if "$PY" - <<'EOF'
import os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from diagnostics import network_probes as engine
import web.incident_history as ih
assert ih.PROBE_LATENCY_MAX_MS > engine.CYCLE_DEADLINE_SECONDS * 1000
assert ih.PROBE_LATENCY_MAX_MS < 3_600_000
assert ih.PROBE_CYCLE_FRESHNESS_SECONDS > engine.CYCLE_DEADLINE_SECONDS
assert ih.PROBE_EGRESS_BASELINE_WINDOW_SECONDS == ih.RETENTION_SECONDS
assert ih.SCHEMA_VERSION == 3
assert ("network_probe_samples", "epoch") in ih._PRUNE_SOURCES
assert len(ih._PRUNE_SOURCES) == 5
EOF
then
    pass "probe bounds + v3 retention membership are coherent"
else
    fail "a probe bound is incoherent with the engine or retention"
fi

# (4) the web surface mirrors the SCHEDULER status object exactly
if "$PY" - <<'EOF'
import os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
from diagnostics import probe_scheduler as ps
from web import server as srv
from web.incident_history import IncidentHistory
import tempfile
h = IncidentHistory(os.path.join(tempfile.mkdtemp(), "diagnostics"), "mirror")
keys = set(ps.ProbeScheduler(h).status())
assert keys == set(srv.PROBE_STATUS_KEYS), "%r != %r" % (
    sorted(keys), sorted(srv.PROBE_STATUS_KEYS))
assert srv.PROBE_STARTUP_TOKENS == {ps.STARTUP_NOT_CONFIGURED,
                                    ps.STARTUP_FILE_ABSENT,
                                    ps.STARTUP_INJECTION_INVALID}
assert srv.PROBE_TARGET_SOURCES == {ps.SOURCE_PRODUCTION, ps.SOURCE_INJECTED,
                                    ps.SOURCE_DARK}
# The projection classes are CLOSED and total: every scheduler key names a
# domain the surface can force back into, and no class key is invented. A
# drifting mirror would otherwise leave the dispatch's fallback branch --
# the one that answers the closed minimum instead of the scheduler's claim
# -- carrying real traffic, which is exactly how a projection leak hides.
classes = (srv.PROBE_STATUS_BOOL_KEYS | srv.PROBE_STATUS_SOURCE_KEYS
           | srv.PROBE_STATUS_TOKEN_KEYS | srv.PROBE_STATUS_REAL_KEYS
           | srv.PROBE_STATUS_INT_KEYS)
assert classes == keys, (
    "projection classes %r != scheduler keys %r" % (sorted(classes),
                                                    sorted(keys)))
assert len(srv.PROBE_STATUS_KEYS) == len(set(srv.PROBE_STATUS_KEYS)) \
    == len(classes)
EOF
then
    pass "the HTTP probe projection covers the scheduler surface exactly"
else
    fail "the scheduler status surface and the HTTP projection drifted"
fi

# (5) web/ answers with closed shapes only: no diagnostics import on the read
# or persistence side.
if grep -qE '^[[:space:]]*(from|import)[[:space:]]+diagnostics' \
    "$HIST_PY" "$SERVER_PY"; then
    fail "web/ imports the probe package (the boundary must stay shape-only)"
else
    pass "history and server persist/project probe shapes without importing diagnostics/"
fi

# (6) R2-B7/B8: the EXACT-TYPE discipline is structural, not a comment.
# isinstance admits subclasses, bool() coerces, and _as_int() converts -- and
# each of those three is exactly how a lying producer used to be adopted as
# an honest value. The AST sees every call site, so a regression to any of
# them is red even if the runtime table happens to still pass.
if "$PY" - <<'EOF'
import ast, os, sys

FORBIDDEN = {"isinstance", "bool", "_as_int"}
TARGETS = {
    "web/server.py": ("probe_status", "closed_probe_bool",
                      "closed_probe_source", "closed_probe_startup",
                      "closed_probe_seconds", "closed_probe_counter"),
    "web/incident_history.py": ("_closed_code_slot",
                                "_probe_boundary_validate_locked",
                                "_result_is_closed", "_canonical_global_ip",
                                "_derive_egress_change"),
}
root = os.environ["MONITOR_V2_ROOT"]
for rel, names in TARGETS.items():
    tree = ast.parse(open(os.path.join(root, rel), encoding="utf-8").read())
    found = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in names:
            found[node.name] = node
    assert sorted(found) == sorted(names), "missing %s in %s" % (
        sorted(set(names) - set(found)), rel)
    for name, fn in found.items():
        for call in ast.walk(fn):
            if not isinstance(call, ast.Call):
                continue
            func = call.func
            called = getattr(func, "id", None) or getattr(func, "attr", None)
            assert called not in FORBIDDEN, "%s in %s uses %s()" % (
                rel, name, called)
EOF
then
    pass "the probe projection and boundary judge every field by EXACT type"
else
    fail "a probe gate coerces (isinstance/bool/_as_int is back)"
fi

# (7) the boundary's latency wall is the one shared closed-slot matrix, and
# it names an EXACT int: two slots families (timed + egress) go through the
# same function, so a per-slot weakening cannot hide, and _as_int must not
# reappear as the judge.
if "$PY" - <<'EOF'
import ast, os, sys
sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
import web.incident_history as ih

tree = ast.parse(open(os.path.join(
    os.environ["MONITOR_V2_ROOT"], "web", "incident_history.py"),
    encoding="utf-8").read())
body = None
for node in ast.walk(tree):
    if isinstance(node, ast.FunctionDef) and node.name == "_closed_code_slot":
        body = node
assert body is not None, "_closed_code_slot is gone"
text = ast.unparse(body)
assert "type(latency) is not int" in text, "latency is no longer an EXACT int"
assert "_as_int" not in text, "latency is judged by a converter again"
# the ONE shared matrix: four slots, no slot-specific latency branch elsewhere
callers = [node for node in ast.walk(tree)
           if isinstance(node, ast.Call)
           and getattr(node.func, "id", None) == "_closed_code_slot"]
assert len(callers) == 2, "expected the timed-slot and egress call sites"
assert ih.PROBE_LATENCY_MAX_MS == 120000
EOF
then
    pass "latency has ONE exact-int wall shared by the timed and egress slots"
else
    fail "the latency wall stopped being an exact-int, exact-slot judgement"
fi

section "S1: the rollback schema gate, wired and non-mutating"

GATE_LN="$(grep -n 'sbmon_rollback_schema_gate "\$target"' "$INSTALL" | head -1 | cut -d: -f1)"
PRESTATE_LN="$(grep -n 'capture the full pre-state' "$INSTALL" | head -1 | cut -d: -f1)"
if [ -n "$GATE_LN" ] && [ -n "$PRESTATE_LN" ] && [ "$GATE_LN" -lt "$PRESTATE_LN" ]; then
    pass "the rollback gate runs BEFORE any pre-state capture or mutation"
else
    fail "the rollback schema gate is not ordered before the first mutation ($GATE_LN vs $PRESTATE_LN)"
fi
if grep -q '未做任何变更' "$INSTALL"; then
    pass "the refusal states that nothing was mutated"
else
    fail "the rollback refusal does not promise zero mutation"
fi
# Everything the gate reads lives between its first helper and the next
# section; that whole region is asserted to be write-free, so "read-only" is
# a property of the code, not of the run that happened to exercise it.
GATE_BLOCK="$(awk '/^sbmon_history_db_path\(\)/,/^sboxjr_log\(\)/' "$LIB")"
if [ -z "$GATE_BLOCK" ]; then
    fail "the rollback gate helper region could not be located"
elif printf '%s\n' "$GATE_BLOCK" \
        | grep -qE 'INSERT|UPDATE|DELETE|PRAGMA|executescript|\.commit\(|migrate'; then
    fail "a rollback-gate reader can issue a write statement"
else
    pass "no rollback-gate helper can issue a write statement"
fi
if [ "$(printf '%s\n' "$GATE_BLOCK" | grep -c 'mode=ro')" = "1" ] \
    && printf '%s\n' "$GATE_BLOCK" | grep -q 'uri=True'; then
    pass "the live database is opened through a read-only uri, exactly once"
else
    fail "the rollback-gate schema reader is not strictly read-only"
fi
if printf '%s\n' "$GATE_BLOCK" \
    | grep -q 'sys.path = \[p for p in sys.path if p not in'; then
    pass "the target-release reader answers from that release, never the caller's tree"
else
    fail "the target-release reader can import the caller's working set"
fi
if grep -qE '^[[:space:]]*sbmon_rollback_schema_gate \|\| sbmon_die' "$INSTALL" \
    || grep -qE 'if ! sbmon_rollback_schema_gate' "$INSTALL"; then
    pass "the gate result is die-checked, never advisory"
else
    fail "the rollback gate is not fail-closed at the call site"
fi

# -- function-level proofs on real files --------------------------------------
# The gate reads exactly two things: the LIVE database's declared
# schema_version and the TARGET release's own declaration (that release
# answers for itself, by import, not by a text scrape). Driving the function
# directly here proves every decision, both readers and the zero-mutation
# promise against real files; the end-to-end `install-monitor.sh rollback`
# refusal rides the packaging lane's full deploy fixture.
FIX="$TMP/rb"
REL="$FIX/releases"
STATE="$FIX/state"
mkdir -p "$STATE/diagnostics" "$REL"
DB="$STATE/diagnostics/history.sqlite3"

make_release() { # <id> <SCHEMA_VERSION value | none>
    local dir="$REL/$1/app/monitor-v2/web"
    mkdir -p "$dir"
    : > "$dir/__init__.py"
    if [ "$2" != "none" ]; then
        printf 'SCHEMA_VERSION = %s\n' "$2" > "$dir/incident_history.py"
    fi
}
make_release v2 2
make_release v3 3
make_release v4 4
make_release prehistory none

seed_db() { # <value | nometa | garbage>
    rm -f "$DB"
    if [ "$1" = "garbage" ]; then
        printf 'this is not a database at all\n' > "$DB"
        return 0
    fi
    "$PY" - "$DB" "$1" <<'PY'
import sqlite3, sys
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE meta (key TEXT NOT NULL PRIMARY KEY, value TEXT NOT NULL)")
if sys.argv[2] != "nometa":
    c.execute("INSERT INTO meta VALUES ('schema_version', ?)", (sys.argv[2],))
c.commit()
c.close()
PY
}
db_hash() { sha256sum "$DB" 2>/dev/null | cut -d' ' -f1; }
state_files() { ls -A "$STATE/diagnostics" 2>/dev/null | LC_ALL=C sort | tr '\n' '+'; }

# The gate's own live reader, driven standalone: one env pair, no mutation.
live_reader() {
    SBMON_STATE_ROOT="$STATE" SBMON_PYTHON3="$PY" SBMON_FIXTURE=1 \
    "$BASH" -c '
        set -uo pipefail
        . "'"$LIB"'" >/dev/null 2>&1
        set +euo pipefail
        sbmon_history_db_schema_version
    ' 2>/dev/null
}

run_gate() { # <target> -> sets RB_RC + RB_OUT (no subshell: the rc must survive)
    SBMON_STATE_ROOT="$STATE" SBMON_RELEASES_DIR="$REL" \
    SBMON_PYTHON3="$PY" SBMON_FIXTURE=1 \
    "$BASH" -c '
        set -uo pipefail
        . "'"$LIB"'" >/dev/null 2>&1
        set +euo pipefail
        sbmon_rollback_schema_gate "'"$1"'"
    ' >"$TMP/gate.log" 2>&1
    RB_RC=$?
    RB_OUT="$(cat "$TMP/gate.log")"
}

section "S2: rollback gate decisions on real files"

seed_db 3
HASH_BEFORE="$(db_hash)"
FILES_BEFORE="$(state_files)"
run_gate v3
assert_eq "$RB_RC" "0" "live v3 -> a v3 target is allowed"
run_gate v4
assert_eq "$RB_RC" "0" "live v3 -> a NEWER target is allowed (forward is a deploy, not a rollback)"
run_gate v2
assert_eq "$RB_RC" "1" "live v3 -> a v2 target is refused"
if printf '%s' "$RB_OUT" | grep -q 'v2' && printf '%s' "$RB_OUT" | grep -q 'v3'; then
    pass "the refusal states both integer versions"
else
    fail "the refusal does not state the versions: $RB_OUT"
fi
if printf '%s' "$RB_OUT" | grep -qF "$TMP" || printf '%s' "$RB_OUT" | grep -qF "$ROOT"; then
    fail "the refusal leaked a filesystem path: $RB_OUT"
else
    pass "the refusal names no path, only versions"
fi
assert_eq "$HASH_BEFORE" "$(db_hash)" "the read-only gate mutated zero bytes"
assert_eq "$FILES_BEFORE" "$(state_files)" "the read-only gate created no side file (-wal/-shm/journal)"
run_gate prehistory
assert_eq "$RB_RC" "1" "a release that predates the history module is refused"
run_gate nosuchrelease
assert_eq "$RB_RC" "1" "a target release directory that is absent is refused"

seed_db 2
run_gate v3
assert_eq "$RB_RC" "0" "live v2 -> a v3 target is allowed (the old database is readable)"
seed_db nometa
run_gate v3
assert_eq "$RB_RC" "1" "a database that claims no version is refused"
seed_db abc
run_gate v3
assert_eq "$RB_RC" "1" "a non-numeric version claim is refused, never guessed"
seed_db -- -1
run_gate v3
assert_eq "$RB_RC" "1" "a negative version claim is refused"
seed_db garbage
run_gate v3
assert_eq "$RB_RC" "1" "a file that is not a database is refused, not adopted"

# and the same decisions against a REAL v3 database, built by the module under
# review: the reader is proven against the production meta row, not a fixture
# that only looks like one
rm -f "$DB"
if "$PY" - "$STATE/diagnostics" "$ROOT/monitor-v2" <<'PY'
import os, sys
sys.path.insert(0, sys.argv[2])
from web.incident_history import IncidentHistory
h = IncidentHistory(sys.argv[1], "c" * 32, monitor_version="test")
h.open()
assert h.health()["enabled"], h.health()
h.close()
PY
then
    pass "the module under review still builds a v3 database at the live path"
else
    fail "could not build a real v3 database for the rollback gate"
fi
assert_eq "3" "$(live_reader)" "the gate's live reader parses the production meta row"
run_gate v3
assert_eq "$RB_RC" "0" "real v3 database -> a v3 target is allowed"
run_gate v2
assert_eq "$RB_RC" "1" "real v3 database -> a v2 target is refused (the shipped v3 table is unreadable there)"

rm -f "$DB"
run_gate v3
assert_eq "$RB_RC" "0" "no database at all means there is nothing to protect"
assert_eq "$(find "$STATE/diagnostics" -mindepth 1 | grep -c .)" "0" \
    "the gate created no database and no side files when none existed"
# Importing a release's own module is part of reading it, and an ordinary
# import writes __pycache__ INSIDE the release tree: a "read-only" precondition
# that creates files is a mutator. -B is therefore contract, not cosmetics.
# Measured over the WHOLE fixture, so a cache nested anywhere under a release
# counts, and a passing run proves zero.
assert_eq "$(find "$REL" -name '__pycache__' -type d 2>/dev/null | grep -c .)" \
    "0" "the target-release reader left no bytecode cache inside any release tree"


section "S3: the packaged opt-in path is deploy/'s only probe surface"
# B4: the opt-in used to be an environment variable that NO shipped unit ever
# supplied, so the frozen production path was unreachable on a real host --
# a reviewer-approved machine could not turn probing on persistently without
# inventing its own plumbing. The packaged monitor unit now names the PATH,
# the OPERATOR supplies the FILE, and nothing in the release tree can create
# the file, read it, or switch probing on by omission.
RENDERED="$TMP/rendered-monitor.unit"
if bash -c '. "$1" >/dev/null 2>&1; sbmon_render_unit > "$2"' _ "$LIB" "$RENDERED" \
    && [ -s "$RENDERED" ]; then
    pass "the packaged monitor unit renders through the deploy lib"
else
    fail "sbmon_render_unit could not render the monitor unit"
fi
if [ "$(grep -c '^Environment=' "$RENDERED")" = "1" ] \
    && grep -q '^Environment=SINGBOX_MONITOR_PROBE_TARGETS_FILE=' "$RENDERED"; then
    pass "the unit carries exactly one Environment= line, and it is the opt-in path"
else
    fail "the unit grew an Environment= knob: $(grep '^Environment=' "$RENDERED")"
fi
if grep -q "^Environment=SINGBOX_MONITOR_PROBE_TARGETS_FILE=$( \
        bash -c '. "$1" >/dev/null 2>&1; sbmon_probe_targets_file' _ "$LIB")$" \
        "$RENDERED" \
    && ! grep -q '@SBMON_' "$RENDERED"; then
    pass "the opt-in path is \$SBMON_CONF_DIR/probe-targets.json, fully substituted"
else
    fail "the rendered opt-in path is not the frozen conf-dir file, or a token is left"
fi
# The installer verifies the path and never writes it: no redirection, no
# touch, no rm, no content read anywhere in deploy/ against that file.
TARGETS_BLOCK="$(awk '/^sbmon_verify_probe_targets\(\)/,/^}/' "$LIB")"
if [ -z "$TARGETS_BLOCK" ]; then
    fail "the probe-targets verifier could not be located"
elif printf '%s\n' "$TARGETS_BLOCK" \
        | grep -qE '>[^&]|\b(touch|rm|cat|tee|cp|mv|install)\b'; then
    fail "the deploy verifier writes to the operator's opt-in file"
else
    pass "deploy/ verifies the opt-in file's shape and modes, and never writes it"
fi
if grep -rqE 'probe-targets' "$INSTALL" "$ROOT/monitor-v2/deploy/app-bin" \
    "$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in"; then
    fail "a shipped surface names or creates the opt-in document"
else
    pass "no installer, entrypoint or reader unit names the opt-in document"
fi
# The verification runs BEFORE anything is staged, like the P6 secret
# delivery: a defective opt-in file must abort with nothing changed.
PT_LN="$(grep -n 'sbmon_verify_probe_targets$' "$INSTALL" | head -1 | cut -d: -f1)"
STAGE_LN="$(grep -n 'sbmon_stage_release' "$INSTALL" | head -1 | cut -d: -f1)"
if [ -n "$PT_LN" ] && [ -n "$STAGE_LN" ] && [ "$PT_LN" -lt "$STAGE_LN" ]; then
    pass "the opt-in path is verified before any release is staged"
else
    fail "the opt-in verification is not ordered before staging (line $PT_LN vs $STAGE_LN)"
fi
# The generated monitor.conf and its strict KEY=VALUE reader are the only
# operator-tunable surface. Neither may be able to express a probe knob: the
# cadence and the target set stay a code review, not a config edit. The gate
# reads KEY NAMES, not prose, because the conf legitimately documents other
# cadences (the dashboard poll).
CONF_BLOCK="$(awk '/^sbmon_write_default_conf\(\)/,/^}/' "$LIB")"
if [ -z "$CONF_BLOCK" ]; then
    fail "the default monitor.conf writer could not be located"
elif printf '%s\n' "$CONF_BLOCK" | grep -oE '^[A-Z_]+=' \
        | grep -qE 'PROBE|CADENCE|TARGET'; then
    fail "the generated monitor.conf has a probe key"
else
    pass "the generated monitor.conf has no probe key"
fi
if printf '%s\n' "$CONF_BLOCK" | grep -oE '^[A-Z_]+=' | grep -q '.'; then
    pass "the generated monitor.conf keys are enumerable (the gate is not vacuous)"
else
    fail "no monitor.conf key could be read -- the probe-knob gate proved nothing"
fi
if printf '%s\n' "$(grep -oE '^[[:space:]]*SBMON_[A-Z_]+\)' \
        "$ROOT/monitor-v2/deploy/app-bin/monitor-env.sh")" \
        | grep -qE 'PROBE|CADENCE|TARGET'; then
    fail "the conf reader's closed allowlist has grown a probe key"
else
    pass "the conf reader cannot deliver a probe key to the service"
fi
# The app wires the scheduler with NO caller-supplied cadence or targets: the
# frozen defaults are the only production shape, and one construction exists.
if [ "$(grep -c 'ProbeScheduler(' "$WEBAPP")" = "1" ] \
    && grep -qE 'ProbeScheduler\(history\)' "$WEBAPP" \
    && ! grep -qE 'cadence_seconds|startup_delay_seconds|targets=' "$WEBAPP"; then
    pass "webapp constructs ProbeScheduler(history) with no cadence or target argument"
else
    fail "the app can pass its own cadence/targets to the scheduler"
fi
# The scheduler's whole filesystem surface is one read of the opt-in file.
if "$PY" - "$SCHED" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
opens, dangerous = [], ("mkdir", "makedirs", "remove", "unlink", "rmdir",
                        "rename", "replace", "chmod", "chown")
for node in ast.walk(tree):
    if isinstance(node, ast.Call):
        func = node.func
        name = getattr(func, "attr", None) or getattr(func, "id", "")
        if name == "open":
            mode = "r"
            for keyword in node.keywords:
                if keyword.arg == "mode" and isinstance(
                        keyword.value, ast.Constant):
                    mode = keyword.value.value
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            opens.append(mode)
        if name in dangerous:
            raise AssertionError("scheduler calls %s()" % name)
assert len(opens) == 1, "expected exactly one open(), got %r" % (opens,)
assert opens == ["r"], "the opt-in file must be opened read-only, got %r" % opens
for banned in ("sqlite3", "shutil", "logging"):
    src = open(sys.argv[1], encoding="utf-8").read()
    assert ("import %s" % banned) not in src, "scheduler imports %s" % banned
EOF
then
    pass "the scheduler opens exactly one file, read-only, and imports no writer"
else
    fail "the scheduler's filesystem surface is not a single read"
fi
# Every address the harness can hand to a socket API is loopback. The suite's
# own IP-literal REJECTION table names 0.0.0.0 as data to refuse, so a text
# grep would prove nothing; the AST sees only real call sites. S4/S5 enforce
# the same promise at runtime, below every abstraction.
if "$PY" - "$HARNESS" <<'EOF'
import ast, sys
SOCKET_CALLS = ("ThreadingHTTPServer", "HTTPServer", "HTTPConnection",
                "HTTPSConnection", "create_connection", "sendto")
bad = []
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
for node in ast.walk(tree):
    if not isinstance(node, ast.Call):
        continue
    name = getattr(node.func, "attr", None) or getattr(node.func, "id", "")
    if name not in SOCKET_CALLS or not node.args:
        continue
    first = node.args[0]
    host = first.elts[0] if (isinstance(first, ast.Tuple) and first.elts) \
        else first
    if isinstance(host, ast.Constant) and isinstance(host.value, str):
        if host.value != "127.0.0.1":
            bad.append((node.lineno, name, host.value))
assert not bad, "non-loopback socket call sites: %r" % (bad,)
EOF
then
    pass "every socket call site in the harness is 127.0.0.1"
else
    fail "the harness has a non-loopback socket call site"
fi
assert_eq '0.3.1' "$(cat "$ROOT/monitor-v2/VERSION")" \
    "VERSION is 0.3.1 for the functional-review head"
if grep -q 'MONITOR_WEB_VERSION = "0.3.1"' "$SERVER_PY"; then
    pass "MONITOR_WEB_VERSION is 0.3.1"
else
    fail "MONITOR_WEB_VERSION moved off 0.3.1"
fi
if grep -q 'test-monitor-v2-probe-ingest.sh' "$ROOT/.github/workflows/tests.yml" \
    && grep -q 'bash -n tests/test-monitor-v2-probe-ingest.sh' \
        "$ROOT/.github/workflows/tests.yml"; then
    pass "suite is registered in CI (bash -n + monitor-regression)"
else
    fail "suite is NOT registered in tests.yml"
fi

section "S4: the CI network guard refuses by construction"
map_verdicts() { # <file> -> count every PASS/FAIL verdict line it holds
    while IFS= read -r line; do
        case "$line" in
            PASS\ *) pass "${line#PASS }" ;;
            FAIL\ *) fail "${line#FAIL }" ;;
            *) [ -n "$line" ] && printf '  ? %s\n' "$line" ;;
        esac
    done < "$1"
}

# A guard that refuses nothing is worse than no guard, so it proves its own
# discrimination before anything runs under it.
"$PY" "$GUARD" --self-test >"$TMP/guard.log" 2>&1
GUARD_RC=$?
map_verdicts "$TMP/guard.log"
if [ "$GUARD_RC" -ne 0 ]; then
    fail "the network guard self-test exited rc=$GUARD_RC"
fi

section "S5: behaviour groups under the guard (real SQLite, real threads, loopback TLS)"
# Every check below runs with public traffic refused at the audit layer: a
# leak is a crash, and a crash is a FAIL, so CI can never probe a public host.
"$PY" "$GUARD" "$HARNESS" >"$TMP/groups.log" 2>&1
RC=$?
map_verdicts "$TMP/groups.log"
if [ "$RC" -ne 0 ]; then
    fail "probe_ingest_groups.py exited rc=$RC under the guard (a crashing or leaking harness is itself a gate)"
    tail -20 "$TMP/groups.log"
fi

section "RESULT"
printf 'checks: %d passed, %d failed (expected %d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '== PR-3B probe-ingest suite: FAILED ==\n'
    exit 1
fi
printf '== PR-3B probe-ingest suite: GREEN ==\n'
exit 0
