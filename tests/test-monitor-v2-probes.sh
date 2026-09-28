#!/usr/bin/env bash
# Monitor 0.3.x -- outbound probe engine (issue #33 Phase 3, PR-3A engine +
# PR-3B activation) suite.
#
# PR-3A delivered the engine DARK; PR-3B activates it, and this suite must
# prove (a) the closed output contract with TRUE discriminators (the
# anti-false-positive UDP round trip bound to the configured peer AND the
# exact question, TLS verification that cannot be off, proxy-env bypass,
# sentinel privacy, absolute per-worker deadlines that reject every late
# outcome, ONE outstanding worker per slot with reservation+start atomic
# under the same lock (concurrent cycles cannot double-claim), hung workers
# cannot accumulate, an entry point that never raises, caller cycle_ids
# admitted ONLY as exact lowercase 32-hex, and egress.ip global-only
# end-to-end with no relaxation knob), and (b) that the ACTIVATION stays
# narrow: ONE importing caller (webapp.py -> ProbeScheduler), no other
# runtime module importing diagnostics/, the staging manifest naming and
# auditing the diagnostics trio EXACTLY, no probe knob in the systemd units,
# the opt-in variable named by the scheduler alone and no reviewed endpoint
# literal outside diagnostics/. The scheduler's own behaviour (dark default,
# fail-closed injection, cadence, durability) is PR-3B's
# test-monitor-v2-probe-ingest.sh.
#
# Every fake server binds 127.0.0.1 only: zero public network dependency,
# so this lane runs identically on any runner. The TCP-refusal
# discriminator is strict on Linux (the CI gate); dev machines whose TUN
# proxies swallow loopback SYNs accept the weaker union there -- the note
# in probe_groups.py C7 carries the reason.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export PROBE_TEST_CERT="$HERE/monitor-probes/tls-test-cert.pem"
export PROBE_TEST_KEY="$HERE/monitor-probes/tls-test-key.pem"

PASS=0
FAIL=0
# PR-3B (activation): 126 -> 138 = +12. Nothing previously counted was
# removed. Breakdown: +1 scheduler stdlib-import whitelist; the DARK scan
# (10 checks: reference scan, 5 per-file no-reference, 3 deploy-surface
# no-reference, app-bin) was REPLACED in place by the 21-check ACTIVATION
# scan (+11): engine-named-outside-diagnostics EXACT set, webapp import,
# 3 wiring patterns, 2 lifecycle orderings, 5 per-file no-import, the
# mirrored-vocabulary comment, manifest trio, exact-set audit, staged
# py_compile membership, 2 unit knobs, opt-in variable locality, endpoint
# literal locality, app-bin.
EXPECTED_PASS=138

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

if [ -z "$PY" ]; then
    printf '  python3 unavailable -- hard gate, failing closed\n'
    printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$((FAIL + 1))"
    exit 1
fi

MODULE="$ROOT/monitor-v2/diagnostics/network_probes.py"
SCHEDULER="$ROOT/monitor-v2/diagnostics/probe_scheduler.py"
PROBE_GROUPS="$HERE/monitor-probes/probe_groups.py"

section "S0: static + activation gates"

if "$PY" -m py_compile "$MODULE" "$SCHEDULER" \
    "$ROOT/monitor-v2/diagnostics/__init__.py" \
    "$PROBE_GROUPS" 2>"$HERE/../.probe-py.err"; then
    pass "py_compile diagnostics package (engine + scheduler) + groups"
else
    fail "py_compile: $(cat "$HERE/../.probe-py.err" 2>/dev/null)"
fi
rm -f "$HERE/../.probe-py.err"

IMPORTS="$("$PY" - "$MODULE" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
mods = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        mods.update(a.name.split(".")[0] for a in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        mods.add(node.module.split(".")[0])
print(",".join(sorted(mods)))
EOF
)"
case ",$IMPORTS," in
    *,requests,*|*,aiohttp,*|*,httpx,*|*,urllib3,*|*,certifi,*|*,dns,*)
        fail "third-party/non-stdlib network dependency: $IMPORTS" ;;
    *)
        if "$PY" -c '
import sys
allowed = {"http","ipaddress","re","socket","ssl","struct","threading",
           "time","uuid","dataclasses","__future__"}
mods = {m for m in sys.argv[1].split(",") if m}
bad = mods - allowed
sys.exit(1 if bad else 0)' "$IMPORTS"; then
            pass "stdlib-only import whitelist ($IMPORTS)"
        else
            fail "import outside the reviewed whitelist: $IMPORTS"
        fi ;;
esac
# PR-3B: the scheduler answers to the SAME discipline, with exactly two
# additions -- "json" (the injection file) and "diagnostics" (the engine).
# Nothing else may appear: no web/, no deploy/, no third-party name.
SCHED_IMPORTS="$("$PY" - "$SCHEDULER" <<'EOF'
import ast, sys
tree = ast.parse(open(sys.argv[1], encoding="utf-8").read())
mods = set()
for node in ast.walk(tree):
    if isinstance(node, ast.Import):
        mods.update(a.name.split(".")[0] for a in node.names)
    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
        mods.add(node.module.split(".")[0])
print(",".join(sorted(mods)))
EOF
)"
case ",$SCHED_IMPORTS," in
    *,requests,*|*,aiohttp,*|*,httpx,*|*,urllib3,*|*,certifi,*)
        fail "scheduler imports a third-party dependency: $SCHED_IMPORTS" ;;
    *)
        if "$PY" -c '
import sys
allowed = {"http","json","os","threading","time","dataclasses",
           "__future__","diagnostics"}
mods = {m for m in sys.argv[1].split(",") if m}
bad = mods - allowed
sys.exit(1 if bad else 0)' "$SCHED_IMPORTS"; then
            pass "scheduler stdlib-only import whitelist ($SCHED_IMPORTS)"
        else
            fail "scheduler import outside its reviewed whitelist: $SCHED_IMPORTS"
        fi ;;
esac

if grep -nE '^\s*(import logging|from logging|print\()' "$MODULE" >/dev/null; then
    fail "network_probes must be silent: logging/print found"
else
    pass "module carries zero logging/print surface"
fi

# -- ACTIVATION (PR-3B): one reviewed caller, opt-in only, narrow surface ----
# PR-3A shipped the engine DARK. PR-3B activates it through exactly ONE
# production module (diagnostics/probe_scheduler.py) that webapp.py owns, and
# persists its closed results through the history v3 boundary. These gates are
# the deliberate inverse of the old dark scan: each one names the surface it
# keeps narrow, so a future round cannot widen the probe blast radius without
# editing a gate on purpose.

# (1) the engine is named OUTSIDE diagnostics/ by exactly two files: the
# staging manifest that ships it, and the history module's documented
# closed-vocabulary mirror comment (gate (3) proves that comment is the whole
# story -- web/ never imports diagnostics/).
REFS="$(grep -rl --include='*.py' --include='*.sh' --include='*.in' \
    --exclude-dir=__pycache__ --exclude-dir=diagnostics \
    'network_probes' "$ROOT/monitor-v2" | sed "s|^$ROOT/monitor-v2/||" \
    | LC_ALL=C sort | tr '\n' ' ')"
if [ "$REFS" = "deploy/lib/monitor-deploy-lib.sh web/incident_history.py " ]; then
    pass "engine named outside diagnostics/ only by the manifest + the mirrored vocabulary"
else
    fail "network_probes named outside diagnostics/ (want manifest + history mirror only): $(printf '%s' "$REFS")"
fi

# (2) webapp.py is the single activation point, in the right order.
if grep -q '^from diagnostics\.probe_scheduler import ProbeScheduler' \
    "$ROOT/monitor-v2/webapp.py"; then
    pass "webapp.py imports the scheduler (the one activation point)"
else
    fail "webapp.py does not import the scheduler"
fi
for pat in 'ProbeScheduler(history)' 'probes.start()' 'probes.stop()'; do
    if grep -qF -- "$pat" "$ROOT/monitor-v2/webapp.py"; then
        pass "webapp.py wires: $pat"
    else
        fail "webapp.py missing wiring: $pat"
    fi
done
OPEN_LN="$(grep -n 'history\.open()' "$ROOT/monitor-v2/webapp.py" | head -1 | cut -d: -f1)"
START_LN="$(grep -n 'probes\.start()' "$ROOT/monitor-v2/webapp.py" | head -1 | cut -d: -f1)"
STOP_LN="$(grep -n 'probes\.stop()' "$ROOT/monitor-v2/webapp.py" | head -1 | cut -d: -f1)"
CLOSE_LN="$(grep -n 'history\.close()' "$ROOT/monitor-v2/webapp.py" | head -1 | cut -d: -f1)"
if [ -n "$OPEN_LN" ] && [ -n "$START_LN" ] && [ "$START_LN" -gt "$OPEN_LN" ]; then
    pass "the scheduler starts only AFTER the history store is open"
else
    fail "scheduler start is not ordered after history.open()"
fi
if [ -n "$STOP_LN" ] && [ -n "$CLOSE_LN" ] && [ "$STOP_LN" -lt "$CLOSE_LN" ]; then
    pass "the scheduler stops BEFORE the history store closes"
else
    fail "scheduler stop is not ordered before history.close()"
fi

# (3) no other runtime module imports the probe package: the DB boundary
# mirrors CLOSED SHAPES, it never gains an engine dependency.
for f in web/broker.py web/server.py web/incident_history.py web/storage.py \
    collector.py; do
    if grep -qE '^[[:space:]]*(from|import)[[:space:]]+diagnostics' \
        "$ROOT/monitor-v2/$f" 2>/dev/null; then
        fail "$f imports the probe package"
    else
        pass "$f never imports diagnostics/"
    fi
done
if grep -q 'Mirror of the PR-3A closed vocabulary' \
    "$ROOT/monitor-v2/web/incident_history.py"; then
    pass "history mirrors the closed probe vocabulary WITHOUT importing it"
else
    fail "the history mirror comment moved: the duplicate vocabulary is unexplained"
fi

# (4) staging: the diagnostics trio is named EXACTLY, audited EXACTLY, and
# syntax-validated as part of the staged runtime.
LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"
if grep -qF 'DIAGNOSTICS_MODULE_FILES=(__init__.py network_probes.py probe_scheduler.py)' \
    "$LIB"; then
    pass "staging manifest names the diagnostics trio exactly"
else
    fail "DIAGNOSTICS_MODULE_FILES is not the reviewed trio"
fi
if grep -qE '^sbmon_diagnostics_audit\(\)' "$LIB" \
    && grep -qE '^[[:space:]]*sbmon_diagnostics_audit "\$staged/\$DIAGNOSTICS_REL"' "$LIB"; then
    pass "staging audits the diagnostics set EXACT (defined and called)"
else
    fail "the diagnostics exact-set audit is missing or uncalled"
fi
if grep -qF '"$staged/$DIAGNOSTICS_REL/"*.py' "$LIB"; then
    pass "staged diagnostics modules join the py_compile validation set"
else
    fail "staged diagnostics modules are not syntax-validated"
fi

# (5) the systemd units stay probe-free: nothing about probing is a unit-level
# knob, and the opt-in variable is named by the scheduler alone.
for f in deploy/singbox-monitor.service.in \
    deploy/singbox-journal-reader.service.in; do
    if grep -qE 'network_probes|probe_scheduler|PROBE_TARGETS' \
        "$ROOT/monitor-v2/$f" 2>/dev/null; then
        fail "$f mentions probing (units carry no probe knob)"
    else
        pass "$f carries no probe knob"
    fi
done
TVAR="$(grep -rl --include='*.py' --include='*.sh' --include='*.in' \
    --exclude-dir=__pycache__ 'SINGBOX_MONITOR_PROBE_TARGETS_FILE' \
    "$ROOT/monitor-v2" || true)"
if [ "$TVAR" = "$ROOT/monitor-v2/diagnostics/probe_scheduler.py" ]; then
    pass "the opt-in variable is named only by the scheduler"
else
    fail "the opt-in variable leaks outside the scheduler: $(printf '%s' "$TVAR")"
fi
# (6) no reviewed public endpoint literal anywhere outside diagnostics/.
LEAK="$(grep -rl --include='*.py' --include='*.sh' --include='*.js' \
    --include='*.html' --exclude-dir=__pycache__ --exclude-dir=diagnostics \
    -E 'api\.ipify\.org|one\.one\.one\.one' "$ROOT/monitor-v2" || true)"
if [ -z "$LEAK" ]; then
    pass "no production endpoint literal outside diagnostics/"
else
    fail "endpoint literal outside diagnostics/: $(printf '%s' "$LEAK")"
fi
for f in "$ROOT"/monitor-v2/deploy/app-bin/*; do
    if grep -q 'network_probes' "$f" 2>/dev/null; then
        fail "entrypoint $(basename "$f") invokes network_probes"
    fi
done
pass "app-bin entrypoints invoke no probe module"

VERSION_NOW="$(cat "$ROOT/monitor-v2/VERSION")"
if [ "$VERSION_NOW" = "0.3.1" ]; then
    pass "VERSION still 0.3.1 (no bump in PR-3A)"
else
    fail "VERSION moved off 0.3.1: $VERSION_NOW"
fi

if grep -q 'test-monitor-v2-probes.sh' "$ROOT/.github/workflows/tests.yml" \
    && grep -q 'bash -n tests/test-monitor-v2-probes.sh' \
        "$ROOT/.github/workflows/tests.yml"; then
    pass "suite is registered in CI (bash -n + monitor-regression)"
else
    fail "suite is NOT registered in tests.yml"
fi

if "$PY" - <<'EOF'
import os, ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(os.environ["PROBE_TEST_CERT"], os.environ["PROBE_TEST_KEY"])
EOF
then
    pass "TLS test fixture loads (throwaway loopback-only certificate)"
else
    fail "TLS test fixture missing/unloadable"
fi

section "S1..S8: behaviour groups (loopback fakes)"
GROUP_OUT="$("$PY" "$PROBE_GROUPS" 2>&1)"
RC=$?
while IFS= read -r line; do
    case "$line" in
        PASS\ *) pass "${line#PASS }" ;;
        FAIL\ *) fail "${line#FAIL }" ;;
        *) [ -n "$line" ] && printf '  ? %s\n' "$line" ;;
    esac
done <<< "$GROUP_OUT"
if [ "$RC" -ne 0 ]; then
    fail "probe_groups.py exited rc=$RC (crash containment is itself a gate)"
fi

section "RESULT"
printf 'checks: %d passed, %d failed (expected %d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '== PR-3A probe suite: FAILED ==\n'
    exit 1
fi
printf '== PR-3A probe suite: GREEN ==\n'
exit 0
