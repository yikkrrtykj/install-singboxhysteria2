#!/usr/bin/env bash
# Monitor 0.3.x -- outbound probe engine (issue #33 Phase 3, PR-3A) suite.
#
# PR-3A is a DARK delivery: the engine and this suite must prove (a) the
# closed output contract with TRUE discriminators (anti-false-positive UDP
# round trip, TLS verification that cannot be off, proxy-env bypass,
# sentinel privacy, deadline/hang isolation), and (b) that NO production
# surface calls the module: repo-wide reference scan, the release staging
# manifest, the systemd units, the app-bin entrypoints and VERSION all
# stay byte-identical to the dark contract.
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
EXPECTED_PASS=97

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

if [ -z "$PY" ]; then
    printf '  python3 unavailable -- hard gate, failing closed\n'
    printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$((FAIL + 1))"
    exit 1
fi

MODULE="$ROOT/monitor-v2/diagnostics/network_probes.py"
PROBE_GROUPS="$HERE/monitor-probes/probe_groups.py"

section "S0: static + DARK gates"

if "$PY" -m py_compile "$MODULE" "$ROOT/monitor-v2/diagnostics/__init__.py" \
    "$PROBE_GROUPS" 2>"$HERE/../.probe-py.err"; then
    pass "py_compile diagnostics package + groups"
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
allowed = {"http","ipaddress","socket","ssl","struct","threading","time",
           "uuid","dataclasses","__future__"}
mods = {m for m in sys.argv[1].split(",") if m}
bad = mods - allowed
sys.exit(1 if bad else 0)' "$IMPORTS"; then
            pass "stdlib-only import whitelist ($IMPORTS)"
        else
            fail "import outside the reviewed whitelist: $IMPORTS"
        fi ;;
esac

if grep -nE '^\s*(import logging|from logging|print\()' "$MODULE" >/dev/null; then
    fail "network_probes must be silent: logging/print found"
else
    pass "module carries zero logging/print surface"
fi

# -- DARK: no production invocation anywhere ---------------------------------
REFS="$(grep -rl --include='*.py' --include='*.sh' --include='*.in' \
    --exclude-dir=__pycache__ --exclude-dir=diagnostics \
    'network_probes' "$ROOT/monitor-v2" || true)"
if [ -z "$REFS" ]; then
    pass "no monitor-v2 file outside diagnostics/ mentions network_probes"
else
    fail "production reference to network_probes: $(printf '%s' "$REFS")"
fi
for f in webapp.py web/broker.py web/server.py web/incident_history.py \
    collector.py; do
    if grep -q 'network_probes' "$ROOT/monitor-v2/$f" 2>/dev/null; then
        fail "$f references network_probes"
    else
        pass "$f carries no probe reference"
    fi
done
for f in deploy/lib/monitor-deploy-lib.sh deploy/singbox-monitor.service.in \
    deploy/singbox-journal-reader.service.in; do
    if grep -qE 'network_probes|diagnostics/' "$ROOT/monitor-v2/$f" \
        2>/dev/null; then
        fail "$f references the probe engine / diagnostics package"
    else
        pass "$f stays out of the probe surface"
    fi
done
if grep -rqq 2>/dev/null; then :; fi  # (no-op guard against grep flag drift)
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
