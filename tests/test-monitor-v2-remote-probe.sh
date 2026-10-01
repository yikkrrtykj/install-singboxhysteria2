#!/usr/bin/env bash
# Monitor 0.6.1 -- P6A dark office remote-probe agent suite (issue #67 PR-6A).
#
# PR-6A ships the office-side agent DARK: new namespace monitor-v2/remote_probe/,
# no server ingest route, no server database, no History/classifier/UI/deploy
# change and NO version bump. This lane owns four properties:
#
#   1. THE AGENT IS COMPLETE AND HONEST. Every contract rule that can be proven
#      without a live server is proven deterministically in
#      tests/remote-probe/probe_groups.py against injected transports and
#      clocks: explicit Reality/HY2 roles (never name-inferred), the four
#      closed active outcomes with delay-0 as FAILURE, a missing configured
#      node as `invalid` (configuration, never path failure), the <=5 s per-node
#      and <=20 s per-cycle budgets, no overlapping cycles, the >=30 s minimum
#      cadence, loopback-only controller parsing, a structurally GET-only
#      Mihomo surface, bounded DNS/HTTPS/TCP/egress slots with transport-only
#      TCP labelling and NO unauthenticated-UDP verdict, the canonical-body +
#      HMAC vector, run/seq grammar and clock-rollback rules, the durable spool
#      (spool-before-ack, torn tail, rotation, symlink/special/mode refusals,
#      7-day / 32 MiB bounds), the total response-disposition matrix, HTTPS-only
#      non-loopback ingest, and the secret leak wall.
#   2. REUSE, NOT FORK. The audited E4/adapter files are BYTE-IDENTICAL: their
#      sha256 is pinned here (over LF-normalised bytes, so a CRLF working copy
#      and the CI checkout agree), so a P6 edit that quietly forked the
#      transport or the secret-file discipline fails this gate instead of
#      passing review.
#   3. THE RED LINES HOLD. No server ingest route, no remote database, History
#      still schema v5 on the eleven-table shape with its six prune sources, no
#      remote reference in the classifier / incident runtime / presenter, and
#      the release identity is unchanged at 0.6.1.
#   4. THE LANE IS WIRED. A suite nobody runs cannot fail.
#
# Deterministic by construction: no Internet, no real Mihomo, no VPS, no
# production server, no timing-sensitive external behaviour.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"

PASS=0
FAIL=0
# Measured on the dev host (Windows, Python 3.14) and re-measured on Linux CI:
# Measured on the dev host (Windows, Python 3.14) and re-measured on Linux CI:
# Measured on the dev host (Windows, Python 3.14) and re-measured on Linux CI:
# 226 = S0 static + red-line gates 19 (py_compile of the package + harness, the
# in-module reuse documentation, the FOUR frozen sha256 pins that prove the
# audited E4 client/model/diag/README were reused and never forked, the E4
# file-set check, the unchanged release identity 0.6.1 in both places, History
# still v5 with its six prune sources and no remote table, the three P4/P5
# modules free of any remote reference, the absent server ingest route, the
# absent server remote store, and the two CI registrations) + S1 harness 206
# verdicts across ELEVEN groups plus the harness rc gate. The RESILIENCE group
# (38 verdicts) pins both reviewed fix rounds: durable per-record retry state
# with bounded unknown quarantine and a consumed backoff curve, retention driven
# by the agent's own open/cycle path, the crash window between the record fsync
# and the state save, deadline legality (an egress-shaped failure slot),
# egress-baseline staging, exact 256-bit key material, and this round's
# residuals -- startup retention fail-closed, rotation published as file fsync +
# rename + directory fsync, unsafe chain members refused, the baseline file
# under the same storage discipline, per-request sent_epoch freshness, and the
# Mihomo/ingest secret non-reuse rule.
EXPECTED_PASS=226
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

PKG="$ROOT/monitor-v2/remote_probe"

# LF-normalised sha256: identical on a CRLF checkout and on CI.
e4_hash() {
    "$PY" -c 'import hashlib, sys
data = open(sys.argv[1], "rb").read().replace(bytes([13, 10]), bytes([10]))
print(hashlib.sha256(data).hexdigest())' "$1"
}
HARNESS="$HERE/remote-probe/probe_groups.py"
MIHOMO="$ROOT/monitor-v2/mihomo"
HIST_PY="$ROOT/monitor-v2/web/incident_history.py"
SERVER_PY="$ROOT/monitor-v2/web/server.py"
WEBAPP="$ROOT/monitor-v2/webapp.py"
WORKFLOW="$ROOT/.github/workflows/tests.yml"
for required in "$PKG/__init__.py" "$PKG/agent.py" "$PKG/payload.py" \
    "$PKG/spool.py" "$PKG/delivery.py" "$PKG/direct_probe.py" \
    "$PKG/mihomo_probe.py" "$PKG/evidence.py" \
    "$HARNESS" "$HIST_PY" "$SERVER_PY" "$WEBAPP" "$WORKFLOW"; do
    [ -f "$required" ] || fail "lane input missing: $required"
done

section "S0: static + red-line gates"

if "$PY" -m py_compile "$PKG"/*.py "$HARNESS" 2>"$TMP/py.err"; then
    pass "py_compile the remote_probe package and the harness"
else
    fail "py_compile: $(cat "$TMP/py.err")"
fi

# The agent architecture and the frozen wire contract live in issue #67:
# PR-6A documents them there rather than as a repo markdown file. What is
# pinned here is that the reuse contract is stated BY THE MODULE that
# implements it, and that the package ships no stray markdown.
if grep -q "REUSE, NEVER FORK" "$PKG/mihomo_probe.py" \
    && [ -z "$(ls "$PKG"/*.md 2>/dev/null)" ]; then
    pass "the reuse contract is documented in the module; the package ships no markdown"
else
    fail "reuse documentation missing, or a stray markdown file appeared"
fi

# (2) The audited E4 pieces are byte-identical: reuse, never fork. The pins
# are taken over LF-normalised bytes, so a CRLF working copy and the LF CI
# checkout agree.
assert_eq "f33e7b2340528f592ecc756b5771dae6ed022fed905fbce2dccc36d920e957ab" \
    "$(e4_hash "$MIHOMO/client.py")" \
    "E4 client.py is byte-identical (transport + loopback parsing + secrets)"
assert_eq "b837653e94409ccb420c3c4a799c7cf7cdea2ed8eb14e73aa7b15e8e17437598" \
    "$(e4_hash "$MIHOMO/model.py")" \
    "E4 model.py is byte-identical (the /proxies payload semantics)"
assert_eq "a528f82a3b4634a50244f27c47088b7fd650e6b6e1f9142b42982f69138341fd" \
    "$(e4_hash "$MIHOMO/diag.py")" \
    "E4 diag.py is byte-identical (the read-only observer)"
assert_eq "9078a564ca31f570cb66ba95616b3613c99ffe83590359b493017f099d8e3334" \
    "$(e4_hash "$MIHOMO/README.md")" \
    "E4 README is byte-identical (its no-delay contract still stands)"
assert_eq "README.md __init__.py client.py diag.py fixtures model.py" \
    "$(ls "$MIHOMO" | grep -v "^__pycache__$" | LC_ALL=C sort | tr "\n" " " | sed "s/ $//")" \
    "the E4 adapter directory has exactly its original source file set"

# (3) Red lines.
assert_eq "0.6.1" "$(tr -d '[:space:]' < "$ROOT/monitor-v2/VERSION")" \
    "VERSION is unchanged at 0.6.1 (PR-6A does not bump the release)"
assert_eq "1" "$(grep -c 'MONITOR_WEB_VERSION = "0.6.1"' "$SERVER_PY")" \
    "MONITOR_WEB_VERSION is unchanged at 0.6.1"
assert_eq "1" "$(grep -c '^SCHEMA_VERSION = 5$' "$HIST_PY")" \
    "History is still schema v5 (no P6 migration)"
if [ "$(grep -A 8 '^_PRUNE_SOURCES = (' "$HIST_PY" | grep -c '^    (\"')" = "6" ] \
    && grep -q '("operator_markers", "epoch"),' "$HIST_PY"; then
    pass "History _PRUNE_SOURCES still has its six sources"
else
    fail "History _PRUNE_SOURCES changed"
fi
if grep -qE 'remote_probe|remote-probes' "$HIST_PY"; then
    fail "the History store references remote probe state"
else
    pass "the History store carries no remote-probe table or path"
fi
for module in incident_classifier incident_runtime incident_presenter; do
    if grep -qiE 'remote_probe|remote-probes' "$ROOT/monitor-v2/web/$module.py"; then
        fail "$module.py references remote probe state (P4/P5 isolation)"
    else
        pass "$module.py carries no remote reference"
    fi
done
if grep -rq 'remote-probes' "$ROOT/monitor-v2/web" "$WEBAPP" 2>/dev/null; then
    fail "a server ingest route for /api/v1/remote-probes exists"
else
    pass "no server ingest route exists (PR-6A is dark)"
fi
if [ -n "$(find "$ROOT/monitor-v2" -name 'remote-probes.sqlite3' 2>/dev/null)" ]; then
    fail "a server-side remote store was created"
else
    pass "no server-side remote store exists anywhere in the tree"
fi

# (4) This lane is registered where the other Monitor lanes run.
if grep -q 'bash -n tests/test-monitor-v2-remote-probe.sh' "$WORKFLOW"; then
    pass "tests.yml syntax-checks this lane"
else
    fail "tests.yml does not bash -n this lane"
fi
if grep -q 'run: bash tests/test-monitor-v2-remote-probe.sh' "$WORKFLOW"; then
    pass "tests.yml runs this lane in the Monitor regression job"
else
    fail "tests.yml never runs this lane"
fi

section "S1: deterministic behaviour groups (agent, boundary, spool, wire)"

"$PY" "$HARNESS" >"$TMP/groups.log" 2>&1
RC=$?
map_verdicts "$TMP/groups.log"
if [ "$RC" -ne 0 ]; then
    fail "probe_groups.py exited rc=$RC (a crashing harness is itself a gate)"
    tail -25 "$TMP/groups.log"
else
    pass "probe_groups.py exited 0 over all eleven groups"
fi

section "RESULT"
printf 'checks: %d passed, %d failed (expected %d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '== P6A remote-probe agent suite: FAILED ==\n'
    exit 1
fi
printf '== P6A remote-probe agent suite: GREEN ==\n'
exit 0
