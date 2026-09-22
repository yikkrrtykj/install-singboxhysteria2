#!/usr/bin/env bash
# sbox-journal-reader (issue #33 P2, PR-2A) regression suite.
#
# Discriminating gates required by the frozen design (v1..v5 + sign-off):
# opaque cursor grammar (D5), journal-time Python<->shell equivalence
# (T31/C5), the B1 eligibility decision table, cv=1 classifier anchors and
# the N1/N2/N3 negatives, HMAC fingerprint privacy (R4), exchange schema
# cross-field rules (v2-R6), the C2 recovery table (rows 1-8), the full
# T28(v5) crash matrix around every durability boundary INCLUDING directory
# fsyncs, the D1 child-outcome table (generic source failure NEVER resets
# a cursor), durable COLD_START/SOURCE_GAP boundary markers (D2), the
# tagged source anchor (D3), the 50k backlog cap committed through the
# last actually processed cursor (C4), terminal-seq continuity
# (T27a/b/c), retention/heartbeat, the operator-only reset path, privacy
# sentinels that must never cross the exchange, and the PR-2A DARK
# contract (zero production call sites, no shipped manifest change, no
# Monitor wiring).
#
# POSIX-only semantics degrade to in-Python booleans (the harness runs the
# same code paths), so the EXPECTED_PASS count is platform-stable. The
# LIVE Ubuntu gates (real journalctl cursor telemetry, systemd-analyze)
# live in tests/journal-reader/test-jr-live.sh on the matrix lane and are
# REQUIRE_LIVE fail-closed there -- never a SKIP.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"
JRDIR="$HERE/journal-reader"
MODS="$ROOT/monitor-v2/journal_reader"

PASS=0
FAIL=0
EXPECTED_PASS=293
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
count_lines() { printf '%s\n' "$1" | grep -c . || true; }

if [ -z "$PY" ]; then
    printf '  SKIP python3 unavailable -- this suite is a hard gate on CI\n'
    printf '\n== RESULT: %d passed, %d failed (hard-fail: no interpreter) ==\n' "$PASS" "$FAIL"
    exit 1
fi

# ===========================================================================
section "S0: static gates (syntax, stdlib, dark wiring)"
# ===========================================================================
if "$PY" -m py_compile "$MODS"/*.py 2>"$TMP/pyc.err"; then
    pass "py_compile: all journal_reader modules"
else
    fail "py_compile: $(cat "$TMP/pyc.err")"
fi
if bash -n "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" \
    && bash -n "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader"; then
    pass "bash -n: deploy library (+sboxjr helpers) and reader entry wrapper"
else
    fail "bash -n deploy sources"
fi
IMPORTS="$("$PY" - "$MODS" <<'EOF'
import ast, os, sys
mods = set()
root = sys.argv[1]
for name in sorted(os.listdir(root)):
    if not name.endswith(".py"):
        continue
    tree = ast.parse(open(os.path.join(root, name), encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            mods.add(node.module.split(".")[0])
print(" ".join(sorted(mods)))
EOF
)"
case " $IMPORTS " in
    *" requests "*|*" aiohttp "*|*" httpx "*|*" sqlite3 "*|*" psutil "*)
        fail "non-stdlib/new dependency in journal_reader: $IMPORTS" ;;
    *) pass "journal_reader imports stay stdlib-only ($IMPORTS)" ;;
esac
# AST-derived import set: a real `import tests` can never hide in a
# docstring; the earlier textual grep matched the C5/G9 doc notes.
case " $IMPORTS " in
    *" tests "*|*" pytest "*|*" mock "*)
        fail "journal_reader imports from tests/ (no runtime dependency on tests allowed)" ;;
    *) pass "no production module depends on tests/ (G8/C5)" ;;
esac
if grep -rnE 'shell=True|os\.system|subprocess\.(run|call|check_output|check_call)|Popen\([^,\[]' "$MODS" --include='*.py'; then
    fail "shell-interpolated subprocess found (argv must be list-form only)"
else
    pass "journalctl children are fixed list-form argv, never shell-interpolated"
fi
# Privilege ESCALATION cannot be a plain-word grep: R7 doc comments
# legitimately NAME runuser/capabilities. Code that would invoke them
# always goes through a string literal or a syscall wrapper.
if grep -rnE "'(runuser|pkexec|sudo|chroot|setuid|setgid)'|\"(runuser|pkexec|sudo|chroot|setuid|setgid)\"|os\.set(uid|gid)|user(add|mod)|groupadd|sudoers" "$MODS" --include='*.py'; then
    fail "reader code requests privilege mechanisms (forbidden)"
else
    pass "reader code contains no privilege mechanism calls (R7: no root fallback)"
fi
if grep -rnE 'BOX_API_SECRET|api_secret|service\.api|gethostname|socket\.' "$MODS" --include='*.py'; then
    fail "credential/host surface referenced in reader (privacy contract)"
else
    pass "no secret-file, hostname or raw-network references in reader modules"
fi
# Exactly 5 stderr writes (3 fail-stop codes, usage, reset=ok), each one
# from the closed literal set -- sanitized codes only, never payloads.
if [ "$(grep -c 'sys.stderr.write' "$MODS/reader.py")" = "5" ] \
   && ! grep 'sys.stderr.write' "$MODS/reader.py" \
        | grep -vE 'sys\.stderr\.write\("\[sbjr\] (failure=%s|failure=usage|reset=ok)'; then
    pass "stderr surface is exactly 5 sanitized code writes, no payloads"
else
    fail "stderr hygiene contract broken"
fi
# --- DARK gates: PR-2A must touch NO activation path -----------------------
SBXJRCALLS="$(grep -c 'sbmon_sboxjr_' "$ROOT/monitor-v2/deploy/install-monitor.sh" || true)"
assert_eq "$SBXJRCALLS" "0" \
    "install-monitor.sh has ZERO sbmon_sboxjr_ call sites (PR-2A dark)"
STAGE_MANIFEST="$("$PY" - "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" <<'EOF'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
body = src.split("sbmon_stage_release()", 1)[1].split("sbmon_activate_release()", 1)[0]
print("journal_reader" in body or "sbox-journal-reader" in body)
EOF
)"
assert_eq "$STAGE_MANIFEST" "False" \
    "sbmon_stage_release manifest untouched: reader code is NOT shipped by the monitor release"
WEBREFS="$(grep -rl 'journal_reader' "$ROOT/monitor-v2/web" "$ROOT/monitor-v2/collector.py" "$ROOT/monitor-v2/webapp.py" 2>/dev/null | wc -l | tr -d ' ')"
assert_eq "$WEBREFS" "0" \
    "Monitor web/collector import nothing from journal_reader (ingest inert, schema-v2 not activated)"
assert_eq "$(cat "$ROOT/monitor-v2/VERSION")" "0.2.0" \
    "VERSION stays 0.2.0 (the 0.3.0 bump belongs to PR-2B)"
ENVCOUNT="$(grep -rc 'os.environ' "$MODS"/*.py | awk -F: '{s+=$2} END {print s+0}')"
assert_eq "$ENVCOUNT" "1" \
    "exactly one env read across the whole reader (SBOX_JR_UNIT, strictly validated)"

# ===========================================================================
section "S1: unit template + wrapper structure"
# ===========================================================================
UNIT="$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in"
UNIT_CODE="$TMP/unit-effective.conf"
grep -v '^[[:space:]]*#' "$UNIT" > "$UNIT_CODE"
if grep -q '^RestrictAddressFamilies=AF_UNIX$' "$UNIT_CODE" \
   && ! grep -q 'AF_INET' "$UNIT_CODE"; then
    pass "reader unit collapses to AF_UNIX-only (no TCP surface, strictest contract)"
else
    fail "reader unit address-family contract wrong"
fi
if grep -q '^User=@SBJR_USER@$' "$UNIT_CODE" && grep -q '^Group=@SBJR_GROUP@$' "$UNIT_CODE" \
   && ! grep -qi 'SupplementaryGroups' "$UNIT_CODE"; then
    pass "identity comes from placeholders; membership NOT silently re-granted by the unit (R7)"
else
    fail "reader unit identity directives wrong"
fi
if grep -q 'ProtectSystem=strict' "$UNIT" && grep -q 'ReadWritePaths=@SBJR_DATA_ROOT@' "$UNIT" \
   && grep -q '^CapabilityBoundingSet=$' "$UNIT" && grep -q '^AmbientCapabilities=$' "$UNIT"; then
    pass "hardening set present: strict fs, single writable exception, zero capabilities"
else
    fail "hardening directives missing"
fi
awk '/^\[Unit\]/{u=1} /^\[Service\]/{u=0} u && /^StartLimit/{f=1} END{exit !f}' "$UNIT" \
    && pass "StartLimit budget declared in [Unit] (placement correct on 22.04/24.04/26.04)" \
    || fail "StartLimit not in [Unit]"
UNRENDERED="$("$PY" - "$UNIT" "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" <<'EOF'
import re, sys
tpl = open(sys.argv[1], encoding="utf-8").read()
lib = open(sys.argv[2], encoding="utf-8").read()
used = set(re.findall(r"@[A-Z_]+@", tpl))
subbed = set(re.findall(r's\|(@[A-Z_]+@)\|', lib))
print(" ".join(sorted(used - subbed)))
EOF
)"
assert_eq "$UNRENDERED" "" \
    "every unit placeholder is substituted by sbmon_sboxjr_render_unit (no unrendered hole)"
if grep -q 'staged_tree_missing' "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader" \
   && ! grep -qE '\bsudo\b' "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader"; then
    pass "entry wrapper fails closed on missing staged tree and never self-privileges"
else
    fail "entry wrapper contract broken"
fi
for fn in sbmon_sboxjr_validate_identity sbmon_sboxjr_ensure_identity \
          sbmon_sboxjr_ensure_data_tree sbmon_sboxjr_stage_code \
          sbmon_sboxjr_render_unit sbmon_sboxjr_install_unit \
          sbmon_sboxjr_readability_probe; do
    grep -qx "$fn () {" <(declare -f | grep '^[a-z_]* () {$' 2>/dev/null) 2>/dev/null \
        || grep -q "^$fn()" "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" \
        || fail "helper missing: $fn"
done
pass "all 7 sboxjr deployment helpers defined (enable/start helpers deliberately ABSENT)"
grep -q 'sbox-jr' "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" \
    && grep -q 'systemd-journal' "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" \
    && pass "R7 exact identity constants (sbox-jr + systemd-journal) live in the shared library"

# ===========================================================================
section "S2: CI registration locks (tests.yml lanes)"
# ===========================================================================
CIY="$ROOT/.github/workflows/tests.yml"
grep -q 'bash -n tests/test-monitor-v2-jr.sh' "$CIY" \
    && pass "fast-checks lane: jr suite bash -n registered" \
    || fail "jr suite not in fast-checks bash -n list"
grep -q 'bash tests/test-monitor-v2-jr.sh' "$CIY" \
    && pass "monitor-regression lane: jr suite registered" \
    || fail "jr suite not registered in monitor-regression"
grep -q 'test-jr-live.sh' "$CIY" \
    && pass "compatibility matrix: jr LIVE lane registered" \
    || fail "jr live lane not registered in matrix"

# ===========================================================================
section "S3: journal-time equivalence, Python <-> canonical shell (T31)"
# ===========================================================================
# shellcheck source=lib/journal-time.sh
source "$HERE/lib/journal-time.sh"
export PYTHONPATH="$MODS/.."
EQ_CASES_OK=(
    "2026-09-14T15:51:50Z"
    "2026-09-14 15:51:50"
    "2026-09-14T15:51:50.123456Z"
    "2026-09-14T15:51:50+00:00"
    "2026-09-14T23:51:50+08:00"
    "2026-09-14T15:51:50"
)
for ts in "${EQ_CASES_OK[@]}"; do
    shell_out="$(journal_time_normalize_jctl "$ts" 2>/dev/null)" && shell_rc=0 || shell_rc=1
    py_out="$("$PY" - "$ts" <<'EOF' 2>/dev/null
import sys
from journal_reader.journal_time import normalize_journalctl_since
print(normalize_journalctl_since(sys.argv[1]), end="")
EOF
)" && py_rc=0 || py_rc=1
    if [ "$shell_rc" = "0" ] && [ "$py_rc" = "0" ] && [ "$py_out" = "$shell_out" ]; then
        pass "jtime equivalence ok: $ts"
    else
        fail "jtime equivalence: $ts (shell='$shell_out' py='$py_out')"
    fi
done
for ts in "" "   " "garbage" "2026-13-45T00:00:00Z"; do
    journal_time_normalize_jctl "$ts" >/dev/null 2>&1 && shell_rc=0 || shell_rc=1
    "$PY" - "$ts" <<'EOF' >/dev/null 2>&1 && py_rc=0 || py_rc=1
import sys
from journal_reader.journal_time import normalize_journalctl_since
normalize_journalctl_since(sys.argv[1])
EOF
    if [ "$shell_rc" = "1" ] && [ "$py_rc" = "1" ]; then
        pass "jtime fail-closed parity: '$ts'"
    else
        fail "jtime fail-closed parity: '$ts' (shell rc=$shell_rc py rc=$py_rc)"
    fi
done

# ===========================================================================
section "S4: behavioral groups (harness-driven, platform-stable)"
# ===========================================================================
GROUPS_OK=1
for g in cursor jtime norm class elig fp schema state crash d1 boundary \
         since backlog ingest retention reset cli privacy cross; do
    OUTFILE="$TMP/group_$g.out"
    "$PY" "$JRDIR/jr_groups.py" "$g" 2>"$TMP/group_$g.err" | cat > "$OUTFILE"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "group $g exited rc=$rc: $(tail -n 3 "$TMP/group_$g.err")"
        GROUPS_OK=0
    fi
    while IFS= read -r line; do
        case "$line" in
            "P "*) pass "[$g] ${line#P }" ;;
            "F "*) fail "[$g] ${line#F }"; GROUPS_OK=0 ;;
            "") ;;
            *) fail "[$g] protocol line: $line" ;;
        esac
    done < "$OUTFILE"
done
if [ "$GROUPS_OK" = "1" ]; then
    pass "all 19 behavioral groups completed with zero internal crashes"
else
    fail "behavioral group sweep incomplete"
fi

# ===========================================================================
printf '\n== RESULT: %d passed, %d failed (expected %d) ==\n' \
    "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
if [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf 'HARD GATE: check count moved (got %d, expect %d) -- a silently skipped group is a failure\n' "$PASS" "$EXPECTED_PASS"
    exit 1
fi
exit 0
