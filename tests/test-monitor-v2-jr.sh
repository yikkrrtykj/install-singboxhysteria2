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
# sentinels that must never cross the exchange, the PR-2B ACTIVATION
# WIRING contract (the reader activates ONLY through the reviewed installer
# transaction -- the PR-2A "zero call sites" DARK gate was replaced by the
# mutation-surface allowlist confinement, never deleted), and the review
# #46 B1-B9 fixes: real '-- cursor:'
# framing (B1, D5 validator untouched), R7 exact-shape identity refusal
# with zero mutation before any change (B3, PATH-stub fixtures),
# sanitized journal_writer_failed for every expected durability OSError
# (B4), fail-closed retention ceilings (B5), whole-batch
# journal_cursor_invalid for undecodable output with pfail reserved for
# payload-only defects (B6), a runtime-env-surface-free production
# wrapper (B7), full HMAC-key fail-closed hardening (B8); the LIVE
# permission proof through a disposable runuser identity (B9) lives in
# test-jr-live.sh L6.
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
# 371 = S0 static 13 + S1 unit/wrapper 10 (B7 gates +2) + S2 CI locks 3
#     + S3 jtime 10 + S4 behavioral 311 (19->20 groups, +1 line: cursor +6
#     B1 framing, fp +12 B8 key +2 B8r dir-fsync proof, d1 +8 B6 semantics,
#     dur group 21 B4/B5 +3 B5r startup re-proves ceiling)
#     + S5 identity fixtures 22 (B3 PATH-stub scenarios)
#     + PR-2B activation-wiring conversion (DARK zero-call gates replaced by
#       the mutation-surface confinement + manifest-ship + verb-inert gates
#       and the 25-helper registry: net +2 lines)
EXPECTED_PASS=371
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
# --- activation-wiring gates: PR-2B (Coding E) replaced the PR-2A DARK      |
#     zero-call-site contract with: "the reader activates ONLY through the    |
#     reviewed installer transaction". The mutating reader surface is a      |
#     closed allowlist of helper names, reachable only from                  |
#     _cmd_install_locked / _cmd_rollback_locked / _cmd_uninstall_locked +   |
#     cmd_status (read-only). Anything else -- health, web-setup, a stray    |
#     top-level call, a direct python import of journal_reader -- must be 0. |
IM="$ROOT/monitor-v2/deploy/install-monitor.sh"
# NB: the file path travels via the environment, NOT argv: some Windows
# python launchers shebang-execute bash-script argv[1]s (the real gate is
# Linux CI, but this suite is documented as platform-stable).
WIRING="$(SBJR_WIRING_TARGET="$IM" "$PY" - <<'EOF'
import os, re
src = open(os.environ["SBJR_WIRING_TARGET"], encoding="utf-8").read()
bodies = {}
for m in re.finditer(r'^([a-z_0-9]+)\(\) \{', src, re.M):
    name = m.group(1)
    end = src.find('\n}\n', m.start())
    body = src[m.start():end] if end >= 0 else src[m.start():]
    # code-only: a comment can never BE a call site
    body = "\n".join(l.split("#", 1)[0] for l in body.splitlines())
    bodies[name] = body
MUTATING = {"sbmon_sboxjr_activation_preflight", "sbmon_sboxjr_capture_prestate",
            "sbmon_sboxjr_converge", "sbmon_sboxjr_restore_prestate",
            "sbmon_sboxjr_release_runtime_dir", "sbmon_sboxjr_unlink_runtime",
            "sbmon_sboxjr_service_stop", "sbmon_sboxjr_service_disable"}
READONLY = {"sbmon_sboxjr_service_active", "sbmon_sboxjr_service_enabled",
            "sbmon_sboxjr_runtime_linked_id"}
ALLOWED_FNS = {"_cmd_install_locked", "_cmd_rollback_locked",
               "_cmd_uninstall_locked", "cmd_status"}
violations = []
for fn, body in bodies.items():
    for call in re.findall(r'sbmon_sboxjr_[a-z_0-9]+', body):
        if call in READONLY and fn in {"cmd_status", "_cmd_rollback_locked",
                                       "_cmd_uninstall_locked"}:
            continue
        if call in MUTATING and fn in ALLOWED_FNS:
            continue
        violations.append(f"{fn}:{call}")
# top-level (column-0, non-comment) call sites outside any function body
toplevel = "\n".join(l for l in src.splitlines()
                     if l and l[0] not in " \t#")
for call in re.findall(r'\b(sbmon_sboxjr_[a-z_0-9]+)', toplevel):
    violations.append(f"toplevel:{call}")
print(",".join(sorted(set(violations))) or "OK")
EOF
)"
assert_eq "$WIRING" "OK" \
    "reader mutation surface confined to the reviewed PR-2B installer transaction (no stray/health/status/web-setup activation)"
if grep -Eq 'python3? .*journal_reader|import journal_reader|journal_reader\.reader' "$IM"; then
    fail "installer directly imports/invokes the reader runtime (must go through the staged unit only)"
else
    pass "installer never imports/executes journal_reader directly"
fi
STAGE_MANIFEST="$("$PY" - "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" <<'EOF'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
body = src.split("sbmon_stage_release()", 1)[1].split("sbmon_activate_release()", 1)[0]
explicit = ("SBOXJR_MODULE_FILES[@]" in body
            and "journal_reader/$jf" in body and "$SBOXJR_TEMPLATE_NAME" in body)
no_wildcard = "cp -R -- \"$SBMON_REPO_MONITOR_DIR/journal_reader\"" not in body
print(explicit and no_wildcard)
EOF
)"
assert_eq "$STAGE_MANIFEST" "True" \
    "sbmon_stage_release ships the reader ONLY via the explicit 12+1+1 manifest (never cp -R)"
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
WRAP="$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader"
if grep -q '^SBJR_LIB_DIR=/usr/local/lib/singbox-journal-reader$' "$WRAP" \
   && grep -q '^SBJR_PYTHON3=/usr/bin/python3$' "$WRAP"; then
    pass "runtime wrapper paths are frozen constants (B7)"
else
    fail "wrapper runtime paths not frozen (B7)"
fi
if grep -qE '\$\{SBOXJR_(LIB_DIR|PYTHON3)|PYTHONPATH:\+' "$WRAP"; then
    fail "wrapper still exposes a runtime env surface (B7)"
else
    pass "wrapper env surface is zero: only the frozen SBOX_JR_UNIT channel remains"
fi
for fn in sbmon_sboxjr_validate_identity sbmon_sboxjr_ensure_identity \
          sbmon_sboxjr_ensure_data_tree sbmon_sboxjr_audit_runtime \
          sbmon_sboxjr_link_runtime sbmon_sboxjr_unlink_runtime \
          sbmon_sboxjr_runtime_linked_id sbmon_sboxjr_release_runtime_dir \
          sbmon_sboxjr_render_unit sbmon_sboxjr_verify_unit \
          sbmon_sboxjr_install_unit \
          sbmon_sboxjr_service_active sbmon_sboxjr_service_enabled \
          sbmon_sboxjr_service_enable sbmon_sboxjr_service_enable_now \
          sbmon_sboxjr_service_restart sbmon_sboxjr_service_stop \
          sbmon_sboxjr_service_disable sbmon_wait_sboxjr_active \
          sbmon_sboxjr_activation_preflight sbmon_sboxjr_capture_prestate \
          sbmon_sboxjr_health_proof sbmon_sboxjr_converge \
          sbmon_sboxjr_restore_prestate sbmon_sboxjr_readability_probe; do
    grep -q "^${fn}()" "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" \
        || fail "helper missing: $fn"
done
pass "all 25 sboxjr deployment helpers defined (enable/start confined to sbmon_sboxjr_converge / restore paths)"
if "$PY" - "$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" <<'PCEOF'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
def body(name):
    m = re.search(r'^%s\(\) \{' % re.escape(name), src, re.M)
    if not m:
        sys.exit(1)
    end = src.find('\n}\n', m.start())
    b = "\n".join(l.split("#", 1)[0] for l in src[m.start():end].splitlines())
    return set(re.findall(r'sbmon_sboxjr_[a-z_0-9]+\b|sbmon_wait_sboxjr_active\b', b))
c = body("sbmon_sboxjr_converge")
iu = body("sbmon_sboxjr_install_unit")
start_calls = {"sbmon_sboxjr_service_enable", "sbmon_sboxjr_service_enable_now",
               "sbmon_sboxjr_service_restart", "sbmon_wait_sboxjr_active"}
# install_unit must stay state-inert; start verbs belong to converge (and
# the restore path), never anywhere else in the library's helpers.
sys.exit(0 if start_calls <= c and not (start_calls & iu) else 1)
PCEOF
then
    pass "enable/start/wait verbs live ONLY in converge (install_unit stays inert)"
else
    fail "activation verb confinement broken (start verbs leaked outside converge)"
fi
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
         since backlog ingest retention dur reset cli privacy cross; do
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
    pass "all 20 behavioral groups completed with zero internal crashes"
else
    fail "behavioral group sweep incomplete"
fi

# ===========================================================================
section "S5: R7 identity fixtures via PATH stubs (B3, review #46)"
# ===========================================================================
# A file-backed fake NSS (getent/id) + logging mutators (groupadd/useradd/
# usermod) drive the REAL library functions in a fresh bash per scenario.
# Every divergent existing identity must be refused BEFORE any mutation,
# and the identity store must come out byte-identical.
S5BIN="$TMP/s5bin"; mkdir -p "$S5BIN" "$TMP/s5"
cat > "$S5BIN/getent" <<'S5E'
#!/usr/bin/env bash
db="${S5_DB:?}"
case "$1" in
    passwd)
        f="$db/passwd.$2"
        [ -f "$f" ] && { cat "$f"; exit 0; }
        exit 2
        ;;
    group)
        f="$db/group.$2"
        [ -f "$f" ] && { cat "$f"; exit 0; }
        for gf in "$db"/group.*; do
            [ -e "$gf" ] || continue
            [ "$(cut -d: -f3 "$gf")" = "$2" ] && { cat "$gf"; exit 0; }
        done
        exit 2
        ;;
esac
exit 2
S5E
cat > "$S5BIN/id" <<'S5E'
#!/usr/bin/env bash
[ "$1" = "-nG" ] || exit 1
db="${S5_DB:?}"
pf="$db/passwd.$2"
[ -f "$pf" ] || exit 1
prim="$(getent group "$(cut -d: -f4 "$pf")" | cut -d: -f1)"
out="$prim"
if [ -f "$db/members.$2" ]; then
    for g in $(tr -d '\r' < "$db/members.$2"); do out="$out $g"; done
fi
printf '%s\n' "$out"
S5E
cat > "$S5BIN/groupadd" <<'S5E'
#!/usr/bin/env bash
printf 'groupadd %s\n' "$*" >> "${S5_MUTLOG:?}"
name=""; for a in "$@"; do name="$a"; done
n=900
for gf in "$S5_DB"/group.*; do [ -e "$gf" ] && n=$((n + 1)); done
printf '%s:x:%d:\n' "$name" "$n" > "$S5_DB/group.$name"
S5E
cat > "$S5BIN/useradd" <<'S5E'
#!/usr/bin/env bash
printf 'useradd %s\n' "$*" >> "${S5_MUTLOG:?}"
name=""; gid=""; home=""; shell=""
while [ $# -gt 0 ]; do
    case "$1" in
        --gid) gid="$2"; shift ;;
        --home-dir) home="$2"; shift ;;
        --shell) shell="$2"; shift ;;
        --*) ;;
        *) name="$1" ;;
    esac
    shift
done
gnum="$(getent group "$gid" | cut -d: -f3)"
printf '%s:x:%s:%s::%s:%s\n' "$name" "$gnum" "$gnum" "$home" "$shell" \
    > "$S5_DB/passwd.$name"
: > "$S5_DB/members.$name"
S5E
cat > "$S5BIN/usermod" <<'S5E'
#!/usr/bin/env bash
printf 'usermod %s\n' "$*" >> "${S5_MUTLOG:?}"
if [ "$1" = "-aG" ]; then printf '%s\n' "$2" >> "$S5_DB/members.$3"; fi
S5E
chmod +x "$S5BIN"/* 2>/dev/null || true

s5_invoke() {  # $1=case dir, $2=library fn -> rc; stderr lands in $1/err
    S5_DB="$1/db" S5_MUTLOG="$1/mutlog" SBMON_FIXTURE=0 \
    SBOXJR_LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh" \
    PATH="$S5BIN:$PATH" \
    bash -c '. "$SBOXJR_LIB" >/dev/null 2>&1; "$1" >/dev/null 2>"$2/err"' \
        _ "$2" "$1"
}
s5_exact_db() {  # exact-shape existing identity (R7 want-set)
    mkdir -p "$1"
    printf 'sbox-jr:x:998:\n' > "$1/group.sbox-jr"
    printf 'systemd-journal:x:999:\n' > "$1/group.systemd-journal"
    printf 'sbox-jr:x:998:998::/nonexistent:/usr/sbin/nologin\n' \
        > "$1/passwd.sbox-jr"
    printf 'systemd-journal\n' > "$1/members.sbox-jr"
}
s5_case() { rm -rf "$TMP/s5/$1"; mkdir -p "$TMP/s5/$1/db"; \
            : > "$TMP/s5/$1/mutlog"; printf '%s' "$TMP/s5/$1"; }

D="$(s5_case ok)"; s5_exact_db "$D/db"
s5_invoke "$D" sbmon_sboxjr_validate_identity \
    && pass "validate accepts the exact-shape identity" || fail "validate rejects a compliant identity"
s5_invoke "$D" sbmon_sboxjr_ensure_identity && [ ! -s "$D/mutlog" ] \
    && pass "ensure mutates NOTHING for an existing compliant identity" \
    || fail "ensure touched a compliant identity"

s5_diverge() {  # $1=case, $2=field= token, $3=mutator fn
    local d m rc
    d="$(s5_case "$1")"; s5_exact_db "$d/db"; "$3" "$d/db"
    cp -r "$d/db" "$d/db0"
    s5_invoke "$d" sbmon_sboxjr_ensure_identity; rc=$?
    [ "$rc" -ne 0 ] && grep -q "field=$2:" "$d/err" \
        && pass "divergent $1 refused before anything else (field=$2)" \
        || fail "divergent $1 not refused with field=$2 (rc=$rc)"
    [ ! -s "$d/mutlog" ] \
        && pass "divergent $1: zero mutations (incl. no groupadd)" \
        || fail "divergent $1: mutator ran before refusal"
    diff -r -- "$d/db0" "$d/db" >/dev/null 2>&1 \
        && pass "divergent $1: passwd/group/id store byte-identical" \
        || fail "divergent $1: identity store was modified"
}
s5_mut_shell()     { printf 'sbox-jr:x:998:998::/nonexistent:/bin/bash\n' > "$1/passwd.sbox-jr"; }
s5_mut_home()      { printf 'sbox-jr:x:998:998::/home/sbox-jr:/usr/sbin/nologin\n' > "$1/passwd.sbox-jr"; }
s5_mut_primary()   { printf 'sbox-jr:x:998:999::/nonexistent:/usr/sbin/nologin\n' > "$1/passwd.sbox-jr"; }
s5_mut_nojournal() { : > "$1/members.sbox-jr"; }
s5_mut_extra()     { printf 'systemd-journal\nadm\n' > "$1/members.sbox-jr"; \
                     printf 'adm:x:997:\n' > "$1/group.adm"; }
s5_diverge shell shell s5_mut_shell
s5_diverge home home s5_mut_home
s5_diverge primary primary_group s5_mut_primary
s5_diverge journal-missing group_set s5_mut_nojournal
s5_diverge extra-group group_set s5_mut_extra

D="$(s5_case absent)"; mkdir -p "$D/db"
s5_invoke "$D" sbmon_sboxjr_validate_identity; rc=$?
[ "$rc" -ne 0 ] && grep -q 'field=user_exists:' "$D/err" \
    && pass "validate refuses an absent identity (no root fallback)" \
    || fail "validate did not refuse an absent identity"

D="$(s5_case create-group-exists)"
printf 'sbox-jr:x:998:\n' > "$D/db/group.sbox-jr"
printf 'systemd-journal:x:999:\n' > "$D/db/group.systemd-journal"
s5_invoke "$D" sbmon_sboxjr_ensure_identity \
    && pass "absent-user creation converges and re-validates exact" \
    || fail "ensure failed to create a compliant identity"
printf 'useradd --system --gid sbox-jr --home-dir /nonexistent --no-create-home --shell /usr/sbin/nologin sbox-jr\nusermod -aG systemd-journal sbox-jr\n' \
    > "$D/expected"
diff -- "$D/expected" "$D/mutlog" >/dev/null 2>&1 \
    && pass "creation order/exactness locked: useradd -> usermod, NO groupadd when the group exists" \
    || fail "creation mutation sequence drifted: $(tr '\n' '|' < "$D/mutlog")"
before_lines="$(grep -c . "$D/mutlog")"
s5_invoke "$D" sbmon_sboxjr_ensure_identity
[ "$(grep -c . "$D/mutlog")" = "$before_lines" ] \
    && pass "second ensure on the created identity is a zero-mutation no-op" \
    || fail "ensure is not idempotent after creation"

D="$(s5_case create-group-absent)"
printf 'systemd-journal:x:999:\n' > "$D/db/group.systemd-journal"
s5_invoke "$D" sbmon_sboxjr_ensure_identity \
    && head -n1 "$D/mutlog" | grep -q '^groupadd --system sbox-jr$' \
    && [ "$(count_lines "$(cat "$D/mutlog")")" = "3" ] \
    && pass "missing primary group: groupadd -> useradd -> usermod, exactly 3 mutations" \
    || fail "groupadd-first creation contract broken: $(tr '\n' '|' < "$D/mutlog")"

# ===========================================================================
printf '\n== RESULT: %d passed, %d failed (expected %d) ==\n' \
    "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -gt 0 ]; then exit 1; fi
if [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf 'HARD GATE: check count moved (got %d, expect %d) -- a silently skipped group is a failure\n' "$PASS" "$EXPECTED_PASS"
    exit 1
fi
exit 0
