#!/usr/bin/env bash
# sbox-journal-reader PR-2B DEPLOY/ACTIVATION regression suite (issue #33 P2,
# Coding E). Proves the reader activation transaction wired into
# install-monitor.sh:
#   preflight -> exact identity -> directories -> runtime link (release
#   libexec) -> unit render -> systemd-analyze verify -> unit install ->
#   enable/start -> health proof, with explicit rollback of EVERY step.
#
# Contract coverage (spec section numbers):
#   §3 exact sbox-jr identity (wrong-shaped pre-existing identity refused
#      with ZERO mutations; creation order groupadd->useradd->usermod);
#   §4 data-tree ownership contract (root:sbox-jr 0750 / state 0700 /
#      out 2750 sbox-jr:sboxweb, symlink/non-dir refusal) -- asserted via
#      recording chown/chmod PATH stubs, so the EXACT call sequence is
#      platform-independent;
#   §5 explicit 12+1+1 staging manifest (no wildcard copy; extra/missing
#      files fail the runtime audit);
#   §6 the rendered unit carries exactly ONE Environment line (SBOX_JR_UNIT)
#      and no secret/host surface;
#   §7 systemd-analyze verify BEFORE install: verify failure = no unit, no
#      enable, no start; missing analyzer is fail-closed outside the fixture;
#   §8 fresh/upgrade/rollback version coherence: the runtime link flips with
#      the release; rollback while the reader is deployed refuses a
#      pre-PR-2B target; the active/enabled/unit/link matrix is preserved
#      (keep-prestate semantics);
#   §9/§10/§18 sing-box and sbox-cm invariants: the accumulated systemctl
#      call log of EVERY scenario must contain no state-changing operation
#      on any unit outside {singbox-monitor, singbox-journal-reader}; the
#      deploy tree must never reference the proxy config, sbox-cm state or
#      firewall tooling;
#   §13 uninstall tears the reader down FIRST, keeps state unless
#      --purge-state, and is idempotent;
#   §14 the installer is WIRED (the PR-2A DARK assertions were replaced in
#      tests/test-monitor-v2-jr.sh by the confinement contract re-asserted
#      positively here).
#
# Platform contract: installer runs use SBMON_FIXTURE=1 (identity/metadata
# semantics move to the direct fixture=0 PATH-stub groups, exactly like the
# established S5 pattern of test-monitor-v2-jr.sh). Scenarios that cross
# sbmon_sboxjr_link_runtime need REAL symlink semantics (ln -s + mv -T +
# readlink + [ -L ]); on platforms whose ln -s degrades to copy semantics
# they are honestly SKIPped, and this suite HARD-FAILS on Linux if any SKIP
# happens there. The root Linux CI lane is the gate for the full activation
# matrix.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"

PASS=0
FAIL=0
SKIP=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s (platform without symlink semantics; Linux CI is the gate)\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_grep() { if grep -qE "$2" "$1" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $2)"; fi; }
assert_no_grep() { if grep -qE "$2" "$1" 2>/dev/null; then fail "$3 (match: $2)"; else pass "$3"; fi; }

if [ -z "$PY" ]; then
    printf '  python3 unavailable -- this suite is a hard gate on CI\n'
    printf '\n== RESULT: %d passed, %d failed (hard-fail: no interpreter) ==\n' "$PASS" "$FAIL"
    exit 1
fi

LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"
W_INSTALL="$ROOT/monitor-v2/deploy/install-monitor.sh"

# ---------------------------------------------------------------------------
# symlink probe (drives the honest SKIP policy described above)
# ---------------------------------------------------------------------------
PROBE="$TMP/probe"; mkdir -p "$PROBE/tgt"
SYMLINK_OK=0
if ln -s "$PROBE/tgt" "$PROBE/link" 2>/dev/null && [ -L "$PROBE/link" ] \
   && [ "$(readlink "$PROBE/link")" = "$PROBE/tgt" ]; then
    SYMLINK_OK=1
fi
require_symlink() { # require_symlink <scenario name> -> rc 1 after logging the SKIP
    if [ "$SYMLINK_OK" = 1 ]; then return 0; fi
    skip "$1"
    return 1
}

# ---------------------------------------------------------------------------
# Stub binaries
# ---------------------------------------------------------------------------
STUB="$TMP/stub"; mkdir -p "$STUB"
META="$TMP/meta-stub"; mkdir -p "$META"   # recording chown/chmod, separate dir

# Per-unit recording systemctl mock. State = marker files
#   $MOCK_MS/<unit>.active / $MOCK_MS/<unit>.enabled (presence == fact)
# Failure knobs under $MOCK_MS, scoped by unit:
#   fail_start.<unit>   enable --now / start marks enabled then FAILS
#   dead.<unit>         start/restart "succeed" but the unit never stays active
#   fail_restart.<unit> / fail_restart_once.<unit> / fail_stop.<unit> /
#   fail_disable.<unit> that mutation op fails (once = marker consumed)
#   reload_fail         holds N: next N daemon-reloads succeed, then fail
cat > "$STUB/systemctl-mock" <<'SME'
#!/usr/bin/env bash
op="$1"; shift
unit=""
for a in "$@"; do case "$a" in --*) ;; *) unit="$a" ;; esac; done
unit="${unit%.service}"
if [ "$op" = "daemon-reload" ]; then unit="<reload>"; fi
printf 'systemctl %s %s\n' "$op" "$unit" >> "$MOCK_CALL_LOG"
act="$MOCK_MS/$unit.active"; ena="$MOCK_MS/$unit.enabled"
has_now=0
for a in "$@"; do [ "$a" = "--now" ] && has_now=1; done
case "$op" in
  is-active)  [ -f "$act" ] && exit 0; exit 1 ;;
  is-enabled) [ -f "$ena" ] && exit 0; exit 1 ;;
  daemon-reload)
    if [ -f "$MOCK_MS/reload_fail" ]; then
      n="$(cat "$MOCK_MS/reload_fail" 2>/dev/null || echo 0)"
      if [ "$n" -gt 0 ] 2>/dev/null; then
        echo "$((n - 1))" > "$MOCK_MS/reload_fail"
        exit 0
      fi
      echo "mock: daemon-reload failed" >&2; exit 1
    fi
    exit 0 ;;
  enable)
    if [ "$has_now" = 1 ] && [ -f "$MOCK_MS/fail_start.$unit" ]; then
      : > "$ena"; echo "mock: start failed" >&2; exit 1
    fi
    : > "$ena"
    if [ "$has_now" = 1 ] && [ ! -f "$MOCK_MS/dead.$unit" ]; then : > "$act"; fi
    exit 0 ;;
  start)
    if [ -f "$MOCK_MS/fail_start.$unit" ]; then echo "mock: start failed" >&2; exit 1; fi
    [ -f "$MOCK_MS/dead.$unit" ] || : > "$act"; exit 0 ;;
  restart)
    if [ -f "$MOCK_MS/fail_restart.$unit" ]; then echo "mock: restart failed" >&2; exit 1; fi
    if [ -f "$MOCK_MS/fail_restart_once.$unit" ]; then
      rm -f "$MOCK_MS/fail_restart_once.$unit"
      echo "mock: one-shot restart failure" >&2; exit 1
    fi
    [ -f "$MOCK_MS/dead.$unit" ] || : > "$act"; exit 0 ;;
  stop)
    if [ -f "$MOCK_MS/fail_stop.$unit" ]; then echo "mock: stop failed" >&2; exit 1; fi
    rm -f "$act"; exit 0 ;;
  disable)
    if [ -f "$MOCK_MS/fail_disable.$unit" ]; then echo "mock: disable failed" >&2; exit 1; fi
    rm -f "$ena"; exit 0 ;;
  *) exit 0 ;;
esac
SME
cat > "$STUB/systemd-analyze-mock" <<'SME'
#!/usr/bin/env bash
printf 'analyze %s\n' "$*" >> "$JR_ANALYZE_LOG"
if [ -f "$MOCK_MS/analyze_fail" ]; then
    echo "mock: systemd-analyze verify failed" >&2
    exit 1
fi
exit 0
SME
# Fake NSS + mutating account tools (jr-suite S5 pattern) + runuser passthrough
cat > "$STUB/getent" <<'SME'
#!/usr/bin/env bash
db="${JRDB:?}"
case "$1" in
    passwd)
        if [ "$#" -ge 2 ]; then
            f="$db/passwd.$2"; [ -f "$f" ] && { cat "$f"; exit 0; }; exit 2
        fi
        for pf in "$db"/passwd.*; do [ -e "$pf" ] && cat "$pf"; done
        exit 0 ;;
    group)
        f="$db/group.$2"
        [ -f "$f" ] && { cat "$f"; exit 0; }
        for gf in "$db"/group.*; do
            [ -e "$gf" ] || continue
            [ "$(cut -d: -f3 "$gf")" = "$2" ] && { cat "$gf"; exit 0; }
        done
        exit 2 ;;
esac
exit 2
SME
cat > "$STUB/id" <<'SME'
#!/usr/bin/env bash
db="${JRDB:?}"
case "$1" in
    -nG)
        name="${2:-${JR_PROBE_USER:-}}"
        [ -n "$name" ] || exit 1
        pf="$db/passwd.$name"; [ -f "$pf" ] || exit 1
        prim="$(getent group "$(cut -d: -f4 "$pf")" | cut -d: -f1)"
        out="$prim"
        [ -f "$db/members.$name" ] && for g in $(tr -d '\r' < "$db/members.$name"); do out="$out $g"; done
        printf '%s\n' "$out" ;;
    -u)
        pf="$db/passwd.$2"; [ -f "$pf" ] || exit 1
        cut -d: -f3 < "$pf" ;;
    *) exit 1 ;;
esac
SME
cat > "$STUB/groupadd" <<'SME'
#!/usr/bin/env bash
printf 'groupadd %s\n' "$*" >> "$JRDB/mutlog"
name=""; gid=""
while [ $# -gt 0 ]; do
    case "$1" in -g) gid="$2"; shift ;; --*) ;; *) name="$1" ;; esac
    shift
done
[ -n "$gid" ] || gid=900
printf '%s:x:%s:\n' "$name" "$gid" > "$JRDB/group.$name"
SME
cat > "$STUB/useradd" <<'SME'
#!/usr/bin/env bash
printf 'useradd %s\n' "$*" >> "$JRDB/mutlog"
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
printf '%s:x:%s:%s::%s:%s\n' "$name" "$gnum" "$gnum" "$home" "$shell" > "$JRDB/passwd.$name"
: > "$JRDB/members.$name"
SME
cat > "$STUB/usermod" <<'SME'
#!/usr/bin/env bash
printf 'usermod %s\n' "$*" >> "$JRDB/mutlog"
if [ "$1" = "-aG" ]; then printf '%s\n' "$2" >> "$JRDB/members.$3"; fi
SME
cat > "$STUB/userdel" <<'SME'
#!/usr/bin/env bash
printf 'userdel %s\n' "$*" >> "$JRDB/mutlog"
rm -f -- "$JRDB/passwd.$2" "$JRDB/members.$2"
SME
cat > "$STUB/groupdel" <<'SME'
#!/usr/bin/env bash
printf 'groupdel %s\n' "$*" >> "$JRDB/mutlog"
rm -f -- "$JRDB/group.$2"
SME
cat > "$STUB/runuser" <<'SME'
#!/usr/bin/env bash
# runuser -u NAME -- cmd...  -> run cmd with the target name exported for the
# fake id/getent stack (a real machine switches credentials here).
[ "$1" = "-u" ] || exit 1
user="$2"; shift 3   # eat: -u NAME --
JR_PROBE_USER="$user" "$@"
SME
# Recording chown/chmod (metadata contract asserts, fixture=0 direct tests)
cat > "$META/chown" <<'SME'
#!/usr/bin/env bash
printf 'chown %s %s\n' "$1" "$2" >> "$JR_META_LOG"
exit 0
SME
cat > "$META/chmod" <<'SME'
#!/usr/bin/env bash
printf 'chmod %s %s\n' "$1" "$2" >> "$JR_META_LOG"
exit 0
SME
chmod +x "$STUB"/* "$META"/* 2>/dev/null || true

# flock shim (same policy as the packaging suite)
if command -v flock >/dev/null 2>&1; then
    FLOCK_BIN=flock
else
    printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB/flock-mock"
    chmod +x "$STUB/flock-mock"
    FLOCK_BIN="$STUB/flock-mock"
fi

# ---------------------------------------------------------------------------
# Mutable source trees (mirror tests/test-monitor-packaging.sh conventions).
# Every CASE gets its OWN copy (upgrade scenarios bump VERSION per case).
# ---------------------------------------------------------------------------
build_src() { # build_src <dest> [--with-jr]
    local dest="$1" with_jr="${2:-}"
    mkdir -p "$dest"
    cp "$ROOT/monitor-v2/collector.py" "$dest/"
    cp "$ROOT/monitor-v2/webapp.py" "$dest/"
    cp -R "$ROOT/monitor-v2/web" "$dest/web"
    cp -R "$ROOT/monitor-v2/api_bridge" "$dest/api_bridge"
    rm -rf "$dest/api_bridge/__pycache__" "$dest/web/__pycache__"
    printf '0.1.0\n' > "$dest/VERSION"
    if [ "$with_jr" = "--with-jr" ]; then
        mkdir -p "$dest/journal_reader"
        local f
        for f in "$ROOT"/monitor-v2/journal_reader/*.py; do
            cp "$f" "$dest/journal_reader/"
        done
        rm -rf "$dest/journal_reader/__pycache__"
    fi
}
SRC="$TMP/src"; build_src "$SRC" --with-jr
SRC_NOJR="$TMP/src-nojr"; build_src "$SRC_NOJR"
SRC_PARTIAL="$TMP/src-partial"; build_src "$SRC_PARTIAL" --with-jr
rm -f "$SRC_PARTIAL/journal_reader/eligibility.py"

# ---------------------------------------------------------------------------
# Case harness
# ---------------------------------------------------------------------------
CASE_DIR=""
OUT=""
LAST_RC=0

new_case() { # new_case <name> [src-dir]
    CASE_DIR="$TMP/case-$1"
    rm -rf "$CASE_DIR"
    mkdir -p "$CASE_DIR/etc" "$CASE_DIR/opt" "$CASE_DIR/var/lib" \
             "$CASE_DIR/var/backups" "$CASE_DIR/proxy" "$CASE_DIR/mockstate"
    printf 'sekret\n' > "$CASE_DIR/proxy/monitor-api.secret"
    cp -R "${2:-$SRC}" "$CASE_DIR/src"
    export SBMON_APP_LINK="$CASE_DIR/opt/singbox-monitor"
    export SBMON_RELEASES_DIR="$CASE_DIR/opt/singbox-monitor-releases"
    export SBMON_STATE_ROOT="$CASE_DIR/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$CASE_DIR/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$CASE_DIR/etc/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$CASE_DIR/var/backups/singbox-monitor"
    export SBMON_LOCK_FILE="$CASE_DIR/deploy.lock"
    export SBMON_API_SECRET_SOURCE="$CASE_DIR/proxy/monitor-api.secret"
    export SBMON_REPO_MONITOR_DIR="$CASE_DIR/src"
    export SBMON_VERSION_FILE="$CASE_DIR/src/VERSION"
    export SBOXJR_DATA_ROOT="$CASE_DIR/var/lib/sbox-journal"
    export SBOXJR_LIB_DIR="$CASE_DIR/jr-runtime"
    export SBOXJR_UNIT_FILE="$CASE_DIR/etc/singbox-journal-reader.service"
    export MOCK_MS="$CASE_DIR/mockstate"
    export MOCK_CALL_LOG="$CASE_DIR/calls.log"
    export JR_ANALYZE_LOG="$CASE_DIR/analyze.log"
    : > "$MOCK_CALL_LOG"; : > "$JR_ANALYZE_LOG"
    OUT="$CASE_DIR/out.log"
    # -- fixture + tooling overrides (identical for every case) --
    export SBMON_FIXTURE=1
    export SBMON_USER=sboxweb SBMON_GROUP=sboxweb
    export SBMON_PYTHON3="$PY"
    export SBMON_SYSTEMCTL="$STUB/systemctl-mock"
    export SBMON_SYSTEMD_ANALYZE="$STUB/systemd-analyze-mock"
    export SBMON_FLOCK="$FLOCK_BIN"
    export SBMON_HEALTH_TIMEOUT=2
    export PATH="$STUB:$PATH"
    if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
        export SBMON_REQUIRED_COMMANDS="stat sha256sum mktemp"
        export SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1
    fi
}

inst() { # inst <subcommand> [args...]  (rc into LAST_RC, output into $OUT)
    LAST_RC=0
    "$W_INSTALL" "$@" > "$OUT" 2>&1 || LAST_RC=$?
    return $LAST_RC
}

call_line_present() { grep -qE "$1" "$MOCK_CALL_LOG"; }
calls_mut_of() { # <unit> -- STATE-CHANGING calls only (reads are always legal)
    grep -cE "systemctl (enable|start|restart|stop|disable) $1( |$)" "$MOCK_CALL_LOG" || true
}
log_mark() { wc -l < "$MOCK_CALL_LOG" | tr -d ' '; }

jr_state() { # -> "active|inactive/enabled|disabled" from the mock facts
    local a=inactive e=disabled
    [ -f "$MOCK_MS/singbox-journal-reader.active" ] && a=active
    [ -f "$MOCK_MS/singbox-journal-reader.enabled" ] && e=enabled
    printf '%s/%s' "$a" "$e"
}
seed_jr_state() { # seed_jr_state <active|inactive> <enabled|disabled>
    case "$1" in active) : > "$MOCK_MS/singbox-journal-reader.active" ;;
                 *) rm -f "$MOCK_MS/singbox-journal-reader.active" ;; esac
    case "$2" in enabled) : > "$MOCK_MS/singbox-journal-reader.enabled" ;;
                 *) rm -f "$MOCK_MS/singbox-journal-reader.enabled" ;; esac
}

current_release_id() {
    [ -L "$SBMON_APP_LINK" ] || return 0
    basename -- "$(readlink -- "$SBMON_APP_LINK")"
}
jr_link_release_id() {
    [ -L "$SBOXJR_LIB_DIR" ] || return 0
    # The link points at <release>/libexec/sbox-journal-reader; the release
    # id is the FIRST component under the releases dir, not the leaf name.
    local t
    t="$(readlink -- "$SBOXJR_LIB_DIR")"
    basename -- "${t%/libexec/sbox-journal-reader}"
}
history_first_id() { # id of the FIRST committed release (oldest history line)
    awk 'NR==1{print $2}' "$SBMON_RELEASES_DIR/releases.history" 2>/dev/null
}

# ===========================================================================
section "S0: static contract gates"
# ===========================================================================
"$PY" -m py_compile "$ROOT"/monitor-v2/journal_reader/*.py 2>/dev/null \
    && pass "py_compile: journal_reader source (suite precondition)" \
    || fail "py_compile: journal_reader source broken"
bash -n "$LIB" && bash -n "$W_INSTALL" \
    && pass "bash -n: deploy library + installer" || fail "bash -n deploy sources"

# WIRED gate (PR-2B replaced PR-2A DARK): the installer names the four
# transaction hooks, in transaction order, inside the install path.
L_PREFLIGHT="$(grep -n 'sbmon_sboxjr_activation_preflight' "$W_INSTALL" | head -n1 | cut -d: -f1)"
L_CAPTURE="$(grep -n 'sbmon_sboxjr_capture_prestate' "$W_INSTALL" | head -n1 | cut -d: -f1)"
L_CONVERGE="$(grep -n 'sbmon_sboxjr_converge' "$W_INSTALL" | head -n1 | cut -d: -f1)"
L_RESTORE="$(grep -n 'sbmon_sboxjr_restore_prestate' "$W_INSTALL" | head -n1 | cut -d: -f1)"
if [ -n "$L_PREFLIGHT" ] && [ -n "$L_CAPTURE" ] && [ -n "$L_CONVERGE" ] \
   && [ -n "$L_RESTORE" ] && [ "$L_PREFLIGHT" -lt "$L_CAPTURE" ] \
   && [ "$L_CAPTURE" -lt "$L_CONVERGE" ] && [ "$L_CONVERGE" -lt "$L_RESTORE" ]; then
    pass "installer wired: preflight -> capture -> converge -> restore (ordered)"
else
    fail "installer wiring order broken (p=$L_PREFLIGHT c=$L_CAPTURE v=$L_CONVERGE r=$L_RESTORE)"
fi
# Uninstall tears the reader down (stop checked BEFORE any deletion).
L_UNINST="$(grep -n '_cmd_uninstall_locked()' "$W_INSTALL" | head -n1 | cut -d: -f1)"
L_JRSTOP="$(awk -v s="${L_UNINST:-0}" 'NR>=s && /sbmon_sboxjr_service_stop/{print NR; exit}' "$W_INSTALL")"
L_JRRM="$(awk -v s="${L_UNINST:-0}" 'NR>=s && /rm -f -- "\$SBOXJR_UNIT_FILE"/{print NR; exit}' "$W_INSTALL")"
if [ -n "$L_JRSTOP" ] && [ -n "$L_JRRM" ] && [ "$L_JRSTOP" -lt "$L_JRRM" ]; then
    pass "uninstall: reader stop precedes unit deletion (teardown-first)"
else
    fail "uninstall reader teardown order broken"
fi
# §5: explicit manifest, never a wildcard directory copy.
assert_no_grep "$LIB" 'cp [^\n]*-R[^\n]*journal_reader' \
    "staging NEVER cp -R journal_reader (explicit manifest only)"
MANIFEST_EQ="$("$PY" - "$LIB" "$ROOT/monitor-v2/journal_reader" <<'EOF'
import re, sys, os
lib = open(sys.argv[1], encoding="utf-8").read()
m = re.search(r"SBOXJR_MODULE_FILES=\(([^)]*)\)", lib, re.S)
names = m.group(1).split()
src = sorted(f for f in os.listdir(sys.argv[2]) if f.endswith(".py"))
print("OK" if sorted(names) == src and len(src) == 12 else "DIFF")
EOF
)"
assert_eq "$MANIFEST_EQ" "OK" "12-module manifest == journal_reader/*.py exactly (conscious update required)"
# §9/§10 boundary: the deploy tree never references proxy/sbox-cm/firewall
# state in EXECUTABLE lines (the lib header legitimately NAMES the forbidden
# surfaces it prevents -- same comment-strip discipline as the packaging gate).
if sed -E 's/^[[:space:]]*#.*$//' "$LIB" "$W_INSTALL" \
    "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader" \
    "$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in" 2>/dev/null \
   | grep -nE '/var/lib/sbox-cm|management\.active|sbconfig_server\.json|ufw |iptables|firewall-cmd'; then
    fail "deploy sources reference forbidden proxy/sbox-cm/firewall surfaces"
else
    pass "no sbox-cm / management.active / proxy config / firewall reference (boundaries held)"
fi
# §6/§17: the unit template exposes exactly the one approved env channel.
TPL="$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in"
assert_eq "$(grep -c '^Environment=' "$TPL")" "1" \
    "template carries exactly one Environment= line"
grep -q '^Environment=SBOX_JR_UNIT=@SBJR_WATCHED_UNIT@$' "$TPL" \
    && pass "the one channel is SBOX_JR_UNIT (no secrets, no new env surface)" \
    || fail "SBOX_JR_UNIT channel drifted"
# CI registration locks (fail-closed if the lanes ever lose this suite).
CIY="$ROOT/.github/workflows/tests.yml"
grep -q 'bash -n tests/test-monitor-v2-jr-deploy.sh' "$CIY" \
    && pass "fast-checks lane: this suite bash -n registered" || fail "suite missing from fast-checks"
grep -q 'bash tests/test-monitor-v2-jr-deploy.sh' "$CIY" \
    && pass "monitor-regression lane: this suite registered" || fail "suite missing from monitor-regression"

# ===========================================================================
section "S1: rendered unit contract (direct render)"
# ===========================================================================
RDIR="$TMP/render"; mkdir -p "$RDIR"
RENDERED="$RDIR/unit"
( export SBMON_FIXTURE=1 SBOXJR_LIB_DIR="$RDIR/runtime" \
      SBOXJR_DATA_ROOT="$RDIR/data" PATH="$STUB:$PATH"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_render_unit > "$2"' _ "$LIB" "$RENDERED" )
if [ -s "$RENDERED" ]; then pass "render produces non-empty unit"; else
    fail "render empty"; : > "$RENDERED"; fi
assert_no_grep "$RENDERED" '@[A-Z_]+@' "no unrendered placeholder survives"
grep -q '^User=sbox-jr$' "$RENDERED" && grep -q '^Group=sbox-jr$' "$RENDERED" \
    && pass "identity renders to sbox-jr/sbox-jr" || fail "identity render wrong"
grep -q "^Environment=SBOX_JR_UNIT=sing-box.service$" "$RENDERED" \
    && pass "SBOX_JR_UNIT renders from the watched-unit constant" || fail "watched unit env render wrong"
assert_eq "$(grep -c '^Environment=' "$RENDERED")" "1" "rendered unit keeps a single Environment line"
grep -q "ExecStart=$RDIR/runtime/sbox-journal-reader" "$RENDERED" \
    && pass "ExecStart targets the (symlinked) runtime wrapper" || fail "ExecStart render wrong"
grep -q "^ReadWritePaths=$RDIR/data$" "$RENDERED" \
    && pass "single writable exception renders to the data root" || fail "ReadWritePaths render wrong"
RENDERED_CODE="$RDIR/unit.code"; grep -v '^[[:space:]]*#' "$RENDERED" > "$RENDERED_CODE"
grep -q '^RestrictAddressFamilies=AF_UNIX$' "$RENDERED_CODE" \
    && ! grep -q 'AF_INET' "$RENDERED_CODE" \
    && pass "rendered unit keeps AF_UNIX-only (executable lines)" || fail "address-family render wrong"
assert_no_grep "$RENDERED" 'BOX_API|api_secret' "rendered unit carries no secret surface"

# ===========================================================================
section "S2: INERT baseline (source tree without journal_reader)"
# ===========================================================================
new_case inert "$SRC_NOJR"
inst install
assert_eq "$LAST_RC" "0" "inert: install succeeds rc=0 (rc=$LAST_RC)"
assert_grep "$OUT" 'reader INERT' "inert: loudly logged as INERT"
[ ! -e "$SBOXJR_UNIT_FILE" ] && pass "inert: no reader unit written" || fail "inert: reader unit exists"
[ ! -e "$SBOXJR_LIB_DIR" ] && pass "inert: no runtime link created" || fail "inert: runtime path created"
[ ! -e "$SBOXJR_DATA_ROOT" ] && pass "inert: no data directories created" || fail "inert: data tree created"
assert_eq "$(calls_mut_of 'singbox-journal-reader')" "0" "inert: ZERO state-changing reader calls"

# ===========================================================================
section "S3: partial manifest source refuses BEFORE staging"
# ===========================================================================
new_case partial "$SRC_PARTIAL"
inst install
[ "$LAST_RC" != "0" ] && pass "partial: install refused rc=$LAST_RC" \
    || fail "partial: install must refuse, got rc=0"
assert_grep "$OUT" '缺少 journal_reader 模块源文件: eligibility.py' \
    "partial: refusal names the missing manifest module"
assert_no_grep "$OUT" 'staging release' "partial: refused BEFORE any staging"
[ -z "$(ls -A "$SBMON_RELEASES_DIR" 2>/dev/null)" ] \
    && pass "partial: releases dir untouched" || fail "partial: staging happened anyway"
assert_eq "$(calls_mut_of 'singbox-journal-reader')" "0" "partial: zero state-changing reader calls"
[ ! -e "$SBOXJR_UNIT_FILE" ] && pass "partial: no unit written" || fail "partial: unit written"

# ===========================================================================
section "S4: fresh activation (happy path, fixture transaction)"
# ===========================================================================
new_case fresh "$SRC"
inst install
assert_eq "$LAST_RC" "0" "fresh: install rc=0 (rc=$LAST_RC)"
assert_grep "$OUT" 'unit 通过 systemd-analyze verify' "fresh: verify ran and passed"
assert_grep "$OUT" 'reader 收敛完成' "fresh: reader converged"
# verify-before-install evidence: exactly one analyze call against a
# dot-prefixed .service temp that leaves NO residue in the unit dir.
assert_eq "$(grep -c '^analyze verify ' "$JR_ANALYZE_LOG")" "1" \
    "fresh: exactly one systemd-analyze verify"
VERIFY_ARG="$(sed -n 's/^analyze verify //p' "$JR_ANALYZE_LOG" | head -n1)"
case "$(basename -- "${VERIFY_ARG:-none}")" in
    .jr-verify.*.service) pass "fresh: verify used the dot-prefixed .service temp" ;;
    *) fail "fresh: verify temp name wrong ($VERIFY_ARG)" ;;
esac
assert_eq "$(find "$CASE_DIR/etc" -maxdepth 1 -name '.jr-verify.*' | wc -l | tr -d ' ')" "0" \
    "fresh: no verify temp residue"
# terminal contract: enabled AND active (§8).
assert_eq "$(jr_state)" "active/enabled" "fresh: reader terminal state active+enabled"
call_line_present 'systemctl enable singbox-journal-reader' \
    && pass "fresh: the enable --now start path was used" \
    || fail "fresh: enable never issued"
[ -e "$SBOXJR_UNIT_FILE" ] && pass "fresh: unit file installed" || fail "fresh: unit missing"
grep -q '^User=sbox-jr$' "$SBOXJR_UNIT_FILE" 2>/dev/null \
    && grep -q "^Environment=SBOX_JR_UNIT=sing-box.service$" "$SBOXJR_UNIT_FILE" 2>/dev/null \
    && pass "fresh: installed unit is the rendered contract" \
    || fail "fresh: installed unit content wrong"
# §5 staged manifest inside the release (exact 12+1+1, no pycache).
RID="$(current_release_id)"
if [ -n "$RID" ]; then
    JL="$SBMON_RELEASES_DIR/$RID/libexec/sbox-journal-reader"
else
    # non-symlink platform: fall back to the single release dir on disk
    JL="$(ls -d "$SBMON_RELEASES_DIR"/*/libexec/sbox-journal-reader 2>/dev/null | head -n1)"
    JL="${JL:-$SBMON_RELEASES_DIR/NONE/libexec/sbox-journal-reader}"
fi
[ -d "$JL/journal_reader" ] && pass "fresh: libexec/journal_reader staged in the release" \
    || fail "fresh: libexec missing from release"
assert_eq "$(find "$JL/journal_reader" -maxdepth 1 -name '*.py' 2>/dev/null | wc -l | tr -d ' ')" "12" \
    "fresh: exactly the 12 manifest modules staged"
[ -f "$JL/sbox-journal-reader" ] && pass "fresh: entry wrapper staged with the release" \
    || fail "fresh: wrapper missing"
[ -f "$JL/singbox-journal-reader.service.in" ] \
    && pass "fresh: unit template bundled with the release (rollback coherence)" \
    || fail "fresh: template missing from release"
assert_eq "$(find "$SBMON_RELEASES_DIR" -name '__pycache__' 2>/dev/null | wc -l | tr -d ' ')" "0" \
    "fresh: no __pycache__ ever reaches a release"
[ -d "$SBOXJR_DATA_ROOT/state" ] && [ -d "$SBOXJR_DATA_ROOT/out" ] \
    && pass "fresh: state/ and out/ created under the data root" \
    || fail "fresh: data tree incomplete"
# §17 status surface reports the activation (read-only)
inst status
assert_grep "$OUT" 'jr state:   active/enabled' "fresh: status reports reader active/enabled"
if require_symlink "fresh: runtime link -> release assertion"; then
    assert_eq "$(jr_link_release_id)" "$RID" "fresh: runtime link points into the current release"
fi

# ===========================================================================
section "S5: verify failure -> NO install/enable/start (§7)"
# ===========================================================================
new_case verifyfail "$SRC"
: > "$MOCK_MS/analyze_fail"
inst install
[ "$LAST_RC" != "0" ] && pass "verifyfail: install refused rc=$LAST_RC" \
    || fail "verifyfail: install must refuse, rc=0"
assert_grep "$OUT" 'systemd-analyze verify 未通过' "verifyfail: refusal names the verify gate"
[ ! -e "$SBOXJR_UNIT_FILE" ] && pass "verifyfail: NO unit installed" \
    || fail "verifyfail: unit leaked past the failed verify"
assert_no_grep "$MOCK_CALL_LOG" 'systemctl (enable|start|restart) singbox-journal-reader' \
    "verifyfail: zero reader enable/start calls"
assert_eq "$(jr_state)" "inactive/disabled" "verifyfail: reader stayed inactive/disabled"
assert_grep "$OUT" '进入事务回滚' \
    "verifyfail: the candidate failure entered the rollback transaction"
if [ "$SYMLINK_OK" = 1 ]; then
    [ ! -e "$SBOXJR_LIB_DIR" ] && pass "verifyfail: runtime link restored to <none>" \
        || fail "verifyfail: runtime link residue"
else
    skip "verifyfail: runtime link residue assertion"
fi
assert_eq "$(find "$CASE_DIR/etc" -maxdepth 1 -name '.jr-verify.*' | wc -l | tr -d ' ')" "0" \
    "verifyfail: verify temp cleaned up"

# ===========================================================================
section "S6: enable --now start failure -> full pre-state restore (§15)"
# ===========================================================================
new_case startfail "$SRC"
: > "$MOCK_MS/fail_start.singbox-journal-reader"
inst install
[ "$LAST_RC" != "0" ] && pass "startfail: install refused rc=$LAST_RC" \
    || fail "startfail: install must refuse, rc=0"
call_line_present 'systemctl disable singbox-journal-reader' \
    && pass "startfail: restore compensated the half-success (enabled -> disable)" \
    || fail "startfail: enable residue not compensated"
assert_eq "$(jr_state)" "inactive/disabled" "startfail: final reader state disabled+inactive"
[ ! -e "$SBOXJR_UNIT_FILE" ] && pass "startfail: candidate unit removed by rollback" \
    || fail "startfail: candidate unit survived"
if [ -e "$SBMON_RELEASES_DIR/releases.history" ]; then
    fail "startfail: history file exists for a failed fresh install"
else
    pass "startfail: failed candidate never entered history (commit-record rule)"
fi

# ===========================================================================
section "S7: service starts but cannot stay active (wait gate)"
# ===========================================================================
new_case dead "$SRC"
: > "$MOCK_MS/dead.singbox-journal-reader"
inst install
[ "$LAST_RC" != "0" ] && pass "dead: install refused rc=$LAST_RC" \
    || fail "dead: install must refuse, rc=0"
assert_grep "$OUT" 'reader 未在 .*s 内 active' "dead: active-wait gate reported the timeout"
call_line_present 'systemctl disable singbox-journal-reader' \
    && pass "dead: rollback disabled the unit after the dead start" \
    || fail "dead: rollback missed the disable compensation"
assert_eq "$(jr_state)" "inactive/disabled" "dead: final state disabled+inactive"
[ ! -e "$SBOXJR_UNIT_FILE" ] && pass "dead: candidate unit rolled back" || fail "dead: unit survived rollback"

# ===========================================================================
section "S8: --no-start deploys files only (unit installed, untouched state)"
# ===========================================================================
new_case nostart "$SRC"
inst install --no-start
assert_eq "$LAST_RC" "0" "nostart: rc=0 (rc=$LAST_RC)"
[ -e "$SBOXJR_UNIT_FILE" ] && pass "nostart: unit deployed" || fail "nostart: unit missing"
assert_eq "$(jr_state)" "inactive/disabled" "nostart: enable/start genuinely skipped"
assert_no_grep "$MOCK_CALL_LOG" 'systemctl (enable|start|restart) singbox-journal-reader' \
    "nostart: zero enable/start calls recorded"
assert_grep "$OUT" '跳过 reader 服务启动' "nostart: skip is loudly logged"

# ===========================================================================
section "S9: uninstall semantics (§13)"
# ===========================================================================
if require_symlink "uninstall scenario (needs link_runtime + unlink)"; then
    new_case uninstall "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "uninstall: precondition install rc=0"
    assert_eq "$(jr_state)" "active/enabled" "uninstall: precondition reader running"
    inst uninstall
    assert_eq "$LAST_RC" "0" "uninstall: rc=0 (rc=$LAST_RC)"
    call_line_present 'systemctl stop singbox-journal-reader' \
        && pass "uninstall: reader stopped" || fail "uninstall: reader not stopped"
    call_line_present 'systemctl disable singbox-journal-reader' \
        && pass "uninstall: reader disabled" || fail "uninstall: reader not disabled"
    [ ! -e "$SBOXJR_UNIT_FILE" ] && pass "uninstall: reader unit removed" || fail "uninstall: unit residue"
    [ ! -e "$SBOXJR_LIB_DIR" ] && pass "uninstall: runtime link removed (ONLY the link)" \
        || fail "uninstall: runtime link residue"
    [ -d "$SBOXJR_DATA_ROOT/state" ] \
        && pass "uninstall: diagnostic state kept by default (no implicit purge)" \
        || fail "uninstall: state purged without --purge-state"
    assert_grep "$OUT" '身份' "uninstall: identity retention logged"
    M="$(log_mark)"
    inst uninstall
    assert_eq "$LAST_RC" "0" "uninstall: idempotent re-run rc=0"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    assert_no_grep "$CASE_DIR/calls.tail" 'systemctl (stop|disable) singbox-journal-reader' \
        "uninstall: second run performs zero reader teardown calls (checked-first)"
    inst install; assert_eq "$LAST_RC" "0" "uninstall: reinstall after purge-free uninstall rc=0"
    inst uninstall --purge-state
    assert_eq "$LAST_RC" "0" "uninstall --purge-state: rc=0"
    [ ! -e "$SBOXJR_DATA_ROOT" ] && pass "uninstall --purge-state: reader data root purged" \
        || fail "uninstall --purge-state: data root survived"
fi

# ===========================================================================
section "S10: upgrade / rollback version coherence (symlink-gated matrix)"
# ===========================================================================
if require_symlink "upgrade+reader restart"; then
    new_case upgrade "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "upgrade: v1 install rc=0"
    R1="$(current_release_id)"
    assert_eq "$(jr_link_release_id)" "$R1" "upgrade: reader link tracks v1 release"
    printf '0.1.1\n' > "$SBMON_VERSION_FILE"
    M="$(log_mark)"
    inst install
    assert_eq "$LAST_RC" "0" "upgrade: v2 install rc=0 (rc=$LAST_RC)"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    R2="$(current_release_id)"
    [ "$R2" != "$R1" ] && pass "upgrade: new release activated" || fail "upgrade: release did not change"
    assert_eq "$(jr_link_release_id)" "$R2" "upgrade: reader runtime relinked to the NEW release"
    assert_eq "$(grep -c 'systemctl restart singbox-journal-reader' "$CASE_DIR/calls.tail")" "1" \
        "upgrade: running reader restarted exactly once (new code live)"
    assert_eq "$(grep -c 'systemctl enable singbox-journal-reader' "$CASE_DIR/calls.tail")" "0" \
        "upgrade: no redundant enable on an already-running reader"
    assert_eq "$(jr_state)" "active/enabled" "upgrade: terminal state still active+enabled"
fi

if require_symlink "upgrade failure -> reader rollback coherence"; then
    new_case upgraderb "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "upgrb: v1 install rc=0"
    R1="$(current_release_id)"
    printf '0.1.1\n' > "$SBMON_VERSION_FILE"
    : > "$MOCK_MS/fail_restart_once.singbox-journal-reader"
    inst install
    [ "$LAST_RC" != "0" ] && pass "upgrb: failed upgrade refused rc=$LAST_RC" \
        || fail "upgrb: must refuse, rc=0"
    assert_eq "$(jr_link_release_id)" "$R1" "upgrb: runtime link RESTORED to the old release (no version mix)"
    assert_grep "$OUT" 'sbox-journal-reader 激活前状态恢复完成' "upgrb: reader pre-state restore logged"
    assert_eq "$(jr_state)" "active/enabled" "upgrb: reader active+enabled preserved through the failed upgrade"
    assert_eq "$(current_release_id)" "$R1" "upgrb: monitor release also restored to v1 (one transaction)"
fi

if require_symlink "rollback keep-prestate matrix"; then
    new_case rollbackpv "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "rb: v1 install rc=0"
    printf '0.1.1\n' > "$SBMON_VERSION_FILE"
    inst install; assert_eq "$LAST_RC" "0" "rb: v2 install rc=0"
    R1="$(history_first_id)"
    [ -n "$R1" ] && pass "rb: oldest release id resolved from history" || fail "rb: history unusable"
    M="$(log_mark)"
    inst rollback "$R1"
    assert_eq "$LAST_RC" "0" "rb: rollback rc=0 (rc=$LAST_RC)"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    assert_eq "$(jr_link_release_id)" "$R1" "rb: reader runtime followed the release rollback (version-coherent)"
    assert_eq "$(grep -c 'systemctl restart singbox-journal-reader' "$CASE_DIR/calls.tail")" "1" \
        "rb: running reader restarted exactly once onto the old runtime"
    assert_eq "$(jr_state)" "active/enabled" "rb: terminal state active+enabled"
    assert_no_grep "$CASE_DIR/calls.tail" 'systemctl (enable|disable) singbox-journal-reader' \
        "rb: boot-enable facts untouched (no enable/disable churn)"
    # enabled but INACTIVE pre-state: rollback must NOT start it (§8 matrix)
    seed_jr_state inactive enabled
    M="$(log_mark)"
    inst rollback "$(jr_link_release_id)"
    assert_eq "$LAST_RC" "0" "rb: rollback under inactive pre-state rc=0"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    assert_no_grep "$CASE_DIR/calls.tail" 'systemctl (enable|start|restart) singbox-journal-reader' \
        "rb: inactive-but-enabled reader stays inactive (no opportunistic start)"
    assert_eq "$(jr_state)" "inactive/enabled" "rb: pre-state facts restored exactly"
fi

if require_symlink "rollback refusal for pre-PR-2B target"; then
    new_case rbguard "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "rbguard: install rc=0"
    printf '0.1.1\n' > "$SBMON_VERSION_FILE"
    inst install; assert_eq "$LAST_RC" "0" "rbguard: second install rc=0"
    R1="$(history_first_id)"
    rm -rf -- "$SBMON_RELEASES_DIR/$R1/libexec"
    M="$(log_mark)"
    inst rollback "$R1"
    [ "$LAST_RC" != "0" ] && pass "rbguard: rollback to libexec-less target refused rc=$LAST_RC" \
        || fail "rbguard: must refuse, rc=0"
    assert_grep "$OUT" '拒绝回滚' "rbguard: refusal message names the version-mix guard"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    assert_no_grep "$CASE_DIR/calls.tail" 'systemctl (restart|enable|disable|stop) ' \
        "rbguard: refusal happened before ANY state-changing systemctl call"
    [ "$(current_release_id)" != "$R1" ] && pass "rbguard: current release untouched by the refusal" \
        || fail "rbguard: release flipped despite the refusal"
fi

if require_symlink "noop re-convergence (needs stable link)"; then
    new_case noop "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "noop: first install rc=0"
    M="$(log_mark)"; L1="$(jr_link_release_id)"
    inst install
    assert_eq "$LAST_RC" "0" "noop: identical-version re-run rc=0"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    assert_no_grep "$CASE_DIR/calls.tail" 'systemctl (restart|enable|disable|stop) singbox-journal-reader' \
        "noop: zero reader mutations while nothing changed (idempotent convergence)"
    assert_no_grep "$OUT" '已存在且不是符号链接' "noop: runtime link stayed a real symlink"
    [ "$(jr_link_release_id)" = "$L1" ] && pass "noop: link identity stable across runs" \
        || fail "noop: link moved unexpectedly"
fi

# ===========================================================================
section "S11: fail-closed mutation gates (disable/reload failure paths)"
# ===========================================================================
if require_symlink "disable-failure rollback (uninstall path crosses link)"; then
    new_case disablefail "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "disablefail: install rc=0"
    : > "$MOCK_MS/fail_disable.singbox-journal-reader"
    inst uninstall
    [ "$LAST_RC" != "0" ] && pass "disablefail: uninstall aborts rc=$LAST_RC" \
        || fail "disablefail: uninstall must abort on disable failure"
    [ -e "$SBOXJR_UNIT_FILE" ] \
        && pass "disablefail: unit NOT deleted while still enabled (abort BEFORE deletion)" \
        || fail "disablefail: destructive path ran despite the failed disable"
fi

if require_symlink "daemon-reload failure rollback"; then
    new_case reloadfail "$SRC"
    echo 1 > "$MOCK_MS/reload_fail"   # monitor reload succeeds, reader reload fails
    inst install
    [ "$LAST_RC" != "0" ] && pass "reloadfail: install refused rc=$LAST_RC" \
        || fail "reloadfail: must refuse on reader daemon-reload failure"
    [ ! -e "$SBOXJR_UNIT_FILE" ] && pass "reloadfail: candidate unit rolled back" \
        || fail "reloadfail: unit residue after failed reload"
    assert_no_grep "$MOCK_CALL_LOG" 'systemctl (enable|start|restart) singbox-journal-reader' \
        "reloadfail: refusal stopped before enable/start"
fi

# ===========================================================================
section "S12: direct fixture=0 groups (identity / data tree / probe / verify)"
# ===========================================================================
JRDB="$TMP/jrdb"
db_exact() { # compliant exact-shape identity
    rm -rf "$JRDB"; mkdir -p "$JRDB"
    printf 'sbox-jr:x:998:\n' > "$JRDB/group.sbox-jr"
    printf 'systemd-journal:x:997:\n' > "$JRDB/group.systemd-journal"
    printf 'sbox-jr:x:998:998::/nonexistent:/usr/sbin/nologin\n' > "$JRDB/passwd.sbox-jr"
    printf 'systemd-journal\n' > "$JRDB/members.sbox-jr"
}
db_diverge() { # db_diverge <shell|home|primary|journal-missing|extra>
    db_exact
    case "$1" in
        shell) printf 'sbox-jr:x:998:998::/nonexistent:/bin/bash\n' > "$JRDB/passwd.sbox-jr" ;;
        home)  printf 'sbox-jr:x:998:998::/home/sbox-jr:/usr/sbin/nologin\n' > "$JRDB/passwd.sbox-jr" ;;
        primary) printf 'sbox-jr:x:998:997::/nonexistent:/usr/sbin/nologin\n' > "$JRDB/passwd.sbox-jr" ;;
        journal-missing) : > "$JRDB/members.sbox-jr" ;;
        extra) printf 'systemd-journal\nadm\n' > "$JRDB/members.sbox-jr"; printf 'adm:x:996:\n' > "$JRDB/group.adm" ;;
    esac
    cp -r "$JRDB" "$JRDB.snapshot"
}
jr_preflight_direct() { # -> rc; stderr to $TMP/pref.err
    ( export SBMON_FIXTURE=0 JRDB PATH="$STUB:$PATH" \
           SBMON_REPO_MONITOR_DIR="$ROOT/monitor-v2" \
           SBMON_SYSTEMD_ANALYZE="$STUB/systemd-analyze-mock" \
           SBOXJR_USER=sbox-jr SBOXJR_GROUP=sbox-jr SBOXJR_JOURNAL_GROUP=systemd-journal \
           JR_ANALYZE_LOG="$TMP/analyze-direct.log"
      : > "$JR_ANALYZE_LOG"
      bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_activation_preflight' _ "$LIB" ) \
        2>"$TMP/pref.err"
}
for v in shell home primary journal-missing extra; do
    db_diverge "$v"
    if jr_preflight_direct; then
        fail "preflight: divergent '$v' identity accepted"
    else
        pass "preflight: divergent '$v' identity refused BEFORE any mutation"
    fi
    assert_no_grep "$TMP/pref.err" 'field=user_exists' "preflight: '$v' refusal names the real field (not existence)"
    grep -q 'field=' "$TMP/pref.err" || fail "preflight: '$v' refusal missing field= tag"
    [ ! -e "$JRDB/mutlog" ] && pass "preflight: '$v' zero account mutations" \
        || fail "preflight: '$v' mutated the identity store"
    diff -r -- "$JRDB.snapshot" "$JRDB" >/dev/null 2>&1 \
        && pass "preflight: '$v' identity store byte-identical" \
        || fail "preflight: '$v' identity store changed"
    rm -rf "$JRDB.snapshot"
done
db_exact
jr_preflight_direct \
    && pass "preflight: exact-shape pre-existing identity accepted (zero mutation path)" \
    || fail "preflight: rejected a COMPLIANT identity"
assert_eq "$([ -f "$JRDB/mutlog" ] && wc -l < "$JRDB/mutlog" | tr -d ' ' || echo 0)" "0" \
    "preflight: compliant identity caused no mutations"

# Creation order for an ABSENT identity (ensure_identity via direct call)
rm -rf "$JRDB"; mkdir -p "$JRDB"
( export SBMON_FIXTURE=0 JRDB PATH="$STUB:$PATH" \
      SBOXJR_USER=sbox-jr SBOXJR_GROUP=sbox-jr SBOXJR_JOURNAL_GROUP=systemd-journal \
      SBMON_SYSTEMD_ANALYZE="$STUB/systemd-analyze-mock" JR_ANALYZE_LOG="$TMP/analyze-direct.log"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_ensure_identity' _ "$LIB" ) >/dev/null 2>&1 \
    && pass "ensure: absent identity created successfully (stubs)" \
    || fail "ensure: creation failed"
assert_eq "$(cut -d' ' -f1 "$JRDB/mutlog" | tr '\n' '>' | sed 's/>$//')" \
    "groupadd>useradd>usermod" "ensure: creation order is exactly groupadd->useradd->usermod"
grep -q 'useradd .*--shell /usr/sbin/nologin' "$JRDB/mutlog" \
    && pass "ensure: created with nologin shell" || fail "ensure: nologin not enforced"
grep -q 'useradd .*--home-dir /nonexistent' "$JRDB/mutlog" \
    && pass "ensure: created with /nonexistent home" || fail "ensure: home contract wrong"
grep -q 'useradd .*--system' "$JRDB/mutlog" \
    && pass "ensure: system account" || fail "ensure: not a system account"
( export SBMON_FIXTURE=0 JRDB PATH="$STUB:$PATH" \
      SBOXJR_USER=sbox-jr SBOXJR_GROUP=sbox-jr SBOXJR_JOURNAL_GROUP=systemd-journal
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_validate_identity' _ "$LIB" ) >/dev/null 2>&1 \
    && pass "validate: round-trip accepts the created exact shape" \
    || fail "validate: rejects its own creation (contract broken)"

# §4 data-tree metadata contract via recording chown/chmod
TREED="$TMP/tree"; mkdir -p "$TREED"
( export SBMON_FIXTURE=0 PATH="$META:$STUB:$PATH" JR_META_LOG="$TREED/meta.log" \
      SBOXJR_DATA_ROOT="$TREED/data" SBOXJR_USER=sbox-jr SBOXJR_GROUP=sbox-jr \
      SBMON_GROUP=sboxweb SBMON_SYSTEMD_ANALYZE="$STUB/systemd-analyze-mock" \
      JRDB="$JRDB"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_ensure_data_tree' _ "$LIB" ) \
    && pass "tree: ensure_data_tree rc=0 (stubs)" || fail "tree: ensure_data_tree failed"
EXPECTED_META="chown root:sbox-jr $TREED/data
chmod 0750 $TREED/data
chown sbox-jr:sbox-jr $TREED/data/state
chmod 0700 $TREED/data/state
chown sbox-jr:sboxweb $TREED/data/out
chmod 2750 $TREED/data/out"
assert_eq "$(cat "$TREED/meta.log")" "$EXPECTED_META" \
    "tree: EXACT chown/chmod sequence (root:sbox-jr 0750 / state 0700 / out 2750 setgid, in order)"
# non-dir refusal BEFORE any metadata mutation
ND="$TMP/nondir"; mkdir -p "$ND"; printf 'x' > "$ND/data"
( export SBMON_FIXTURE=0 PATH="$META:$STUB:$PATH" JR_META_LOG="$ND/meta.log" \
      SBOXJR_DATA_ROOT="$ND/data" SBOXJR_USER=sbox-jr SBOXJR_GROUP=sbox-jr \
      SBMON_GROUP=sboxweb JRDB="$JRDB"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_ensure_data_tree' _ "$LIB" ) 2>/dev/null \
    && fail "tree: regular-file data root accepted" \
    || pass "tree: existing non-directory refused (fail-closed)"
[ ! -s "$ND/meta.log" ] && pass "tree: non-dir refusal caused ZERO metadata calls" \
    || fail "tree: metadata ran despite the refusal"
if [ "$SYMLINK_OK" = 1 ]; then
    SL="$TMP/slroot"; mkdir -p "$SL"; ln -s "$TREED" "$SL/data"
    ( export SBMON_FIXTURE=0 PATH="$META:$STUB:$PATH" JR_META_LOG="$SL/meta.log" \
          SBOXJR_DATA_ROOT="$SL/data" SBOXJR_USER=sbox-jr SBOXJR_GROUP=sbox-jr \
          SBMON_GROUP=sboxweb JRDB="$JRDB"
      bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_ensure_data_tree' _ "$LIB" ) 2>/dev/null \
        && fail "tree: symlinked data root accepted" \
        || pass "tree: symlink data root refused before mutation (no link traversal)"
    [ ! -s "$SL/meta.log" ] && pass "tree: symlink refusal caused ZERO metadata calls" \
        || fail "tree: metadata ran on a symlinked root"
else
    skip "tree: symlinked data-root refusal"
fi

# §17 readability probe (runuser -> fake id): group present vs missing
probe_run() { # probe_run <groups-line...> -> rc
    rm -rf "$JRDB"; mkdir -p "$JRDB"
    printf 'sbox-jr:x:998:\n' > "$JRDB/group.sbox-jr"
    printf 'systemd-journal:x:997:\n' > "$JRDB/group.systemd-journal"
    printf 'sbox-jr:x:998:998::/nonexistent:/usr/sbin/nologin\n' > "$JRDB/passwd.sbox-jr"
    local g
    for g in "$@"; do printf '%s\n' "$g"; done > "$JRDB/members.sbox-jr"
    ( export SBMON_FIXTURE=0 JRDB PATH="$STUB:$PATH" \
          SBOXJR_USER=sbox-jr SBOXJR_JOURNAL_GROUP=systemd-journal \
          SBOXJR_RUNUSER="$STUB/runuser" SBOXJR_LIB_DIR="$TMP/none" \
          SBOXJR_UNIT_FILE="$TMP/none.service"
      bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_readability_probe' _ "$LIB" ) >/dev/null 2>&1
}
probe_run systemd-journal && pass "probe: systemd-journal membership proves readable identity" \
    || fail "probe: valid membership refused"
probe_run adm && fail "probe: missing systemd-journal membership accepted" \
    || pass "probe: journal-group-less identity FAILS the readability proof"
( export SBMON_FIXTURE=0 JRDB PATH="$STUB:$PATH" SBOXJR_USER=sbox-jr \
      SBOXJR_JOURNAL_GROUP=systemd-journal SBOXJR_RUNUSER="$TMP/no-such-runuser"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_readability_probe' _ "$LIB" ) 2>/dev/null \
    && fail "probe: absent runuser silently passed" \
    || pass "probe: absent runuser is fail-closed"

# §7 verify gate OUTSIDE the fixture: missing analyzer = refuse, never hope
( export SBMON_FIXTURE=0 PATH="$STUB:$PATH" \
      SBMON_SYSTEMD_ANALYZE="$TMP/definitely-not-here" \
      SBOXJR_UNIT_FILE="$TMP/v.service" JR_ANALYZE_LOG="$TMP/analyze-direct.log"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_verify_unit /etc/hostname' _ "$LIB" ) 2>/dev/null \
    && fail "verify: missing analyzer passed silently (should be fail-closed)" \
    || pass "verify: missing systemd-analyze refuses OUTSIDE the fixture (no skip-and-hope)"
( export SBMON_FIXTURE=1 PATH="$STUB:$PATH" \
      SBMON_SYSTEMD_ANALYZE="$TMP/definitely-not-here" \
      SBOXJR_UNIT_FILE="$TMP/v.service" JR_ANALYZE_LOG="$TMP/analyze-direct.log"
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_verify_unit /etc/hostname' _ "$LIB" ) 2>/dev/null \
    && pass "verify: fixture degrades the missing-analyzer case loudly (documented platform rule)" \
    || fail "verify: fixture run broke"

# ===========================================================================
section "S13: runtime manifest audit (extra/missing/pycache all refuse)"
# ===========================================================================
mk_runtime() { # mk_runtime <dir> [ok|extra|omit|pycache]
    local dir="$1" mode="${2:-ok}"
    mkdir -p "$dir/journal_reader"
    local f
    for f in "$ROOT"/monitor-v2/journal_reader/*.py; do
        [ "$(basename "$f")" = "codes.py" ] && [ "$mode" = "omit" ] && continue
        cp "$f" "$dir/journal_reader/"
    done
    cp "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader" "$dir/sbox-journal-reader"
    cp "$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in" "$dir/singbox-journal-reader.service.in"
    if [ "$mode" = "extra" ]; then printf 'x' > "$dir/README.md"; fi
    if [ "$mode" = "pycache" ]; then mkdir -p "$dir/journal_reader/__pycache__"; fi
}
audit_run() { # <dir> -> rc
    ( export SBMON_FIXTURE=1 PATH="$STUB:$PATH"
      bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_audit_runtime "$2"' _ "$LIB" "$1" ) 2>/dev/null
}
AUD="$TMP/audit"
mk_runtime "$AUD/ok"
audit_run "$AUD/ok" && pass "audit: exact 12+1+1 tree accepted" || fail "audit: compliant tree refused"
mk_runtime "$AUD/extra" extra
audit_run "$AUD/extra" && fail "audit: extra file accepted" || pass "audit: unexpected extra file FAILS the manifest"
mk_runtime "$AUD/omit" omit
audit_run "$AUD/omit" && fail "audit: missing module accepted" || pass "audit: missing module FAILS the manifest"
mk_runtime "$AUD/pycache" pycache
audit_run "$AUD/pycache" && fail "audit: __pycache__ accepted" || pass "audit: __pycache__ residue FAILS the manifest"
mkdir -p "$AUD/empty"
audit_run "$AUD/empty" && fail "audit: empty dir accepted" || pass "audit: empty runtime dir refused"
if [ "$SYMLINK_OK" = 1 ]; then
    ln -s "$AUD/ok" "$AUD/linkdir"
    audit_run "$AUD/linkdir" && fail "audit: symlinked runtime root accepted" \
        || pass "audit: symlinked runtime root refused (never traversed)"
else
    skip "audit: symlinked runtime root refusal"
fi
# link_runtime refuses a REAL directory at the link slot (manual-migrate hint)
BADMIG="$TMP/badmig"
mkdir -p "$BADMIG/releases/any/libexec"
mk_runtime "$BADMIG/releases/any/libexec/sbox-journal-reader"
( export SBMON_FIXTURE=1 PATH="$STUB:$PATH" SBMON_RELEASES_DIR="$BADMIG/releases" \
      SBOXJR_LIB_DIR="$BADMIG/releases/any/libexec/sbox-journal-reader/../.."
  bash -c '. "$1" >/dev/null 2>&1; sbmon_sboxjr_link_runtime any' _ "$LIB" ) 2>"$TMP/badlib.err" \
    && fail "link: real-dir LIB slot accepted" \
    || pass "link: non-symlink existing path refused (never silently overwritten)"
assert_grep "$TMP/badlib.err" '人工处理' "link: refusal message asks for human action (fail-closed)"

# ===========================================================================
section "S13b: runtime link provenance tri-state (review-round fail-closed)"
# ===========================================================================
# sbmon_sboxjr_runtime_linked_id must STRICTLY separate three states:
#   (1) NO symlink at $SBOXJR_LIB_DIR -> empty + rc0 (legal: never linked);
#   (2) target EXACTLY releases/<id>/libexec/sbox-journal-reader (single-
#       component id under the releases root, target passes the manifest
#       audit) -> that exact id;
#   (3) ANY other symlink -> rc1 + human-action demand. Never basename-
#       guessed, never silently treated as absent, never auto-repaired.
# Placed BEFORE S14 so the global §9/§10/§18 invariant roll-up also covers
# every scenario below.
jr_probe_id() { # -> "<rc>:<stdout>" of the decoder under the case env
    bash -c '. "$1" >/dev/null 2>&1
        out="$(sbmon_sboxjr_runtime_linked_id 2>/dev/null)"; rc=$?
        printf "%s:%s\n" "$rc" "$out"' _ "$LIB"
}
prune_probe() { # run retention under the case env -> rc (output silenced)
    bash -c '. "$1" >/dev/null 2>&1; sbmon_prune_releases' _ "$LIB" >/dev/null 2>&1
}
mk_foreign_link() { # raw-swap the runtime link slot to <target> (no validation)
    rm -f -- "$SBOXJR_LIB_DIR"
    ln -s "$1" "$SBOXJR_LIB_DIR"
}
if require_symlink "runtime link provenance tri-state"; then
    new_case prov "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "prov: precondition install rc=0"
    R1="$(current_release_id)"
    # (1) legal canonical link decodes to the EXACT release id
    assert_eq "$(jr_probe_id)" "0:$R1" "prov: canonical link -> exact release id (rc0)"
    # (1b) absent link is legal: empty + rc0, never an error
    rm -f -- "$SBOXJR_LIB_DIR"
    assert_eq "$(jr_probe_id)" "0:" "prov: absent link -> empty + rc0 (legal, not guessed)"
    # (2) foreign absolute target: rc1, stdout silent
    mk_foreign_link /etc/hostname
    assert_eq "$(jr_probe_id)" "1:" "prov: foreign absolute target refused (rc1, stdout silent)"
    # (3) suffix-coincidence decoy OUTSIDE the releases dir -- a fully
    #     manifest-valid tree must STILL be refused (no basename guessing)
    mk_runtime "$CASE_DIR/foreign/libexec/sbox-journal-reader"
    mk_foreign_link "$CASE_DIR/foreign/libexec/sbox-journal-reader"
    assert_eq "$(jr_probe_id)" "1:" "prov: releases-external target ENDING IN the libexec suffix refused"
    # (4) inside the releases dir, wrong depth in BOTH directions
    mkdir -p "$SBMON_RELEASES_DIR/deep/er/libexec/sbox-journal-reader" \
             "$SBMON_RELEASES_DIR/libexec/sbox-journal-reader"
    mk_foreign_link "$SBMON_RELEASES_DIR/deep/er/libexec/sbox-journal-reader"
    assert_eq "$(jr_probe_id)" "1:" "prov: extra directory level under releases refused"
    mk_foreign_link "$SBMON_RELEASES_DIR/libexec/sbox-journal-reader"
    assert_eq "$(jr_probe_id)" "1:" "prov: release id collapsing onto libexec refused"
    # (5) right depth, wrong final component
    mk_foreign_link "$SBMON_RELEASES_DIR/$R1/libexec/other"
    assert_eq "$(jr_probe_id)" "1:" "prov: wrong libexec suffix refused"
    # (6) broken link in the canonical SHAPE: dangling runtime is an
    #     integrity finding (audit refuses), NOT the legal 'absent' state
    mk_foreign_link "$SBMON_RELEASES_DIR/ghost/libexec/sbox-journal-reader"
    assert_eq "$(jr_probe_id)" "1:" "prov: broken runtime link refused via manifest audit"
    # e2e: deploy must REFUSE before any mutation and demand human action,
    # and must never auto-repair the illegal link it found.
    M="$(log_mark)"
    inst install
    [ "$LAST_RC" != "0" ] && pass "prov: deploy refuses illegal link provenance before mutation (rc=$LAST_RC)" \
        || fail "prov: deploy accepted an illegal runtime link"
    assert_grep "$OUT" 'provenance 非法' "prov: refusal names the provenance gate"
    assert_grep "$OUT" '人工处理' "prov: refusal demands human action (fail-closed)"
    tail -n +"$((M + 1))" "$MOCK_CALL_LOG" > "$CASE_DIR/calls.tail"
    assert_no_grep "$CASE_DIR/calls.tail" 'systemctl (start|stop|restart|enable|disable|kill|daemon-reload)' \
        "prov: zero state-changing systemctl calls in the refusal window"
    assert_eq "$(readlink -- "$SBOXJR_LIB_DIR")" \
        "$SBMON_RELEASES_DIR/ghost/libexec/sbox-journal-reader" \
        "prov: the illegal link was left exactly as found (never silently overwritten)"
    [ "$(current_release_id)" = "$R1" ] && pass "prov: live monitor release untouched by the refusal" \
        || fail "prov: refusal mutated the live release"
fi

if require_symlink "provenance-aware retention"; then
    new_case provprune "$SRC"
    export SBMON_KEEP_RELEASES=2
    mk_rel_set() { # 3 manifest-valid releases with pinned ages (old->new)
        rm -rf -- "$SBMON_RELEASES_DIR"
        mkdir -p "$SBMON_RELEASES_DIR"
        local id
        for id in r-old r-mid r-new; do
            mkdir -p "$SBMON_RELEASES_DIR/$id"
            mk_runtime "$SBMON_RELEASES_DIR/$id/libexec/sbox-journal-reader"
        done
        touch -d '2026-01-01 00:00:00' "$SBMON_RELEASES_DIR/r-old"
        touch -d '2026-01-02 00:00:00' "$SBMON_RELEASES_DIR/r-mid"
        touch -d '2026-01-03 00:00:00' "$SBMON_RELEASES_DIR/r-new"
        ln -sfn -- "$SBMON_RELEASES_DIR/r-new" "$SBMON_APP_LINK"
    }
    # (7) a VALID link protects the release it references -- even the oldest
    mk_rel_set
    mk_foreign_link "$SBMON_RELEASES_DIR/r-old/libexec/sbox-journal-reader"
    if prune_probe; then pass "prune: legal provenance prunes normally"; else fail "prune: valid link refused?"; fi
    [ -d "$SBMON_RELEASES_DIR/r-old" ] \
        && pass "prune: reader-referenced release protected by its EXACT id (oldest kept)" \
        || fail "prune: protected release was deleted (link-id mismatch)"
    [ ! -d "$SBMON_RELEASES_DIR/r-mid" ] && pass "prune: next-oldest eligible release pruned" \
        || fail "prune: retention did not run (nothing removed)"
    [ -d "$SBMON_RELEASES_DIR/r-new" ] && pass "prune: live monitor release untouched" \
        || fail "prune: live release was deleted"
    # (8) an ILLEGAL link fails the prune PRECONDITION closed -- it must not
    #     be ignored while the other releases silently disappear
    mk_rel_set
    mk_foreign_link /etc/hostname
    if prune_probe; then
        fail "prune: pruned despite unverifiable reader link provenance"
    else
        pass "prune: refuses ALL retention when link provenance is illegal (fail-closed)"
    fi
    [ -d "$SBMON_RELEASES_DIR/r-old" ] && [ -d "$SBMON_RELEASES_DIR/r-mid" ] && [ -d "$SBMON_RELEASES_DIR/r-new" ] \
        && pass "prune: zero releases deleted on the refused path" \
        || fail "prune: deletion happened despite the refusal"
    unset SBMON_KEEP_RELEASES
fi

if require_symlink "failed-upgrade restore uses only the exact captured id"; then
    new_case provrb "$SRC"
    inst install; assert_eq "$LAST_RC" "0" "provr: v1 install rc=0"
    R1="$(current_release_id)"
    printf '0.1.1\n' > "$SBMON_VERSION_FILE"
    : > "$MOCK_MS/fail_restart_once.singbox-journal-reader"
    inst install
    [ "$LAST_RC" != "0" ] && pass "provr: failed upgrade refused rc=$LAST_RC" || fail "provr: must refuse, rc=0"
    assert_grep "$OUT" "runtime=$R1" "provr: restore log carries the EXACT release id (never a leaf-name fake)"
    assert_eq "$(readlink -- "$SBOXJR_LIB_DIR")" \
        "$SBMON_RELEASES_DIR/$R1/libexec/sbox-journal-reader" \
        "provr: restored link is the full canonical shape for the captured release"
    assert_eq "$(jr_probe_id)" "0:$R1" "provr: post-restore link decodes cleanly"
fi

# ===========================================================================
section "S14: global invariants (spec §9/§10/§18 across EVERY scenario)"
# ===========================================================================
ALLCALLS="$TMP/all-calls.log"; : > "$ALLCALLS"
cat "$TMP"/case-*/calls.log >> "$ALLCALLS" 2>/dev/null
if grep -E 'systemctl (start|stop|restart|enable|disable|kill) sing-box' "$ALLCALLS"; then
    fail "INVARIANT: a sing-box unit operation occurred (absolute boundary §9)"
else
    pass "INVARIANT: zero sing-box unit operations across the whole suite (§9)"
fi
if grep -E 'systemctl (start|stop|restart|enable|disable|kill) ' "$ALLCALLS" \
   | grep -vE 'singbox-(monitor|journal-reader)( |$)'; then
    fail "INVARIANT: state change against an unauthorized unit"
else
    pass "INVARIANT: only singbox-monitor + singbox-journal-reader ever receive state changes (§12 product boundary)"
fi
if grep -lE 'BOX_API_SECRET|api_secret|gethostname' \
    "$ROOT/monitor-v2/deploy/app-bin/sbox-journal-reader" \
    "$ROOT/monitor-v2/deploy/singbox-journal-reader.service.in" >/dev/null 2>&1; then
    fail "INVARIANT: credential/host surface in reader deploy assets"
else
    pass "INVARIANT: reader deploy assets carry no credential or hostname surface (§6)"
fi
assert_no_grep "$LIB" '/var/lib/sbox-cm' "INVARIANT: library never references the sbox-cm state path (§10)"
assert_no_grep "$W_INSTALL" '/var/lib/sbox-cm' "INVARIANT: installer never references the sbox-cm state path (§10)"
SBMON_AUTH_IN_JR="$("$PY" - "$LIB" <<'EOF'
import re, sys
src = open(sys.argv[1], encoding="utf-8").read()
i = src.find("SBOXJR_USER=")
body = src[i:]
print("HIT" if re.search(r"auth\.json|access\.json|monitor\.conf", body) else "CLEAN")
EOF
)"
assert_eq "$SBMON_AUTH_IN_JR" "CLEAN" "INVARIANT: reader section touches no monitor auth/conf files (§18)"

# ===========================================================================
printf '\n== RESULT: %d passed, %d failed, %d skipped ==\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" != "0" ]; then
    exit 1
fi
if [ "$(uname -s 2>/dev/null)" = "Linux" ] && [ "$SKIP" != "0" ]; then
    printf 'Linux runners must not skip ANY scenario (activation matrix is the gate)\n' >&2
    exit 1
fi
if [ "$SYMLINK_OK" = 0 ] && [ "$SKIP" = 0 ]; then
    printf 'sanity: symlink-less platform reported zero skips -- probe broken?\n' >&2
    exit 1
fi
exit 0
