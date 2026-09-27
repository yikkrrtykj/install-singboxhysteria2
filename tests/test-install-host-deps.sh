#!/usr/bin/env bash
# Host dependency bootstrap regression tests.
#
# Target: the `# >>> host-dependencies <<<` block of install.sh -- the top-level
# server install path's package bootstrap, which the Monitor 0.3.1 journal
# reader activation depends on (package `acl` provides setfacl/getfacl for the
# least-privilege traversal convergence, package `util-linux` provides runuser
# for the real-identity readability proof).
#
# The contract under test, and why it is a map and not a package list: a
# dependency counts as satisfied only when every COMMAND it must put on PATH
# resolves, an install is believed only after those commands are re-checked, and
# anything still missing aborts the flow before anything is deployed.
#
# Like the phase-c / phase-d / S0 suites, these tests really EXECUTE the
# extracted shell functions. install.sh cannot be sourced (no `set -e`, no
# BASH_SOURCE guard, and a top-level flow that starts installing a server), so
# the block is extracted between its markers and run by a driver whose PATH is
# exactly [stub package-manager dir, simulated provided-commands dir]: no real
# host command can leak into a probe result, and every package-manager call is
# logged by a stub. The LIVE section then runs the same block against the real
# host and the real Monitor predicate.
#
# Nothing here installs a package, contacts the network, or touches /root/sbox.
# LIVE gates SKIP off Linux and become hard FAILs under SBHOST_REQUIRE_LIVE=1,
# which is how CI is forced to execute the real half.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="$HERE/../install.sh"
LIB="$HERE/../monitor-v2/deploy/lib/monitor-deploy-lib.sh"

PASS=0
FAIL=0
SKIP=0
CASE=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_rc() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected rc=$1, got rc=$2)"; fi; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected [$1], got [$2])"; fi; }
assert_grep() { if grep -qE "$1" "$2" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $1)"; fi; }
assert_no_grep() { if grep -qE "$1" "$2" 2>/dev/null; then fail "$3 (unexpected match: $1)"; else pass "$3"; fi; }
count_grep() { grep -cE "$1" "$2" 2>/dev/null || true; }

IS_LINUX=1
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) IS_LINUX=0 ;;
esac
REQUIRE_LIVE=0
[ "${SBHOST_REQUIRE_LIVE:-0}" = "1" ] && REQUIRE_LIVE=1

SYS_DIRS="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
PROV_SYS="/usr/bin"

# ---------------------------------------------------------------------------
section "static checks (OS independent)"
# ---------------------------------------------------------------------------
if bash -n "$INSTALL_SH" 2>"$TMP/syntax.err"; then
    pass "bash -n install.sh"
else
    fail "bash -n install.sh: $(cat "$TMP/syntax.err")"
fi
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_SH" >"$TMP/sc.out" 2>&1; then
        pass "shellcheck -S warning install.sh"
    else
        fail "shellcheck -S warning install.sh: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"
    fi
else
    skip "shellcheck 未安装"
fi

# The dependency map itself: PACKAGE -> probe COMMANDS, spelled out.
assert_grep '^HOST_DEP_SPECS=\($' "$INSTALL_SH" "dependencies declared as a package:command map"
assert_grep '"acl:setfacl,getfacl"' "$INSTALL_SH" "acl maps to the setfacl+getfacl command pair"
assert_grep '"util-linux:runuser"' "$INSTALL_SH" "util-linux maps to runuser"
assert_grep '"qrencode:qrencode"' "$INSTALL_SH" "pre-existing qrencode dependency kept"
assert_grep '"jq:jq"' "$INSTALL_SH" "pre-existing jq dependency kept"
assert_grep '"iptables:iptables"' "$INSTALL_SH" "pre-existing iptables dependency kept"

# The forbidden shapes: probing the package NAME, the old bare list, and
# believing an install without re-checking the commands.
assert_no_grep 'command -v +"acl"' "$INSTALL_SH" "no probe of a package name (command -v acl proves nothing)"
assert_no_grep 'local pkgs=\("qrencode"' "$INSTALL_SH" "old bare package-name array is gone"
assert_no_grep '\$pkg 安装成功' "$INSTALL_SH" "no unconditional post-install success message"
# Two probe passes by design: before an install (idempotence) and after it
# (verification). One pass would be the old bootstrap again.
assert_eq 2 "$(count_grep 'host_dep_probes_ok "\$probes"' "$INSTALL_SH")" \
    "probes checked both before and after an install"
# Fail-closed through the script's own aborting error(), not a warning.
assert_grep 'error "主机依赖缺失' "$INSTALL_SH" "unresolved dependency aborts through error()"

# Both top-level call sites still run the bootstrap (existing-install repair
# branch + fresh install path).
assert_eq 2 "$(count_grep '^[[:space:]]*install_pkgs$' "$INSTALL_SH")" \
    "install_pkgs still called on both top-level paths"
# Boundary: the top-level script does not call the Monitor installer -- this
# only makes the host usable; the Monitor preflight stays the authority.
assert_no_grep 'install-monitor\.sh' "$INSTALL_SH" "no coupling added to the Monitor installer"

# ---------------------------------------------------------------------------
section "extract the host-dependency block"
# ---------------------------------------------------------------------------
awk '/# >>> host-dependencies >>>/,/# <<< host-dependencies <<</' \
    "$INSTALL_SH" > "$TMP/block.sh"
if grep -q 'install_pkgs()' "$TMP/block.sh" && grep -q 'HOST_DEP_SPECS' "$TMP/block.sh"; then
    pass "host-dependency block extracted"
else
    fail "host-dependency block extraction"
fi
if bash -n "$TMP/block.sh" 2>"$TMP/block.syn"; then
    pass "bash -n extracted block"
else
    fail "bash -n extracted block: $(cat "$TMP/block.syn")"
fi

# install.sh's message helpers, with the one behaviour that matters here:
# error() prints and EXITS.
cat > "$TMP/shim.sh" <<'SHIM'
warning() { printf 'W: %s\n' "$*"; }
info()    { printf 'I: %s\n' "$*"; }
hint()    { printf 'H: %s\n' "$*"; }
error()   { warning "$*" && exit 1; }
SHIM

# The driver: narrowed PATH, shim + extracted block, then the real function.
# The marker line after install_pkgs stands for every later step of the
# top-level flow, so its ABSENCE is the proof that a failed bootstrap never
# reaches deployment.
cat > "$TMP/driver.sh" <<'DRV'
export PATH="$SBHOST_BIN:$SBHOST_PROV"
# shellcheck disable=SC1090
source "$SBHOST_SHIM"
# shellcheck disable=SC1090
source "$SBHOST_BLOCK"
install_pkgs
printf 'FLOW-CONTINUED\n'
DRV

BIN="$TMP/bin"
PROV="$TMP/prov"
STOCK="$TMP/stock"          # fake media for EVERY command (fixture cases)
PARTIAL="$TMP/partial"      # fake media except setfacl/getfacl (live L4)
NOSTOCK="$TMP/nostock"      # no media at all -> always link the real binary
DB="$TMP/db"
CALLS="$TMP/calls.log"
mkdir -p "$BIN" "$PROV" "$NOSTOCK" "$DB" "$STOCK" "$PARTIAL"

# package -> commands, as the stub installer's database.
printf 'setfacl\ngetfacl\n' > "$DB/acl"
printf 'runuser\n'          > "$DB/util-linux"
printf 'jq\n'               > "$DB/jq"
printf 'qrencode\n'         > "$DB/qrencode"
printf 'iptables\n'         > "$DB/iptables"
for c in setfacl getfacl runuser jq iptables qrencode acl; do
    printf '#!/bin/sh\nexit 0\n' > "$STOCK/$c"
    chmod 0755 "$STOCK/$c"
done
for c in runuser jq iptables qrencode; do
    printf '#!/bin/sh\nexit 0\n' > "$PARTIAL/$c"
    chmod 0755 "$PARTIAL/$c"
done

# A package-manager stub: logs the invocation, then materialises the commands
# the requested package provides. Builtins and absolute paths only, because it
# runs under the same narrowed PATH as the code under test.
make_pm() { # <apt|yum|dnf|none>
    rm -f "$BIN/apt" "$BIN/yum" "$BIN/dnf"
    local name="$1"
    if [ "$name" != "none" ]; then
        cat > "$BIN/$name" <<'PM'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >> "${SBHOST_CALLS:?}"
case "$*" in
    update*) exit "${SBHOST_UPDATE_RC:-0}" ;;
esac
if [ "${SBHOST_PM_RC:-0}" != "0" ]; then
    exit "$SBHOST_PM_RC"
fi
for a in "$@"; do
    [ -f "$SBHOST_DB/$a" ] || continue
    while read -r c; do
        [ -n "$c" ] || continue
        case " ${SBHOST_SKIP_CMDS:-} " in *" $c "*) continue ;; esac
        /bin/rm -f -- "$SBHOST_PROV/$c"
        if [ -e "$SBHOST_STOCK/$c" ]; then
            /bin/cp -f -- "$SBHOST_STOCK/$c" "$SBHOST_PROV/$c"
        else
            /bin/ln -s -- "$SBHOST_REAL/$c" "$SBHOST_PROV/$c"
        fi
        /bin/chmod 0755 -- "$SBHOST_PROV/$c"
    done < "$SBHOST_DB/$a"
done
exit 0
PM
        chmod 0755 "$BIN/$name"
    fi
    cat > "$BIN/sudo" <<'SUDO'
#!/bin/sh
printf 'sudo %s\n' "$*" >> "${SBHOST_CALLS:-/dev/null}"
exec "$@"
SUDO
    chmod 0755 "$BIN/sudo"
}

seed_prov() { # <space separated commands> -- already on this host
    local c
    for c in $1; do
        [ -e "$STOCK/$c" ] || continue
        cp -f "$STOCK/$c" "$PROV/$c"
        chmod 0755 "$PROV/$c"
    done
}

reset_env() { # <pm>
    rm -rf "$BIN" "$PROV"; mkdir -p "$BIN" "$PROV"; : > "$CALLS"
    make_pm "$1"
}

ALL_OK="qrencode jq iptables setfacl getfacl runuser"
NO_ACL="qrencode jq iptables runuser"

run_bootstrap() { # <pm> <present> [KNOb=value ...] -> OUT_FILE, RC, CALLS
    local pm="$1" present="$2"; shift 2
    reset_env "$pm"
    seed_prov "$present"
    CASE=$((CASE + 1))
    OUT_FILE="$TMP/out.$CASE"
    RC=0
    env SBHOST_SHIM="$TMP/shim.sh" SBHOST_BLOCK="$TMP/block.sh" \
        SBHOST_BIN="$BIN" SBHOST_PROV="$PROV" SBHOST_STOCK="$STOCK" \
        SBHOST_REAL="$PROV_SYS" SBHOST_DB="$DB" SBHOST_CALLS="$CALLS" \
        "$@" bash "$TMP/driver.sh" > "$OUT_FILE" 2>&1 || RC=$?
}

# ---------------------------------------------------------------------------
section "F1 fresh Ubuntu host: no acl -> bootstrap installs it -> probes resolve"
# ---------------------------------------------------------------------------
run_bootstrap apt "$NO_ACL"
assert_rc 0 "$RC" "F1 bootstrap succeeds once acl is provided"
assert_grep '开始安装 acl（提供命令: setfacl,getfacl）' "$OUT_FILE" "F1 acl install is attempted"
assert_grep 'acl 安装完成，命令验证通过: setfacl,getfacl' "$OUT_FILE" \
    "F1 success is reported only after the commands resolve"
assert_grep '^apt install -y acl$' "$CALLS" "F1 the PACKAGE name (acl) is what gets installed"
assert_no_grep 'install -y util-linux' "$CALLS" "F1 runuser already present -> no util-linux install"
assert_eq 0 "$([ -x "$PROV/setfacl" ] && [ -x "$PROV/getfacl" ] && echo 0 || echo 1)" \
    "F1 both acl commands exist afterwards"
assert_grep 'FLOW-CONTINUED' "$OUT_FILE" "F1 the flow continues only on a satisfied host"

section "F2 every dependency already satisfied: NO package-manager call at all"
run_bootstrap apt "$ALL_OK"
assert_rc 0 "$RC" "F2 idempotent re-run succeeds"
assert_eq 0 "$(wc -l < "$CALLS" | tr -d ' ')" \
    "F2 zero package-manager invocations (no apt update, no install)"
assert_eq 5 "$(count_grep '已经安装（命令: ' "$OUT_FILE")" \
    "F2 all five dependencies reported satisfied by command probe"
assert_grep 'FLOW-CONTINUED' "$OUT_FILE" "F2 idempotent re-run reaches the later steps"

section "F3 per-dependency granularity: only the missing package is installed"
run_bootstrap apt "qrencode jq iptables"
assert_rc 0 "$RC" "F3 both missing dependencies get their packages"
assert_grep '^apt install -y acl$' "$CALLS" "F3 acl installed"
assert_grep '^apt install -y util-linux$' "$CALLS" "F3 util-linux installed"
assert_eq 2 "$(count_grep '^apt install -y ' "$CALLS")" "F3 exactly two install calls"
assert_eq 0 "$([ -x "$PROV/setfacl" ] && [ -x "$PROV/getfacl" ] && [ -x "$PROV/runuser" ] && echo 0 || echo 1)" \
    "F3 all three probe commands present afterwards"

section "F4 package install fails -> fail closed, never enters deployment"
run_bootstrap apt "$NO_ACL" SBHOST_PM_RC=1
assert_rc 1 "$RC" "F4 a failed install aborts the top-level flow"
assert_grep '主机依赖缺失（命令: setfacl getfacl）' "$OUT_FILE" \
    "F4 the abort names the missing COMMANDS, not just the package"
assert_no_grep '安装完成，命令验证通过: setfacl' "$OUT_FILE" "F4 no fake success for acl"
assert_no_grep 'FLOW-CONTINUED' "$OUT_FILE" "F4 the flow stops before any deployment step"
assert_eq 1 "$([ -e "$PROV/setfacl" ] && echo 0 || echo 1)" "F4 nothing pretends to be installed"

section "F5 package manager exits 0 but getfacl is still missing -> fail closed"
run_bootstrap apt "$NO_ACL" SBHOST_SKIP_CMDS="getfacl"
assert_rc 1 "$RC" "F5 a half-materialised acl aborts the flow"
assert_grep '^apt install -y acl$' "$CALLS" "F5 the install really ran"
assert_grep 'W: acl 安装后命令仍缺失: setfacl,getfacl' "$OUT_FILE" \
    "F5 the re-check reports the residual gap after a nominal success"
assert_grep '主机依赖缺失（命令: getfacl）' "$OUT_FILE" "F5 only the truly missing command is named"
assert_no_grep '主机依赖缺失（命令:[^）]*setfacl' "$OUT_FILE" \
    "F5 the working setfacl is not falsely reported missing"
assert_no_grep 'FLOW-CONTINUED' "$OUT_FILE" \
    "F5 one missing acl command is enough to stop before deployment"

section "F6 runuser missing after a nominal util-linux success -> fail closed"
run_bootstrap apt "qrencode jq iptables setfacl getfacl" SBHOST_SKIP_CMDS="runuser"
assert_rc 1 "$RC" "F6 the runuser gap aborts too"
assert_grep '主机依赖缺失（命令: runuser）' "$OUT_FILE" "F6 runuser named as missing"
assert_no_grep 'FLOW-CONTINUED' "$OUT_FILE" "F6 no deployment after a missing runuser"

section "F7 no package manager on the host -> fail closed, no pretend success"
run_bootstrap none "$NO_ACL"
assert_rc 1 "$RC" "F7 an unbootstrappable host aborts"
assert_grep '主机依赖缺失' "$OUT_FILE" "F7 the abort still reports the gap"
assert_no_grep 'FLOW-CONTINUED' "$OUT_FILE" "F7 nothing continues without a way to install"

section "F8 RPM-shaped host: yum carries the same package->command mapping"
run_bootstrap yum "$NO_ACL"
assert_rc 0 "$RC" "F8 the yum path satisfies the same contract"
assert_grep '^yum install -y acl$' "$CALLS" "F8 yum used, package acl"
assert_no_grep 'apt' "$CALLS" "F8 apt is never touched on a yum host"
assert_grep 'FLOW-CONTINUED' "$OUT_FILE" "F8 satisfied host continues"

section "F9 a command literally named acl must NOT count as the dependency"
run_bootstrap apt "$NO_ACL acl" SBHOST_PM_RC=1
assert_rc 1 "$RC" "F9 an acl binary without setfacl/getfacl is still unsatisfied"
assert_no_grep 'acl 已经安装' "$OUT_FILE" "F9 the package name is never probed as a command"
assert_grep '开始安装 acl（提供命令: setfacl,getfacl）' "$OUT_FILE" \
    "F9 the real commands are what drive the decision"

# ---------------------------------------------------------------------------
section "LIVE host gates (real acl tools + the real Monitor predicate)"
# ---------------------------------------------------------------------------
# The Monitor library's own fail-closed consumer gate, asked about a concrete
# pair of paths. Sourcing monitor-deploy-lib.sh turns on `set -Eeuo pipefail`,
# so it is loaded in a guarded child shell; the two indirection variables are
# the library's own documented seam, not a mock.
predicate_at() { # -> PRED_RC
    PRED_RC=0
    SBOXJR_SETFACL="$PROV/setfacl" SBOXJR_GETFACL="$PROV/getfacl" \
    bash -c '. "$1" >/dev/null 2>&1; set +e
             export SBOXJR_SETFACL SBOXJR_GETFACL
             sbmon_sboxjr_acl_tools_available' _ "$LIB" \
        > "$TMP/pred.out" 2>&1 || PRED_RC=$?
}

if [ "$IS_LINUX" = "1" ]; then
    # L1 the three Monitor-relevant commands really resolve on this host.
    # Asked through the standard system PATH (what a root-run installer and the
    # Monitor gate see), not the harness's inherited PATH.
    for c in setfacl getfacl runuser; do
        found="$(PATH="$SYS_DIRS" bash -c 'command -v "$1" 2>/dev/null' _ "$c")"
        if [ -n "$found" ]; then
            pass "L1 real host provides $c ($found)"
        else
            fail "L1 real host lacks $c on the standard system PATH"
        fi
    done

    # L2 the extracted bootstrap, on the REAL host PATH, makes zero
    # package-manager calls: idempotence proven against real binaries. The
    # three non-Monitor dependencies are seeded as fakes first (a CI runner has
    # no reason to carry qrencode), so what is being judged is exactly the
    # acl/util-linux trio against the genuine system PATH.
    SEED="$TMP/seed"; mkdir -p "$SEED"
    for c in qrencode jq iptables; do cp -f "$STOCK/$c" "$SEED/$c"; chmod 0755 "$SEED/$c"; done
    reset_env apt
    L2RC=0
    env SBHOST_SHIM="$TMP/shim.sh" SBHOST_BLOCK="$TMP/block.sh" \
        SBHOST_BIN="$BIN" SBHOST_PROV="$PROV" SBHOST_STOCK="$NOSTOCK" \
        SBHOST_REAL="$PROV_SYS" SBHOST_DB="$DB" SBHOST_CALLS="$CALLS" \
        bash -c "export PATH=\"\$SBHOST_BIN:$SEED:$SYS_DIRS\"
                 source \"\$SBHOST_SHIM\"; source \"\$SBHOST_BLOCK\"
                 install_pkgs && printf 'FLOW-CONTINUED\n'" > "$TMP/l2.out" 2>&1 || L2RC=$?
    assert_rc 0 "$L2RC" "L2 bootstrap exits 0 on the real host"
    assert_eq 0 "$(wc -l < "$CALLS" | tr -d ' ')" \
        "L2 no package-manager call on an already-satisfied real host"
    assert_grep 'FLOW-CONTINUED' "$TMP/l2.out" "L2 the real host reaches the later steps"
    assert_grep 'acl 已经安装（命令: setfacl,getfacl）' "$TMP/l2.out" \
        "L2 the real host's acl pair is judged satisfied by probe"
    assert_grep 'util-linux 已经安装（命令: runuser）' "$TMP/l2.out" \
        "L2 the real host's runuser is judged satisfied by probe"

    # L3 agreement with the consumer on the untouched host: the Monitor
    # library's predicates pass on exactly what the bootstrap guarantees.
    if [ -f "$LIB" ]; then
        bash -c '. "$1" >/dev/null 2>&1; set +e
                 declare -F sbmon_sboxjr_acl_tools_available > /dev/null' \
            _ "$LIB" > "$TMP/l3def.out" 2>&1
        assert_rc 0 $? "L3 the real deploy library loads and exposes its predicate"
        bash -c '. "$1" >/dev/null 2>&1; set +e; sbmon_sboxjr_acl_tools_available' \
            _ "$LIB" > "$TMP/l3.out" 2>&1
        assert_rc 0 $? "L3 sbmon_sboxjr_acl_tools_available agrees on the real host"
        bash -c '. "$1" >/dev/null 2>&1; set +e
                 export PATH="'"$SYS_DIRS"'"
                 command -v "$SBOXJR_RUNUSER" > /dev/null' _ "$LIB" > "$TMP/l3b.out" 2>&1
        assert_rc 0 $? "L3 the library runuser gate agrees on the real host (system PATH)"

        # L4 the fresh-host shape end to end with the REAL acl tools: hide the
        # system's setfacl/getfacl by narrowing PATH, prove the Monitor
        # predicate refuses that host, let the bootstrap install `acl` (linking
        # the genuine binaries), then prove the same predicate continues.
        reset_env apt
        predicate_at
        assert_rc 1 "$PRED_RC" "L4 pre-state: no setfacl/getfacl -> the Monitor predicate refuses"
        L4RC=0
        env SBHOST_SHIM="$TMP/shim.sh" SBHOST_BLOCK="$TMP/block.sh" \
            SBHOST_BIN="$BIN" SBHOST_PROV="$PROV" SBHOST_STOCK="$PARTIAL" \
            SBHOST_REAL="$PROV_SYS" SBHOST_DB="$DB" SBHOST_CALLS="$CALLS" \
            bash "$TMP/driver.sh" > "$TMP/l4.out" 2>&1 || L4RC=$?
        assert_rc 0 "$L4RC" "L4 bootstrap completes on the hidden-acl host"
        assert_grep '^apt install -y acl$' "$CALLS" \
            "L4 the acl package is what the bootstrap installs"
        assert_eq 0 "$([ -x "$PROV/setfacl" ] && [ -x "$PROV/getfacl" ] && echo 0 || echo 1)" \
            "L4 setfacl/getfacl resolvable afterwards"
        predicate_at
        assert_rc 0 "$PRED_RC" "L4 post-state: the Monitor preflight can continue"
        if [ -x "$PROV_SYS/getfacl" ]; then
            "$PROV/getfacl" -p "$TMP" > "$TMP/g1" 2>&1
            "$PROV_SYS/getfacl" -p "$TMP" > "$TMP/g2" 2>&1
            if cmp -s "$TMP/g1" "$TMP/g2" && [ -s "$TMP/g1" ]; then
                pass "L4 the installed getfacl is the real ACL tool (byte-identical output)"
            else
                fail "L4 the installed getfacl does not behave like the system getfacl"
            fi
        fi

        # L5 one of the two is still not enough, decided by the real library
        # (the behavioural twin of F5).
        rm -f "$PROV/getfacl"
        predicate_at
        assert_rc 1 "$PRED_RC" "L5 setfacl alone does not satisfy the real predicate"
    else
        fail "L3 monitor-deploy-lib.sh not found"
    fi
else
    for l in "L1 real host provides setfacl/getfacl/runuser" \
             "L2 real-host bootstrap idempotence" \
             "L3 consumer predicate agreement" \
             "L4 hidden acl -> install -> preflight continues" \
             "L5 half-installed acl refused by the consumer"; do
        if [ "$REQUIRE_LIVE" = "1" ]; then
            fail "$l requires a live Linux host (SBHOST_REQUIRE_LIVE=1)"
        else
            skip "$l (Linux only)"
        fi
    done
fi

printf '\n== summary ==\n'
printf '  pass=%d fail=%d skip=%d\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
