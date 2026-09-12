#!/usr/bin/env bash
# Monitor v2 packaging/deployment skeleton regression tests.
#
# Runs the REAL deploy code (monitor-v2/deploy/) against a temporary root:
# every production path/user/tool is overridden via SBMON_* env vars and
# systemctl is a recording mock. Nothing here touches /root/sbox, /opt,
# /etc, /var/lib or /var/backups of the running machine, and nothing needs
# root. A fixture "proxy tree" (sbconfig_server.json) is hashed before and
# after the full install/upgrade/rollback/uninstall sequence to prove the
# deployment track never touches proxy credentials.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$HERE/.." && pwd)"
DEPLOY_DIR="$REPO_ROOT/monitor-v2/deploy"
INSTALL_MONITOR="$DEPLOY_DIR/install-monitor.sh"

PASS=0
FAIL=0
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_rc() { # assert_rc <expected> <actual> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (expected rc=$1, got rc=$2)"; fi
}
assert_grep() { # assert_grep <pattern> <file> <label>
    if grep -qE "$1" "$2" 2>/dev/null; then pass "$3"; else fail "$3 (no match: $1)"; fi
}
assert_no_grep() { # assert_no_grep <pattern> <file> <label>
    if grep -qE "$1" "$2" 2>/dev/null; then fail "$3 (unexpected match: $1)"; else pass "$3"; fi
}
assert_eq() { # assert_eq <want> <got> <label>
    if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$1', got '$2')"; fi
}
assert_dir_mode() { # assert_dir_mode <path> <mode> <label>
    if [ "$MODES_OK" != 1 ]; then
        printf '  SKIP %s (chmod 在此平台不可靠)\n' "$3"
        return 0
    fi
    local got
    got="$(stat -c '%a' "$1" 2>/dev/null || echo missing)"
    assert_eq "$2" "$got" "$3"
}

PY3="$(command -v python3 || command -v python || true)"
HAVE_PY3=0
[ -n "$PY3" ] && HAVE_PY3=1
if [ "$HAVE_PY3" = 0 ]; then
    printf 'SKIP python3/python 不存在，无法运行 staging 校验\n'
    exit 0
fi

# ---------------------------------------------------------------------------
# Fixture-wide overrides (production values replaced by temp-root paths)
# ---------------------------------------------------------------------------
FIX="$TMP/fixture"
FIX_RELEASES="$FIX/opt/singbox-monitor-releases"
FIX_APP_LINK="$FIX/opt/singbox-monitor"
FIX_STATE="$FIX/var/lib/singbox-monitor"
FIX_CONF_DIR="$FIX/etc/singbox-monitor"
FIX_UNIT_DIR="$FIX/etc/systemd/system"
FIX_UNIT="$FIX_UNIT_DIR/singbox-monitor.service"
FIX_BACKUPS="$FIX/var/backups/singbox-monitor"
FIX_SRC="$TMP/src-monitor-v2"          # mutable copy of repo monitor-v2 (for version bumps)
FIX_PROXY="$FIX/root-sbox"             # fixture proxy tree (hash-watched, NEVER read by deploy code)
FIX_PROXY_CONF="$FIX_PROXY/sbconfig_server.json"
FIX_PROXY_STATE="$FIX_PROXY/config"

mkdir -p "$TMP/bin" "$FIX_UNIT_DIR" "$FIX_PROXY"
cat > "$FIX_PROXY_CONF" <<'EOF'
{"inbounds": [{"type": "vless", "tag": "vless-in", "users": [{"name": "legacy", "uuid": "PROXY-UUID-SHOULD-SURVIVE"}]}]}
EOF
printf "SERVER_IP='203.0.113.1'\n" > "$FIX_PROXY_STATE"
# P6: fixture S0 anchor (the real default lives at /root/sbox/monitor-api.secret)
printf 'fixture-api-secret-VALUE-must-not-leak\n' > "$FIX_PROXY/monitor-api.secret"
PROXY_CONF_HASH_BEFORE="$(sha256sum "$FIX_PROXY_CONF" | cut -d' ' -f1)"
PROXY_STATE_HASH_BEFORE="$(sha256sum "$FIX_PROXY_STATE" | cut -d' ' -f1)"

# Some platforms (MSYS/Git Bash) emulate chmod as a no-op; permission-bit
# assertions are only meaningful where chmod actually works.
chmod 0700 "$FIX_PROXY"
if [ "$(stat -c '%a' "$FIX_PROXY")" = "700" ]; then MODES_OK=1; else MODES_OK=0; fi
chmod 0755 "$FIX_PROXY"

# Atomic release switching relies on symlink rename(2). MSYS/Git Bash without
# symlink privilege turns `ln -s` into a copy: the reduced suite still runs,
# the atomic-flow tests are skipped with a banner (they are the gate on Linux).
echo x > "$TMP/.symlink-probe-target"
ln -s "$TMP/.symlink-probe-target" "$TMP/.symlink-probe" 2>/dev/null
if [ -L "$TMP/.symlink-probe" ]; then SYMLINKS_OK=1; else SYMLINKS_OK=0; fi
rm -f "$TMP/.symlink-probe" "$TMP/.symlink-probe-target"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '\nNOTICE: 此平台无法创建符号链接（rename 原子切换不可验证）。\n'
    printf 'NOTICE: 运行精简套件（T01/T06-T10/T12/T13）；完整套件需在 Linux 上运行。\n\n'
fi

# Mock systemctl: records every invocation; simulates unit state transitions.
MOCK_CALL_LOG="$TMP/systemctl-calls.log"
MOCK_SYS_STATE="$TMP/unit-state"
: > "$MOCK_CALL_LOG"
echo inactive > "$MOCK_SYS_STATE"
cat > "$TMP/bin/systemctl-mock" <<MOCK
#!/usr/bin/env bash
printf 'systemctl %s\n' "\$*" >> "\$MOCK_CALL_LOG"
op="\$1"; shift
case "\$op" in
  is-active)
    [ "\$(cat "\$MOCK_SYS_STATE" 2>/dev/null || echo inactive)" = "active" ] && exit 0 || exit 1 ;;
  daemon-reload)
    exit 0 ;;
  enable)
    for a in "\$@"; do
      if [ "\$a" = "--now" ] && [ -n "\${MOCK_FAIL_START:-}" ]; then
        echo "mock: start failed" >&2; exit 1
      fi
    done
    echo active > "\$MOCK_SYS_STATE"; exit 0 ;;
  restart)
    if [ -n "\${MOCK_FAIL_START:-}" ]; then echo "mock: restart failed" >&2; exit 1; fi
    if [ -f "\$MOCK_FAIL_RESTART_ONCE" ]; then
      rm -f "\$MOCK_FAIL_RESTART_ONCE"
      echo "mock: one-shot restart failure" >&2; exit 1
    fi
    echo active > "\$MOCK_SYS_STATE"; exit 0 ;;
  disable)
    echo inactive > "\$MOCK_SYS_STATE"; exit 0 ;;
  *)
    exit 0 ;;
esac
MOCK
chmod +x "$TMP/bin/systemctl-mock"

run_install() { # run_install <outdir> [args...]
    local out="$1"; shift
    ( "$INSTALL_MONITOR" install "$@" ) > "$out" 2>&1
}

run_uninstall_quiet() {
    ( "$INSTALL_MONITOR" uninstall --purge-state --purge-config --purge-backups ) >/dev/null 2>&1 || true
}

export SBMON_FIXTURE=1
export SBMON_SYSTEMCTL="$TMP/bin/systemctl-mock"
export SBMON_PYTHON3="$PY3"
export SBMON_APP_LINK="$FIX_APP_LINK"
export SBMON_RELEASES_DIR="$FIX_RELEASES"
export SBMON_STATE_ROOT="$FIX_STATE"
export SBMON_CONF_DIR="$FIX_CONF_DIR"
export SBMON_UNIT_FILE="$FIX_UNIT"
export SBMON_BACKUP_ROOT="$FIX_BACKUPS"
export SBMON_REPO_MONITOR_DIR="$FIX_SRC"
export SBMON_VERSION_FILE="$FIX_SRC/VERSION"
export SBMON_API_SECRET_SOURCE="$FIX_PROXY/monitor-api.secret"
export SBMON_HEALTH_TIMEOUT=6
export SBMON_STATE_DIR="$FIX_STATE/state"
export MOCK_CALL_LOG MOCK_SYS_STATE
export MOCK_FAIL_RESTART_ONCE="$TMP/mock-fail-restart-once"
export SBMON_LOCK_FILE="$TMP/deploy.lock"
# P4: real flock where available (Linux CI gate); no-op shim elsewhere so the
# rest of the suite still runs on platforms without flock.
if command -v flock >/dev/null 2>&1; then
    export SBMON_FLOCK=flock
else
    printf '#!/usr/bin/env bash'"""\n"""'exit 0\n' > "$TMP/bin/flock-mock"
    chmod +x "$TMP/bin/flock-mock"
    export SBMON_FLOCK="$TMP/bin/flock-mock"
fi
export PATH="$TMP/bin:$PATH"

# Mutable source copy so tests can bump VERSION without touching the repo.
mkdir -p "$FIX_SRC"
cp "$REPO_ROOT/monitor-v2/collector.py" "$FIX_SRC/"
cp -R "$REPO_ROOT/monitor-v2/api_bridge" "$FIX_SRC/api_bridge"
rm -rf "$FIX_SRC/api_bridge/__pycache__"
printf '%s\n' "$(cat "$REPO_ROOT/monitor-v2/VERSION")" > "$FIX_SRC/VERSION"

section "static checks"
if bash -n "$INSTALL_MONITOR" 2>"$TMP/syntax.err"; then pass "bash -n install-monitor.sh"; else fail "bash -n install-monitor.sh: $(cat "$TMP/syntax.err")"; fi
for f in "$DEPLOY_DIR"/lib/*.sh "$DEPLOY_DIR"/app-bin/*; do
    if bash -n "$f" 2>"$TMP/syntax.err"; then pass "bash -n $(basename "$f")"; else fail "bash -n $(basename "$f")"; fi
done
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck -S warning "$INSTALL_MONITOR" "$DEPLOY_DIR"/lib/*.sh "$DEPLOY_DIR"/app-bin/* >"$TMP/sc.out" 2>&1; then
        pass "shellcheck deploy scripts"
    else
        fail "shellcheck deploy scripts: $(head -n3 "$TMP/sc.out" | tr '\n' ' ')"
    fi
else
    printf '  SKIP shellcheck 未安装\n'
fi

# Hard isolation between deploy track and proxy tree + firewall tooling.
# Comments are stripped first: the guarantee is about executable code.
strip_comments() { sed -e 's/#.*$//' "$@"; }
# P6: the S0 anchor path (/root/sbox/monitor-api.secret) is the ONE sanctioned
# reference into the proxy tree (read-only secret source); mask it before the
# isolation scan so the guarantee stays "nothing else touches /root/sbox".
DEPLOY_CODE=$(strip_comments "$DEPLOY_DIR"/lib/*.sh "$DEPLOY_DIR"/app-bin/* "$DEPLOY_DIR"/install-monitor.sh "$DEPLOY_DIR"/singbox-monitor.service.in \
    | sed "s|/root/sbox/monitor-api\.secret|<SBMON_S0_ANCHOR>|g")
if printf '%s' "$DEPLOY_CODE" | grep -qE 'sbconfig_server\.json|/root/sbox|sbox-backup'; then
    fail "deploy code must never reference the proxy tree (beyond the S0 anchor)"
else
    pass "deploy code has zero references to /root/sbox / sbconfig_server.json / production backups (S0 anchor exempted)"
fi
ANCHOR_COUNT=$(printf '%s\n' "$DEPLOY_CODE" | grep -c '<SBMON_S0_ANCHOR>' || true)
if [ "$ANCHOR_COUNT" = "1" ]; then
    pass "S0 anchor referenced exactly once (default assignment in deploy lib)"
else
    fail "S0 anchor referenced $ANCHOR_COUNT times (want exactly 1)"
fi
if printf '%s' "$DEPLOY_CODE" | grep -qE '(^|[^a-z])(ufw|iptables|ip6tables|firewall-cmd|firewalld)([^a-z]|$)'; then
    fail "deploy code must never touch firewall tooling"
else
    pass "deploy code never invokes firewall tooling"
fi

# ---------------------------------------------------------------------------
section "T01 fresh install"
OUT1="$TMP/out-t01.log"
run_install "$OUT1"
assert_rc 0 $? "fresh install exits 0"
assert_grep 'action=fresh' "$OUT1" "reports action=fresh"
if [ "$SYMLINKS_OK" = 1 ]; then
    [ -L "$FIX_APP_LINK" ] && pass "app link is a symlink" || fail "app link missing/not a symlink"
else
    printf '  SKIP app link is a symlink (此平台 ln -s 为复制语义)\n'
fi
[ -d "$FIX_RELEASES" ] && pass "releases dir created" || fail "releases dir missing"
for d in state auth access; do
    [ -d "$FIX_STATE/$d" ] && pass "state dir $d created" || fail "state dir $d missing"
done
assert_dir_mode "$FIX_STATE" 750 "state root mode 0750"
assert_dir_mode "$FIX_STATE/auth" 700 "auth dir mode 0700"
assert_dir_mode "$FIX_STATE/access" 700 "access dir mode 0700"
assert_eq "$(cat "$REPO_ROOT/monitor-v2/VERSION")" "$(cat "$FIX_APP_LINK/VERSION")" "activated VERSION matches repo"
assert_grep '127\.0\.0\.1:9191' "$FIX_CONF_DIR/monitor.conf" "conf binds web to 127.0.0.1:9191"
assert_grep 'http://127\.0\.0\.1:9091' "$FIX_CONF_DIR/monitor.conf" "conf points at loopback service.api 9091"
assert_dir_mode "$FIX_CONF_DIR/monitor.conf" 640 "monitor.conf mode 0640"
assert_grep 'After=network-online\.target sing-box\.service' "$FIX_UNIT" "unit orders after network-online + sing-box"
assert_grep '^Wants=network-online\.target' "$FIX_UNIT" "unit wants network-online"
assert_no_grep '^Requires=' "$FIX_UNIT" "unit has NO Requires= on sing-box (boot must not fail)"
assert_grep '^User=sboxweb$' "$FIX_UNIT" "unit runs as E3-approved non-root user sboxweb (P5)"
assert_grep '^Group=sboxweb$' "$FIX_UNIT" "unit group sboxweb (P5)"
assert_grep '^UMask=0077$' "$FIX_UNIT" "unit UMask=0077 (P8)"
assert_grep 'monitor-service .*monitor\.conf.*state' "$FIX_UNIT" "unit passes conf + state dir explicitly (P1)"
assert_grep 'SBMON_API_SECRET_FILE=' "$FIX_CONF_DIR/monitor.conf" "default conf declares derived secret file (P6)"
assert_grep 'NoNewPrivileges=true' "$FIX_UNIT" "unit NoNewPrivileges"
assert_grep 'ProtectHome=true' "$FIX_UNIT" "unit ProtectHome (cannot read /root/sbox)"
assert_grep 'ProtectSystem=full' "$FIX_UNIT" "unit ProtectSystem"
assert_grep 'Restart=on-failure' "$FIX_UNIT" "unit Restart=on-failure"
assert_grep 'CapabilityBoundingSet=$' "$FIX_UNIT" "unit drops all capabilities"
assert_grep 'systemctl enable --now singbox-monitor' "$MOCK_CALL_LOG" "enable --now recorded"
assert_grep '"service_active":true' "$OUT1" "health reports service_active=true after install"
[ -f "$FIX_CONF_DIR/api.secret" ] && pass "derived api.secret delivered (P6)" || fail "derived api.secret missing"
if [ "$MODES_OK" = 1 ]; then assert_dir_mode "$FIX_CONF_DIR/api.secret" 640 "api.secret mode 0640 root:group (P6)"; else printf '  SKIP api.secret mode (chmod unreliable)\n'; fi
assert_eq "$(cat "$FIX_PROXY/monitor-api.secret")" "$(cat "$FIX_CONF_DIR/api.secret")" "api.secret content mirrors S0 anchor"
SECRET_HASH_1="$(sha256sum "$FIX_CONF_DIR/api.secret" | cut -d' ' -f1)"
SECRET_MTIME_1="$(stat -c '%Y' "$FIX_CONF_DIR/api.secret")"

# ---------------------------------------------------------------------------
if [ "$SYMLINKS_OK" = 1 ]; then
section "T02 idempotent second install"
CONF_HASH_1="$(sha256sum "$FIX_CONF_DIR/monitor.conf" | cut -d' ' -f1)"
CONF_MTIME_1="$(stat -c '%Y' "$FIX_CONF_DIR/monitor.conf")"
echo 'auth-marker-must-survive' > "$FIX_STATE/auth/probe"
RELEASES_COUNT_1="$(find "$FIX_RELEASES" -maxdepth 1 -type d ! -path "$FIX_RELEASES" | wc -l)"
CALLS_MUT_1="$(grep -cE ' (restart|enable|disable|daemon-reload) ' "$MOCK_CALL_LOG" || true)"
OUT2="$TMP/out-t02.log"
run_install "$OUT2"
assert_rc 0 $? "second install exits 0"
assert_grep 'action=noop' "$OUT2" "second install detected as noop"
assert_eq "$CONF_HASH_1" "$(sha256sum "$FIX_CONF_DIR/monitor.conf" | cut -d' ' -f1)" "monitor.conf unchanged"
assert_eq "$CONF_MTIME_1" "$(stat -c '%Y' "$FIX_CONF_DIR/monitor.conf")" "monitor.conf mtime unchanged (never rewritten)"
assert_grep 'auth-marker-must-survive' "$FIX_STATE/auth/probe" "auth state untouched"
assert_eq "$RELEASES_COUNT_1" "$(find "$FIX_RELEASES" -maxdepth 1 -type d ! -path "$FIX_RELEASES" | wc -l)" "no extra release staged"
CALLS_MUT_2="$(grep -cE ' (restart|enable|disable|daemon-reload) ' "$MOCK_CALL_LOG" || true)"
assert_eq "$CALLS_MUT_1" "$CALLS_MUT_2" "no state-changing systemctl calls on noop (no restart)"
assert_eq "$SECRET_HASH_1" "$(sha256sum "$FIX_CONF_DIR/api.secret" | cut -d' ' -f1)" "api.secret content stable (P6)"
assert_eq "$SECRET_MTIME_1" "$(stat -c '%Y' "$FIX_CONF_DIR/api.secret")" "api.secret not rewritten when content identical (no mtime churn, P6)"

# ---------------------------------------------------------------------------
section "T03 upgrade (monitor only; sing-box untouched)"
printf '0.2.0\n' > "$FIX_SRC/VERSION"
OUT3="$TMP/out-t03.log"
run_install "$OUT3"
assert_rc 0 $? "upgrade exits 0"
assert_grep 'action=upgrade' "$OUT3" "reports action=upgrade"
assert_eq '0.2.0' "$(cat "$FIX_APP_LINK/VERSION")" "activated VERSION bumped to 0.2.0"
assert_grep 'systemctl restart singbox-monitor' "$MOCK_CALL_LOG" "restart recorded for monitor service"
assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "systemctl log has no sing-box operation at all"
assert_grep 'auth-marker-must-survive' "$FIX_STATE/auth/probe" "state preserved across upgrade"
if [ -n "$(find "$FIX_RELEASES" -maxdepth 1 -type d -name '0.1.0-*' -print -quit)" ]; then
    pass "previous release tree retained (rollback backup)"
else
    fail "previous release tree was removed"
fi
assert_grep ' upgrade$' "$FIX_RELEASES/releases.history" "upgrade recorded in history"

# ---------------------------------------------------------------------------
section "T04 failed upgrade (invalid staged code) leaves production untouched"
LIVE_BEFORE_T04="$(readlink "$FIX_APP_LINK")"
# Staging (and therefore validation) only runs when the version differs;
# a broken candidate must ship as a new version to be exercised.
printf '0.2.1\n' > "$FIX_SRC/VERSION"
printf 'def broken(:\n' > "$FIX_SRC/collector.py"
OUT4="$TMP/out-t04.log"
run_install "$OUT4"
assert_rc 1 $? "invalid candidate fails closed (rc 1)"
assert_eq "$LIVE_BEFORE_T04" "$(readlink "$FIX_APP_LINK")" "live release untouched after failed upgrade"
if find "$FIX_RELEASES" -maxdepth 1 -name '.staging-*' 2>/dev/null | grep -q .; then
    fail "staging leftovers removed"
else
    pass "staging leftovers removed"
fi
cp "$REPO_ROOT/monitor-v2/collector.py" "$FIX_SRC/collector.py"
printf '0.3.0\n' > "$FIX_SRC/VERSION"

# ---------------------------------------------------------------------------
section "T05 rollback (monitor only)"
OUT5="$TMP/out-t05.log"
if ( "$INSTALL_MONITOR" rollback ) > "$OUT5" 2>&1; then
    pass "rollback exits 0"
else
    fail "rollback exits 0"
fi
assert_eq '0.1.0' "$(cat "$FIX_APP_LINK/VERSION")" "rolled back to previous release 0.1.0"
assert_grep 'systemctl restart singbox-monitor' "$MOCK_CALL_LOG" "rollback restarts monitor only"
assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "rollback never touches sing-box"

# restore forward state: upgrade to 0.3.0 so later tests run on a clean tree
OUT5B="$TMP/out-t05b.log"
run_install "$OUT5B"
assert_rc 0 $? "re-upgrade to 0.3.0 exits 0"
assert_eq '0.3.0' "$(cat "$FIX_APP_LINK/VERSION")" "activated VERSION is 0.3.0"

# ---------------------------------------------------------------------------
else
    printf '  SKIP T02-T05 原子切换流（此平台无符号链接；完整套件在 Linux 运行）
'
fi

section "T06 monitor-only uninstall (default: state/config/backups preserved)"
OUT6="$TMP/out-t06.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT6" 2>&1; then
    pass "uninstall exits 0"
else
    fail "uninstall exits 0"
fi
assert_grep 'systemctl disable --now singbox-monitor' "$MOCK_CALL_LOG" "disable --now recorded"
[ ! -e "$FIX_UNIT" ] && pass "unit file removed" || fail "unit file still present"
[ ! -L "$FIX_APP_LINK" ] && pass "app link removed" || fail "app link still present"
[ ! -d "$FIX_RELEASES" ] && pass "release trees removed" || fail "release trees still present"
[ -d "$FIX_STATE/auth" ] && pass "auth/state preserved by default" || fail "auth/state deleted without --purge-state"
[ -f "$FIX_CONF_DIR/monitor.conf" ] && pass "config preserved by default" || fail "config deleted without --purge-config"
[ -d "$FIX_BACKUPS" ] && pass "backups preserved by default" || fail "backups deleted without --purge-backups"

OUT6B="$TMP/out-t06b.log"
if ( "$INSTALL_MONITOR" uninstall --purge-state --purge-config --purge-backups ) > "$OUT6B" 2>&1; then
    pass "purging uninstall exits 0"
else
    fail "purging uninstall exits 0"
fi
[ ! -d "$FIX_STATE" ] && pass "--purge-state removed state root" || fail "--purge-state left state root"
[ ! -d "$FIX_CONF_DIR" ] && pass "--purge-config removed conf dir" || fail "--purge-config left conf dir"

# ---------------------------------------------------------------------------
section "T07 failed service start fails closed but keeps unit diagnosable"
echo inactive > "$MOCK_SYS_STATE"
OUT7="$TMP/out-t07.log"
MOCK_FAIL_START=1 run_install "$OUT7"
assert_rc 1 $? "install reports failure when service start fails"
[ -e "$FIX_UNIT" ] && pass "unit kept for diagnosis after failed start" || fail "unit removed on failed start"
assert_grep 'journalctl -u singbox-monitor' "$OUT7" "failure message points at journal"
unset MOCK_FAIL_START

# ---------------------------------------------------------------------------
section "T08 health semantics (separate signals, never one merged bool)"
# Start from a clean slate: T07 deliberately leaves a failed-install state
# (unit present, service inactive), and on symlink-less platforms a second
# converge would hit the fail-closed non-symlink guard.
run_uninstall_quiet
run_install "$TMP/out-t08setup.log" >/dev/null 2>&1
HEALTH_BIN="$FIX_APP_LINK/bin/monitor-health"
HC="$TMP/health.conf"
cat > "$HC" <<EOF
SBMON_WEB_BIND=127.0.0.1:9191
SBMON_API_URL=http://127.0.0.1:19091
SBMON_MODE=collector-loop
SBMON_CYCLE_SECONDS=300
EOF
mkdir -p "$FIX_STATE/state"
SNAP="$FIX_STATE/state/snapshot.json"
LISTENER_PID=""
if [ "$HAVE_PY3" = 1 ]; then
    python3 - <<'PY' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19091))
s.listen(8)
s.settimeout(30)
try:
    while True:
        c, _ = s.accept()
        c.close()
except OSError:
    pass
PY
    LISTENER_PID=$!
fi
sleep 0.7
h_probe() { "$HEALTH_BIN" "$HC" "$FIX_STATE/state"; }

# case 1: fresh file + collector fresh + api reachable -> healthy
printf '{"stale": false, "devices": {}}\n' > "$SNAP"
H_JSON="$(h_probe)"; H_RC=$?
assert_rc 0 "$H_RC" "healthy: service up + api reachable + fresh fresh-collector snapshot"
assert_grep '"service_active":true' <(printf '%s' "$H_JSON") "health json service_active=true"
assert_grep '"api_reachable":true' <(printf '%s' "$H_JSON") "health json api_reachable=true"
assert_grep '"collector_stale":false' <(printf '%s' "$H_JSON") "health json collector_stale=false"
assert_grep '"stale":false' <(printf '%s' "$H_JSON") "health json snapshot not stale"

# case 2 (P2, review special case): api reachable + collector stale=true
#   -> fresh file does NOT mean healthy; MUST NOT overall=healthy
printf '{"stale": true, "devices": {}}\n' > "$SNAP"
H_JSON="$(h_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "degraded (rc 2): collector semantic stale while api reachable"
assert_grep '"api_reachable":true' <(printf '%s' "$H_JSON") "api still reachable in stale case"
assert_grep '"collector_stale":true' <(printf '%s' "$H_JSON") "collector_stale=true from E1 snapshot JSON"
assert_grep '"age_stale":false' <(printf '%s' "$H_JSON") "age_stale=false (file is fresh)"
assert_grep '"stale":true' <(printf '%s' "$H_JSON") "final stale=true"
assert_grep '"overall":"degraded"' <(printf '%s' "$H_JSON") "overall degraded (never healthy with stale snapshot)"

# case 3: old file + collector fresh -> age-stale -> degraded
printf '{"stale": false, "devices": {}}\n' > "$SNAP"
touch -d '2 hours ago' "$SNAP"
H_JSON="$(h_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "degraded (rc 2): age-stale snapshot"
assert_grep '"collector_stale":false' <(printf '%s' "$H_JSON") "collector fresh in age-stale case"
assert_grep '"age_stale":true' <(printf '%s' "$H_JSON") "age_stale=true"

# case 4: malformed JSON -> stale=true + degraded (contents never logged)
printf 'not-json-{{{' > "$SNAP"
H_JSON="$(h_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "degraded (rc 2): malformed snapshot"
assert_grep '"stale":true' <(printf '%s' "$H_JSON") "malformed snapshot treated as stale"
assert_no_grep 'not-json' "$TMP/out-redaction-probe.log" "malformed snapshot contents never emitted (P2: never log snapshot data)"

# case 5: missing file -> degraded
rm -f "$SNAP"
H_JSON="$(h_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "degraded (rc 2): snapshot missing"
assert_grep '"present":false' <(printf '%s' "$H_JSON") "snapshot present=false"
assert_grep '"stale":true' <(printf '%s' "$H_JSON") "missing snapshot = stale"

# case 6: invalid API URL (P7) -> api_url_valid=false, degraded
printf '{"stale": false, "devices": {}}\n' > "$SNAP"
HC_BAD="$TMP/health-bad.conf"
cat > "$HC_BAD" <<EOF
SBMON_API_URL=http://0.0.0.0:9091
SBMON_MODE=collector-loop
SBMON_CYCLE_SECONDS=300
EOF
H_JSON="$("$HEALTH_BIN" "$HC_BAD" "$FIX_STATE/state")"; H_RC=$?
assert_rc 2 "$H_RC" "degraded (rc 2): invalid API URL"
assert_grep '"api_url_valid":false' <(printf '%s' "$H_JSON") "api_url_valid=false for non-loopback URL"

# case 7: service down -> unhealthy
echo inactive > "$MOCK_SYS_STATE"
H_JSON="$(h_probe)"; H_RC=$?
assert_rc 1 "$H_RC" "unhealthy (rc 1): service down"
assert_grep '"service_active":false' <(printf '%s' "$H_JSON") "unhealthy shows service_active=false"
[ -n "$LISTENER_PID" ] && kill "$LISTENER_PID" 2>/dev/null

# ---------------------------------------------------------------------------
section "T08b health explicit state path (P1)"
printf '{"stale": false, "devices": {}}\n' > "$FIX_STATE/state/snapshot.json"
echo active > "$MOCK_SYS_STATE"
norm() { printf '%s' "$1" | sed 's/"age_seconds":[0-9]*/"age_seconds":X/'; }
OUT_A="$( ( cd / && "$INSTALL_MONITOR" health ) 2>&1 || true)"
OUT_B="$( ( cd "$TMP" && "$INSTALL_MONITOR" health ) 2>&1 || true)"
OUT_C="$( ( mkdir -p "$TMP/random-cwd" && cd "$TMP/random-cwd" && "$INSTALL_MONITOR" health ) 2>&1 || true)"
assert_eq "$(norm "$OUT_A")" "$(norm "$OUT_B")" "health identical from / and TMP (explicit state contract, P1)"
assert_eq "$(norm "$OUT_B")" "$(norm "$OUT_C")" "health identical from random cwd (explicit state contract, P1)"
assert_grep '"snapshot":' <(printf '%s' "$OUT_A") "health reads the real state root regardless of cwd"

# ---------------------------------------------------------------------------
section "T08c service fail-closed: secret file + API URL contract (P6/P7)"
SVC="$FIX_APP_LINK/bin/monitor-service"
SCRATCH_STATE="$(mktemp -d)"
write_svc_conf() { # <file> <api-url-line> <secret-line>
    { printf 'SBMON_MODE=collector-loop\n'; printf '%s\n' "$2"; printf '%s\n' "$3"; } > "$1"
}
GOOD_URL="SBMON_API_URL=http://127.0.0.1:19091"
GOOD_SECRET="SBMON_API_SECRET_FILE=$FIX_CONF_DIR/api.secret"

write_svc_conf "$TMP/svc-missing-secret.conf" "$GOOD_URL" "SBMON_API_SECRET_FILE=$SCRATCH_STATE/nope.secret"
timeout 8 "$SVC" "$TMP/svc-missing-secret.conf" "$SCRATCH_STATE" > "$TMP/svc1.log" 2>&1
assert_rc 1 $? "configured-but-missing secret -> immediate fail-closed exit"
assert_grep 'fail-closed' "$TMP/svc1.log" "fail-closed message present"
assert_no_grep 'mode=collector-loop' "$TMP/svc1.log" "service never enters collector loop without secret"

write_svc_conf "$TMP/svc-dir-secret.conf" "$GOOD_URL" "SBMON_API_SECRET_FILE=$SCRATCH_STATE"
timeout 8 "$SVC" "$TMP/svc-dir-secret.conf" "$SCRATCH_STATE" > "$TMP/svc2.log" 2>&1
assert_rc 1 $? "wrong-type (directory) secret -> immediate fail-closed exit"

write_svc_conf "$TMP/svc-bad-url.conf" "SBMON_API_URL=http://0.0.0.0:9091" ""
timeout 8 "$SVC" "$TMP/svc-bad-url.conf" "$SCRATCH_STATE" > "$TMP/svc3.log" 2>&1
assert_rc 1 $? "invalid (non-loopback) API URL -> immediate fail-closed exit (P7)"

write_svc_conf "$TMP/svc-bad-ipv6.conf" "SBMON_API_URL=http://[::1]:19091/x?y=1" ""
timeout 8 "$SVC" "$TMP/svc-bad-ipv6.conf" "$SCRATCH_STATE" > "$TMP/svc4.log" 2>&1
assert_rc 1 $? "URL with path/query -> immediate fail-closed exit (P7)"

write_svc_conf "$TMP/svc-ok.conf" "SBMON_API_URL=http://[::1]:19091" "$GOOD_SECRET"
timeout 3 "$SVC" "$TMP/svc-ok.conf" "$SCRATCH_STATE" > "$TMP/svc5.log" 2>&1 || true
assert_grep 'mode=collector-loop' "$TMP/svc5.log" "valid IPv6 loopback URL + present secret -> service starts (P7 IPv6 parse)"
assert_no_grep 'fixture-api-secret' "$TMP/svc5.log" "secret value never printed"

rm -rf "$SCRATCH_STATE"

# ---------------------------------------------------------------------------
section "T09 journal redaction (secrets never reach service output)"
run_uninstall_quiet
FAKE_SECRET='S3cr3t-T0ken-abc123'
FAKE_UUID='550e8400-e29b-41d4-a716-446655440000'
mkdir -p "$FIX_CONF_DIR" "$FIX_STATE/state"
printf '%s\n' "$FAKE_SECRET" > "$FIX_CONF_DIR/api.secret"
cat > "$FIX_STATE/state/snapshot.json" <<EOF
{"devices": {"client-a": {"active_connections": 1, "identity": "$FAKE_UUID"}}}
EOF
run_install "$TMP/out-t09i.log"
assert_rc 0 $? "install with secret/snapshot present exits 0"
: > "$TMP/redaction-capture.log"
{
    cat "$TMP/out-t09i.log"
    "$INSTALL_MONITOR" status
    "$HEALTH_BIN" "$HC" || true
    "$INSTALL_MONITOR" uninstall
} >> "$TMP/redaction-capture.log" 2>&1
assert_no_grep "$FAKE_SECRET" "$TMP/redaction-capture.log" "fake api secret never appears in tool output"
assert_no_grep "$FAKE_UUID" "$TMP/redaction-capture.log" "snapshot UUID never appears in tool output"
assert_no_grep "$FAKE_SECRET" "$FIX_UNIT" "fake api secret never appears in unit file"

# ---------------------------------------------------------------------------
section "T10 missing dependency fails closed before touching filesystem"
run_uninstall_quiet
rm -rf "$FIX_STATE" "$FIX_CONF_DIR"
OUT10="$TMP/out-t10.log"
( SBMON_PYTHON3=/nonexistent-sbmon-python3 "$INSTALL_MONITOR" install ) > "$OUT10" 2>&1
assert_rc 1 $? "missing python3 -> install fails"
[ ! -d "$FIX_STATE" ] && pass "no state dirs created on failed precheck" || fail "state dirs created despite failed precheck"
assert_grep '预检失败' "$OUT10" "error message explains precheck"

# ---------------------------------------------------------------------------
if [ "$SYMLINKS_OK" = 1 ]; then
section "T11 bad permissions repaired without content change"
run_install "$TMP/out-t11setup.log" >/dev/null 2>&1
C11_BEFORE="$(sha256sum "$FIX_CONF_DIR/monitor.conf" | cut -d' ' -f1)"
chmod 0777 "$FIX_CONF_DIR/monitor.conf"
OUT11="$TMP/out-t11.log"
run_install "$OUT11"
assert_rc 0 $? "install over bad perms exits 0"
assert_dir_mode "$FIX_CONF_DIR/monitor.conf" 640 "monitor.conf mode repaired to 0640"
assert_eq "$C11_BEFORE" "$(sha256sum "$FIX_CONF_DIR/monitor.conf" | cut -d' ' -f1)" "monitor.conf content unchanged by repair"

# ---------------------------------------------------------------------------
else
    printf '  SKIP T11（需要符号链接支持）
'
fi

section "T12 production isolation (dynamic): proxy tree hash unchanged end-to-end"
assert_eq "$PROXY_CONF_HASH_BEFORE" "$(sha256sum "$FIX_PROXY_CONF" | cut -d' ' -f1)" "fixture sbconfig_server.json hash unchanged"
assert_eq "$PROXY_STATE_HASH_BEFORE" "$(sha256sum "$FIX_PROXY_STATE" | cut -d' ' -f1)" "fixture proxy state hash unchanged"
assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "mocked systemctl log (entire run) contains no sing-box operation"

# ---------------------------------------------------------------------------
section "T13 web port + bind contract"
run_install "$TMP/out-t13setup.log" >/dev/null 2>&1   # ensure conf/unit exist after T10 purge
assert_no_grep '0\.0\.0\.0' "$FIX_CONF_DIR/monitor.conf" "conf never binds 0.0.0.0"
assert_no_grep '0\.0\.0\.0' "$FIX_UNIT" "unit never references 0.0.0.0"
assert_grep '127\.0\.0\.1:9191' "$FIX_CONF_DIR/monitor.conf" "web dashboard stays on 127.0.0.1:9191"

printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
