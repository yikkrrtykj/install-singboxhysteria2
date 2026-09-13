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
MOCK_ENABLED_STATE="$TMP/unit-enabled"
: > "$MOCK_CALL_LOG"
echo inactive > "$MOCK_SYS_STATE"
echo disabled > "$MOCK_ENABLED_STATE"
cat > "$TMP/bin/systemctl-mock" <<MOCK
#!/usr/bin/env bash
printf 'systemctl %s\n' "\$*" >> "\$MOCK_CALL_LOG"
op="\$1"; shift
case "\$op" in
  is-active)
    # SKIP file: first K calls behave normally (e.g. the transaction
    # capture must observe the REAL state); COUNT file: next N calls fail.
    if [ -f "\$MOCK_FAIL_IS_ACTIVE_SKIP" ]; then
      m="\$(cat "\$MOCK_FAIL_IS_ACTIVE_SKIP" 2>/dev/null || echo 0)"
      if [ "\$m" -gt 0 ] 2>/dev/null; then
        echo "\$((m - 1))" > "\$MOCK_FAIL_IS_ACTIVE_SKIP"
      else
      if [ -f "\$MOCK_FAIL_IS_ACTIVE_COUNT" ]; then
        n="\$(cat "\$MOCK_FAIL_IS_ACTIVE_COUNT" 2>/dev/null || echo 0)"
        if [ "\$n" -gt 0 ] 2>/dev/null; then
          echo "\$((n - 1))" > "\$MOCK_FAIL_IS_ACTIVE_COUNT"
          exit 1
        fi
      fi
      fi
    else
      if [ -f "\$MOCK_FAIL_IS_ACTIVE_COUNT" ]; then
        n="\$(cat "\$MOCK_FAIL_IS_ACTIVE_COUNT" 2>/dev/null || echo 0)"
        if [ "\$n" -gt 0 ] 2>/dev/null; then
          echo "\$((n - 1))" > "\$MOCK_FAIL_IS_ACTIVE_COUNT"
          exit 1
        fi
      fi
    fi
    [ "\$(cat "\$MOCK_SYS_STATE" 2>/dev/null || echo inactive)" = "active" ] && exit 0 || exit 1 ;;
  is-enabled)
    [ "\$(cat "\$MOCK_ENABLED_STATE" 2>/dev/null || echo disabled)" = "enabled" ] && exit 0 || exit 1 ;;
  daemon-reload)
    if [ -f "\$MOCK_FAIL_DAEMON_RELOAD_COUNT" ]; then
      n="\$(cat "\$MOCK_FAIL_DAEMON_RELOAD_COUNT" 2>/dev/null || echo 0)"
      if [ "\$n" -gt 0 ] 2>/dev/null; then
        echo "\$((n - 1))" > "\$MOCK_FAIL_DAEMON_RELOAD_COUNT"
        echo "mock: daemon-reload failed" >&2; exit 1
      fi
    fi
    exit 0 ;;
  enable)
    # real semantics: plain enable succeeds even when the subsequent start
    # of enable --now fails (unit enabled, service inactive).
    now=0
    for a in "\$@"; do [ "\$a" = "--now" ] && now=1; done
    if [ "\$now" = 1 ] && [ -n "\${MOCK_FAIL_START:-}" ]; then
      echo enabled > "\$MOCK_ENABLED_STATE"
      echo "mock: start failed" >&2; exit 1
    fi
    echo enabled > "\$MOCK_ENABLED_STATE"
    if [ "\$now" = 1 ]; then echo active > "\$MOCK_SYS_STATE"; fi
    exit 0 ;;
  stop)
    if [ -f "\$MOCK_FAIL_STOP" ]; then
      echo "mock: stop failed" >&2; exit 1
    fi
    echo inactive > "\$MOCK_SYS_STATE"; exit 0 ;;
  restart)
    if [ -n "\${MOCK_FAIL_START:-}" ]; then echo "mock: restart failed" >&2; exit 1; fi
    if [ -f "\$MOCK_FAIL_RESTART_ONCE" ]; then
      rm -f "\$MOCK_FAIL_RESTART_ONCE"
      echo "mock: one-shot restart failure" >&2; exit 1
    fi
    echo active > "\$MOCK_SYS_STATE"; exit 0 ;;
  disable)
    if [ -f "\$MOCK_FAIL_DISABLE" ]; then
      echo "mock: disable failed" >&2; exit 1
    fi
    now=0
    for a in "\$@"; do [ "\$a" = "--now" ] && now=1; done
    echo disabled > "\$MOCK_ENABLED_STATE"
    if [ "\$now" = 1 ]; then echo inactive > "\$MOCK_SYS_STATE"; fi
    exit 0 ;;
  *)
    exit 0 ;;
esac
MOCK
chmod +x "$TMP/bin/systemctl-mock"

run_install() { # run_install <outdir> [args...]
    local out="$1"; shift
    local rc=0
    ( "$INSTALL_MONITOR" install "$@" ) > "$out" 2>&1 || rc=$?
    if [ "$rc" != 0 ]; then
        printf '%s
' "--- install output (rc=$rc) ---" >&2
        cat -- "$out" >&2
        printf '%s
' "--- end install output ---" >&2
    fi
    return "$rc"
}

run_uninstall_quiet() {
    ( "$INSTALL_MONITOR" uninstall --purge-state --purge-config --purge-backups ) >/dev/null 2>&1 || true
}

# F3: when the harness runs as root (Linux CI second pass), user/group
# management and file metadata run FOR REAL (SBMON_FIXTURE=0): real
# useradd/groupadd, real chown/chgrp, real uid/gid assertions. Non-root
# runs use the fixture identity shim.
if [ "$(id -u)" = "0" ]; then
    export SBMON_FIXTURE=0
else
    export SBMON_FIXTURE=1
fi
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
export MOCK_CALL_LOG MOCK_SYS_STATE MOCK_ENABLED_STATE
export MOCK_FAIL_DAEMON_RELOAD_COUNT="$TMP/mock-fail-daemon-reload-count"
export MOCK_FAIL_IS_ACTIVE_COUNT="$TMP/mock-fail-is-active-count"
export MOCK_FAIL_IS_ACTIVE_SKIP="$TMP/mock-fail-is-active-skip"
export MOCK_FAIL_STOP="$TMP/mock-fail-stop"
export MOCK_FAIL_DISABLE="$TMP/mock-fail-disable"
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
if [ "$SBMON_FIXTURE" = "0" ]; then
    SBOXWEB_GID="$(getent group sboxweb | cut -d: -f3)"
    assert_eq "0" "$(stat -c '%u' "$FIX_CONF_DIR/monitor.conf")" "monitor.conf owner root (real metadata, F3)"
    assert_eq "$SBOXWEB_GID" "$(stat -c '%g' "$FIX_CONF_DIR/monitor.conf")" "monitor.conf group sboxweb (real metadata, F3)"
    assert_eq "0" "$(stat -c '%u' "$FIX_CONF_DIR/api.secret")" "api.secret owner root (real metadata, F3)"
    assert_eq "$SBOXWEB_GID" "$(stat -c '%g' "$FIX_CONF_DIR/api.secret")" "api.secret group sboxweb (real metadata, F3)"
else
    printf '  SKIP real uid/gid assertions (non-root fixture pass; root CI pass covers them)\n'
fi
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
assert_grep ' upgrade$' "$FIX_RELEASES/releases.history" "successful upgrade recorded in history (F1)"

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
assert_no_grep ' 0\.2\.1 ' "$FIX_RELEASES/releases.history" "failed candidate never enters history (F1)"
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
assert_grep ' rollback$' "$FIX_RELEASES/releases.history" "successful rollback recorded in history (F1)"
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

if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP T15/T16/F1/F2a/F2b 原子事务流（此平台无符号链接；完整套件在 Linux 运行）\n'
else
# ---------------------------------------------------------------------------
section "T15 transactional unit rollback (release + unit + service state)"
# Simulate admin drift on the unit so the upgrade transaction actually
# rewrites it; the one-shot restart failure trips the health gate and the
# transaction must restore release, unit AND service state.
echo "# admin-drift" >> "$FIX_UNIT"
UNIT_DRIFT_HASH="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
LINK_BEFORE_T15="$(readlink "$FIX_APP_LINK")"
printf '0.4.0\n' > "$FIX_SRC/VERSION"
: > "$MOCK_FAIL_RESTART_ONCE"
RESTARTS_B15=$(grep -c 'systemctl restart singbox-monitor' "$MOCK_CALL_LOG" || true)
OUT15="$TMP/out-t15.log"
run_install "$OUT15"
RC15=$?
assert_rc 1 "$RC15" "upgrade gate failure exits nonzero"
assert_eq "$LINK_BEFORE_T15" "$(readlink "$FIX_APP_LINK")" "release restored to pre-transaction target"
assert_eq "$UNIT_DRIFT_HASH" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit restored to pre-transaction content (P3)"
assert_grep '事务前状态已恢复' "$OUT15" "rollback completion reported"
RESTORE_CALLS=$(grep -c 'systemctl restart singbox-monitor' "$MOCK_CALL_LOG")
if [ "$((RESTORE_CALLS - RESTARTS_B15))" -eq 2 ]; then
    pass "exactly 2 restarts in this transaction (failed + restoration)"
else
    fail "expected exactly 2 monitor restarts in T15, got $((RESTORE_CALLS - RESTARTS_B15))"
fi
assert_eq "active" "$(cat "$MOCK_SYS_STATE")" "old service active after transaction rollback"
assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "rollback never touches sing-box"
assert_no_grep ' 0\.4\.0 ' "$FIX_RELEASES/releases.history" "failed upgrade candidate (0.4.0) absent from history (F1)"

# ---------------------------------------------------------------------------
section "T16 rollback restore failure -> CRITICAL, never claims success"
printf '0.5.0\n' > "$FIX_SRC/VERSION"
OUT16="$TMP/out-t16.log"
MOCK_FAIL_START=1 run_install "$OUT16"
RC16=$?
unset MOCK_FAIL_START
assert_rc 2 "$RC16" "restore failure exits 2 (CRITICAL)"
assert_grep 'CRITICAL' "$OUT16" "CRITICAL reported"
assert_no_grep '事务前状态已恢复' "$OUT16" "must NOT claim rollback complete (P3)"
assert_no_grep ' 0\.5\.0 ' "$FIX_RELEASES/releases.history" "CRITICAL-failed candidate (0.5.0) absent from history (F1)"
# clean state for later sections
printf '0.3.0\n' > "$FIX_SRC/VERSION"

# ---------------------------------------------------------------------------
section "F1 history hygiene: rollback never selects a failed candidate"
# manual rollback after the failed 0.4.0/0.5.0 attempts: the only successful
# releases in history are 0.1.0 / 0.2.0 / 0.3.0 -- the target must come from
# those, never from the failed candidates.
OUT_F1="$TMP/out-f1.log"
if ( "$INSTALL_MONITOR" rollback ) > "$OUT_F1" 2>&1; then
    pass "rollback exits 0"
else
    fail "rollback exits 0"
fi
assert_eq '0.1.0' "$(cat "$FIX_APP_LINK/VERSION")" "rollback target is a historically successful release (not 0.4.0/0.5.0)"
printf '0.4.0\n' > "$FIX_SRC/VERSION"
OUT_F1B="$TMP/out-f1b.log"
run_install "$OUT_F1B"
assert_rc 0 $? "successful 0.4.0 deploy"
F1_COUNT=$(grep -c ' 0\.4\.0 upgrade$' "$FIX_RELEASES/releases.history" || true)
assert_eq "1" "$F1_COUNT" "successful 0.4.0 appears exactly once in history (F1)"

# ---------------------------------------------------------------------------
section "F2a existing inactive+disabled install: failed deploy fully restored"
echo inactive > "$MOCK_SYS_STATE"
echo disabled > "$MOCK_ENABLED_STATE"
UNIT_F2A="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
printf '0.5.0\n' > "$FIX_SRC/VERSION"
OUT_F2A="$TMP/out-f2a.log"
MOCK_FAIL_START=1 run_install "$OUT_F2A"
RC_F2A=$?
unset MOCK_FAIL_START
assert_rc 1 "$RC_F2A" "inactive existing install: failed deploy exits nonzero"
assert_eq '0.4.0' "$(cat "$FIX_APP_LINK/VERSION")" "release restored (F2)"
assert_eq "$UNIT_F2A" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit restored (F2)"
assert_eq "inactive" "$(cat "$MOCK_SYS_STATE")" "service inactive restored (F2)"
assert_eq "disabled" "$(cat "$MOCK_ENABLED_STATE")" "service disabled restored (F2)"
assert_no_grep ' 0\.5\.0 ' "$FIX_RELEASES/releases.history" "failed 0.5.0 absent from history (F1/F2)"
assert_grep '事务前状态已恢复' "$OUT_F2A" "rollback completion reported (F2)"

section "F2b existing inactive+enabled install: failed deploy fully restored"
echo inactive > "$MOCK_SYS_STATE"
echo enabled > "$MOCK_ENABLED_STATE"
UNIT_F2B="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
printf '0.6.0\n' > "$FIX_SRC/VERSION"
OUT_F2B="$TMP/out-f2b.log"
MOCK_FAIL_START=1 run_install "$OUT_F2B"
RC_F2B=$?
unset MOCK_FAIL_START
assert_rc 1 "$RC_F2B" "inactive+enabled existing install: failed deploy exits nonzero"
assert_eq '0.4.0' "$(cat "$FIX_APP_LINK/VERSION")" "release restored (F2b)"
assert_eq "$UNIT_F2B" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit restored (F2b)"
assert_eq "inactive" "$(cat "$MOCK_SYS_STATE")" "service inactive restored (F2b)"
assert_eq "enabled" "$(cat "$MOCK_ENABLED_STATE")" "service ENABLED state restored (F2b)"
assert_no_grep ' 0\.6\.0 ' "$FIX_RELEASES/releases.history" "failed 0.6.0 absent from history (F1/F2)"
printf '0.4.0\n' > "$FIX_SRC/VERSION"
fi  # end SYMLINKS_OK block (T15/T16/F1/F2a/F2b)

section "F2c fresh-install failure: cleanup, never active/enabled"
run_uninstall_quiet
MOCK_FAIL_START=1 run_install "$TMP/out-f2c.log"
RC_F2C=$?
unset MOCK_FAIL_START
assert_rc 1 "$RC_F2C" "fresh install with failed start exits nonzero"
if [ ! -L "$FIX_APP_LINK" ] && [ ! -e "$FIX_APP_LINK" ]; then pass "no live symlink left behind (F2c)"; else fail "live symlink still present after fresh failure"; fi
if [ ! -e "$FIX_UNIT" ]; then pass "new unit removed after fresh failure (F2c)"; else fail "unit still present after fresh failure"; fi
[ -d "$FIX_RELEASES" ] && pass "immutable release tree retained for diagnosis (F2c)" || fail "release tree removed"
if [ ! -e "$FIX_RELEASES/releases.history" ]; then pass "no history entry for failed fresh install (F1)"; else fail "history written for failed fresh install"; fi
assert_eq "inactive" "$(cat "$MOCK_SYS_STATE")" "service inactive after fresh failure (F2c)"
assert_eq "disabled" "$(cat "$MOCK_ENABLED_STATE")" "service disabled after fresh failure (F2c)"

section "R3-3 fresh cleanup daemon-reload failure -> CRITICAL exit 2"
run_uninstall_quiet
# fresh failure path: apply's daemon-reload fails (count 1), then the
# cleanup's own daemon-reload fails too (count 2) -> CRITICAL, never a
# false "restored to uninstalled state" claim.
echo 2 > "$MOCK_FAIL_DAEMON_RELOAD_COUNT"
MOCK_FAIL_START=1 run_install "$TMP/out-r33.log"
RC_R33=$?
unset MOCK_FAIL_START
assert_rc 2 "$RC_R33" "fresh cleanup daemon-reload failure exits 2 (R3-3)"
assert_grep 'CRITICAL' "$TMP/out-r33.log" "CRITICAL reported (R3-3)"
assert_no_grep '已恢复到未安装状态' "$TMP/out-r33.log" "no false restored-to-uninstalled claim (R3-3)"

# ---------------------------------------------------------------------------
section "T17 deployment lock serialization (P4, flock-gated)"
if command -v flock >/dev/null 2>&1; then
    LINK_B=$(readlink "$FIX_APP_LINK" 2>/dev/null || true); UNIT_B=$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)
    flock "$SBMON_LOCK_FILE" -c 'sleep 9' & LOCK_HOLDER=$!
    sleep 0.4
    ( SBMON_LOCK_TIMEOUT=2 "$INSTALL_MONITOR" install ) > "$TMP/out-t17i.log" 2>&1
    assert_rc 1 $? "install aborts fail-closed while lock held"
    ( SBMON_LOCK_TIMEOUT=2 "$INSTALL_MONITOR" rollback ) > "$TMP/out-t17r.log" 2>&1
    assert_rc 1 $? "rollback aborts fail-closed while lock held"
    ( SBMON_LOCK_TIMEOUT=2 "$INSTALL_MONITOR" uninstall ) > "$TMP/out-t17u.log" 2>&1
    assert_rc 1 $? "uninstall aborts fail-closed while lock held"
    assert_eq "$LINK_B" "$(readlink "$FIX_APP_LINK" 2>/dev/null || true)" "app link unchanged during lock contention"
    assert_eq "$UNIT_B" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit unchanged during lock contention"
    wait "$LOCK_HOLDER" 2>/dev/null || true
    run_install "$TMP/out-t17ok.log"
    assert_rc 0 $? "install proceeds after lock released"
    assert_grep 'deployment lock acquired' "$TMP/out-t17ok.log" "lock acquisition logged"
else
    printf '  SKIP T17 (flock 不可用；Linux CI 为最终 gate)\n'
fi

# ---------------------------------------------------------------------------
section "F4 upgrade precondition inside the deployment lock"
# Simulate: upgrade blocks on the lock; while the lock is held another
# (out-of-band) deploy removes the current release; the lock is released.
# The upgrade must then re-check INSIDE the lock and fail -- never
# degrade into a fresh install.
if command -v flock >/dev/null 2>&1; then
    UNIT_F4="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
    flock "$SBMON_LOCK_FILE" -c "sleep 2; rm -rf '$SBMON_RELEASES_DIR' '$SBMON_APP_LINK'" & F4_HOLDER=$!
    sleep 0.4
    OUT_F4="$TMP/out-f4.log"
    ( SBMON_LOCK_TIMEOUT=15 "$INSTALL_MONITOR" upgrade ) > "$OUT_F4" 2>&1
    RC_F4=$?
    assert_rc 1 "$RC_F4" "upgrade fails after concurrent removal (precondition re-checked under lock)"
    assert_grep '升级前置检查' "$OUT_F4" "locked precondition error message (F4)"
    if [ ! -L "$SBMON_APP_LINK" ] && [ ! -e "$SBMON_APP_LINK" ]; then pass "no fresh release created (F4)"; else fail "upgrade degraded into fresh install"; fi
    if [ ! -d "$SBMON_RELEASES_DIR" ]; then pass "no releases dir recreated (F4)"; else fail "releases dir recreated"; fi
    assert_eq "$UNIT_F4" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit untouched by failed upgrade (F4)"
    if [ ! -e "$SBMON_RELEASES_DIR/releases.history" ]; then pass "no history entry (F4)"; else fail "history entry written by failed upgrade"; fi
    wait "$F4_HOLDER" 2>/dev/null || true
else
    printf '  SKIP F4 (flock 不可用；Linux CI 为最终 gate)\n'
fi

# ---------------------------------------------------------------------------
section "R3-1a forward unit atomic-write failure -> transaction rollback"
if [ "$SYMLINKS_OK" = 1 ]; then
    OUT_R3A="$TMP/out-r3a.log"
    run_install "$OUT_R3A"          # fresh 0.4.0
    assert_rc 0 $? "baseline install for R3 tests"
    LINK_R3="$(readlink "$FIX_APP_LINK")"
    UNIT_R3="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
    HIST_R3="$(cat "$FIX_RELEASES/releases.history")"
    printf '0.5.0\n' > "$FIX_SRC/VERSION"
    # REAL atomic-write failure: mktemp under a nonexistent directory (ENOENT).
    OUT_R3B="$TMP/out-r3b.log"
    ( SBMON_UNIT_FILE="$FIX_UNIT_DIR/missing-dir/singbox-monitor.service" "$INSTALL_MONITOR" install ) > "$OUT_R3B" 2>&1
    assert_rc 1 $? "unit atomic-write failure -> install exits nonzero"
    assert_eq "$LINK_R3" "$(readlink "$FIX_APP_LINK")" "release restored after forward unit-write failure (R3-1)"
    assert_eq "$UNIT_R3" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit unchanged after forward unit-write failure (R3-1)"
    assert_eq "$HIST_R3" "$(cat "$FIX_RELEASES/releases.history")" "history unchanged by forward unit-write failure (R3-5)"
    assert_grep '事务前状态已恢复' "$OUT_R3B" "transaction rollback ran (R3-1)"
    assert_grep 'unit 原子写入失败' "$OUT_R3B" "unit write failure reported (R3-1)"

    # a successful upgrade so the later rollback tests have a target
    OUT_R3C="$TMP/out-r3c.log"
    run_install "$OUT_R3C"
    assert_rc 0 $? "successful 0.5.0 upgrade"
else
    printf '  SKIP R3-1a/c 原子事务流（此平台无符号链接）\n'
fi

section "R3-1b forward daemon-reload failure -> transaction rollback"
if [ "$SYMLINKS_OK" = 1 ]; then
    echo "# r3-1b-drift" >> "$FIX_UNIT"   # unit must CHANGE so the reload fires
    UNIT_R3B="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
    LINK_R3B="$(readlink "$FIX_APP_LINK")"
    printf '0.6.0\n' > "$FIX_SRC/VERSION"
    echo 1 > "$MOCK_FAIL_DAEMON_RELOAD_COUNT"
    OUT_R3D="$TMP/out-r3d.log"
    run_install "$OUT_R3D"
    assert_rc 1 $? "daemon-reload failure -> install exits nonzero"
    assert_eq "$LINK_R3B" "$(readlink "$FIX_APP_LINK")" "release restored after daemon-reload failure (R3-1)"
    assert_eq "$UNIT_R3B" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit restored after daemon-reload failure (R3-1)"
    assert_no_grep ' 0\.6\.0 ' "$FIX_RELEASES/releases.history" "failed 0.6.0 absent from history (R3-5)"
    assert_grep '事务前状态已恢复' "$OUT_R3D" "transaction rollback ran (R3-1)"
    assert_eq "active" "$(cat "$MOCK_SYS_STATE")" "service active after rollback (R3-1b)"
else
    printf '  SKIP R3-1b 原子事务流（此平台无符号链接）\n'
fi

section "R3-1c forward wait-active failure -> transaction rollback"
if [ "$SYMLINKS_OK" = 1 ]; then
    rm -f "$MOCK_FAIL_DAEMON_RELOAD_COUNT" "$MOCK_FAIL_IS_ACTIVE_COUNT" "$MOCK_FAIL_IS_ACTIVE_SKIP"   # no leftover fault flags
    echo 1 > "$MOCK_FAIL_IS_ACTIVE_SKIP"   # capture observes the real active state
    echo 6 > "$MOCK_FAIL_IS_ACTIVE_COUNT"  # all 6 gate polls fail (timeout 6)
    UNIT_R3C="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
    LINK_R3C="$(readlink "$FIX_APP_LINK")"
    printf '0.7.0\n' > "$FIX_SRC/VERSION"
    # is-active fails for the next 7 calls: all 6 polls inside the 6s gate
    # deadline fail, the rollback's own wait then succeeds on a fresh poll.
    echo 7 > "$MOCK_FAIL_IS_ACTIVE_COUNT"
    OUT_R3E="$TMP/out-r3e.log"
    run_install "$OUT_R3E"
    assert_rc 1 $? "wait-active failure -> install exits nonzero"
    assert_eq "$LINK_R3C" "$(readlink "$FIX_APP_LINK")" "release restored after wait-active failure (R3-1)"
    assert_eq "$UNIT_R3C" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit restored after wait-active failure (R3-1)"
    assert_no_grep ' 0\.7\.0 ' "$FIX_RELEASES/releases.history" "failed 0.7.0 absent from history (R3-5)"
    assert_grep '事务前状态已恢复' "$OUT_R3E" "transaction rollback ran (R3-1)"
    assert_eq "active" "$(cat "$MOCK_SYS_STATE")" "service active after rollback (R3-1c)"
    printf '0.5.0\n' > "$FIX_SRC/VERSION"
else
    printf '  SKIP R3-1c 原子事务流（此平台无符号链接）\n'
fi

section "R3-2a manual rollback failure restores original release"
if [ "$SYMLINKS_OK" = 1 ]; then
    UNIT_R3D="$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)"
    ROLLBACKS_B=$(grep -c ' rollback$' "$FIX_RELEASES/releases.history" || true)
    : > "$MOCK_FAIL_RESTART_ONCE"
    OUT_R3F="$TMP/out-r3f.log"
    ( "$INSTALL_MONITOR" rollback ) > "$OUT_R3F" 2>&1
    RC_R3F=$?
    assert_rc 1 "$RC_R3F" "failed rollback exits nonzero"
    assert_eq '0.5.0' "$(cat "$FIX_APP_LINK/VERSION")" "original release restored after failed rollback (R3-2)"
    assert_eq "active" "$(cat "$MOCK_SYS_STATE")" "service active on original release (R3-2)"
    assert_eq "$UNIT_R3D" "$(sha256sum "$FIX_UNIT" | cut -d' ' -f1)" "unit untouched by rollback apply/restore (R3-2)"
    ROLLBACKS_A=$(grep -c ' rollback$' "$FIX_RELEASES/releases.history" || true)
    assert_eq "$ROLLBACKS_B" "$ROLLBACKS_A" "failed rollback writes no history (R3-2/R3-5)"
    assert_grep '已恢复到原 release' "$OUT_R3F" "restore-original reported (R3-2)"

    section "R3-2b rollback restore failure -> CRITICAL exit 2"
    OUT_R3G="$TMP/out-r3g.log"
    RC_R3G=0
    ( export MOCK_FAIL_START=1; "$INSTALL_MONITOR" rollback ) > "$OUT_R3G" 2>&1 || RC_R3G=$?
    unset MOCK_FAIL_START
    assert_rc 2 "$RC_R3G" "rollback restore failure exits 2 (R3-2)"
    assert_grep 'CRITICAL' "$OUT_R3G" "CRITICAL reported (R3-2)"
    assert_no_grep '回滚完成' "$OUT_R3G" "no false rollback-complete claim (R3-2)"
    ROLLBACKS_C=$(grep -c ' rollback$' "$FIX_RELEASES/releases.history" || true)
    assert_eq "$ROLLBACKS_B" "$ROLLBACKS_C" "CRITICAL rollback writes no history (R3-2/R3-5)"
else
    printf '  SKIP R3-2 手动回滚事务（此平台无符号链接）\n'
fi

section "R4-1a rollback unit-removal failure -> CRITICAL exit 2"
if [ "$SYMLINKS_OK" = 1 ]; then
    # PATH-level rm injection: refuses exactly one path, delegates everything
    # else to the real rm binary.
    REAL_RM="$(command -v rm)"
    cat > "$TMP/bin/rm" <<MOCK
#!/usr/bin/env bash
for a in "\$@"; do
  if [ -n "\$SBMON_RM_FAIL_PATH" ] && [ "\$a" = "\$SBMON_RM_FAIL_PATH" ]; then
    echo "mock: rm refused \$a" >&2; exit 1
  fi
done
exec "$REAL_RM" "\$@"
MOCK
    chmod +x "$TMP/bin/rm"
    rm -f -- "$FIX_UNIT"            # old unit absent at capture (old_unit_existed=0)
    LINK_R4A="$(readlink "$FIX_APP_LINK")"
    HIST_R4A="$(cat "$FIX_RELEASES/releases.history")"
    printf '0.6.0\n' > "$FIX_SRC/VERSION"
    echo 1 > "$MOCK_FAIL_IS_ACTIVE_SKIP"
    echo 6 > "$MOCK_FAIL_IS_ACTIVE_COUNT"
    OUT_R4A="$TMP/out-r4a.log"
    ( export SBMON_RM_FAIL_PATH="$FIX_UNIT"; "$INSTALL_MONITOR" install ) > "$OUT_R4A" 2>&1
    RC_R4A=$?
    unset SBMON_RM_FAIL_PATH
    rm -f "$MOCK_FAIL_IS_ACTIVE_SKIP" "$MOCK_FAIL_IS_ACTIVE_COUNT"
    assert_rc 2 "$RC_R4A" "rollback unit-removal failure exits 2 (R4-1)"
    assert_grep 'CRITICAL' "$OUT_R4A" "CRITICAL reported (R4-1)"
    assert_no_grep '事务前状态已恢复' "$OUT_R4A" "no false restore-complete claim (R4-1)"
    assert_no_grep ' 0\.6\.0 ' "$FIX_RELEASES/releases.history" "failed 0.6.0 absent from history (R3-5)"
    if [ -e "$FIX_UNIT" ]; then pass "candidate unit still present (rm was refused, R4-1)"; else fail "candidate unit vanished despite rm failure"; fi
    assert_eq "$LINK_R4A" "$(readlink "$FIX_APP_LINK")" "release restored before the failing step (R4-1)"
    assert_eq "$HIST_R4A" "$(cat "$FIX_RELEASES/releases.history")" "history unchanged (R3-5)"
else
    printf '  SKIP R4-1a 原子事务流（此平台无符号链接）\n'
fi

section "R4-1b rollback stop failure -> CRITICAL exit 2"
if [ "$SYMLINKS_OK" = 1 ]; then
    echo inactive > "$MOCK_SYS_STATE"   # old_active=0
    printf '0.6.0\n' > "$FIX_SRC/VERSION"
    : > "$MOCK_FAIL_STOP"
    export MOCK_FAIL_START=1   # mock reads non-emptiness only
    OUT_R4B="$TMP/out-r4b.log"
    run_install "$OUT_R4B"
    RC_R4B=$?
    unset MOCK_FAIL_START
    rm -f "$MOCK_FAIL_STOP"
    assert_rc 2 "$RC_R4B" "rollback stop failure exits 2 (R4-1)"
    assert_grep 'CRITICAL' "$OUT_R4B" "CRITICAL reported (R4-1b)"
    assert_no_grep '事务前状态已恢复' "$OUT_R4B" "no false restore-complete claim (R4-1b)"
    assert_no_grep ' 0\.6\.0 ' "$FIX_RELEASES/releases.history" "failed 0.6.0 absent from history (R3-5)"
else
    printf '  SKIP R4-1b 原子事务流（此平台无符号链接）\n'
fi

section "R4-3 prune ordering is deployment chronology, not version lexical order"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP R4-3（此平台无符号链接；完整套件在 Linux 运行）\n'
fi
if [ "$SYMLINKS_OK" = 1 ]; then
run_uninstall_quiet
printf '0.9.0\n' > "$FIX_SRC/VERSION"
run_install "$TMP/out-r43a.log"
assert_rc 0 $? "deploy 0.9.0"
touch -d '3 hours ago' "$FIX_RELEASES"/0.9.0-* 2>/dev/null   # distinct creation ages
printf '0.10.0\n' > "$FIX_SRC/VERSION"
run_install "$TMP/out-r43b.log"
assert_rc 0 $? "deploy 0.10.0"
touch -d '2 hours ago' "$FIX_RELEASES"/0.10.0-* 2>/dev/null   # distinct creation ages
printf '0.2.0\n' > "$FIX_SRC/VERSION"
( SBMON_KEEP_RELEASES=2 "$INSTALL_MONITOR" install --allow-downgrade ) > "$TMP/out-r43c.log" 2>&1
assert_rc 0 $? "deploy 0.2.0 --allow-downgrade (prune keeps 2 by deployment age)"
if ls -d "$FIX_RELEASES/0.9.0-"* >/dev/null 2>&1; then
    fail "0.9.0 retained -- lexicographic order leaked into prune"
else
    pass "oldest DEPLOYED release (0.9.0) pruned first (chronology)"
fi
if ls -d "$FIX_RELEASES/0.10.0-"* >/dev/null 2>&1; then
    pass "0.10.0 retained (lexicographically smallest, deployment-newer)"
else
    fail "0.10.0 was pruned by version lexical order (R4-3)"
fi

section "R4-3 default rollback skips pruned history entries"
OUT_R43D="$TMP/out-r43d.log"
if ( "$INSTALL_MONITOR" rollback ) > "$OUT_R43D" 2>&1; then
    pass "default rollback exits 0"
else
    fail "default rollback exits 0"
fi
assert_eq '0.10.0' "$(cat "$FIX_APP_LINK/VERSION")" "default rollback selects 0.10.0, skipping the pruned 0.9.0 (R4-3)"

section "R4-3 no retained rollback target -> clean fail"
# remove every NON-current release tree (the live 0.10.0 stays; removing the
# live tree would not exercise the pruned-target scan)
rm -rf "$FIX_RELEASES"/0.2.0-* "$FIX_RELEASES"/0.9.0-* 2>/dev/null
HIST_R43="$(cat "$FIX_RELEASES/releases.history")"
VER_R43="$(cat "$FIX_APP_LINK/VERSION")"
OUT_R43E="$TMP/out-r43e.log"
if ( "$INSTALL_MONITOR" rollback ) > "$OUT_R43E" 2>&1; then
    fail "rollback with no retained target must fail"
    RC_R43E=0
else
    RC_R43E=$?
    pass "rollback with no retained target fails (rc=$RC_R43E)"
fi
assert_grep '没有仍保留的可回滚' "$OUT_R43E" "clean fail message (R4-3)"
assert_eq "$VER_R43" "$(cat "$FIX_APP_LINK/VERSION")" "current (0.10.0) unchanged after clean fail (R4-3)"
assert_eq '0.10.0' "$(cat "$FIX_APP_LINK/VERSION")" "live release still 0.10.0 after clean fail (R4-3)"
assert_eq "$HIST_R43" "$(cat "$FIX_RELEASES/releases.history")" "no new history entry after clean fail (R4-3)"
fi  # end SYMLINKS_OK block (R4-3)

section "R4.1-1 repeated history release id does not distort creation-age prune"
if [ "$SYMLINKS_OK" = 1 ]; then
    run_uninstall_quiet
    printf '1.0.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r411a.log"
    assert_rc 0 $? "deploy 1.0.0 (A)"
    printf '1.1.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r411b.log"
    assert_rc 0 $? "deploy 1.1.0 (B)"
    printf '1.2.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r411c.log"
    assert_rc 0 $? "deploy 1.2.0 (C)"
    touch -d '4 hours ago' "$FIX_RELEASES"/1.0.0-* 2>/dev/null
    touch -d '3 hours ago' "$FIX_RELEASES"/1.1.0-* 2>/dev/null
    touch -d '2 hours ago' "$FIX_RELEASES"/1.2.0-* 2>/dev/null
    A_ID="$(find "$FIX_RELEASES" -maxdepth 1 -type d -name '1.0.0-*' -printf '%f\n' | head -n 1)"
    ( "$INSTALL_MONITOR" rollback "$A_ID" ) > "$TMP/out-r411d.log" 2>&1
    assert_rc 0 $? "rollback back to A (1.0.0)"
    printf '1.3.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r411e.log"
    assert_rc 0 $? "deploy 1.3.0 (D; total 4 trees > KEEP=3)"
    # creation-age contract: A is the OLDEST tree even though the latest
    # history entry references it via rollback -> A is pruned, B/C/D retained.
    if ls -d "$FIX_RELEASES/1.0.0-"* >/dev/null 2>&1; then
        fail "A (oldest creation) should have been pruned"
    else
        pass "A pruned by creation age despite latest history reference (R4.1-1)"
    fi
    ls -d "$FIX_RELEASES/1.1.0-"* >/dev/null 2>&1 && pass "B retained" || fail "B pruned unexpectedly"
    ls -d "$FIX_RELEASES/1.2.0-"* >/dev/null 2>&1 && pass "C retained" || fail "C pruned unexpectedly"
    ls -d "$FIX_RELEASES/1.3.0-"* >/dev/null 2>&1 && pass "D retained" || fail "D pruned unexpectedly"
    assert_grep ' 1\.0\.0 fresh$' "$FIX_RELEASES/releases.history" "A install entry still in history (R4.1-5)"
    assert_grep ' 1\.0\.0 rollback$' "$FIX_RELEASES/releases.history" "A rollback entry still in history (R4.1-5)"
    # default rollback must skip the pruned A entry by directory existence
    OUT_R411F="$TMP/out-r411f.log"
    if ( "$INSTALL_MONITOR" rollback ) > "$OUT_R411F" 2>&1; then
        pass "default rollback after A-prune exits 0"
    else
        fail "default rollback after A-prune exits 0"
    fi
    assert_eq '1.2.0' "$(cat "$FIX_APP_LINK/VERSION")" "default rollback selects C, skipping the pruned A entry (R4.1-1)"
else
    printf '  SKIP R4.1-1 原子事务流（此平台无符号链接）\n'
fi

section "R4.1-2 old failed candidate pruned by real age, not appended as newest"
if [ "$SYMLINKS_OK" = 1 ]; then
    run_uninstall_quiet
    mkdir -p "$FIX_RELEASES/0.0.9-1000010101"   # fake FAILED-candidate tree
    touch -d '6 hours ago' "$FIX_RELEASES/0.0.9-1000010101"
    printf '1.0.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r412a.log"
    assert_rc 0 $? "deploy 1.0.0"
    touch -d '3 hours ago' "$FIX_RELEASES"/1.0.0-* 2>/dev/null
    printf '1.1.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r412b.log"
    assert_rc 0 $? "deploy 1.1.0"
    touch -d '2 hours ago' "$FIX_RELEASES"/1.1.0-* 2>/dev/null
    printf '1.2.0\n' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r412c.log"
    assert_rc 0 $? "deploy 1.2.0 (total 4 > KEEP=3; oldest is the failed candidate)"
    if ls -d "$FIX_RELEASES/0.0.9-"* >/dev/null 2>&1; then
        fail "old failed candidate retained -- non-history trees treated as newest (R4.1-4)"
    else
        pass "old failed candidate pruned by real age (R4.1-4)"
    fi
    ls -d "$FIX_RELEASES/1.0.0-"* >/dev/null 2>&1 && pass "1.0.0 retained" || fail "1.0.0 pruned unexpectedly"
    ls -d "$FIX_RELEASES/1.1.0-"* >/dev/null 2>&1 && pass "1.1.0 retained" || fail "1.1.0 pruned unexpectedly"
    ls -d "$FIX_RELEASES/1.2.0-"* >/dev/null 2>&1 && pass "1.2.0 retained" || fail "1.2.0 pruned unexpectedly"
    assert_no_grep ' 0\.0\.9 ' "$FIX_RELEASES/releases.history" "failed candidate never enters history (R4.1-5)"
else
    printf '  SKIP R4.1-2 原子事务流（此平台无符号链接）\n'
fi

section "R4.1-3 live-oldest protection: prune continues past live until count met"
if [ "$SYMLINKS_OK" = 1 ]; then
    run_uninstall_quiet
    printf '1.0.0\n' > "$FIX_SRC/VERSION"
    ( SBMON_KEEP_RELEASES=2 "$INSTALL_MONITOR" install ) > "$TMP/out-r413a.log" 2>&1
    assert_rc 0 $? "deploy 1.0.0 (A)"
    touch -d '4 hours ago' "$FIX_RELEASES"/1.0.0-* 2>/dev/null
    printf '1.1.0\n' > "$FIX_SRC/VERSION"
    ( SBMON_KEEP_RELEASES=2 "$INSTALL_MONITOR" install ) > "$TMP/out-r413b.log" 2>&1
    assert_rc 0 $? "deploy 1.1.0 (B)"
    touch -d '3 hours ago' "$FIX_RELEASES"/1.1.0-* 2>/dev/null
    A_ID="$(find "$FIX_RELEASES" -maxdepth 1 -type d -name '1.0.0-*' -printf '%f\n' | head -n 1)"
    ( "$INSTALL_MONITOR" rollback "$A_ID" ) > "$TMP/out-r413c.log" 2>&1
    assert_rc 0 $? "rollback to A (live = oldest tree)"
    # An install-prune always runs with the freshly activated (newest) tree
    # as live, so the live-oldest edge is exercised by invoking the REAL
    # sbmon_prune_releases (sourced from the deploy lib with the same
    # fixture environment) with KEEP=2 while A is live.
    ( SBMON_KEEP_RELEASES=2 source "$REPO_ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"; sbmon_prune_releases ) > "$TMP/out-r413d.log" 2>&1         || { RC_R413D=$?; echo "--- prune invocation output (rc=$RC_R413D) ---" >&2; cat "$TMP/out-r413d.log" >&2; echo "--- end ---" >&2; false; }
    assert_rc 0 $? "prune with live=oldest succeeds (R4.1-3)"
    ls -d "$FIX_RELEASES/1.0.0-"* >/dev/null 2>&1 && pass "live A retained despite being oldest (R4.1-3)" || fail "live A was pruned"
    if ls -d "$FIX_RELEASES/1.1.0-"* >/dev/null 2>&1; then
        fail "B retained -- live-skip broke the retention count (R4.1-3)"
    else
        pass "B pruned (loop continued past live, R4.1-3)"
    fi
    ls -d "$FIX_RELEASES/1.2.0-"* >/dev/null 2>&1 && pass "C retained (newest)" || fail "C pruned unexpectedly"
    DIRCOUNT=$(find "$FIX_RELEASES" -mindepth 1 -maxdepth 1 -type d ! -name '.staging-*' | wc -l)
    assert_eq "2" "$DIRCOUNT" "final retained count == KEEP (live-skip did not over-retain, R4.1-3)"
else
    printf '  SKIP R4.1-3 原子事务流（此平台无符号链接）\n'
fi

section "R4-2 uninstall idempotent when already inactive+disabled"
run_uninstall_quiet
OUT_R42A="$TMP/out-r42a.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT_R42A" 2>&1; then
    pass "uninstall on already-absent deployment is idempotent (R4-2)"
else
    fail "uninstall on already-absent deployment must succeed"
fi
assert_grep '卸载完成' "$OUT_R42A" "idempotent uninstall still completes (R4-2)"

section "R4-2 uninstall stop failure -> fail-closed, deployment retained"
printf '0.5.0\n' > "$FIX_SRC/VERSION"
run_install "$TMP/out-r42setup.log"
assert_rc 0 $? "baseline install for R4-2 tests"
: > "$MOCK_FAIL_STOP"
OUT_R42B="$TMP/out-r42b.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT_R42B" 2>&1; then
    fail "uninstall with failing stop must fail"
else
    pass "uninstall with failing stop aborts (R4-2)"
fi
rm -f "$MOCK_FAIL_STOP"
assert_grep '拒绝在 Monitor 运行时删除部署文件' "$OUT_R42B" "stop failure aborts before deletion (R4-2)"
if [ -e "$FIX_UNIT" ]; then pass "unit retained after stop failure (R4-2)"; else fail "unit deleted despite stop failure"; fi
if [ -e "$FIX_APP_LINK" ]; then pass "app link retained after stop failure (R4-2)"; else fail "app link deleted despite stop failure"; fi
[ -d "$FIX_RELEASES" ] && pass "release trees retained after stop failure (R4-2)" || fail "releases deleted despite stop failure"

section "R4-2 uninstall disable failure -> fail-closed, deployment retained"
echo enabled > "$MOCK_ENABLED_STATE"   # enabled, but the disable call will fail
: > "$MOCK_FAIL_DISABLE"
OUT_R42C="$TMP/out-r42c.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT_R42C" 2>&1; then
    fail "uninstall with failing disable must fail"
else
    pass "uninstall with failing disable aborts (R4-2)"
fi
rm -f "$MOCK_FAIL_DISABLE"
assert_grep '拒绝在 enabled 状态下删除部署文件' "$OUT_R42C" "disable failure aborts before deletion (R4-2)"
if [ -e "$FIX_UNIT" ]; then pass "unit retained after disable failure (R4-2)"; else fail "unit deleted despite disable failure"; fi
if [ -e "$FIX_APP_LINK" ]; then pass "app link retained after disable failure (R4-2)"; else fail "app link deleted despite disable failure"; fi

section "R4-2 uninstall post-delete daemon-reload failure -> CRITICAL"
echo 1 > "$MOCK_FAIL_DAEMON_RELOAD_COUNT"
OUT_R42D="$TMP/out-r42d.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT_R42D" 2>&1; then
    fail "uninstall with failing post-delete daemon-reload must not claim success"
    RC_R42D=0
else
    RC_R42D=$?
    pass "uninstall reports failure when post-delete daemon-reload fails (rc=$RC_R42D)"
fi
assert_grep 'CRITICAL' "$OUT_R42D" "CRITICAL for partial destructive state (R4-2)"
assert_no_grep '卸载完成' "$OUT_R42D" "no false uninstall-complete claim (R4-2)"

section "R4-2 uninstall success leaves service stopped and disabled"
run_uninstall_quiet   # R4-2d's CRITICAL left a partial deployment behind
run_install "$TMP/out-r42e.log"
assert_rc 0 $? "baseline install for final uninstall check"
OUT_R42F="$TMP/out-r42f.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT_R42F" 2>&1; then
    pass "normal uninstall succeeds (R4-2)"
else
    fail "normal uninstall succeeds (R4-2)"
fi
assert_eq "inactive" "$(cat "$MOCK_SYS_STATE")" "final state inactive (R4-2)"
assert_eq "disabled" "$(cat "$MOCK_ENABLED_STATE")" "final state disabled (R4-2)"
assert_grep '卸载完成' "$OUT_R42F" "success message after verified stop/disable (R4-2)"

section "T06 monitor-only uninstall (default: state/config/backups preserved)"
OUT6="$TMP/out-t06.log"
if ( "$INSTALL_MONITOR" uninstall ) > "$OUT6" 2>&1; then
    pass "uninstall exits 0"
else
    fail "uninstall exits 0"
fi
assert_grep 'systemctl stop singbox-monitor' "$MOCK_CALL_LOG" "strict stop recorded (R4-2)"
assert_grep 'systemctl disable singbox-monitor' "$MOCK_CALL_LOG" "strict disable recorded (R4-2)"
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
if [ ! -e "$FIX_UNIT" ]; then pass "new unit removed after failed start (F2c contract)"; else fail "unit kept after failed fresh start"; fi
if [ ! -L "$FIX_APP_LINK" ] && [ ! -e "$FIX_APP_LINK" ]; then pass "no live symlink after failed start (F2c)"; else fail "live symlink kept after failed start"; fi
[ -d "$FIX_RELEASES" ] && pass "release tree retained for diagnosis" || fail "release tree removed"
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
# ---------------------------------------------------------------------------
section "F3a chgrp failure -> install fails closed, no half-config"
# Real chgrp semantics: as non-root, chgrp to a group we do not belong to
# fails with EPERM. Probe first (platforms where chgrp is a no-op skip).
CHGRP_REAL=0
if [ "$(id -u)" != "0" ]; then
    printf x > "$TMP/chgrp-probe"
    if ! chgrp daemon "$TMP/chgrp-probe" 2>/dev/null; then CHGRP_REAL=1; fi
fi
if [ "$CHGRP_REAL" = 1 ]; then
    run_uninstall_quiet
    rm -rf "$FIX_STATE" "$FIX_CONF_DIR"
    OUT_F3A="$TMP/out-f3a.log"
    ( SBMON_REAL_CHGRP=1 SBMON_GROUP=daemon "$INSTALL_MONITOR" install ) > "$OUT_F3A" 2>&1
    assert_rc 1 $? "chgrp failure -> install fails closed (F3)"
    assert_grep '组设置失败' "$OUT_F3A" "fail-closed ownership message (F3)"
    if [ ! -e "$FIX_CONF_DIR/monitor.conf" ]; then pass "no half-config accepted (F3)"; else fail "half-written monitor.conf left behind"; fi
    if [ ! -L "$SBMON_APP_LINK" ] && [ ! -e "$SBMON_APP_LINK" ]; then pass "no release activated (F3)"; else fail "release activated despite ownership failure"; fi
    if [ ! -e "$FIX_RELEASES/releases.history" ]; then pass "no history entry (F3)"; else fail "history written despite ownership failure"; fi
else
    printf '  SKIP F3a (需要非 root + 真实 chgrp 语义；Linux CI 为最终 gate)\n'
fi

section "F3b wrong-group metadata repaired (root real-metadata pass)"
if [ "$(id -u)" = "0" ]; then
    chgrp root "$FIX_CONF_DIR/monitor.conf" "$FIX_CONF_DIR/api.secret"
    OUT_F3B="$TMP/out-f3b.log"
    run_install "$OUT_F3B"
    assert_rc 0 $? "metadata drift repair succeeds as root (F3)"
    SBOXWEB_GID="$(getent group sboxweb | cut -d: -f3)"
    assert_eq "$SBOXWEB_GID" "$(stat -c '%g' "$FIX_CONF_DIR/monitor.conf")" "monitor.conf group repaired to sboxweb (F3)"
    assert_eq "$SBOXWEB_GID" "$(stat -c '%g' "$FIX_CONF_DIR/api.secret")" "api.secret group repaired to sboxweb (F3)"
else
    printf '  SKIP F3b (root real-metadata pass on Linux CI covers this)\n'
fi

section "R3-4a api.secret directory target -> fail-closed"
run_uninstall_quiet
rm -rf "$FIX_STATE" "$FIX_CONF_DIR"
mkdir -p "$FIX_CONF_DIR/api.secret"   # target is a DIRECTORY
OUT_R34A="$TMP/out-r34a.log"
run_install "$OUT_R34A"
assert_rc 1 $? "api.secret directory target -> install fails closed (R3-4)"
[ -d "$FIX_CONF_DIR/api.secret" ] && pass "directory target unchanged (R3-4)" || fail "directory target replaced"
NESTED=$(find "$FIX_CONF_DIR/api.secret" -name '.api.secret.*' 2>/dev/null | wc -l)
assert_eq "0" "$NESTED" "no temp artifact nested inside the directory (R3-4)"
if [ ! -L "$SBMON_APP_LINK" ] && [ ! -e "$SBMON_APP_LINK" ]; then pass "no release activated (R3-4a)"; else fail "release activated despite wrong-type target"; fi

section "R3-4b api.secret symlink target -> fail-closed"
if [ "$SYMLINKS_OK" = 1 ]; then
    rm -rf "$FIX_CONF_DIR"
    mkdir -p "$FIX_CONF_DIR"
    ln -s "$FIX_PROXY/monitor-api.secret" "$FIX_CONF_DIR/api.secret"
    OUT_R34B="$TMP/out-r34b.log"
    run_install "$OUT_R34B"
    assert_rc 1 $? "api.secret symlink target -> install fails closed (R3-4)"
    [ -L "$FIX_CONF_DIR/api.secret" ] && pass "symlink target unchanged (R3-4)" || fail "symlink target replaced/followed"
    assert_eq "$(cat "$FIX_PROXY/monitor-api.secret")" "$(cat "$FIX_CONF_DIR/api.secret")" "symlink target content untouched (R3-4)"
else
    printf '  SKIP R3-4b（此平台无符号链接）\n'
fi

section "R3-4c monitor.conf symlink -> fail-closed"
if [ "$SYMLINKS_OK" = 1 ]; then
    rm -rf "$FIX_CONF_DIR"
    mkdir -p "$FIX_CONF_DIR"
    ln -s "$FIX_PROXY/monitor-api.secret" "$FIX_CONF_DIR/monitor.conf"
    OUT_R34C="$TMP/out-r34c.log"
    run_install "$OUT_R34C"
    assert_rc 1 $? "monitor.conf symlink -> install fails closed (R3-4)"
    [ -L "$FIX_CONF_DIR/monitor.conf" ] && pass "monitor.conf symlink unchanged (R3-4)" || fail "monitor.conf symlink replaced"
    assert_eq "$(cat "$FIX_PROXY/monitor-api.secret")" "$(cat "$FIX_CONF_DIR/monitor.conf")" "monitor.conf symlink target untouched (R3-4)"
else
    printf '  SKIP R3-4c（此平台无符号链接）\n'
fi
run_uninstall_quiet

# ---------------------------------------------------------------------------
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
