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

# R1.1-A: fixtures that pre-create <data-root>/state must mirror the production
# reality -- the state tree is SERVICE-USER owned. In the root real-metadata
# pass the harness runs as root, so a bare `mkdir -p` would leave a root-owned
# state/ that the installer must (by the privilege boundary) refuse to
# converge. Only the HARNESS sets up fixture ownership this way; the installer
# itself never chowns a service-owned child.
ensure_fixture_state_dir() {
    mkdir -p "$FIX_STATE/state"
    if [ "$SBMON_FIXTURE" = "0" ]; then
        chown "${SBMON_USER:-sboxweb}:${SBMON_GROUP:-sboxweb}" "$FIX_STATE/state"
    fi
}

# F3: when the harness runs as root (Linux CI second pass), user/group
# management and file metadata run FOR REAL (SBMON_FIXTURE=0): real
# useradd/groupadd, real chown/chgrp, real uid/gid assertions. Non-root
# runs use the fixture identity shim.
if [ "$(id -u)" = "0" ]; then
    export SBMON_FIXTURE=0
    # R1.1: several production paths now execute AS the service user (state/
    # convergence and web-setup). Like /var/lib and /opt in a real install,
    # the fixture tree must be traversable by that identity.
    chmod 0755 "$TMP" "$FIX"
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
export SBMON_STATE_DIR="$FIX_STATE"   # R1: explicit DATA ROOT contract
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
# Compatibility preflight scope: the production default requires the full
# command set (Ubuntu 22.04/24.04/26.04 baselines; see monitor-deploy-lib.sh).
# On non-Linux dev platforms the reduced suite runs the same production code
# against the commands that actually exist there (journalctl/ss/systemd do
# not exist on MSYS); the fail-closed path itself is exercised below via a
# synthetic missing tool, so coverage is not lost.
if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
    export SBMON_REQUIRED_COMMANDS="stat sha256sum mktemp"
    # The override is only ever honored behind the explicit test-only gate
    # (production invocations refuse the bypass -- see T00).
    export SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1
fi

# Mutable source copy so tests can bump VERSION without touching the repo.
mkdir -p "$FIX_SRC"
cp "$REPO_ROOT/monitor-v2/collector.py" "$FIX_SRC/"
cp "$REPO_ROOT/monitor-v2/webapp.py" "$FIX_SRC/"
cp -R "$REPO_ROOT/monitor-v2/web" "$FIX_SRC/web"
cp -R "$REPO_ROOT/monitor-v2/api_bridge" "$FIX_SRC/api_bridge"
rm -rf "$FIX_SRC/api_bridge/__pycache__" "$FIX_SRC/web/__pycache__"
# Freeze the installed baseline independently of the candidate repo version.
printf '0.1.0\n' > "$FIX_SRC/VERSION"

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
if [ "$(printf '%s' "$DEPLOY_CODE" | grep -cE 'sbconfig_server\.json|/root/sbox|sbox-backup')" -gt 0 ]; then
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
if [ "$(printf '%s' "$DEPLOY_CODE" | grep -cE '(^|[^a-z])(ufw|iptables|ip6tables|firewall-cmd|firewalld)([^a-z]|$)')" -gt 0 ]; then
    fail "deploy code must never touch firewall tooling"
else
    pass "deploy code never invokes firewall tooling"
fi
if [ "$(printf '%s' "$DEPLOY_CODE" | grep -c 'mihomo')" -eq 0 ]; then
    pass "deploy code never stages or references E4/mihomo (repo-only client component)"
else
    fail "deploy code references mihomo"
fi
if [ "$(printf '%s' "$DEPLOY_CODE" | grep -c 'app/web/serve')" -eq 0 ]; then
    pass "deferred app/web/serve hook gone (real E2 entrypoint wired, R1)"
else
    fail "deploy code still references the fake app/web/serve hook"
fi

# Compatibility preflight wiring (static): runtime shims and deploy lib must
# call the capability-based preflight; the shims must expose the environment
# diagnostics recorder (no secrets).
assert_grep 'monitor_env_require_commands' "$DEPLOY_DIR/app-bin/monitor-service" "monitor-service runs the command preflight"
assert_grep 'monitor_env_require_commands' "$DEPLOY_DIR/app-bin/monitor-health" "monitor-health runs the command preflight"
assert_grep 'monitor_env_record_environment' "$DEPLOY_DIR/app-bin/monitor-service" "monitor-service records environment diagnostics"
assert_grep 'sbmon_preflight_commands' "$DEPLOY_DIR/install-monitor.sh" "install path runs the preflight"
if [ "$(grep -c 'sbmon_preflight_commands' "$DEPLOY_DIR/install-monitor.sh")" -ge 3 ]; then
    pass "install/rollback/uninstall paths all run the preflight (>=3 call sites)"
else
    fail "preflight not wired into all mutating command paths (want >=3 call sites)"
fi
assert_grep 'journal_time_normalize' "$REPO_ROOT/tests/lib/journal-time.sh" "journal-time normalizer present (B6 regression)"

# ---------------------------------------------------------------------------
section "T00 compatibility preflight: missing required command -> fail closed"
# Runs BEFORE the first real install: nothing may be created when the
# preflight rejects the environment.
(
    export SBMON_REQUIRED_COMMANDS="sbmon-synthetic-missing-tool"
    export SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1
    "$INSTALL_MONITOR" install
) > "$TMP/out-t00-preflight.log" 2>&1
assert_rc 1 $? "install aborts (rc 1) when a required command is missing"
assert_grep '缺少必需依赖命令' "$TMP/out-t00-preflight.log" "preflight names the missing dependency clearly"
assert_grep 'sbmon-synthetic-missing-tool' "$TMP/out-t00-preflight.log" "preflight names the exact missing tool"
assert_no_grep 'install 完成' "$TMP/out-t00-preflight.log" "no success message after preflight failure"
[ ! -e "$FIX_UNIT" ] && pass "no unit file written before preflight passes" || fail "unit file written despite preflight failure"
if [ ! -d "$FIX_RELEASES" ] || [ -z "$(ls -A "$FIX_RELEASES" 2>/dev/null)" ]; then
    pass "no release staged before preflight passes"
else
    fail "release staged despite preflight failure"
fi
(
    export SBMON_REQUIRED_COMMANDS="sbmon-synthetic-missing-tool"
    export SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1
    "$INSTALL_MONITOR" rollback
) > "$TMP/out-t00-rollback.log" 2>&1
assert_rc 1 $? "rollback aborts (rc 1) when a required command is missing"
assert_grep '缺少必需依赖命令' "$TMP/out-t00-rollback.log" "rollback preflight names the missing dependency"

# Production invocations can NEVER bypass the preflight via
# SBMON_REQUIRED_COMMANDS: without the explicit test-only gate the override
# is refused (fail-closed), even though every command in this environment
# actually exists.
(
    export SBMON_REQUIRED_COMMANDS="stat sha256sum mktemp"
    unset SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE
    "$INSTALL_MONITOR" install
) > "$TMP/out-t00-bypass.log" 2>&1
assert_rc 1 $? "production install rejects the SBMON_REQUIRED_COMMANDS bypass"
assert_grep '绕过必需命令预检' "$TMP/out-t00-bypass.log" "bypass refusal diagnostic is explicit"
assert_no_grep 'install 完成' "$TMP/out-t00-bypass.log" "no install happens under a refused bypass"

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
[ -d "$FIX_STATE/state" ] && pass "state dir created" || fail "state dir missing"
for d in auth access; do
    if [ ! -e "$FIX_STATE/$d" ]; then pass "fresh install no longer creates $d/ dir (R1 flat-file model)"; else fail "fresh install created legacy $d/ dir"; fi
done
assert_dir_mode "$FIX_STATE" 700 "data root mode 0700 (private, R1)"
assert_dir_mode "$FIX_STATE/state" 700 "state dir mode 0700"
assert_eq '0.1.0' "$(cat "$FIX_APP_LINK/VERSION")" "installed baseline VERSION is 0.1.0"
[ -f "$FIX_APP_LINK/app/monitor-v2/collector.py" ] && pass "release stages collector.py under app/monitor-v2" || fail "collector.py not staged under app/monitor-v2"
[ -f "$FIX_APP_LINK/app/monitor-v2/webapp.py" ] && pass "release stages webapp.py (real E2 entrypoint)" || fail "webapp.py not staged"
[ -d "$FIX_APP_LINK/app/monitor-v2/api_bridge" ] && pass "release stages api_bridge" || fail "api_bridge not staged"
[ -d "$FIX_APP_LINK/app/monitor-v2/web" ] && pass "release stages web/" || fail "web/ not staged"
[ -f "$FIX_APP_LINK/app/monitor-v2/web/static/app.js" ] && pass "release stages web static assets" || fail "web static assets not staged"
[ ! -e "$FIX_APP_LINK/app/collector" ] && pass "no duplicate independent collector runtime tree" || fail "legacy app/collector tree also staged (two collector runtimes)"
if [ "$(find "$FIX_APP_LINK" -name '*mihomo*' 2>/dev/null | wc -l)" -eq 0 ]; then
    pass "E4/mihomo NOT staged (repo-only)"
else
    fail "E4/mihomo found in release tree"
fi
assert_grep '127\.0\.0\.1:9191' "$FIX_CONF_DIR/monitor.conf" "conf binds web to 127.0.0.1:9191"
assert_grep 'http://127\.0\.0\.1:9091' "$FIX_CONF_DIR/monitor.conf" "conf points at loopback service.api 9091"
assert_dir_mode "$FIX_CONF_DIR/monitor.conf" 640 "monitor.conf mode 0640"
assert_grep 'After=network-online\.target sing-box\.service' "$FIX_UNIT" "unit orders after network-online + sing-box"
assert_grep '^Wants=network-online\.target' "$FIX_UNIT" "unit wants network-online"
assert_no_grep '^Requires=' "$FIX_UNIT" "unit has NO Requires= on sing-box (boot must not fail)"
assert_grep '^User=sboxweb$' "$FIX_UNIT" "unit runs as E3-approved non-root user sboxweb (P5)"
assert_grep '^Group=sboxweb$' "$FIX_UNIT" "unit group sboxweb (P5)"
assert_grep '^UMask=0077$' "$FIX_UNIT" "unit UMask=0077 (P8)"
assert_eq "ExecStart=$FIX_APP_LINK/bin/monitor-service $FIX_CONF_DIR/monitor.conf $FIX_STATE" "$(grep '^ExecStart=' "$FIX_UNIT")" "unit passes conf + DATA ROOT explicitly (P1/R1)"
assert_grep 'SBMON_API_SECRET_FILE=' "$FIX_CONF_DIR/monitor.conf" "default conf declares derived secret file (P6)"
assert_grep '^SBMON_MODE=web$' "$FIX_CONF_DIR/monitor.conf" "fresh default is SBMON_MODE=web (R1)"
assert_grep '^SBMON_WEB_POLL_SECONDS=1$' "$FIX_CONF_DIR/monitor.conf" "fresh conf sets SBMON_WEB_POLL_SECONDS=1"
assert_grep 'NoNewPrivileges=true' "$FIX_UNIT" "unit NoNewPrivileges"
assert_grep 'ProtectHome=yes' "$FIX_UNIT" "unit ProtectHome=yes (cannot read /root/sbox)"
assert_grep 'ProtectSystem=strict' "$FIX_UNIT" "unit ProtectSystem=strict (M0.5 G4)"
assert_eq "ReadWritePaths=$FIX_STATE" "$(grep '^ReadWritePaths=' "$FIX_UNIT")" "unit re-opens ONLY the monitor data root for writing (M0.5 G4; M2 final review B5: least privilege restored)"
assert_grep 'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX' "$FIX_UNIT" "unit keeps the monitor address-family contract (not AF_UNIX-only)"
assert_grep 'ProtectKernelTunables=true' "$FIX_UNIT" "unit ProtectKernelTunables"
assert_grep 'ProtectControlGroups=true' "$FIX_UNIT" "unit ProtectControlGroups"
assert_grep 'RestrictSUIDSGID=true' "$FIX_UNIT" "unit RestrictSUIDSGID"
assert_grep 'AmbientCapabilities=$' "$FIX_UNIT" "unit drops ambient capabilities"
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
mkdir -p "$FIX_STATE/auth" "$FIX_STATE/access"
echo 'auth-marker-must-survive' > "$FIX_STATE/auth/probe"
echo 'access-marker-must-survive' > "$FIX_STATE/access/probe"
printf '{"legacy": true}\n' > "$FIX_STATE/auth.json"
printf '{"whitelist": ["198.51.100.9/32"]}\n' > "$FIX_STATE/access.json"
AUTH_JSON_HASH_1="$(sha256sum "$FIX_STATE/auth.json" | cut -d' ' -f1)"
ACCESS_JSON_HASH_1="$(sha256sum "$FIX_STATE/access.json" | cut -d' ' -f1)"
RELEASES_COUNT_1="$(find "$FIX_RELEASES" -maxdepth 1 -type d ! -path "$FIX_RELEASES" | wc -l)"
CALLS_MUT_1="$(grep -cE ' (restart|enable|disable|daemon-reload) ' "$MOCK_CALL_LOG" || true)"
OUT2="$TMP/out-t02.log"
run_install "$OUT2"
assert_rc 0 $? "second install exits 0"
assert_grep 'action=noop' "$OUT2" "second install detected as noop"
assert_eq "$CONF_HASH_1" "$(sha256sum "$FIX_CONF_DIR/monitor.conf" | cut -d' ' -f1)" "monitor.conf unchanged"
assert_eq "$CONF_MTIME_1" "$(stat -c '%Y' "$FIX_CONF_DIR/monitor.conf")" "monitor.conf mtime unchanged (never rewritten)"
assert_grep 'auth-marker-must-survive' "$FIX_STATE/auth/probe" "legacy auth dir preserved"
assert_grep 'access-marker-must-survive' "$FIX_STATE/access/probe" "legacy access dir preserved"
assert_eq "$AUTH_JSON_HASH_1" "$(sha256sum "$FIX_STATE/auth.json" | cut -d' ' -f1)" "flat auth.json untouched by install"
assert_eq "$ACCESS_JSON_HASH_1" "$(sha256sum "$FIX_STATE/access.json" | cut -d' ' -f1)" "flat access.json untouched by install"
assert_eq "$RELEASES_COUNT_1" "$(find "$FIX_RELEASES" -maxdepth 1 -type d ! -path "$FIX_RELEASES" | wc -l)" "no extra release staged"
CALLS_MUT_2="$(grep -cE ' (restart|enable|disable|daemon-reload) ' "$MOCK_CALL_LOG" || true)"
assert_eq "$CALLS_MUT_1" "$CALLS_MUT_2" "no state-changing systemctl calls on noop (no restart)"
assert_eq "$SECRET_HASH_1" "$(sha256sum "$FIX_CONF_DIR/api.secret" | cut -d' ' -f1)" "api.secret content stable (P6)"
assert_eq "$SECRET_MTIME_1" "$(stat -c '%Y' "$FIX_CONF_DIR/api.secret")" "api.secret not rewritten when content identical (no mtime churn, P6)"

# ---------------------------------------------------------------------------
section "T03 upgrade (monitor only; sing-box untouched)"
BASE_RELEASE_T03="$(readlink -f "$FIX_APP_LINK")"
BASE_HASH_T03="$(find "$BASE_RELEASE_T03" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)"
RESTARTS_T03="$(grep -c 'systemctl restart singbox-monitor' "$MOCK_CALL_LOG" || true)"
cp "$REPO_ROOT/monitor-v2/VERSION" "$FIX_SRC/VERSION"
OUT3="$TMP/out-t03.log"
"$INSTALL_MONITOR" upgrade > "$OUT3" 2>&1
assert_rc 0 $? "upgrade exits 0"
assert_grep 'action=upgrade' "$OUT3" "reports action=upgrade"
assert_eq "$(cat "$REPO_ROOT/monitor-v2/VERSION")" "$(cat "$FIX_APP_LINK/VERSION")" "normal upgrade activates repo VERSION (0.1.0 -> 0.1.1)"
assert_eq "$((RESTARTS_T03 + 1))" "$(grep -c 'systemctl restart singbox-monitor' "$MOCK_CALL_LOG")" "normal upgrade restarts monitor exactly once"
assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "systemctl log has no sing-box operation at all"
assert_grep 'auth-marker-must-survive' "$FIX_STATE/auth/probe" "legacy auth dir preserved across upgrade"
assert_eq "$AUTH_JSON_HASH_1" "$(sha256sum "$FIX_STATE/auth.json" | cut -d' ' -f1)" "flat auth.json byte-identical across upgrade"
assert_eq "$ACCESS_JSON_HASH_1" "$(sha256sum "$FIX_STATE/access.json" | cut -d' ' -f1)" "flat access.json byte-identical across upgrade"
if [ "$(readlink -f "$FIX_APP_LINK")" != "$BASE_RELEASE_T03" ] \
    && [ -d "$BASE_RELEASE_T03" ] \
    && [ "$BASE_HASH_T03" = "$(find "$BASE_RELEASE_T03" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)" ]; then
    pass "new immutable release activated; previous 0.1.0 release retained byte-identical"
else
    fail "upgrade reused or modified the previous release tree"
fi
assert_grep ' upgrade$' "$FIX_RELEASES/releases.history" "successful upgrade recorded in history (F1)"

# ---------------------------------------------------------------------------
section "T04 failed upgrade (invalid staged code) leaves production untouched"
LIVE_BEFORE_T04="$(readlink "$FIX_APP_LINK")"
# Staging (and therefore validation) only runs when the version differs;
# a broken candidate must ship as a new version to be exercised.
BROKEN_VERSION="9.9.99"
printf '%s\n' "$BROKEN_VERSION" > "$FIX_SRC/VERSION"
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
assert_no_grep " $BROKEN_VERSION " "$FIX_RELEASES/releases.history" "failed candidate never enters history (F1)"
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
assert_eq "$AUTH_JSON_HASH_1" "$(sha256sum "$FIX_STATE/auth.json" | cut -d' ' -f1)" "flat auth.json byte-identical across rollback"
assert_eq "$ACCESS_JSON_HASH_1" "$(sha256sum "$FIX_STATE/access.json" | cut -d' ' -f1)" "flat access.json byte-identical across rollback"

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
# releases in history are 0.1.0 / repo VERSION / 0.3.0 -- the target must come from
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
    printf '1.2.0
' > "$FIX_SRC/VERSION"
    run_install "$TMP/out-r413c2.log"   # KEEP=3 (default): no prune yet, 3 trees
    assert_rc 0 $? "deploy 1.2.0 (C)"
    touch -d '2 hours ago' "$FIX_RELEASES"/1.2.0-* 2>/dev/null
    A_ID="$(find "$FIX_RELEASES" -maxdepth 1 -type d -name '1.0.0-*' -printf '%f\n' | head -n 1)"
    ( "$INSTALL_MONITOR" rollback "$A_ID" ) > "$TMP/out-r413c.log" 2>&1
    assert_rc 0 $? "rollback to A (live = oldest tree)"
    # An install-prune always runs with the freshly activated (newest) tree
    # as live, so the live-oldest edge is exercised by invoking the REAL
    # sbmon_prune_releases (sourced from the deploy lib with the same
    # fixture environment) with KEEP=2 while A is live.
    ( export SBMON_KEEP_RELEASES=2; source "$REPO_ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"; sbmon_prune_releases ) > "$TMP/out-r413d.log" 2>&1         || { RC_R413D=$?; echo "--- prune invocation output (rc=$RC_R413D) ---" >&2; cat "$TMP/out-r413d.log" >&2; echo "--- end ---" >&2; false; }
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
# Seed legacy dirs + flat access files: earlier sections purge the state
# root, and uninstall must PRESERVE whatever is there.
mkdir -p "$FIX_STATE/auth" "$FIX_STATE/access"
ensure_fixture_state_dir
printf 'legacy-auth\n' > "$FIX_STATE/auth/probe"
printf '{"legacy": true}\n' > "$FIX_STATE/auth.json"
printf '{"whitelist": []}\n' > "$FIX_STATE/access.json"
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
[ -d "$FIX_STATE/state" ] && pass "state/ preserved by default" || fail "state/ deleted without --purge-state"
[ -d "$FIX_STATE/auth" ] && pass "legacy auth/ dir preserved by default" || fail "legacy auth/ dir deleted without --purge-state"
[ -f "$FIX_STATE/auth.json" ] && pass "flat auth.json preserved by default" || fail "flat auth.json deleted without --purge-state"
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
ensure_fixture_state_dir
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
h_probe() { "$HEALTH_BIN" "$HC" "$FIX_STATE"; }

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
H_JSON="$("$HEALTH_BIN" "$HC_BAD" "$FIX_STATE")"; H_RC=$?
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
assert_grep '"mode":"web"' <(printf '%s' "$OUT_A") "health reads the real data root regardless of cwd (web default)"
assert_grep '"broker_health":' <(printf '%s' "$OUT_A") "default (web) health reports broker_health from <data-root>/state"

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

# Production invocation of the runtime shim can NEVER bypass the preflight
# via SBMON_REQUIRED_COMMANDS: without the explicit test-only gate the
# override is refused even though every listed command actually exists.
printf 'SBMON_MODE=collector-loop\n' > "$TMP/svc-bypass.conf"
(
    export SBMON_REQUIRED_COMMANDS="stat sha256sum mktemp"
    unset SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE
    "$SVC" "$TMP/svc-bypass.conf" "$SCRATCH_STATE"
) > "$TMP/out-t00-bypass-shim.log" 2>&1
assert_rc 1 $? "runtime shim rejects the bypass in a production invocation"
assert_grep 'override refused outside fixture/test mode' "$TMP/out-t00-bypass-shim.log" "shim bypass refusal named"

rm -rf "$SCRATCH_STATE"

# ---------------------------------------------------------------------------
section "T08c-W web runtime contract (R1-3/R1-4/R1-5)"
WEB_SVC="$FIX_APP_LINK/bin/monitor-service"
WEB_SCRATCH="$(mktemp -d)"
write_web_conf() { # <file> <bind-line> <secret-line>
    { printf 'SBMON_MODE=web\n';
      printf 'SBMON_API_URL=http://127.0.0.1:19091\n';
      printf '%s\n' "$2";
      printf '%s\n' "$3"; } > "$1"
}
WEB_OK_BIND="SBMON_WEB_BIND=127.0.0.1:19191"
GOOD_WEB_SECRET="SBMON_API_SECRET_FILE=$FIX_CONF_DIR/api.secret"

# D: secret matrix -- BOX_API_SECRET must never rescue web mode
write_web_conf "$TMP/web-nosecret.conf" "$WEB_OK_BIND" ""
BOX_API_SECRET='env-secret-MUST-NOT-WORK' timeout 8 "$WEB_SVC" "$TMP/web-nosecret.conf" "$WEB_SCRATCH" > "$TMP/web1.log" 2>&1
assert_rc 1 $? "web mode without SBMON_API_SECRET_FILE -> fail-closed even with BOX_API_SECRET set"
assert_no_grep 'env-secret-MUST-NOT-WORK' "$TMP/web1.log" "BOX_API_SECRET value never leaked"

write_web_conf "$TMP/web-missing.conf" "$WEB_OK_BIND" "SBMON_API_SECRET_FILE=$WEB_SCRATCH/nope.secret"
timeout 8 "$WEB_SVC" "$TMP/web-missing.conf" "$WEB_SCRATCH" > "$TMP/web2.log" 2>&1
assert_rc 1 $? "web mode missing secret file -> fail-closed"

write_web_conf "$TMP/web-dir.conf" "$WEB_OK_BIND" "SBMON_API_SECRET_FILE=$WEB_SCRATCH"
timeout 8 "$WEB_SVC" "$TMP/web-dir.conf" "$WEB_SCRATCH" > "$TMP/web3.log" 2>&1
assert_rc 1 $? "web mode directory secret -> fail-closed"

write_web_conf "$TMP/web-empty.conf" "$WEB_OK_BIND" "SBMON_API_SECRET_FILE=$TMP/empty.secret"
: > "$TMP/empty.secret"
timeout 8 "$WEB_SVC" "$TMP/web-empty.conf" "$WEB_SCRATCH" > "$TMP/web4.log" 2>&1
assert_rc 1 $? "web mode empty secret file -> fail-closed"

if [ "$SYMLINKS_OK" = 1 ]; then
    ln -s "$FIX_CONF_DIR/api.secret" "$TMP/link.secret"
    write_web_conf "$TMP/web-link.conf" "$WEB_OK_BIND" "SBMON_API_SECRET_FILE=$TMP/link.secret"
    timeout 8 "$WEB_SVC" "$TMP/web-link.conf" "$WEB_SCRATCH" > "$TMP/web5.log" 2>&1
    assert_rc 1 $? "web mode symlinked secret -> fail-closed (regular-file contract)"
fi

if [ "$(id -u)" != "0" ] && [ "$MODES_OK" = 1 ]; then
    printf 'unreadable\n' > "$TMP/noperm.secret"
    chmod 000 "$TMP/noperm.secret"
    write_web_conf "$TMP/web-noperm.conf" "$WEB_OK_BIND" "SBMON_API_SECRET_FILE=$TMP/noperm.secret"
    timeout 8 "$WEB_SVC" "$TMP/web-noperm.conf" "$WEB_SCRATCH" > "$TMP/web6.log" 2>&1
    assert_rc 1 $? "web mode unreadable secret -> fail-closed"
    chmod 644 "$TMP/noperm.secret"
else
    printf '  SKIP unreadable-secret case: needs real chmod/root semantics\n'
fi

# C: web bind contract
for badbind in '0.0.0.0:19191' '192.168.1.50:19191' '10.1.2.3:19191' '8.8.8.8:19191' '[::1]:99999' '127.0.0.1:0' 'user@127.0.0.1:19191' '127.0.0.1:19191/x' '[::1]:19191?x=1' ':::19191'; do
    write_web_conf "$TMP/web-bind.conf" "SBMON_WEB_BIND=$badbind" "$GOOD_WEB_SECRET"
    timeout 8 "$WEB_SVC" "$TMP/web-bind.conf" "$WEB_SCRATCH" > "$TMP/web-bind.log" 2>&1
    assert_rc 1 $? "web bind '$badbind' refused (loopback-only contract)"
done

# C/D: valid web starts (IPv4 + IPv6 loopback) with the real webapp entry
write_web_conf "$TMP/web-ok.conf" "$WEB_OK_BIND" "$GOOD_WEB_SECRET"
timeout 6 "$WEB_SVC" "$TMP/web-ok.conf" "$WEB_SCRATCH" > "$TMP/web-ok.log" 2>&1 || true
assert_grep 'mode=web' "$TMP/web-ok.log" "web mode starts with a valid 0640 secret (real webapp serve exec)"
assert_no_grep 'fixture-api-secret' "$TMP/web-ok.log" "secret value never printed"

write_web_conf "$TMP/web-ok6.conf" "SBMON_WEB_BIND=[::1]:19192" "$GOOD_WEB_SECRET"
timeout 6 "$WEB_SVC" "$TMP/web-ok6.conf" "$WEB_SCRATCH" > "$TMP/web-ok6.log" 2>&1 || true
assert_grep 'mode=web' "$TMP/web-ok6.log" "web mode starts with the IPv6 loopback bind form [::1]:port"
rm -rf "$WEB_SCRATCH"

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
section "T18 web-mode health probe (broker_health + web_http, R1-6/R1-7)"
run_install "$TMP/out-t18setup.log" >/dev/null 2>&1
HWB="$FIX_APP_LINK/bin/monitor-health"
HCW="$TMP/health-web.conf"
cat > "$HCW" <<EOF
SBMON_WEB_BIND=127.0.0.1:19193
SBMON_API_URL=http://127.0.0.1:19091
SBMON_API_SECRET_FILE=$FIX_CONF_DIR/api.secret
SBMON_MODE=web
SBMON_WEB_POLL_SECONDS=1
EOF
ensure_fixture_state_dir
HEALTH_FILE="$FIX_STATE/state/health.json"
WEB_LIVE_PID=""
API_LIVE_PID=""
python3 - <<'PY1' &
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19091))
s.listen(8)
s.settimeout(60)
try:
    while True:
        c, _ = s.accept()
        c.close()
except OSError:
    pass
PY1
API_LIVE_PID=$!
python3 - <<'PY2' &
import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # R1.1-C: mirror the REAL E2 /api/v1/session shape (200 + JSON) so the
        # "web_http ok" assertion proves an identity check, not just "<500".
        body = json.dumps({
            "authenticated": False,
            "current_ip": "127.0.0.1",
            "whitelist_allowed": True,
            "password_configured": False,
            "recovery_configured": False,
            "remote_mode": False,
            "version": "e2-session-stub",
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", 19193), H)
srv.timeout = 60
try:
    while True:
        srv.handle_request()
except OSError:
    pass
PY2
WEB_LIVE_PID=$!
sleep 0.8
hw_probe() { "$HWB" "$HCW" "$FIX_STATE"; }

printf '{"schema_version":1,"snapshot_version":7,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":true}\n' > "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 0 "$H_RC" "web healthy: service up + api reachable + fresh broker health + web endpoint up"
assert_grep '"broker_health":' <(printf '%s' "$H_JSON") "web health reports broker_health object (R1-7)"
assert_grep '"age_stale":false' <(printf '%s' "$H_JSON") "broker health age_stale=false"
assert_grep '"collector_stale":false' <(printf '%s' "$H_JSON") "broker health collector_stale=false"
assert_grep '"consumer_alive":true' <(printf '%s' "$H_JSON") "broker health consumer_alive=true"
assert_grep '"web_http":"ok"' <(printf '%s' "$H_JSON") "web_http probe reaches loopback /api/v1/session unauthenticated"
assert_no_grep 'snapshot' <(printf '%s' "$H_JSON") "web mode does NOT report the collector-loop snapshot object"

printf '{"schema_version":1,"snapshot_version":8,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":true,"consumer_alive":true}\n' > "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): collector_stale=true"
assert_grep '"collector_stale":true' <(printf '%s' "$H_JSON") "collector_stale reflected from health file"

printf '{"schema_version":1,"snapshot_version":9,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":false}\n' > "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): consumer_alive=false"
assert_grep '"consumer_alive":false' <(printf '%s' "$H_JSON") "consumer_alive=false reported"

printf 'not-json{{{' > "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): malformed health file"
assert_no_grep 'not-json' <(printf '%s' "$H_JSON") "malformed health contents never echoed"

rm -f "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): health file missing"
assert_grep '"present":false' <(printf '%s' "$H_JSON") "health file present=false when missing"

printf '{"schema_version":1,"snapshot_version":10,"published_at":"2020-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":true}\n' > "$HEALTH_FILE"
touch -d '2 hours ago' "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): health file too old"
assert_grep '"age_stale":true' <(printf '%s' "$H_JSON") "age_stale=true for old health file"

printf '{"schema_version":1,"snapshot_version":11,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":true}\n' > "$HEALTH_FILE"
kill "$WEB_LIVE_PID" 2>/dev/null
WEB_LIVE_PID=""
sleep 0.5
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): web HTTP endpoint unavailable"
assert_grep '"web_http":"unavailable"' <(printf '%s' "$H_JSON") "web_http reported unavailable"

HCW_BAD="$TMP/health-web-bad.conf"
cat > "$HCW_BAD" <<EOF
SBMON_WEB_BIND=127.0.0.1:19193
SBMON_API_URL=http://0.0.0.0:9091
SBMON_MODE=web
EOF
H_JSON="$("$HWB" "$HCW_BAD" "$FIX_STATE")"; H_RC=$?
assert_rc 2 "$H_RC" "web degraded (rc 2): non-loopback API URL"
assert_grep '"api_url_valid":false' <(printf '%s' "$H_JSON") "api_url_valid=false for non-loopback API URL"

echo inactive > "$MOCK_SYS_STATE"
printf '{"schema_version":1,"snapshot_version":12,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":true}\n' > "$HEALTH_FILE"
H_JSON="$(hw_probe)"; H_RC=$?
assert_rc 1 "$H_RC" "web unhealthy (rc 1): service down"
assert_grep '"service_active":false' <(printf '%s' "$H_JSON") "web unhealthy reports service_active=false"
echo active > "$MOCK_SYS_STATE"
rm -f "$HEALTH_FILE"
[ -n "$API_LIVE_PID" ] && kill "$API_LIVE_PID" 2>/dev/null

# ---------------------------------------------------------------------------
section "T20 web health identity check (R1.1-C)"
# The probe must verify this really is the E2 dashboard -- HTTP 200 AND a JSON
# object with the minimal stable session shape -- not merely "any <500 answer".
# A controllable loopback stub re-reads a spec file per request so status/body
# can be flipped between probes.
C_SPEC="$TMP/c-stub-spec.json"
C_PORT=19197
cat > "$TMP/c-stub.py" <<'PY'
import http.server, json, sys
spec_path, port = sys.argv[1], int(sys.argv[2])
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            with open(spec_path, encoding="utf-8") as fh:
                spec = json.load(fh)
        except Exception:
            spec = {"status": 500, "body": ""}
        body = str(spec.get("body", "")).encode("utf-8")
        self.send_response(int(spec.get("status", 500)))
        ctype = spec.get("content_type")
        if ctype:
            self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
srv = http.server.HTTPServer(("127.0.0.1", port), H)
srv.serve_forever()
PY
python3 "$TMP/c-stub.py" "$C_SPEC" "$C_PORT" &
C_STUB_PID=$!
python3 - <<'PYAPI' &
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19091)); s.listen(8); s.settimeout(120)
try:
    while True:
        c, _ = s.accept(); c.close()
except OSError:
    pass
PYAPI
C_API_PID=$!
sleep 0.8

C_CONF="$TMP/health-c.conf"
cat > "$C_CONF" <<EOF
SBMON_WEB_BIND=127.0.0.1:$C_PORT
SBMON_API_URL=http://127.0.0.1:19091
SBMON_MODE=web
SBMON_WEB_POLL_SECONDS=1
EOF
ensure_fixture_state_dir
C_HEALTH="$FIX_STATE/state/health.json"
set_c_stub() { # <status> <content_type> <body-string>
    python3 - "$C_SPEC" "$1" "$2" "$3" <<'PY'
import json, sys
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump({"status": int(sys.argv[2]),
               "content_type": sys.argv[3],
               "body": sys.argv[4]}, fh)
PY
}
write_c_health() {
    printf '{"schema_version":1,"snapshot_version":1,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":true}\n' > "$C_HEALTH"
}
c_probe() { write_c_health; "$HWB" "$C_CONF" "$FIX_STATE"; }
echo active > "$MOCK_SYS_STATE"

C_JSON='{"authenticated": false, "whitelist_allowed": true, "version": "e2-test"}'
set_c_stub 200 application/json "$C_JSON"
H_JSON="$(c_probe)"; H_RC=$?
assert_rc 0 "$H_RC" "200 + valid E2 session JSON -> healthy (R1.1-C)"
assert_grep '"web_http":"ok"' <(printf '%s' "$H_JSON") "web_http ok for the real session shape (R1.1-C)"

for c_status in 404 401 403 500; do
    set_c_stub "$c_status" application/json "$C_JSON"
    H_JSON="$(c_probe)"; H_RC=$?
    assert_rc 2 "$H_RC" "HTTP $c_status from the web port -> degraded (R1.1-C)"
    assert_grep '"web_http":"unavailable"' <(printf '%s' "$H_JSON") "web_http unavailable for HTTP $c_status (R1.1-C)"
done

set_c_stub 200 text/html '<html><body>definitely not the dashboard</body></html>'
H_JSON="$(c_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "200 + non-JSON body -> degraded (R1.1-C)"
assert_grep '"web_http":"unavailable"' <(printf '%s' "$H_JSON") "web_http unavailable for a foreign 200 body (R1.1-C)"

set_c_stub 200 application/json '{"foo": 1, "bar": true}'
H_JSON="$(c_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "200 + wrong JSON shape -> degraded (R1.1-C)"

# body privacy: an ignored field is never echoed into probe output
C_SENTINEL='probe-body-sentinel-9f3a'
set_c_stub 200 application/json "{\"authenticated\": false, \"whitelist_allowed\": true, \"version\": \"e2-test\", \"current_ip\": \"$C_SENTINEL\"}"
H_JSON="$(c_probe)"; H_RC=$?
assert_rc 0 "$H_RC" "extra session fields tolerated (stable shape check) (R1.1-C)"
assert_no_grep "$C_SENTINEL" <(printf '%s' "$H_JSON") "session body contents never appear in probe output (R1.1-C)"

kill "$C_STUB_PID" 2>/dev/null
C_STUB_PID=""
sleep 0.4
H_JSON="$(c_probe)"; H_RC=$?
assert_rc 2 "$H_RC" "no listener on the web port -> degraded (R1.1-C)"

# real E2 server end to end (the strongest identity proof)
C_REAL_PORT=19198
C_REAL_DATA="$TMP/c-real-data"
mkdir -p "$C_REAL_DATA"
python3 "$FIX_APP_LINK/app/monitor-v2/webapp.py" serve \
    --listen 127.0.0.1 --port "$C_REAL_PORT" \
    --url http://127.0.0.1:19091 \
    --secret-file "$FIX_CONF_DIR/api.secret" \
    --data-dir "$C_REAL_DATA" --poll 0.5 > "$TMP/c-real-web.log" 2>&1 &
C_REAL_PID=$!
C_REAL_CONF="$TMP/health-c-real.conf"
cat > "$C_REAL_CONF" <<EOF
SBMON_WEB_BIND=127.0.0.1:$C_REAL_PORT
SBMON_API_URL=http://127.0.0.1:19091
SBMON_MODE=web
SBMON_WEB_POLL_SECONDS=1
EOF
C_REAL_UP=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
    if python3 -c "import socket,sys; s=socket.socket(); s.settimeout(0.3); sys.exit(0 if s.connect_ex(('127.0.0.1', $C_REAL_PORT)) == 0 else 1)" 2>/dev/null; then
        C_REAL_UP=1; break
    fi
    sleep 0.5
done
if [ "$C_REAL_UP" = 1 ]; then
    write_c_health
    H_JSON="$("$HWB" "$C_REAL_CONF" "$FIX_STATE")"; H_RC=$?
    assert_rc 0 "$H_RC" "real E2 session endpoint (200 + valid JSON) -> healthy (R1.1-C)"
    assert_grep '"web_http":"ok"' <(printf '%s' "$H_JSON") "web_http ok against the real E2 server (R1.1-C)"
else
    fail "real E2 web server did not come up for the identity probe (R1.1-C)"
fi
kill "$C_REAL_PID" 2>/dev/null
rm -rf "$C_REAL_DATA"
[ -n "$C_API_PID" ] && kill "$C_API_PID" 2>/dev/null

# ---------------------------------------------------------------------------
section "T21 SBMON_WEB_POLL_SECONDS strict finite>0 contract (R1.1-D)"
D_ENV="$FIX_APP_LINK/lib/monitor-env.sh"
for d_good in 1 1.0 0.5 2.25; do
    if ( . "$D_ENV"; monitor_env_validate_poll_seconds "$d_good" ); then
        pass "helper accepts poll=$d_good (R1.1-D)"
    else
        fail "helper rejects poll=$d_good (R1.1-D)"
    fi
done
for d_bad in 0 0.0 -1 NaN nan inf Infinity . 1..2 abc ''; do
    if ( . "$D_ENV"; monitor_env_validate_poll_seconds "$d_bad" ); then
        fail "helper accepts invalid poll='$d_bad' (R1.1-D)"
    else
        pass "helper rejects poll='$d_bad' (R1.1-D)"
    fi
done
assert_eq "20" "$( ( . "$D_ENV"; monitor_env_poll_max_age 1 ) )" "max_age(1)=20 (R1.1-D)"
assert_eq "18" "$( ( . "$D_ENV"; monitor_env_poll_max_age 0.5 ) )" "max_age(0.5)=ceil(17.5)=18 (no truncation) (R1.1-D)"
assert_eq "27" "$( ( . "$D_ENV"; monitor_env_poll_max_age 2.25 ) )" "max_age(2.25)=ceil(26.25)=27 (R1.1-D)"
assert_rc 1 "$( ( . "$D_ENV"; monitor_env_poll_max_age 0 ) >/dev/null 2>&1; echo $? )" "max_age(0) fails closed (R1.1-D)"

D_SCRATCH="$(mktemp -d)"
d_write_conf() { # <file> <poll>
    { printf 'SBMON_MODE=web\n';
      printf 'SBMON_API_URL=http://127.0.0.1:19091\n';
      printf 'SBMON_WEB_BIND=127.0.0.1:19199\n';
      printf 'SBMON_API_SECRET_FILE=%s\n' "$FIX_CONF_DIR/api.secret";
      printf 'SBMON_WEB_POLL_SECONDS=%s\n' "$2"; } > "$1"
}
for d_good in 1 1.0 0.5 2.25; do
    d_write_conf "$TMP/d-good.conf" "$d_good"
    timeout 3 "$WEB_SVC" "$TMP/d-good.conf" "$D_SCRATCH" > "$TMP/d-good.log" 2>&1 || true
    assert_grep 'mode=web' "$TMP/d-good.log" "service accepts poll=$d_good and reaches web exec (R1.1-D)"
done
for d_bad in 0 0.0 -1 NaN nan inf Infinity . 1..2 abc ''; do
    d_write_conf "$TMP/d-bad.conf" "$d_bad"
    timeout 5 "$WEB_SVC" "$TMP/d-bad.conf" "$D_SCRATCH" > "$TMP/d-bad.log" 2>&1
    assert_rc 1 $? "service rejects poll='$d_bad' fail-closed (R1.1-D)"
    assert_no_grep 'mode=web' "$TMP/d-bad.log" "rejected poll='$d_bad' never execs webapp (no busy-loop path) (R1.1-D)"
done
rm -rf "$D_SCRATCH"

# health applies the SAME contract: an invalid poll cannot look fresh
D_HCONF="$TMP/d-health-badpoll.conf"
cat > "$D_HCONF" <<EOF
SBMON_WEB_BIND=127.0.0.1:19199
SBMON_API_URL=http://127.0.0.1:19091
SBMON_MODE=web
SBMON_WEB_POLL_SECONDS=0
EOF
echo active > "$MOCK_SYS_STATE"
ensure_fixture_state_dir
printf '{"schema_version":1,"snapshot_version":1,"published_at":"2030-01-01T00:00:00+00:00","collector_stale":false,"consumer_alive":true}\n' > "$FIX_STATE/state/health.json"
H_JSON="$("$HWB" "$D_HCONF" "$FIX_STATE")"; H_RC=$?
assert_rc 2 "$H_RC" "health: poll=0 cannot look fresh -> degraded (R1.1-D)"
assert_grep '"age_stale":true' <(printf '%s' "$H_JSON") "health poll=0 -> age_stale=true (same rule as service) (R1.1-D)"

section "T09 journal redaction (secrets never reach service output)"
run_uninstall_quiet
FAKE_SECRET='S3cr3t-T0ken-abc123'
FAKE_UUID='550e8400-e29b-41d4-a716-446655440000'
mkdir -p "$FIX_CONF_DIR"
ensure_fixture_state_dir
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
assert_grep '缺少必需依赖命令' "$OUT10" "error message explains precheck (names the missing dependency)"
assert_grep 'fail-closed' "$OUT10" "precheck is fail-closed"

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
section "R1.1-A service-owned state tree privilege boundary"
# Root must never path-chown/chmod a child inside the sboxweb-owned data root:
# a service-user-controlled state/ entry could be swapped for a symlink and a
# privileged metadata mutation would follow it. Fail-closed BEFORE any release
# or history mutation; existing auth/access bytes always preserved.
run_uninstall_quiet
rm -rf "$FIX_STATE" "$FIX_RELEASES"
mkdir -p "$FIX_STATE"
printf '{"legacy": true}\n' > "$FIX_STATE/auth.json"
printf '{"whitelist": ["198.51.100.9/32"]}\n' > "$FIX_STATE/access.json"
STATE_AUTH_HASH="$(sha256sum "$FIX_STATE/auth.json" | cut -d' ' -f1)"
STATE_ACCESS_HASH="$(sha256sum "$FIX_STATE/access.json" | cut -d' ' -f1)"

# A1: wrong-type (regular file) state/ -> fail closed, entry untouched
printf 'not-a-directory\n' > "$FIX_STATE/state"
OUT_R11A1="$TMP/out-r11a1.log"
run_install "$OUT_R11A1"
assert_rc 1 $? "state/ wrong type (regular file) -> install fails closed (R1.1-A)"
assert_eq "not-a-directory" "$(cat "$FIX_STATE/state")" "wrong-type state/ entry unchanged (R1.1-A)"
rm -f "$FIX_STATE/state"

if [ "$SYMLINKS_OK" = 1 ]; then
    # A2: state/ replaced with a symlink to a sentinel -> root must not follow
    # it. Sentinel uid:gid:mode and content stay byte-for-byte identical.
    SENTINEL="$TMP/state-sentinel"
    rm -rf "$SENTINEL"
    mkdir -p "$SENTINEL"
    printf 'sentinel-must-survive\n' > "$SENTINEL/marker"
    chmod 0705 "$SENTINEL"
    SENT_META_BEFORE="$(stat -c '%u:%g:%a' "$SENTINEL")"
    SENT_MARK_BEFORE="$(sha256sum "$SENTINEL/marker" | cut -d' ' -f1)"
    ln -s "$SENTINEL" "$FIX_STATE/state"
    OUT_R11A2="$TMP/out-r11a2.log"
    run_install "$OUT_R11A2"
    assert_rc 1 $? "state/ symlink -> install fails closed (R1.1-A)"
    assert_grep 'state/' "$OUT_R11A2" "fail-closed message names state/ (R1.1-A)"
    assert_eq "$SENT_META_BEFORE" "$(stat -c '%u:%g:%a' "$SENTINEL")" "symlink-target sentinel uid:gid:mode untouched (R1.1-A)"
    assert_eq "$SENT_MARK_BEFORE" "$(sha256sum "$SENTINEL/marker" | cut -d' ' -f1)" "symlink-target sentinel content untouched (R1.1-A)"
    [ -L "$FIX_STATE/state" ] && pass "state/ symlink left in place (never replaced/followed) (R1.1-A)" || fail "state/ symlink replaced (R1.1-A)"
    if [ ! -L "$SBMON_APP_LINK" ] && [ ! -e "$SBMON_APP_LINK" ]; then pass "no release activated on state/ failure (R1.1-A)"; else fail "release activated despite state/ failure (R1.1-A)"; fi
    if [ ! -e "$FIX_RELEASES/releases.history" ]; then pass "no history written on state/ failure (R1.1-A)"; else fail "history mutated despite state/ failure (R1.1-A)"; fi
    rm -f "$FIX_STATE/state"
else
    printf '  SKIP R1.1-A symlink sentinel case（此平台无符号链接）\n'
fi

assert_eq "$STATE_AUTH_HASH" "$(sha256sum "$FIX_STATE/auth.json" | cut -d' ' -f1)" "existing auth.json bytes unchanged (R1.1-A)"
assert_eq "$STATE_ACCESS_HASH" "$(sha256sum "$FIX_STATE/access.json" | cut -d' ' -f1)" "existing access.json bytes unchanged (R1.1-A)"

# A3: a normal state/ dir converges and the install succeeds.
OUT_R11A3="$TMP/out-r11a3.log"
run_install "$OUT_R11A3"
assert_rc 0 $? "state/ normal directory -> install succeeds (R1.1-A)"
assert_dir_mode "$FIX_STATE" 700 "data root converges to 0700 (R1.1-A)"
assert_dir_mode "$FIX_STATE/state" 700 "state/ converges to 0700 (R1.1-A)"

# A4 (root real-metadata pass): an existing state/ owned by ROOT cannot be
# converged AS the service user -- install must fail closed with a manual-fix
# hint BEFORE any release/history mutation. The installer never "rescues" it
# with a root chown of a service-owned child.
if [ "$SBMON_FIXTURE" = "0" ]; then
    run_uninstall_quiet
    rm -rf "$FIX_STATE" "$FIX_RELEASES"
    mkdir -p "$FIX_STATE/state"
    chown root:root "$FIX_STATE/state"
    OUT_R11A4="$TMP/out-r11a4.log"
    run_install "$OUT_R11A4"
    assert_rc 1 $? "root-owned state/ -> install fails closed (R1.1-A)"
    assert_grep '不属于服务用户' "$OUT_R11A4" "root-owned state/ manual-fix hint (R1.1-A)"
    if [ ! -L "$SBMON_APP_LINK" ] && [ ! -e "$SBMON_APP_LINK" ]; then pass "no release activated on root-owned state/ (R1.1-A)"; else fail "release activated despite root-owned state/ (R1.1-A)"; fi
    if [ ! -e "$FIX_RELEASES/releases.history" ]; then pass "no history written on root-owned state/ (R1.1-A)"; else fail "history mutated despite root-owned state/ (R1.1-A)"; fi
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

# ---------------------------------------------------------------------------
section "T19 web-setup command (R1-8)"
run_uninstall_quiet
rm -rf "$FIX_STATE" "$FIX_CONF_DIR"
run_install "$TMP/out-t19setup.log" >/dev/null 2>&1
assert_rc 0 $? "install before web-setup exits 0"
"$INSTALL_MONITOR" web-setup </dev/null > "$TMP/t19reg.log" 2>&1 || true
assert_no_grep '未知命令' "$TMP/t19reg.log" "web-setup is a registered command"

if [ "$SYMLINKS_OK" = 1 ]; then
    # The reviewed E2 setup is interactive. Seed a COMPLETE, service-user
    # readable AuthStore so the whitelist/password/recovery prompts are
    # already satisfied and the packaging path runs end to end against the
    # real command (no stub).
    mkdir -p "$FIX_STATE"
    printf '{"version": 1, "password": {"hash": "seed"}, "recovery": {"hash": "seed"}}\n' > "$FIX_STATE/auth.json"
    printf '{"whitelist": ["198.51.100.9/32"]}\n' > "$FIX_STATE/access.json"
    chmod 0700 "$FIX_STATE"
    chmod 0600 "$FIX_STATE/auth.json" "$FIX_STATE/access.json"
    if [ "$SBMON_FIXTURE" = "0" ]; then
        # Production path: setup runs AS the service user, so the seeded store
        # must be readable by that identity (mirrors a real /var/lib install),
        # and the fixture tree must be traversable like /opt.
        chmod 0755 "$TMP" "$FIX_RELEASES"
        chown "${SBMON_USER:-sboxweb}:${SBMON_GROUP:-sboxweb}" "$FIX_STATE" "$FIX_STATE/auth.json" "$FIX_STATE/access.json"
    fi
    CALLS_BEFORE_SU="$(wc -l < "$MOCK_CALL_LOG")"
    SETUP_OUT="$TMP/out-t19.log"
    SETUP_RC=0
    SSH_CONNECTION='203.0.113.77 55222 198.51.100.5 22' "$INSTALL_MONITOR" web-setup < /dev/null > "$SETUP_OUT" 2>&1 || SETUP_RC=$?
    assert_grep 'deployment lock acquired' "$SETUP_OUT" "web-setup runs under the deployment lock"
    if [ "$SETUP_RC" != 0 ]; then
        # Diagnostic only: token-looking strings are masked so no secret or
        # recovery key can reach the CI log.
        printf '  --- web-setup output (masked) ---\n'
        sed -E 's/[A-Za-z0-9_-]{24,}/<redacted>/g' "$SETUP_OUT" 2>/dev/null | head -25
        printf '  --- end web-setup output ---\n'
    fi
    assert_rc 0 "$SETUP_RC" "web-setup runs the reviewed E2 setup to completion as the service identity"
    assert_grep 'singbox-monitor' "$SETUP_OUT" "web-setup reports the monitor-only restart"

    # Loopback-only access hint (operator UX hardening; additive, no security
    # model change): printed on SUCCESS output only, never the server IP.
    assert_grep '127.0.0.1:9191' "$SETUP_OUT" "web-setup prints the loopback listen hint"
    # T19 access-hint contract (only this contract is asserted about IPs):
    #   * the E2 setup itself MAY print the DETECTED SSH CLIENT source IP
    #     (203.0.113.77 in this fixture) -- that is reviewed E2 behaviour;
    #   * the installer hint must require the explicit root@<server> form;
    #   * the SERVER-side SSH IP (198.51.100.5 = SSH_CONNECTION field 3) must
    #     never be printed or inferred anywhere in the output.
    assert_grep 'ssh -L 19191:127\.0\.0\.1:9191 root@<server>' "$SETUP_OUT" "web-setup access hint requires root@<server>"
    assert_grep 'http://127.0.0.1:19191' "$SETUP_OUT" "web-setup prints the dashboard URL hint"
    assert_no_grep '198\.51\.100\.5' "$SETUP_OUT" "web-setup never prints/infers the server-side SSH IP"
    assert_no_grep 'sshd_config' "$SETUP_OUT" "web-setup never suggests changing sshd_config"
    tail -n +"$((CALLS_BEFORE_SU + 1))" "$MOCK_CALL_LOG" > "$TMP/t19-calls.log"
    assert_grep 'restart singbox-monitor' "$TMP/t19-calls.log" "web-setup restarted ONLY singbox-monitor (was active)"
    assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "web-setup never touches sing-box (whole run)"
    if [ ! -e "$FIX_STATE/auth" ]; then
        pass "web-setup writes flat files (no legacy auth/ dir created)"
    else
        fail "web-setup created a legacy auth/ directory"
    fi
    assert_no_grep 'Traceback' "$SETUP_OUT" "no unhandled python traceback in web-setup output"
    if grep -q '203.0.113.77' "$FIX_STATE/access.json"; then
        fail "web-setup auto-added the SSH source to the whitelist"
    else
        pass "web-setup never auto-adds a whitelist entry"
    fi
    assert_grep '198.51.100.9/32' "$FIX_STATE/access.json" "pre-existing whitelist entry untouched"
    if [ "$SBMON_FIXTURE" = "0" ]; then
        assert_eq "sboxweb" "$(stat -c '%U' "$FIX_STATE/auth.json")" "auth.json owned by sboxweb after web-setup (real metadata)"
        assert_eq "sboxweb" "$(stat -c '%U' "$FIX_STATE/access.json")" "access.json owned by sboxweb after web-setup"
        assert_eq "700" "$(stat -c '%a' "$FIX_STATE")" "data root private 0700 after web-setup"
        # R1.1-B: full owner:group + mode contract, guaranteed by E2 itself.
        assert_eq "sboxweb" "$(stat -c '%G' "$FIX_STATE/auth.json")" "auth.json group sboxweb (R1.1-B)"
        assert_eq "600" "$(stat -c '%a' "$FIX_STATE/auth.json")" "auth.json mode 0600 (R1.1-B)"
        assert_eq "sboxweb" "$(stat -c '%G' "$FIX_STATE/access.json")" "access.json group sboxweb (R1.1-B)"
        assert_eq "600" "$(stat -c '%a' "$FIX_STATE/access.json")" "access.json mode 0600 (R1.1-B)"
    else
        printf '  SKIP real-owner assertion (non-root fixture pass; root CI covers it)\n'
    fi

    # R1.1-B: the installer must contain NO root chown/chmod inside web-setup
    # and must never accept credentials via argv (comments stripped first).
    WS_FN="$(sed -n '/^_cmd_web_setup_locked()/,/^}/p' "$INSTALL_MONITOR")"
    WS_CODE="$(printf '%s' "$WS_FN" | strip_comments)"
    if printf '%s' "$WS_CODE" | grep -qE '(^|[^[:alnum:]_])(chown|chmod)([^[:alnum:]_]|$)'; then
        fail "web-setup still performs a root chown/chmod (R1.1-B)"
    else
        pass "web-setup performs no root chown/chmod on service-owned children (R1.1-B)"
    fi
    if printf '%s' "$WS_CODE" | grep -qE -- '--password|--recovery-out'; then
        fail "web-setup accepts password/recovery via argv (R1.1-E)"
    else
        pass "web-setup never passes password/recovery key via argv (R1.1-E)"
    fi

    # R1.1-B: a symlink attack on a service-owned child must never mutate a
    # root-owned sentinel, and a verify failure must not restart the monitor.
    if [ "$SBMON_FIXTURE" = "0" ]; then
        SENT="$TMP/access-sentinel"
        printf 'root-sentinel-body\n' > "$SENT"
        chmod 0600 "$SENT"
        chown root:root "$SENT"
        SENT_META_BEFORE2="$(stat -c '%u:%g:%a' "$SENT")"
        SENT_HASH_BEFORE2="$(sha256sum "$SENT" | cut -d' ' -f1)"
        rm -f "$FIX_STATE/access.json"
        ln -s "$SENT" "$FIX_STATE/access.json"
        CALLS_BEFORE_SYM="$(wc -l < "$MOCK_CALL_LOG")"
        OUT_T19SYM="$TMP/out-t19-symlink.log"
        "$INSTALL_MONITOR" web-setup </dev/null > "$OUT_T19SYM" 2>&1 || true
        assert_eq "$SENT_META_BEFORE2" "$(stat -c '%u:%g:%a' "$SENT")" "root-owned sentinel metadata unchanged (R1.1-B)"
        assert_eq "$SENT_HASH_BEFORE2" "$(sha256sum "$SENT" | cut -d' ' -f1)" "root-owned sentinel content unchanged (R1.1-B)"
        tail -n +"$((CALLS_BEFORE_SYM + 1))" "$MOCK_CALL_LOG" > "$TMP/t19-sym-calls.log"
        assert_no_grep 'restart' "$TMP/t19-sym-calls.log" "verify-failed web-setup does not restart the monitor (R1.1-B)"
        rm -f "$FIX_STATE/access.json"
        printf '{"whitelist": ["198.51.100.9/32"]}\n' > "$FIX_STATE/access.json"
        chown "${SBMON_USER:-sboxweb}:${SBMON_GROUP:-sboxweb}" "$FIX_STATE/access.json"
        chmod 0600 "$FIX_STATE/access.json"
    fi

    # R1.1-B: an explicit setup failure must propagate the rc, be honest about
    # possible partial writes, and never restart the monitor.
    FAILPY="$TMP/fail-python.sh"
    printf '#!/usr/bin/env bash\nexit 7\n' > "$FAILPY"
    chmod 0755 "$FAILPY"
    CALLS_BEFORE_FAIL="$(wc -l < "$MOCK_CALL_LOG")"
    FAIL_OUT="$TMP/out-t19-fail.log"
    FAIL_RC=0
    SBMON_PYTHON3="$FAILPY" "$INSTALL_MONITOR" web-setup </dev/null > "$FAIL_OUT" 2>&1 || FAIL_RC=$?
    assert_rc 7 "$FAIL_RC" "web-setup propagates the setup failure rc (R1.1-B)"
    assert_grep '可能已完成部分持久化写入' "$FAIL_OUT" "setup failure is honest about possible partial writes (R1.1-B)"
    assert_no_grep '保持不变' "$FAIL_OUT" "setup failure no longer claims byte-identical data (R1.1-B)"
    tail -n +"$((CALLS_BEFORE_FAIL + 1))" "$MOCK_CALL_LOG" > "$TMP/t19-fail-calls.log"
    assert_no_grep 'restart' "$TMP/t19-fail-calls.log" "failed web-setup does not restart the monitor (R1.1-B)"

    # R1.1-E: setup must run under an EXPLICIT CLEAN environment. A thin
    # python wrapper (resolved as the interpreter) records the child env.
    PROBE_DIR="$TMP/env-probe"
    mkdir -p "$PROBE_DIR"
    chmod 0777 "$PROBE_DIR"
    ENV_DUMP="$PROBE_DIR/dump"
    ENV_PY="$PROBE_DIR/pywrap"
    cat > "$ENV_PY" <<WRAP
#!/usr/bin/env bash
{
  printf 'HOME=%s\n' "\${HOME:-}"
  printf 'PATH=%s\n' "\${PATH:-}"
  printf 'SSH_CONNECTION=%s\n' "\${SSH_CONNECTION:-}"
  [ -z "\${BOX_API_SECRET:-}" ] || printf 'LEAK_BOX_API_SECRET=1\n'
  [ -z "\${RANDOM_TEST_ENV:-}" ] || printf 'LEAK_RANDOM_TEST_ENV=1\n'
} > "$ENV_DUMP"
exec "$PY3" "\$@"
WRAP
    chmod 0755 "$ENV_PY"
    rm -f "$ENV_DUMP"
    ENV_OUT="$TMP/out-t19-env.log"
    ENV_RC=0
    BOX_API_SECRET='sentinel-box-secret' RANDOM_TEST_ENV='sentinel-random-env' \
    SBMON_PYTHON3="$ENV_PY" SSH_CONNECTION='203.0.113.9 55222 198.51.100.5 22' \
        "$INSTALL_MONITOR" web-setup </dev/null > "$ENV_OUT" 2>&1 || ENV_RC=$?
    assert_rc 0 "$ENV_RC" "clean-env web-setup completes (R1.1-E)"
    if [ -s "$ENV_DUMP" ]; then pass "env probe observed the setup child (R1.1-E)"; else fail "env probe did not run (R1.1-E)"; fi
    ENV_DUMP_TEXT="$(cat "$ENV_DUMP" 2>/dev/null || true)"
    assert_grep "^HOME=$FIX_STATE$" <(printf '%s' "$ENV_DUMP_TEXT") "setup HOME == data root (R1.1-E)"
    assert_grep '^PATH=/usr/sbin:/usr/bin:/sbin:/bin$' <(printf '%s' "$ENV_DUMP_TEXT") "setup PATH == explicitly approved path (R1.1-E)"
    assert_grep '^SSH_CONNECTION=203\.0\.113\.9' <(printf '%s' "$ENV_DUMP_TEXT") "SSH_CONNECTION forwarded to setup (R1.1-E)"
    assert_no_grep 'LEAK_BOX_API_SECRET' <(printf '%s' "$ENV_DUMP_TEXT") "BOX_API_SECRET not visible to setup (R1.1-E)"
    assert_no_grep 'LEAK_RANDOM_TEST_ENV' <(printf '%s' "$ENV_DUMP_TEXT") "arbitrary caller env not visible to setup (R1.1-E)"
else
    printf '  SKIP T19 success path (此平台无符号链接 -> 无已激活 release)\n'
    OUT_T19NC="$TMP/out-t19nc.log"
    "$INSTALL_MONITOR" web-setup </dev/null > "$OUT_T19NC" 2>&1 || true
    assert_grep 'deployment lock acquired' "$OUT_T19NC" "web-setup takes the deployment lock even when it must refuse"
    assert_grep '没有已激活的 release' "$OUT_T19NC" "web-setup fails closed without an activated release"
    if [ ! -e "$FIX_STATE/auth" ]; then
        pass "refused web-setup created no legacy auth/ dir"
    else
        fail "refused web-setup created a legacy auth/ directory"
    fi
    assert_no_grep 'sing-box' "$MOCK_CALL_LOG" "refused web-setup never touches sing-box"
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

# ---------------------------------------------------------------------------
section "T14 CI systemd verify gate contract (fail-closed rc)"
# Static contract for the systemd validation step in
# .github/workflows/tests.yml:
#   1. verify's rc is CAPTURED and judged (never ignored);
#   2. a nonzero verify rc with UNCLASSIFIED diagnostics fails the step;
#   3. a nonzero verify rc with EMPTY diagnostics fails the step;
#   4. only a mechanical UNRELATED-runner-noise allowlist may excuse a
#      nonzero rc, and the allowlist classification never touches
#      singbox-monitor.service lines;
#   5. the old note-only escape hatch (nonzero rc + "no target-unit match"
#      => success) must stay gone forever.
WF="$REPO_ROOT/.github/workflows/tests.yml"
assert_rc 0 "$([ -f "$WF" ] && echo 0 || echo 1)" "workflow file exists"
assert_grep 'systemd-analyze verify "\$UNIT" 2>&1 \| tee "\$RUNNER_TEMP/unit-verify\.log" \|\| vrc=\$\?' \
    "$WF" "verify rc is captured through tee (rc-aware)"
assert_grep 'UNCLASSIFIED diagnostics \(fail-closed' "$WF" \
    "nonzero verify rc + unclassified diagnostics => hard failure"
assert_grep 'EMPTY diagnostics \(fail-closed hard gate\)' "$WF" \
    "nonzero verify rc + empty diagnostics => hard failure"
assert_grep 'UNRELATED_NOISE_RE=' "$WF" \
    "unrelated runner noise is excused only via a mechanical allowlist"
assert_grep "grep -v 'singbox-monitor\\\\.service'" "$WF" \
    "allowlist classification never touches target-unit lines"
assert_grep 'rejected or ignored a directive in the production unit' "$WF" \
    "target-unit directive errors remain a hard failure"
assert_no_grep 'the hard gate holds for the production unit' "$WF" \
    "old note-only escape hatch (nonzero rc + no target-unit match => success) is gone"

# ---------------------------------------------------------------------------
section "T22 production-real upgrade: installed 0.1.1 -> repo VERSION (isolated fixture, R7)"
# Pins the production 0.1.1 -> current delta: a server with 0.1.1 installed
# runs the normal install-monitor.sh upgrade against the repo candidate.
# The candidate version is read from the repo (not hardcoded), so this
# historical baseline stays meaningful across releases. Runs in its OWN
# fixture root with a dedicated systemctl call log (fresh SBMON_*
# overrides), so no historical baseline of the other sections is touched.
T22_NEW_VER="$(cat "$REPO_ROOT/monitor-v2/VERSION")"
T22="$TMP/t22"
T22_APP="$T22/opt/singbox-monitor"
T22_REL="$T22/opt/singbox-monitor-releases"
T22_LOG="$TMP/out-t22.log"
T22_CALLS="$TMP/t22-calls.log"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP T22 原子升级流（此平台无符号链接；Linux pass 是门禁）\n'
else
(
    mkdir -p "$T22/etc/systemd/system" "$T22/src"
    cp "$REPO_ROOT/monitor-v2/collector.py" "$REPO_ROOT/monitor-v2/webapp.py" "$T22/src/"
    cp -R "$REPO_ROOT/monitor-v2/web" "$REPO_ROOT/monitor-v2/api_bridge" "$T22/src/"
    rm -rf "$T22/src/api_bridge/__pycache__" "$T22/src/web/__pycache__"
    printf '0.1.1\n' > "$T22/src/VERSION"
    export SBMON_APP_LINK="$T22_APP"
    export SBMON_RELEASES_DIR="$T22_REL"
    export SBMON_STATE_ROOT="$T22/var/lib/singbox-monitor"
    export SBMON_STATE_DIR="$T22/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$T22/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$T22/etc/systemd/system/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$T22/var/backups/singbox-monitor"
    export SBMON_REPO_MONITOR_DIR="$T22/src"
    export SBMON_VERSION_FILE="$T22/src/VERSION"
    export SBMON_LOCK_FILE="$T22/deploy.lock"
    export MOCK_CALL_LOG="$T22_CALLS"
    : > "$T22_CALLS"
    "$INSTALL_MONITOR" install > "$TMP/out-t22-base.log" 2>&1 || exit 1
    base_dir="$(readlink -f "$T22_APP")"
    [ -n "$base_dir" ] || exit 1
    printf '%s\n' "$base_dir" > "$TMP/t22-basedir"
    find "$base_dir" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1 \
        > "$TMP/t22-basehash"
    grep -c 'systemctl restart singbox-monitor' "$T22_CALLS" > "$TMP/t22-restarts-before" || true
    cp "$REPO_ROOT/monitor-v2/VERSION" "$T22/src/VERSION"
    "$INSTALL_MONITOR" upgrade > "$T22_LOG" 2>&1 || exit 1
)
rc=$?
if [ "$rc" != 0 ]; then
    fail "isolated 0.1.1 install + $T22_NEW_VER upgrade failed (rc=$rc): $(tail -n 5 "$TMP/out-t22-base.log" 2>/dev/null | tr '\n' ' ')"
else
    pass "isolated 0.1.1 install + $T22_NEW_VER upgrade succeed (rc 0)"
    if [ "$T22_NEW_VER" != '0.1.1' ]; then
        pass "the repo candidate ($T22_NEW_VER) really differs from the 0.1.1 baseline"
    else
        fail "T22 candidate equals the 0.1.1 baseline -- the fixture tests no delta"
    fi
    assert_eq "$T22_NEW_VER" "$(cat "$T22_APP/VERSION" 2>/dev/null)" "the new immutable $T22_NEW_VER release is active"
    assert_grep 'action=upgrade' "$T22_LOG" "normal install-monitor.sh upgrade reports action=upgrade"
    BASE_DIR_T22="$(cat "$TMP/t22-basedir" 2>/dev/null || true)"
    if [ -n "$BASE_DIR_T22" ] && [ "$(readlink -f "$T22_APP")" != "$BASE_DIR_T22" ] \
       && [ -d "$BASE_DIR_T22" ] \
       && [ "$(cat "$TMP/t22-basehash")" = "$(find "$BASE_DIR_T22" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)" ]; then
        pass "previous 0.1.1 release retained byte-identical beside the new $T22_NEW_VER release"
    else
        fail "T22 reused or damaged the previous 0.1.1 release"
    fi
    assert_eq "$(( $(cat "$TMP/t22-restarts-before") + 1 ))" \
        "$(grep -c 'systemctl restart singbox-monitor' "$T22_CALLS")" \
        "the upgrade restarted singbox-monitor exactly once"
    assert_no_grep 'sing-box' "$T22_CALLS" "the upgrade never restarted or reloaded sing-box"
    assert_grep ' 0\.1\.1 fresh$' "$T22_REL/releases.history" "the 0.1.1 baseline release is recorded in history"
    assert_grep " ${T22_NEW_VER//./\\.} upgrade\$" "$T22_REL/releases.history" "the $T22_NEW_VER upgrade is recorded in history"
fi
fi

section "T23 production-real upgrade: installed 0.1.2 -> repo VERSION (isolated fixture, 0.1.3)"
# Pins the REAL production delta this release ships: a server with 0.1.2
# installed runs the normal install-monitor.sh upgrade against the 0.1.3
# candidate. Same isolation discipline as T22 (own fixture root, own
# systemctl call log). Beyond T22 it also pins the Monitor-only boundary:
# the upgrade performs ZERO sbox-cm/helper deployment or update actions.
T23_NEW_VER="$(cat "$REPO_ROOT/monitor-v2/VERSION")"
T23="$TMP/t23"
T23_APP="$T23/opt/singbox-monitor"
T23_REL="$T23/opt/singbox-monitor-releases"
T23_LOG="$TMP/out-t23.log"
T23_CALLS="$TMP/t23-calls.log"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP T23 原子升级流（此平台无符号链接；Linux pass 是门禁）\n'
else
(
    mkdir -p "$T23/etc/systemd/system" "$T23/src"
    cp "$REPO_ROOT/monitor-v2/collector.py" "$REPO_ROOT/monitor-v2/webapp.py" "$T23/src/"
    cp -R "$REPO_ROOT/monitor-v2/web" "$REPO_ROOT/monitor-v2/api_bridge" "$T23/src/"
    rm -rf "$T23/src/api_bridge/__pycache__" "$T23/src/web/__pycache__"
    printf '0.1.2\n' > "$T23/src/VERSION"
    export SBMON_APP_LINK="$T23_APP"
    export SBMON_RELEASES_DIR="$T23_REL"
    export SBMON_STATE_ROOT="$T23/var/lib/singbox-monitor"
    export SBMON_STATE_DIR="$T23/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$T23/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$T23/etc/systemd/system/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$T23/var/backups/singbox-monitor"
    export SBMON_REPO_MONITOR_DIR="$T23/src"
    export SBMON_VERSION_FILE="$T23/src/VERSION"
    export SBMON_LOCK_FILE="$T23/deploy.lock"
    export MOCK_CALL_LOG="$T23_CALLS"
    : > "$T23_CALLS"
    "$INSTALL_MONITOR" install > "$TMP/out-t23-base.log" 2>&1 || exit 1
    base_dir="$(readlink -f "$T23_APP")"
    [ -n "$base_dir" ] || exit 1
    printf '%s\n' "$base_dir" > "$TMP/t23-basedir"
    find "$base_dir" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1 \
        > "$TMP/t23-basehash"
    grep -c 'systemctl restart singbox-monitor' "$T23_CALLS" > "$TMP/t23-restarts-before" || true
    cp "$REPO_ROOT/monitor-v2/VERSION" "$T23/src/VERSION"
    "$INSTALL_MONITOR" upgrade > "$T23_LOG" 2>&1 || exit 1
)
rc=$?
if [ "$rc" != 0 ]; then
    fail "isolated 0.1.2 install + $T23_NEW_VER upgrade failed (rc=$rc): $(tail -n 5 "$TMP/out-t23-base.log" 2>/dev/null | tr '\n' ' ')"
else
    pass "isolated 0.1.2 install + $T23_NEW_VER upgrade succeed (rc 0)"
    if [ "$T23_NEW_VER" != '0.1.2' ]; then
        pass "the repo candidate ($T23_NEW_VER) really differs from the 0.1.2 baseline (the real production delta)"
    else
        fail "T23 candidate equals the 0.1.2 baseline -- the fixture tests no delta"
    fi
    assert_eq "$T23_NEW_VER" "$(cat "$T23_APP/VERSION" 2>/dev/null)" "the new immutable $T23_NEW_VER release is active"
    assert_eq '0.1.2' "$(cat "$T23_REL/0.1.2-"*/VERSION 2>/dev/null | head -n 1)" "the 0.1.2 baseline release tree still reports 0.1.2"
    assert_grep 'action=upgrade' "$T23_LOG" "normal install-monitor.sh upgrade reports action=upgrade"
    BASE_DIR_T23="$(cat "$TMP/t23-basedir" 2>/dev/null || true)"
    if [ -n "$BASE_DIR_T23" ] && [ "$(readlink -f "$T23_APP")" != "$BASE_DIR_T23" ] \
       && [ -d "$BASE_DIR_T23" ] \
       && [ "$(cat "$TMP/t23-basehash")" = "$(find "$BASE_DIR_T23" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)" ]; then
        pass "previous 0.1.2 release retained byte-identical beside the new $T23_NEW_VER release (retention within KEEP)"
    else
        fail "T23 reused or damaged the previous 0.1.2 release"
    fi
    assert_eq "$(( $(cat "$TMP/t23-restarts-before") + 1 ))" \
        "$(grep -c 'systemctl restart singbox-monitor' "$T23_CALLS")" \
        "the upgrade restarted singbox-monitor exactly once"
    assert_no_grep 'sing-box' "$T23_CALLS" "the upgrade never restarted or reloaded sing-box"
    assert_no_grep 'sbox-cm' "$T23_CALLS" "the upgrade ran ZERO sbox-cm/helper systemctl actions (Monitor-only boundary)"
    assert_no_grep 'helper' "$T23_LOG" "the upgrade log records no helper deployment or update"
    assert_grep ' 0\.1\.2 fresh$' "$T23_REL/releases.history" "the 0.1.2 baseline release is recorded in history"
    assert_grep " ${T23_NEW_VER//./\\.} upgrade\$" "$T23_REL/releases.history" "the $T23_NEW_VER upgrade is recorded in history"
fi
fi

section "T24 production-real upgrade: installed 0.1.3 -> repo VERSION (isolated fixture, 0.1.4)"
# Same production-real discipline as T23, one release step later: a server
# that converged its view via the 0.1.3 invalidation upgrade now moves to
# the 0.1.4 convergence-endpoint candidate. Still Monitor-only: ZERO
# sbox-cm/helper deployment or update actions.
T24_NEW_VER="$(cat "$REPO_ROOT/monitor-v2/VERSION")"
T24="$TMP/t24"
T24_APP="$T24/opt/singbox-monitor"
T24_REL="$T24/opt/singbox-monitor-releases"
T24_LOG="$TMP/out-t24.log"
T24_CALLS="$TMP/t24-calls.log"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP T24 原子升级流（此平台无符号链接；Linux pass 是门禁）\n'
else
(
    mkdir -p "$T24/etc/systemd/system" "$T24/src"
    cp "$REPO_ROOT/monitor-v2/collector.py" "$REPO_ROOT/monitor-v2/webapp.py" "$T24/src/"
    cp -R "$REPO_ROOT/monitor-v2/web" "$REPO_ROOT/monitor-v2/api_bridge" "$T24/src/"
    rm -rf "$T24/src/api_bridge/__pycache__" "$T24/src/web/__pycache__"
    printf '0.1.3\n' > "$T24/src/VERSION"
    export SBMON_APP_LINK="$T24_APP"
    export SBMON_RELEASES_DIR="$T24_REL"
    export SBMON_STATE_ROOT="$T24/var/lib/singbox-monitor"
    export SBMON_STATE_DIR="$T24/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$T24/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$T24/etc/systemd/system/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$T24/var/backups/singbox-monitor"
    export SBMON_REPO_MONITOR_DIR="$T24/src"
    export SBMON_VERSION_FILE="$T24/src/VERSION"
    export SBMON_LOCK_FILE="$T24/deploy.lock"
    export MOCK_CALL_LOG="$T24_CALLS"
    : > "$T24_CALLS"
    "$INSTALL_MONITOR" install > "$TMP/out-t24-base.log" 2>&1 || exit 1
    base_dir="$(readlink -f "$T24_APP")"
    [ -n "$base_dir" ] || exit 1
    printf '%s\n' "$base_dir" > "$TMP/t24-basedir"
    find "$base_dir" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1 \
        > "$TMP/t24-basehash"
    grep -c 'systemctl restart singbox-monitor' "$T24_CALLS" > "$TMP/t24-restarts-before" || true
    cp "$REPO_ROOT/monitor-v2/VERSION" "$T24/src/VERSION"
    "$INSTALL_MONITOR" upgrade > "$T24_LOG" 2>&1 || exit 1
)
rc=$?
if [ "$rc" != 0 ]; then
    fail "isolated 0.1.3 install + $T24_NEW_VER upgrade failed (rc=$rc): $(tail -n 5 "$TMP/out-t24-base.log" 2>/dev/null | tr '\n' ' ')"
else
    pass "isolated 0.1.3 install + $T24_NEW_VER upgrade succeed (rc 0)"
    if [ "$T24_NEW_VER" != '0.1.3' ]; then
        pass "the repo candidate ($T24_NEW_VER) really differs from the 0.1.3 baseline (the real production delta)"
    else
        fail "T24 candidate equals the 0.1.3 baseline -- the fixture tests no delta"
    fi
    assert_eq "$T24_NEW_VER" "$(cat "$T24_APP/VERSION" 2>/dev/null)" "the new immutable $T24_NEW_VER release is active"
    assert_eq '0.1.3' "$(cat "$T24_REL/0.1.3-"*/VERSION 2>/dev/null | head -n 1)" "the 0.1.3 baseline release tree still reports 0.1.3"
    assert_grep 'action=upgrade' "$T24_LOG" "normal install-monitor.sh upgrade reports action=upgrade"
    BASE_DIR_T24="$(cat "$TMP/t24-basedir" 2>/dev/null || true)"
    if [ -n "$BASE_DIR_T24" ] && [ "$(readlink -f "$T24_APP")" != "$BASE_DIR_T24" ] \
       && [ -d "$BASE_DIR_T24" ] \
       && [ "$(cat "$TMP/t24-basehash")" = "$(find "$BASE_DIR_T24" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)" ]; then
        pass "previous 0.1.3 release retained byte-identical beside the new $T24_NEW_VER release (retention within KEEP)"
    else
        fail "T24 reused or damaged the previous 0.1.3 release"
    fi
    assert_eq "$(( $(cat "$TMP/t24-restarts-before") + 1 ))" \
        "$(grep -c 'systemctl restart singbox-monitor' "$T24_CALLS")" \
        "the upgrade restarted singbox-monitor exactly once"
    assert_no_grep 'sing-box' "$T24_CALLS" "the upgrade never restarted or reloaded sing-box"
    assert_no_grep 'sbox-cm' "$T24_CALLS" "the upgrade ran ZERO sbox-cm/helper systemctl actions (Monitor-only boundary)"
    assert_no_grep 'helper' "$T24_LOG" "the upgrade log records no helper deployment or update"
    assert_grep ' 0\.1\.3 fresh$' "$T24_REL/releases.history" "the 0.1.3 baseline release is recorded in history"
    assert_grep " ${T24_NEW_VER//./\\.} upgrade\$" "$T24_REL/releases.history" "the $T24_NEW_VER upgrade is recorded in history"
fi
fi

section "T25 production-real upgrade: installed 0.1.4 -> repo VERSION (isolated fixture, 0.1.5)"
# Same production-real discipline as T24, one release step later: a server
# that converged its view with the 0.1.4 convergence endpoint now moves to
# the 0.1.5 target-binding delete UX candidate. The upgrade surface is
# unchanged: same atomic release switch, ZERO sbox-cm/helper actions.
T25_NEW_VER="$(cat "$REPO_ROOT/monitor-v2/VERSION")"
T25="$TMP/t25"
T25_APP="$T25/opt/singbox-monitor"
T25_REL="$T25/opt/singbox-monitor-releases"
T25_LOG="$TMP/out-t25.log"
T25_CALLS="$TMP/t25-calls.log"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP T25 原子升级流（此平台无符号链接；Linux pass 是门禁）\n'
else
(
    mkdir -p "$T25/etc/systemd/system" "$T25/src"
    cp "$REPO_ROOT/monitor-v2/collector.py" "$REPO_ROOT/monitor-v2/webapp.py" "$T25/src/"
    cp -R "$REPO_ROOT/monitor-v2/web" "$REPO_ROOT/monitor-v2/api_bridge" "$T25/src/"
    rm -rf "$T25/src/api_bridge/__pycache__" "$T25/src/web/__pycache__"
    printf '0.1.4\n' > "$T25/src/VERSION"
    export SBMON_APP_LINK="$T25_APP"
    export SBMON_RELEASES_DIR="$T25_REL"
    export SBMON_STATE_ROOT="$T25/var/lib/singbox-monitor"
    export SBMON_STATE_DIR="$T25/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$T25/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$T25/etc/systemd/system/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$T25/var/backups/singbox-monitor"
    export SBMON_REPO_MONITOR_DIR="$T25/src"
    export SBMON_VERSION_FILE="$T25/src/VERSION"
    export SBMON_LOCK_FILE="$T25/deploy.lock"
    export MOCK_CALL_LOG="$T25_CALLS"
    : > "$T25_CALLS"
    "$INSTALL_MONITOR" install > "$TMP/out-t25-base.log" 2>&1 || exit 1
    base_dir="$(readlink -f "$T25_APP")"
    [ -n "$base_dir" ] || exit 1
    printf '%s\n' "$base_dir" > "$TMP/t25-basedir"
    find "$base_dir" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1 \
        > "$TMP/t25-basehash"
    grep -c 'systemctl restart singbox-monitor' "$T25_CALLS" > "$TMP/t25-restarts-before" || true
    cp "$REPO_ROOT/monitor-v2/VERSION" "$T25/src/VERSION"
    "$INSTALL_MONITOR" upgrade > "$T25_LOG" 2>&1 || exit 1
)
rc=$?
if [ "$rc" != 0 ]; then
    fail "isolated 0.1.4 install + $T25_NEW_VER upgrade failed (rc=$rc): $(tail -n 5 "$TMP/out-t25-base.log" 2>/dev/null | tr '\n' ' ')"
else
    pass "isolated 0.1.4 install + $T25_NEW_VER upgrade succeed (rc 0)"
    if [ "$T25_NEW_VER" != '0.1.4' ]; then
        pass "the repo candidate ($T25_NEW_VER) really differs from the 0.1.4 baseline (the real production delta)"
    else
        fail "T25 candidate equals the 0.1.4 baseline -- the fixture tests no delta"
    fi
    assert_eq "$T25_NEW_VER" "$(cat "$T25_APP/VERSION" 2>/dev/null)" "the new immutable $T25_NEW_VER release is active"
    assert_eq '0.1.4' "$(cat "$T25_REL/0.1.4-"*/VERSION 2>/dev/null | head -n 1)" "the 0.1.4 baseline release tree still reports 0.1.4"
    assert_grep 'action=upgrade' "$T25_LOG" "normal install-monitor.sh upgrade reports action=upgrade"
    BASE_DIR_T25="$(cat "$TMP/t25-basedir" 2>/dev/null || true)"
    if [ -n "$BASE_DIR_T25" ] && [ "$(readlink -f "$T25_APP")" != "$BASE_DIR_T25" ] \
       && [ -d "$BASE_DIR_T25" ] \
       && [ "$(cat "$TMP/t25-basehash")" = "$(find "$BASE_DIR_T25" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)" ]; then
        pass "previous 0.1.4 release retained byte-identical beside the new $T25_NEW_VER release (retention within KEEP)"
    else
        fail "T25 reused or damaged the previous 0.1.4 release"
    fi
    assert_eq "$(( $(cat "$TMP/t25-restarts-before") + 1 ))" \
        "$(grep -c 'systemctl restart singbox-monitor' "$T25_CALLS")" \
        "the upgrade restarted singbox-monitor exactly once"
    assert_no_grep 'sing-box' "$T25_CALLS" "the upgrade never restarted or reloaded sing-box"
    assert_no_grep 'sbox-cm' "$T25_CALLS" "the upgrade ran ZERO sbox-cm/helper systemctl actions (Monitor-only boundary)"
    assert_no_grep 'helper' "$T25_LOG" "the upgrade log records no helper deployment or update"
    assert_grep ' 0\.1\.4 fresh$' "$T25_REL/releases.history" "the 0.1.4 baseline release is recorded in history"
    assert_grep " ${T25_NEW_VER//./\\.} upgrade\$" "$T25_REL/releases.history" "the $T25_NEW_VER upgrade is recorded in history"
fi
fi

section "T26 production-real upgrade: installed 0.1.5 -> repo VERSION (isolated fixture, 0.2.0)"
# Same production-real discipline as T25, one release step later: a server
# running the 0.1.5 target-binding delete UX now moves to the 0.2.0
# incident-history candidate. The upgrade surface is unchanged: same atomic
# release switch, ZERO sbox-cm/helper actions, and the retained 0.1.5
# release tree stays byte-identical.
T26_NEW_VER="$(cat "$REPO_ROOT/monitor-v2/VERSION")"
T26="$TMP/t26"
T26_APP="$T26/opt/singbox-monitor"
T26_REL="$T26/opt/singbox-monitor-releases"
T26_LOG="$TMP/out-t26.log"
T26_CALLS="$TMP/t26-calls.log"
if [ "$SYMLINKS_OK" != 1 ]; then
    printf '  SKIP T26 原子升级流（此平台无符号链接；Linux pass 是门禁）\n'
else
(
    mkdir -p "$T26/etc/systemd/system" "$T26/src"
    cp "$REPO_ROOT/monitor-v2/collector.py" "$REPO_ROOT/monitor-v2/webapp.py" "$T26/src/"
    cp -R "$REPO_ROOT/monitor-v2/web" "$REPO_ROOT/monitor-v2/api_bridge" "$T26/src/"
    rm -rf "$T26/src/api_bridge/__pycache__" "$T26/src/web/__pycache__"
    printf '0.1.5\n' > "$T26/src/VERSION"
    export SBMON_APP_LINK="$T26_APP"
    export SBMON_RELEASES_DIR="$T26_REL"
    export SBMON_STATE_ROOT="$T26/var/lib/singbox-monitor"
    export SBMON_STATE_DIR="$T26/var/lib/singbox-monitor"
    export SBMON_CONF_DIR="$T26/etc/singbox-monitor"
    export SBMON_UNIT_FILE="$T26/etc/systemd/system/singbox-monitor.service"
    export SBMON_BACKUP_ROOT="$T26/var/backups/singbox-monitor"
    export SBMON_REPO_MONITOR_DIR="$T26/src"
    export SBMON_VERSION_FILE="$T26/src/VERSION"
    export SBMON_LOCK_FILE="$T26/deploy.lock"
    export MOCK_CALL_LOG="$T26_CALLS"
    : > "$T26_CALLS"
    "$INSTALL_MONITOR" install > "$TMP/out-t26-base.log" 2>&1 || exit 1
    base_dir="$(readlink -f "$T26_APP")"
    [ -n "$base_dir" ] || exit 1
    printf '%s\n' "$base_dir" > "$TMP/t26-basedir"
    find "$base_dir" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1 \
        > "$TMP/t26-basehash"
    grep -c 'systemctl restart singbox-monitor' "$T26_CALLS" > "$TMP/t26-restarts-before" || true
    cp "$REPO_ROOT/monitor-v2/VERSION" "$T26/src/VERSION"
    "$INSTALL_MONITOR" upgrade > "$T26_LOG" 2>&1 || exit 1
)
rc=$?
if [ "$rc" != 0 ]; then
    fail "isolated 0.1.5 install + $T26_NEW_VER upgrade failed (rc=$rc): $(tail -n 5 "$TMP/out-t26-base.log" 2>/dev/null | tr '\n' ' ')"
else
    pass "isolated 0.1.5 install + $T26_NEW_VER upgrade succeed (rc 0)"
    if [ "$T26_NEW_VER" != '0.1.5' ]; then
        pass "the repo candidate ($T26_NEW_VER) really differs from the 0.1.5 baseline (the real production delta)"
    else
        fail "T26 candidate equals the 0.1.5 baseline -- the fixture tests no delta"
    fi
    assert_eq "$T26_NEW_VER" "$(cat "$T26_APP/VERSION" 2>/dev/null)" "the new immutable $T26_NEW_VER release is active"
    if [ -f "$T26_APP/app/monitor-v2/web/incident_history.py" ]; then
        pass "0.2.0 release stages the new web/incident_history.py module (whole-web/-R copy)"
    else
        fail "incident_history.py missing from the staged $T26_NEW_VER release"
    fi
    assert_eq '0.1.5' "$(cat "$T26_REL/0.1.5-"*/VERSION 2>/dev/null | head -n 1)" "the 0.1.5 baseline release tree still reports 0.1.5"
    assert_grep 'action=upgrade' "$T26_LOG" "normal install-monitor.sh upgrade reports action=upgrade"
    BASE_DIR_T26="$(cat "$TMP/t26-basedir" 2>/dev/null || true)"
    if [ -n "$BASE_DIR_T26" ] && [ "$(readlink -f "$T26_APP")" != "$BASE_DIR_T26" ] \
       && [ -d "$BASE_DIR_T26" ] \
       && [ "$(cat "$TMP/t26-basehash")" = "$(find "$BASE_DIR_T26" -type f -exec sha256sum {} + | sort | sha256sum | cut -d' ' -f1)" ]; then
        pass "previous 0.1.5 release retained byte-identical beside the new $T26_NEW_VER release (retention within KEEP)"
    else
        fail "T26 reused or damaged the previous 0.1.5 release"
    fi
    assert_eq "$(( $(cat "$TMP/t26-restarts-before") + 1 ))" \
        "$(grep -c 'systemctl restart singbox-monitor' "$T26_CALLS")" \
        "the upgrade restarted singbox-monitor exactly once"
    assert_no_grep 'sing-box' "$T26_CALLS" "the upgrade never restarted or reloaded sing-box"
    assert_no_grep 'sbox-cm' "$T26_CALLS" "the upgrade ran ZERO sbox-cm/helper systemctl actions (Monitor-only boundary)"
    assert_no_grep 'helper' "$T26_LOG" "the upgrade log records no helper deployment or update"
    assert_grep ' 0\.1\.5 fresh$' "$T26_REL/releases.history" "the 0.1.5 baseline release is recorded in history"
    assert_grep " ${T26_NEW_VER//./\\.} upgrade\$" "$T26_REL/releases.history" "the $T26_NEW_VER upgrade is recorded in history"
fi
fi

printf '\n== RESULT: %d passed, %d failed ==\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
