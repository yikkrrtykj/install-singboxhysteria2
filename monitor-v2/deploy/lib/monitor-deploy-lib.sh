# monitor-deploy-lib.sh -- Monitor v2 deployment primitives (skeleton, E2/E3-aware).
#
# Design contract (see monitor-v2/deploy/README.md):
#   * Idempotent converge: install/upgrade/repair/uninstall can be re-run; an
#     existing monitor.conf, /var/lib state and auth data are NEVER overwritten
#     or reset by any path in this library.
#   * Proxy isolation: this library must not contain any reference to the
#     proxy tree (/root/sbox, sbconfig_server.json) or to firewall tooling
#     (ufw/iptables/firewall-cmd). tests/test-monitor-packaging.sh enforces
#     this statically -- do not add such strings, even in comments.
#   * sing-box is never started/stopped/restarted/reloaded here. Monitor
#     upgrades restart ONLY singbox-monitor.service.
#   * Every privileged binary goes through an overridable wrapper
#     (SBMON_SYSTEMCTL, SBMON_PYTHON3, ...) so the test harness can run the
#     exact production code against a throwaway fixture root without root.
#
# All paths/users can be overridden for a temporary-root fixture; defaults are
# the production locations.

set -Eeuo pipefail

# ---------------------------------------------------------------------------
# Overridable configuration (production defaults)
# ---------------------------------------------------------------------------
SBMON_USER="${SBMON_USER:-singbox-monitor}"
SBMON_GROUP="${SBMON_GROUP:-$SBMON_USER}"

SBMON_APP_LINK="${SBMON_APP_LINK:-/opt/singbox-monitor}"                 # symlink -> current release
SBMON_RELEASES_DIR="${SBMON_RELEASES_DIR:-/opt/singbox-monitor-releases}" # immutable release trees
SBMON_STATE_ROOT="${SBMON_STATE_ROOT:-/var/lib/singbox-monitor}"
SBMON_CONF_DIR="${SBMON_CONF_DIR:-/etc/singbox-monitor}"
SBMON_UNIT_FILE="${SBMON_UNIT_FILE:-/etc/systemd/system/singbox-monitor.service}"
SBMON_BACKUP_ROOT="${SBMON_BACKUP_ROOT:-/var/backups/singbox-monitor}"

SBMON_SERVICE_NAME="${SBMON_SERVICE_NAME:-singbox-monitor}"
SBMON_WEB_BIND_DEFAULT="${SBMON_WEB_BIND_DEFAULT:-127.0.0.1:9191}"
SBMON_API_URL_DEFAULT="${SBMON_API_URL_DEFAULT:-http://127.0.0.1:9091}"   # matches PHASE_D_API_* in install.sh
SBMON_KEEP_RELEASES="${SBMON_KEEP_RELEASES:-3}"
SBMON_HEALTH_TIMEOUT="${SBMON_HEALTH_TIMEOUT:-20}"

# Tooling (overridable for fixtures/mocks)
SBMON_SYSTEMCTL="${SBMON_SYSTEMCTL:-systemctl}"
SBMON_PYTHON3="${SBMON_PYTHON3:-python3}"
SBMON_FIXTURE="${SBMON_FIXTURE:-0}"   # 1 = skip user/group/chown (non-root test runs)

# Repo-side sources, resolved relative to this file:
#   deploy/lib/monitor-deploy-lib.sh -> deploy/ -> monitor-v2/
DEPLOY_LIB_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd -- "$DEPLOY_LIB_DIR/.." && pwd)"
MONITOR_SRC_DIR_DEFAULT="$(cd -- "$DEPLOY_DIR/.." && pwd)"
SBMON_REPO_MONITOR_DIR="${SBMON_REPO_MONITOR_DIR:-$MONITOR_SRC_DIR_DEFAULT}"
SBMON_VERSION_FILE="${SBMON_VERSION_FILE:-$SBMON_REPO_MONITOR_DIR/VERSION}"

SBMON_HISTORY_FILE="${SBMON_HISTORY_FILE:-$SBMON_RELEASES_DIR/releases.history}"

# ---------------------------------------------------------------------------
# Logging (journal-safe: never echo conf values, secrets or snapshot data)
# ---------------------------------------------------------------------------
sbmon_info() { printf '[sbmon] %s\n' "$*"; }
sbmon_warn() { printf '[sbmon] WARNING: %s\n' "$*" >&2; }
sbmon_die() { printf '[sbmon] ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------
sbmon_repo_version() {
    [ -r "$SBMON_VERSION_FILE" ] || sbmon_die "VERSION 文件不存在: $SBMON_VERSION_FILE"
    local v
    v="$(tr -d ' \t\r\n' < "$SBMON_VERSION_FILE")"
    [ -n "$v" ] || sbmon_die "VERSION 文件为空: $SBMON_VERSION_FILE"
    printf '%s\n' "$v"
}

sbmon_version_ge() { # sbmon_version_ge <a> <b> -> rc 0 iff a >= b (semver-ish, ignores pre-release suffixes)
    local a="${1%%-*}" b="${2%%-*}"
    local -a A B
    IFS=. read -r -a A <<< "$a"
    IFS=. read -r -a B <<< "$b"
    local i
    for i in 0 1 2; do
        local x="${A[i]:-0}" y="${B[i]:-0}"
        x="${x//[!0-9]/}"; y="${y//[!0-9]/}"
        x="${x:-0}"; y="${y:-0}"
        if (( 10#$x > 10#$y )); then return 0; fi
        if (( 10#$x < 10#$y )); then return 1; fi
    done
    return 0
}

# Current release id (basename of the symlink target), empty when not installed.
sbmon_current_release_id() {
    [ -L "$SBMON_APP_LINK" ] || return 0
    local target
    target="$(readlink "$SBMON_APP_LINK")"
    basename -- "$target"
}

sbmon_current_version() {
    local id
    id="$(sbmon_current_release_id)"
    [ -n "$id" ] || return 0
    local vfile="$SBMON_RELEASES_DIR/$id/VERSION"
    [ -r "$vfile" ] || return 0
    tr -d ' \t\r\n' < "$vfile"
}

# ---------------------------------------------------------------------------
# Privilege / user model
# ---------------------------------------------------------------------------
sbmon_ensure_group() {
    if [ "$SBMON_FIXTURE" = "1" ]; then
        sbmon_info "fixture: 确认组存在（跳过真实 groupadd）: $SBMON_GROUP"
        return 0
    fi
    if getent group "$SBMON_GROUP" >/dev/null 2>&1; then
        return 0
    fi
    sbmon_info "创建系统组: $SBMON_GROUP"
    groupadd --system "$SBMON_GROUP"
}

sbmon_ensure_user() {
    if [ "$SBMON_FIXTURE" = "1" ]; then
        sbmon_info "fixture: 确认系统用户存在（跳过真实 useradd）: $SBMON_USER"
        return 0
    fi
    if getent passwd "$SBMON_USER" >/dev/null 2>&1; then
        return 0
    fi
    sbmon_info "创建无登录 shell 的系统用户: $SBMON_USER"
    useradd --system --gid "$SBMON_GROUP" \
        --home-dir "$SBMON_STATE_ROOT" --no-create-home \
        --shell /usr/sbin/nologin "$SBMON_USER"
}

sbmon_chown() { # sbmon_chown <path> [mode]
    local path="$1" mode="${2:-}"
    if [ "$SBMON_FIXTURE" != "1" ]; then
        chown -R "$SBMON_USER:$SBMON_GROUP" "$path"
    fi
    if [ -n "$mode" ]; then
        chmod "$mode" "$path"
    fi
}

# ---------------------------------------------------------------------------
# Directory layout (created fresh; NEVER emptied by upgrade/repair)
# ---------------------------------------------------------------------------
sbmon_create_layout() {
    sbmon_info "创建目录布局（不清理既有内容）"
    # App side: root-owned, service user only reads.
    mkdir -p "$SBMON_RELEASES_DIR"
    chmod 0755 "$SBMON_RELEASES_DIR"
    # State side: service-user-owned, no group/other access.
    mkdir -p "$SBMON_STATE_ROOT/state" "$SBMON_STATE_ROOT/auth" "$SBMON_STATE_ROOT/access"
    sbmon_chown "$SBMON_STATE_ROOT" 0750
    chmod 0700 "$SBMON_STATE_ROOT/state" "$SBMON_STATE_ROOT/auth" "$SBMON_STATE_ROOT/access"
    # Config side: root-owned, group-readable (service user reads, never writes).
    mkdir -p "$SBMON_CONF_DIR"
    chmod 0755 "$SBMON_CONF_DIR"
    # Backup root for rollback history / manual archives.
    mkdir -p "$SBMON_BACKUP_ROOT"
    chmod 0700 "$SBMON_BACKUP_ROOT"
}

# ---------------------------------------------------------------------------
# monitor.conf -- written ONCE (fresh install); never overwritten.
# ---------------------------------------------------------------------------
sbmon_conf_file() { printf '%s/monitor.conf\n' "$SBMON_CONF_DIR"; }

sbmon_write_default_conf() {
    local conf
    conf="$(sbmon_conf_file)"
    if [ -e "$conf" ]; then
        sbmon_info "monitor.conf 已存在，保留不动: $conf"
        return 0
    fi
    sbmon_info "写入默认 monitor.conf（仅首次）"
    cat > "$conf" <<EOF
# sing-box Monitor v2 configuration (KEY=VALUE, parsed strictly; no shell eval)
# Written once by install-monitor.sh; upgrades and repairs NEVER overwrite it.

# Web dashboard bind address. Loopback by default: remote access must be an
# explicit, separate admin step (firewall rules are NEVER touched by the
# installer). E2 owns the web process; this value is consumed by it.
SBMON_WEB_BIND=$SBMON_WEB_BIND_DEFAULT

# sing-box service.api endpoint (Phase D pins 127.0.0.1:9091; do not expose).
SBMON_API_URL=$SBMON_API_URL_DEFAULT

# Optional Authorization bearer secret for service.api (S0 owns provisioning).
# Installer never creates this file; if present it is permission-checked.
# SBMON_API_SECRET_FILE=$SBMON_CONF_DIR/api.secret

# Runtime mode: collector-loop (E1-only snapshot engine; honest skeleton).
# E2 integration switches this to "web" once app/serve entry exists.
SBMON_MODE=collector-loop

# Collector stream window per snapshot cycle (seconds).
SBMON_CYCLE_SECONDS=300
EOF
    chmod 0640 "$conf"
    if [ "$SBMON_FIXTURE" != "1" ]; then
        chgrp "$SBMON_GROUP" "$conf"
    fi
}

# Strict KEY=VALUE parsing for the deployed shims lives in
# app-bin/monitor-env.sh (shipped into each release tree). The deploy-side
# tooling never needs to interpret conf values, only write/permission-check
# the file -- this keeps conf contents out of deploy-tool memory entirely.

# Fix ownership/mode of an existing conf without touching its contents.
sbmon_repair_conf_perms() {
    local conf
    conf="$(sbmon_conf_file)"
    [ -e "$conf" ] || return 0
    local mode
    mode="$(stat -c '%a' "$conf")"
    if [ "$mode" != "640" ]; then
        sbmon_warn "monitor.conf 权限为 $mode，修复为 0640（内容未改动）"
        chmod 0640 "$conf"
    fi
    if [ "$SBMON_FIXTURE" != "1" ]; then
        chgrp "$SBMON_GROUP" "$conf"
    fi
}

# ---------------------------------------------------------------------------
# Release staging / atomic switch
# ---------------------------------------------------------------------------
sbmon_stage_release() { # sbmon_stage_release <version> -> prints release id on stdout (logs -> stderr)
    local version="$1"
    local id="${version}-$(date +%Y%m%d%H%M%S)"
    while [ -e "$SBMON_RELEASES_DIR/$id" ]; do
        id="${id}-x$RANDOM"
    done
    local staged="$SBMON_RELEASES_DIR/.staging-$id"

    sbmon_info "staging release: $id" >&2
    rm -rf -- "$staged"
    mkdir -p "$staged/app" "$staged/bin" "$staged/lib"

    # Code: E1 collector + api_bridge (the only components that exist today).
    [ -f "$SBMON_REPO_MONITOR_DIR/collector.py" ] || sbmon_die "缺少 collector.py: $SBMON_REPO_MONITOR_DIR"
    [ -d "$SBMON_REPO_MONITOR_DIR/api_bridge" ] || sbmon_die "缺少 api_bridge/: $SBMON_REPO_MONITOR_DIR"
    mkdir -p "$staged/app/collector"
    cp -- "$SBMON_REPO_MONITOR_DIR/collector.py" "$staged/app/collector/"
    cp -R -- "$SBMON_REPO_MONITOR_DIR/api_bridge" "$staged/app/collector/api_bridge"
    rm -rf -- "$staged/app/collector/api_bridge/__pycache__"

    # Shims + shared env lib from deploy templates.
    cp -- "$DEPLOY_DIR/app-bin/monitor-service" "$staged/bin/monitor-service"
    cp -- "$DEPLOY_DIR/app-bin/monitor-health" "$staged/bin/monitor-health"
    cp -- "$DEPLOY_DIR/app-bin/monitor-env.sh" "$staged/lib/monitor-env.sh"

    printf '%s\n' "$version" > "$staged/VERSION"

    # Validate BEFORE it can become live: python syntax + shell syntax.
    "$SBMON_PYTHON3" -m py_compile \
        "$staged/app/collector/collector.py" \
        "$staged/app/collector/api_bridge/"*.py >/dev/null 2>&1 \
        || { rm -rf -- "$staged"; sbmon_die "staged python 代码校验失败，放弃发布"; }
    bash -n "$staged/bin/monitor-service" "$staged/bin/monitor-health" "$staged/lib/monitor-env.sh" \
        || { rm -rf -- "$staged"; sbmon_die "staged shell 脚本校验失败，放弃发布"; }

    find "$staged" -type d -exec chmod 0755 {} +
    find "$staged" -type f -exec chmod 0644 {} +
    chmod 0755 "$staged/bin/monitor-service" "$staged/bin/monitor-health"

    mv -- "$staged" "$SBMON_RELEASES_DIR/$id"
    printf '%s\n' "$id"
}

sbmon_activate_release() { # sbmon_activate_release <id> -- atomic symlink flip
    local id="$1"
    [ -d "$SBMON_RELEASES_DIR/$id" ] || sbmon_die "release 不存在: $id"
    local tmp_link="$SBMON_RELEASES_DIR/.switch-tmp"
    rm -f -- "$tmp_link"
    ln -s "$SBMON_RELEASES_DIR/$id" "$tmp_link"
    # mv -T performs rename(2): readers see either the old or the new link.
    mv -T -- "$tmp_link" "$SBMON_APP_LINK"
    sbmon_info "已激活 release: $id"
}

sbmon_record_history() { # sbmon_record_history <id> <version> <action>
    printf '%s %s %s %s\n' "$(date +%Y%m%d%H%M%S)" "$1" "$2" "$3" >> "$SBMON_HISTORY_FILE"
    chmod 0644 "$SBMON_HISTORY_FILE" 2>/dev/null || true
}

sbmon_prune_releases() {
    # Keep the newest SBMON_KEEP_RELEASES releases; never remove the live one.
    local live
    live="$(sbmon_current_release_id)"
    local -a ids=()
    local d
    for d in "$SBMON_RELEASES_DIR"/*; do
        [ -d "$d" ] || continue
        [ "$(basename -- "$d")" = "$live" ] && continue
        ids+=("$(basename -- "$d")")
    done
    local total="${#ids[@]}"
    local keep="$SBMON_KEEP_RELEASES"
    (( total > keep )) || return 0
    # ids are glob-ordered (timestamp suffix => chronological)
    local i
    for (( i = 0; i < total - keep; i++ )); do
        sbmon_info "清理旧 release: ${ids[$i]}"
        rm -rf -- "$SBMON_RELEASES_DIR/${ids[$i]}"
    done
}

# ---------------------------------------------------------------------------
# systemd unit
# ---------------------------------------------------------------------------
sbmon_render_unit() {
    sed -e "s|@SBMON_USER@|$SBMON_USER|g" \
        -e "s|@SBMON_GROUP@|$SBMON_GROUP|g" \
        -e "s|@SBMON_APP_DIR@|$SBMON_APP_LINK|g" \
        -e "s|@SBMON_CONF@|$(sbmon_conf_file)|g" \
        -e "s|@SBMON_STATE_ROOT@|$SBMON_STATE_ROOT|g" \
        "$DEPLOY_DIR/singbox-monitor.service.in"
}

SBMON_UNIT_CHANGED=0

sbmon_install_unit() {
    local rendered
    rendered="$(sbmon_render_unit)"
    if [ -e "$SBMON_UNIT_FILE" ]; then
        if [ "$(cat "$SBMON_UNIT_FILE")" = "$rendered" ]; then
            sbmon_info "systemd unit 无变化"
            return 0
        fi
        cp -a -- "$SBMON_UNIT_FILE" "$SBMON_UNIT_FILE.bak.$(date +%Y%m%d%H%M%S)"
        sbmon_warn "systemd unit 已存在且内容变化，已备份旧 unit 后覆盖"
    fi
    printf '%s\n' "$rendered" > "$SBMON_UNIT_FILE"
    chmod 0644 "$SBMON_UNIT_FILE"
    SBMON_UNIT_CHANGED=1
    sbmon_systemctl daemon-reload
}

sbmon_systemctl() {
    "$SBMON_SYSTEMCTL" "$@"
}

sbmon_service_restart() { sbmon_systemctl restart "$SBMON_SERVICE_NAME"; }
sbmon_service_enable_now() { sbmon_systemctl enable --now "$SBMON_SERVICE_NAME"; }
sbmon_service_stop_disable() {
    sbmon_systemctl disable --now "$SBMON_SERVICE_NAME" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Health (delegates to the deployed probe so prod and tests run the same code)
# ---------------------------------------------------------------------------
sbmon_health_cmd() { printf '%s/bin/monitor-health\n' "$SBMON_APP_LINK"; }

sbmon_health_json() {
    local probe
    probe="$(sbmon_health_cmd)"
    [ -x "$probe" ] || { printf '{"error":"probe missing"}'; return 1; }
    # Always pass the conf explicitly: the probe's default is the production
    # path, which is wrong under a fixture root.
    "$probe" "$(sbmon_conf_file)" 2>/dev/null || true   # degraded(2)/unhealthy(1) still print JSON
}

sbmon_service_active() {
    sbmon_systemctl is-active --quiet "$SBMON_SERVICE_NAME" 2>/dev/null
}

sbmon_wait_service_active() {
    local deadline=$(( SECONDS + SBMON_HEALTH_TIMEOUT ))
    while (( SECONDS < deadline )); do
        if sbmon_service_active; then return 0; fi
        sleep 1
    done
    return 1
}
