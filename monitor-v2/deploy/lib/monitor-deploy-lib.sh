# monitor-deploy-lib.sh -- Monitor v2 deployment primitives (skeleton, E2/E3-aware).
# shellcheck shell=bash
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
# Runtime identity follows the E3 rev4 approved user model: the unprivileged
# web/service user is `sboxweb`. Product/service/paths keep the
# singbox-monitor name; the user name does not have to match either. This
# lets E3 land without re-migrating the service identity (spool
# root:sboxweb 0710, sudoers, exact-token reads all key off this user).
SBMON_USER="${SBMON_USER:-sboxweb}"
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

# P4: serialization of ALL mutating deployment commands. Fail-closed: a
# missing flock binary, an unopenable lock file, or a timeout aborts the
# command before any mutation -- never warn-and-continue.
SBMON_LOCK_FILE="${SBMON_LOCK_FILE:-/run/lock/singbox-monitor-deploy.lock}"
SBMON_LOCK_TIMEOUT="${SBMON_LOCK_TIMEOUT:-15}"
SBMON_FLOCK="${SBMON_FLOCK:-flock}"

# P6: S0 anchor. The service.api secret's single source of truth stays the
# sing-box config / the root-side S0 anchor file (root:root 0600). Packaging
# only delivers a least-privilege DERIVED copy to the non-root monitor; this
# is the one sanctioned reference into the proxy tree and nothing else may
# read from it.
SBMON_API_SECRET_SOURCE="${SBMON_API_SECRET_SOURCE:-/root/sbox/monitor-api.secret}"

# Tooling (overridable for fixtures/mocks)
SBMON_SYSTEMCTL="${SBMON_SYSTEMCTL:-systemctl}"
SBMON_PYTHON3="${SBMON_PYTHON3:-python3}"
SBMON_SUDO="${SBMON_SUDO:-sudo}"   # web-setup drops to the service identity
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
# P3: rollback itself failed. The deployment must NOT claim success or
# "rollback complete"; loud non-zero exit for operator attention.
sbmon_critical() { printf '[sbmon] CRITICAL: %s\n' "$*" >&2; exit 2; }

# ---------------------------------------------------------------------------
# P4: deployment serialization lock (mutating commands only)
# ---------------------------------------------------------------------------
sbmon_acquire_deploy_lock() {
    command -v "$SBMON_FLOCK" >/dev/null 2>&1 \
        || sbmon_die "缺少 flock（部署锁 fail-closed，拒绝在无锁状态下变更）"
    mkdir -p -- "$(dirname -- "$SBMON_LOCK_FILE")" 2>/dev/null || true
    exec 9>>"$SBMON_LOCK_FILE" \
        || sbmon_die "部署锁文件无法打开: fail-closed（$SBMON_LOCK_FILE）"
    if ! "$SBMON_FLOCK" -w "$SBMON_LOCK_TIMEOUT" 9; then
        sbmon_die "部署锁获取失败（超时 ${SBMON_LOCK_TIMEOUT}s 或被拒绝）；另一部署操作可能正在进行，已放弃变更"
    fi
    sbmon_info "deployment lock acquired: $SBMON_LOCK_FILE"
}

# ---------------------------------------------------------------------------
# P3: atomic file primitives (same-filesystem temp + rename)
# ---------------------------------------------------------------------------
sbmon_atomic_write() { # sbmon_atomic_write <path> <mode> [group]  (content on stdin)
    # F3: ownership is a functional requirement, decided EXPLICITLY by the
    # caller -- never implicitly by this helper. When <group> is given, the
    # chgrp MUST succeed BEFORE the rename (a replaced-but-unreadable file
    # must never exist). The fixture without SBMON_REAL_CHGRP=1 delegates
    # metadata semantics to the root Linux CI gate.
    local target="$1" mode="$2" group="${3:-}"
    # R3-7: inside a deployment transaction this helper must RETURN nonzero
    # (never exit) so the transaction owner can roll back. Callers that are
    # NOT in a live transaction turn the rc into sbmon_die themselves.
    local dir
    dir="$(dirname -- "$target")" || return 1
    local tmp
    tmp="$(mktemp "$dir/.sbmon-write.XXXXXX")" || return 1
    if ! cat > "$tmp"; then rm -f -- "$tmp"; return 1; fi
    if ! chmod "$mode" "$tmp"; then rm -f -- "$tmp"; return 1; fi
    if [ -n "$group" ] && { [ "$SBMON_FIXTURE" != "1" ] || [ "${SBMON_REAL_CHGRP:-0}" = "1" ]; }; then
        if ! chgrp "$group" "$tmp"; then
            rm -f -- "$tmp"
            sbmon_warn "组设置失败（$group）：目标文件未被替换"
            return 1
        fi
    fi
    sync -f "$tmp" 2>/dev/null || true   # best-effort fsync where the platform supports it
    if ! mv -f -- "$tmp" "$target"; then rm -f -- "$tmp"; return 1; fi
    return 0
}

# R3-4: a runtime file target must be absent or a REGULAR file (never a
# directory / symlink / fifo / ...). -f follows symlinks, so -L is excluded
# explicitly; no symlink target is ever followed or replaced.
sbmon_require_regular_or_absent() { # sbmon_require_regular_or_absent <path> <label>
    local path="$1" label="$2"
    if [ -L "$path" ] || { [ -e "$path" ] && [ ! -f "$path" ]; }; then
        sbmon_die "$label 目标已存在且不是普通文件（symlink/directory/其他）：fail-closed，未做任何变更"
    fi
}

# F3: verify (and repair) the runtime metadata contract of a file the
# sboxweb service user MUST be able to read: regular file, exact mode,
# owner root, group <SBMON_GROUP>. Metadata drift is repaired; repair
# failure aborts. Never warn-and-continue. (Fixture runs without
# SBMON_REAL_CHGRP=1 delegate these checks to the root Linux CI gate.)
sbmon_verify_runtime_meta() { # sbmon_verify_runtime_meta <path> <mode>
    local path="$1" want_mode="$2"
    # compare modes numerically in octal ("640" == "0640")
    sbmon_norm8() { printf '%o
' "$(( 8#$1 ))"; }
    [ -f "$path" ] || sbmon_die "runtime 文件不是普通文件: $path（fail-closed）"
    local mode
    mode="$(stat -c '%a' "$path")"
    if [ "$(sbmon_norm8 "$mode")" != "$(sbmon_norm8 "$want_mode")" ]; then
        chmod "$want_mode" "$path" || sbmon_die "权限修复失败（$path -> $want_mode）：fail-closed"
    fi
    if [ "$SBMON_FIXTURE" = "1" ] && [ "${SBMON_REAL_CHGRP:-0}" != "1" ]; then
        return 0
    fi
    local want_gid cur_gid cur_uid
    want_gid="$(getent group "$SBMON_GROUP" | cut -d: -f3)"
    [ -n "$want_gid" ] || sbmon_die "组 $SBMON_GROUP 不存在：runtime 文件组契约无法满足（fail-closed）"
    cur_uid="$(stat -c '%u' "$path")"
    cur_gid="$(stat -c '%g' "$path")"
    if [ "$cur_uid" != "0" ]; then
        chown root "$path" || sbmon_die "owner 修复失败（$path -> root）：fail-closed"
    fi
    if [ "$cur_gid" != "$want_gid" ]; then
        chgrp "$SBMON_GROUP" "$path" || sbmon_die "组修复失败（$path -> $SBMON_GROUP）：fail-closed"
    fi
    # post-repair verification: contract must actually hold
    [ "$(stat -c '%u' "$path")" = "0" ] || sbmon_die "owner 仍非 root（$path）：fail-closed"
    [ "$(stat -c '%g' "$path")" = "$want_gid" ] || sbmon_die "组仍非 $SBMON_GROUP（$path）：fail-closed"
    [ "$(sbmon_norm8 "$(stat -c '%a' "$path")")" = "$(sbmon_norm8 "$want_mode")" ]         || sbmon_die "权限仍非 $want_mode（$path）：fail-closed"
}

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
# R1.1-A: SERVICE-OWNED STATE TREE -- root privilege boundary.
#
# /var/lib/singbox-monitor is the E2 DATA ROOT. Its parent (/var/lib) is
# root-controlled, so root may safely create it and converge its metadata.
# EVERYTHING BELOW it (state/, auth.json, access.json, ...) lives inside a
# directory the sboxweb service user OWNS: it can replace child entries at
# will, so a root pathname chown/chmod of a child would be a symlink-follow /
# TOCTOU privilege-escalation primitive (`check -> chown/chmod` is still
# racy, so `[ ! -L path ]` alone is NOT a fix). Therefore:
#   * root only creates/confirms the TOP-LEVEL data root (a REAL directory,
#     never a symlink / non-directory) and converges its owner/mode;
#   * state/ is created and mode-converged AS THE SERVICE USER, never by root.
# A symlink race after our checks cannot escalate: the mutation itself runs
# with sboxweb privileges, so it can only ever affect sboxweb-owned data.
#   * No recursive chown/chmod of the data root is EVER performed.
# auth.json / access.json / legacy auth//access/ directories are never
# rewritten or metadata-mutated here (migration-safe).
# ---------------------------------------------------------------------------
sbmon_ensure_state_tree_as_service_user() {
    local root="$SBMON_STATE_ROOT"
    local state="$SBMON_STATE_ROOT/state"

    # --- top-level data root: root-owned boundary; real directory only ---
    if [ -L "$root" ]; then
        sbmon_die "数据根 $root 是符号链接：fail-closed，未做任何变更"
    fi
    if [ -e "$root" ] && [ ! -d "$root" ]; then
        sbmon_die "数据根 $root 已存在但不是目录：fail-closed，未做任何变更"
    fi
    mkdir -p -- "$root" || sbmon_die "无法创建数据根 $root：fail-closed"
    if [ -L "$root" ] || [ ! -d "$root" ]; then
        sbmon_die "数据根 $root 不是真实目录：fail-closed，未做任何变更"
    fi
    if [ "$SBMON_FIXTURE" != "1" ]; then
        chown "$SBMON_USER:$SBMON_GROUP" "$root" \
            || sbmon_die "数据根属主设置失败（$root -> $SBMON_USER:$SBMON_GROUP）：fail-closed"
    fi
    chmod 0700 "$root" || sbmon_die "数据根权限设置失败（$root -> 0700）：fail-closed"

    # --- state/: created + mode-converged AS THE SERVICE USER ---
    # Explicit refusal of a symlink / non-directory BEFORE any mutation.
    if [ -L "$state" ]; then
        sbmon_die "state/ 是符号链接（$state）：fail-closed，未做任何变更"
    fi
    if [ -e "$state" ] && [ ! -d "$state" ]; then
        sbmon_die "state/ 已存在但不是目录（$state）：fail-closed，未做任何变更"
    fi

    if [ "$SBMON_FIXTURE" = "1" ]; then
        mkdir -p -- "$state" || sbmon_die "无法创建 state/（$state）：fail-closed"
        chmod 0700 -- "$state" || sbmon_die "state/ 权限设置失败（$state）：fail-closed"
    else
        command -v "$SBMON_SUDO" >/dev/null 2>&1 \
            || sbmon_die "缺少 sudo，无法以 $SBMON_USER 收敛 state/：fail-closed"
        # Non-mutating precheck: an existing state/ the service user does NOT
        # own (e.g. hand-created as root after a purge) can never be converged
        # AS the service user. Fail closed with a manual-fix hint -- root never
        # chowns a service-owned child (that check->chown race is exactly what
        # this boundary exists to prevent).
        if [ -d "$state" ]; then
            local want_uid state_uid
            want_uid="$(id -u "$SBMON_USER" 2>/dev/null)" || want_uid=""
            state_uid="$(stat -c '%u' "$state" 2>/dev/null)" || state_uid=""
            if [ -z "$want_uid" ] || [ -z "$state_uid" ] || [ "$state_uid" != "$want_uid" ]; then
                sbmon_die "state/ 已存在但不属于服务用户 $SBMON_USER（uid=${state_uid:-?}，期望 ${want_uid:-?}）：请人工执行 chown $SBMON_USER:$SBMON_GROUP '$state' 或删除该目录后重试；安装器绝不以 root 修改 service-owned 子项：fail-closed"
            fi
        fi
        # env -i: an explicit, minimal environment -- never the caller's.
        "$SBMON_SUDO" -n -u "$SBMON_USER" -- env -i \
            HOME="$SBMON_STATE_ROOT" \
            PATH=/usr/sbin:/usr/bin:/sbin:/bin \
            sh -c '
                set -e
                state="$1"
                [ ! -L "$state" ] || exit 3
                { [ ! -e "$state" ] || [ -d "$state" ]; } || exit 4
                mkdir -p -- "$state"
                chmod 0700 -- "$state"
            ' sh "$state" \
            || sbmon_die "以 $SBMON_USER 身份收敛 state/ 失败（$state）：fail-closed"
    fi
    # Post-check (non-mutating): the converged path must be a real directory.
    if [ -L "$state" ] || [ ! -d "$state" ]; then
        sbmon_die "state/ 不是真实目录（$state）：fail-closed"
    fi
}

# R1.1-B: NON-DESTRUCTIVE postcondition for files the E2 setup/storage owns.
# The installer must never root-chown/chmod a pathname inside the service-user
# data root; it only VERIFIES the contract and, on drift, fails closed with a
# manual-fix hint. Ownership checks are skipped under the fixture identity
# shim (SBMON_FIXTURE=1); mode/regular-file checks still run.
sbmon_verify_service_owned_child_file() { # <path> <mode> <label> -> rc 0 ok
    local path="$1" want_mode="$2" label="$3"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        return 0   # absent is tolerated; E2 decides whether to create it
    fi
    if [ -L "$path" ] || [ ! -f "$path" ]; then
        sbmon_warn "$label 不是普通文件（symlink/目录/其他）：请人工检查 $path（未做任何变更）"
        return 1
    fi
    local mode
    mode="$(stat -c '%a' "$path" 2>/dev/null)" || return 1
    if [ "$(( 8#${mode:-0} ))" != "$(( 8#$want_mode ))" ]; then
        sbmon_warn "$label 权限为 ${mode:-?}（期望 $want_mode）：请人工修复（未做任何变更）"
        return 1
    fi
    if [ "$SBMON_FIXTURE" = "1" ]; then
        return 0
    fi
    local wuid wgid cuid cgid
    wuid="$(id -u "$SBMON_USER" 2>/dev/null)" || { sbmon_warn "$label: 无法解析服务用户 $SBMON_USER"; return 1; }
    wgid="$(getent group "$SBMON_GROUP" | cut -d: -f3)"
    [ -n "$wgid" ] || { sbmon_warn "$label: 组 $SBMON_GROUP 不存在"; return 1; }
    cuid="$(stat -c '%u' "$path")"
    cgid="$(stat -c '%g' "$path")"
    if [ "$cuid" != "$wuid" ] || [ "$cgid" != "$wgid" ]; then
        sbmon_warn "$label 属主非 $SBMON_USER:$SBMON_GROUP（uid=$cuid gid=$cgid）：请人工修复（未做任何变更）"
        return 1
    fi
    return 0
}

sbmon_verify_service_owned_tree() { # non-mutating postcondition; rc 0 ok
    local root="$SBMON_STATE_ROOT"
    if [ -L "$root" ] || [ ! -d "$root" ]; then
        sbmon_warn "数据根 $root 不是真实目录：请人工检查（未做任何变更）"
        return 1
    fi
    local mode
    mode="$(stat -c '%a' "$root" 2>/dev/null || echo '')"
    if [ "$(( 8#${mode:-0} ))" != "$(( 8#700 ))" ]; then
        sbmon_warn "数据根 $root 权限为 ${mode:-?}（期望 700）：请人工修复（未做任何变更）"
        return 1
    fi
    if [ "$SBMON_FIXTURE" != "1" ]; then
        local wuid wgid cuid cgid
        wuid="$(id -u "$SBMON_USER" 2>/dev/null)" || { sbmon_warn "无法解析服务用户 $SBMON_USER：fail-closed"; return 1; }
        wgid="$(getent group "$SBMON_GROUP" | cut -d: -f3)"
        [ -n "$wgid" ] || { sbmon_warn "组 $SBMON_GROUP 不存在：fail-closed"; return 1; }
        cuid="$(stat -c '%u' "$root")"
        cgid="$(stat -c '%g' "$root")"
        if [ "$cuid" != "$wuid" ] || [ "$cgid" != "$wgid" ]; then
            sbmon_warn "数据根 $root 属主非 $SBMON_USER:$SBMON_GROUP：请人工修复（未做任何变更）"
            return 1
        fi
    fi
    sbmon_verify_service_owned_child_file "$root/auth.json" 0600 "auth.json" || return 1
    sbmon_verify_service_owned_child_file "$root/access.json" 0600 "access.json" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# Directory layout (created fresh; NEVER emptied by upgrade/repair)
# ---------------------------------------------------------------------------
sbmon_create_layout() {
    sbmon_info "创建目录布局（不清理既有内容）"
    # State side (R1 / R1.1-A): the data root + state/ tree is created through
    # the service-owned boundary helper -- root converges only the top-level
    # data root, state/ is created AS the service user, and no child pathname
    # inside the service-owned root is ever root-chown'ed/chmod'ed. Fresh
    # installs create ONLY state/ -- the legacy auth/ and access/ DIRECTORIES
    # are no longer created; if an old install has them they are preserved
    # untouched (never deleted, never repurposed).
    sbmon_ensure_state_tree_as_service_user
    # App side: root-owned, service user only reads.
    mkdir -p "$SBMON_RELEASES_DIR"
    chmod 0755 "$SBMON_RELEASES_DIR"
    # Config side: root-owned, group-readable (service user reads, never writes).
    mkdir -p "$SBMON_CONF_DIR"
    chmod 0755 "$SBMON_CONF_DIR"
    # Backup root for rollback history / manual archives.
    mkdir -p "$SBMON_BACKUP_ROOT"
    chmod 0700 "$SBMON_BACKUP_ROOT"
}

# ---------------------------------------------------------------------------
# monitor.conf -- written ONCE (fresh install, atomically); never overwritten.
# ---------------------------------------------------------------------------
sbmon_conf_file() { printf '%s/monitor.conf\n' "$SBMON_CONF_DIR"; }

sbmon_conf_get() { # sbmon_conf_get <KEY> -> value or empty (never logged)
    local key="$1" line
    line="$(grep -E "^${key}=" "$(sbmon_conf_file)" 2>/dev/null | tail -n 1)" || return 0
    printf '%s\n' "${line#*=}"
}

sbmon_write_default_conf() {
    local conf
    conf="$(sbmon_conf_file)"
    if [ -e "$conf" ] || [ -L "$conf" ]; then
        # R3-4: existing non-regular / symlink conf is fail-closed, never
        # chmod/chgrp'd through a symlink or replaced.
        sbmon_require_regular_or_absent "$conf" "monitor.conf"
        sbmon_info "monitor.conf 已存在，保留不动: $conf"
        return 0
    fi
    sbmon_info "写入默认 monitor.conf（仅首次，原子写入）"
    sbmon_atomic_write "$conf" 0640 "$SBMON_GROUP" <<EOF || sbmon_die "monitor.conf 原子写入失败"
# sing-box Monitor v2 configuration (KEY=VALUE, parsed strictly; no shell eval)
# Written once by install-monitor.sh; upgrades and repairs NEVER overwrite it.

# Web dashboard bind address. Loopback by default: remote access must be an
# explicit, separate admin step (firewall rules are NEVER touched by the
# installer). E2 owns the web process; this value is consumed by it.
SBMON_WEB_BIND=$SBMON_WEB_BIND_DEFAULT

# sing-box service.api endpoint (Phase D pins 127.0.0.1:9091; do not expose).
# Validated against the loopback http contract at service start and health.
SBMON_API_URL=$SBMON_API_URL_DEFAULT

# P6 S0 bridge: DERIVED copy of the service.api secret, delivered by
# install-monitor.sh from the root-side S0 anchor (root:root 0600) to
# root:sboxweb 0640. The anchor stays the only source of truth; this file is
# a least-privilege delivery copy. The monitor service FAILS CLOSED when this
# file is configured but missing/unreadable/wrong-type -- it never silently
# downgrades to an unauthenticated connection. Pre-S0 escape hatch: comment
# this line out AND remove the derived file to run without API auth.
SBMON_API_SECRET_FILE=$SBMON_CONF_DIR/api.secret

# Runtime mode (R1): the INTEGRATED default is "web" -- one E1 Collector,
# one SnapshotBroker, one loopback dashboard, one health export. The
# collector-loop skeleton stays available as an explicit compatibility mode.
SBMON_MODE=web

# Web dashboard snapshot cadence (seconds). Drives the SnapshotBroker poll
# and the health-record freshness window.
SBMON_WEB_POLL_SECONDS=1

# Collector-loop compatibility: stream window per snapshot cycle (seconds).
SBMON_CYCLE_SECONDS=300
EOF
}

# Strict KEY=VALUE parsing for the deployed shims lives in
# app-bin/monitor-env.sh (shipped into each release tree). The deploy-side
# tooling never needs to interpret conf values, only write/permission-check
# the file -- this keeps conf contents out of deploy-tool memory entirely.

# Fix ownership/mode of an existing conf without touching its contents.
sbmon_repair_conf_perms() {
    local conf
    conf="$(sbmon_conf_file)"
    [ -e "$conf" ] || [ -L "$conf" ] || return 0
    # R3-4: never repair through a symlink/non-regular target.
    sbmon_require_regular_or_absent "$conf" "monitor.conf"
    # F3: monitor.conf is runtime-read by the service user -> ownership and
    # mode are functional requirements; repair is fail-closed.
    sbmon_verify_runtime_meta "$conf" 0640
}

# ---------------------------------------------------------------------------
# P6: S0 service.api secret -> non-root monitor bridge.
#
# Design (README §"S0 secret bridge"):
#   * single source of truth: sing-box service.api secret / S0 root-side
#     anchor (root:root 0600). NEVER chmod/chgrp the anchor; NEVER weaken
#     ProtectHome to read it directly at runtime.
#   * packaging delivers a DERIVED copy at the conf-declared path with
#     root:<SBMON_GROUP> 0640 via temp+atomic rename.
#   * source missing while the conf expects a secret file -> fail closed
#     (the monitor must never silently degrade to unauthenticated).
#   * content-identical -> no rewrite, no mtime churn.
#   * write failure -> installer aborts. Contents are never printed.
# ---------------------------------------------------------------------------
sbmon_sync_api_secret() {
    local dest
    dest="$(sbmon_conf_get SBMON_API_SECRET_FILE)"
    if [ -z "$dest" ]; then
        sbmon_info "monitor.conf 未配置 SBMON_API_SECRET_FILE：跳过 secret bridge（无 API auth 模式）"
        return 0
    fi
    local source="$SBMON_API_SECRET_SOURCE"
    if [ ! -e "$source" ]; then
        sbmon_die "S0 anchor 缺失（$source 不存在）而 conf 要求 secret（$dest）：fail-closed，未做任何变更"
    fi
    if [ ! -f "$source" ] || [ ! -r "$source" ]; then
        sbmon_die "S0 anchor 不是可读的普通文件（$source）：fail-closed，未做任何变更"
    fi
    # R3-4: dest must be absent or a regular file; never follow/replace a
    # symlink and never mv INTO a directory target.
    sbmon_require_regular_or_absent "$dest" "api.secret"
    if [ -f "$dest" ] && cmp -s -- "$source" "$dest"; then
        # F3: content-identical still requires the FULL metadata contract:
        # regular file + 0640 + owner root + group sboxweb. Drift is
        # repaired; repair failure aborts the install (the monitor would
        # otherwise be unreadable at runtime while health shows green).
        sbmon_verify_runtime_meta "$dest" 0640
        sbmon_info "api.secret 内容一致，不重写（无 mtime churn）"
    else
        local ddir
        ddir="$(dirname -- "$dest")"
        [ -d "$ddir" ] || sbmon_die "secret 目标目录不存在: $ddir"
        sbmon_atomic_write "$dest" 0640 "$SBMON_GROUP" < "$source" \
            || sbmon_die "api.secret 原子写入失败：安装中止"
        sbmon_info "api.secret 已同步（derived copy, root:$SBMON_GROUP 0640）"
    fi
}

# ---------------------------------------------------------------------------
# Release staging / atomic switch
# ---------------------------------------------------------------------------
sbmon_stage_release() { # sbmon_stage_release <version> -> prints release id on stdout (logs -> stderr)
    local version="$1"
    local id
    id="${version}-$(date +%Y%m%d%H%M%S)"
    while [ -e "$SBMON_RELEASES_DIR/$id" ]; do
        id="${id}-x$RANDOM"
    done
    local staged="$SBMON_RELEASES_DIR/.staging-$id"

    sbmon_info "staging release: $id" >&2
    rm -rf -- "$staged"
    mkdir -p "$staged/app/monitor-v2" "$staged/bin" "$staged/lib"

    # R1: ONE coherent server runtime tree -- app/monitor-v2/ holds the E1
    # collector (with api_bridge) AND the E2 web runtime (webapp.py + web/).
    # There is exactly ONE collector.py in the release; no second, separate
    # collector runtime tree exists. monitor-v2/mihomo (E4) is deliberately
    # NOT staged: it stays a repo-only/optional client component.
    [ -f "$SBMON_REPO_MONITOR_DIR/collector.py" ] || sbmon_die "缺少 collector.py: $SBMON_REPO_MONITOR_DIR"
    [ -d "$SBMON_REPO_MONITOR_DIR/api_bridge" ] || sbmon_die "缺少 api_bridge/: $SBMON_REPO_MONITOR_DIR"
    [ -f "$SBMON_REPO_MONITOR_DIR/webapp.py" ] || sbmon_die "缺少 webapp.py: $SBMON_REPO_MONITOR_DIR"
    [ -d "$SBMON_REPO_MONITOR_DIR/web" ] || sbmon_die "缺少 web/: $SBMON_REPO_MONITOR_DIR"
    cp -- "$SBMON_REPO_MONITOR_DIR/collector.py" "$staged/app/monitor-v2/"
    cp -- "$SBMON_REPO_MONITOR_DIR/webapp.py" "$staged/app/monitor-v2/"
    cp -R -- "$SBMON_REPO_MONITOR_DIR/api_bridge" "$staged/app/monitor-v2/api_bridge"
    rm -rf -- "$staged/app/monitor-v2/api_bridge/__pycache__"
    cp -R -- "$SBMON_REPO_MONITOR_DIR/web" "$staged/app/monitor-v2/web"
    rm -rf -- "$staged/app/monitor-v2/web/__pycache__"

    # Shims + shared env lib from deploy templates.
    cp -- "$DEPLOY_DIR/app-bin/monitor-service" "$staged/bin/monitor-service"
    cp -- "$DEPLOY_DIR/app-bin/monitor-health" "$staged/bin/monitor-health"
    cp -- "$DEPLOY_DIR/app-bin/monitor-env.sh" "$staged/lib/monitor-env.sh"

    printf '%s\n' "$version" > "$staged/VERSION"

    # Validate BEFORE it can become live: python syntax for the WHOLE staged
    # runtime (collector, api_bridge, webapp, web/*.py) + shell syntax for
    # the shims. JS syntax is a CI/development gate -- Node.js is never a
    # production installer dependency.
    "$SBMON_PYTHON3" -m py_compile \
        "$staged/app/monitor-v2/collector.py" \
        "$staged/app/monitor-v2/webapp.py" \
        "$staged/app/monitor-v2/api_bridge/"*.py \
        "$staged/app/monitor-v2/web/"*.py >/dev/null 2>&1 \
        || { rm -rf -- "$staged"; sbmon_die "staged python 代码校验失败，放弃发布"; }
    bash -n "$staged/bin/monitor-service" "$staged/bin/monitor-health" "$staged/lib/monitor-env.sh" \
        || { rm -rf -- "$staged"; sbmon_die "staged shell 脚本校验失败，放弃发布"; }

    find "$staged" -type d -exec chmod 0755 {} +
    find "$staged" -type f -exec chmod 0644 {} +
    chmod 0755 "$staged/bin/monitor-service" "$staged/bin/monitor-health"

    mv -- "$staged" "$SBMON_RELEASES_DIR/$id"
    printf '%s\n' "$id"
}

sbmon_activate_release() { # sbmon_activate_release <id> -- atomic symlink flip; rc 0/1 (R3-7)
    local id="$1"
    [ -d "$SBMON_RELEASES_DIR/$id" ] || { sbmon_warn "release 不存在: $id"; return 1; }
    local tmp_link="$SBMON_RELEASES_DIR/.switch-tmp"
    rm -f -- "$tmp_link" || return 1
    ln -s "$SBMON_RELEASES_DIR/$id" "$tmp_link" || return 1
    # mv -T performs rename(2): readers see either the old or the new link.
    if ! mv -T -- "$tmp_link" "$SBMON_APP_LINK"; then
        rm -f -- "$tmp_link" 2>/dev/null || true
        return 1
    fi
    sbmon_info "已激活 release: $id"
}

sbmon_record_history() { # sbmon_record_history <id> <version> <action>
    printf '%s %s %s %s\n' "$(date +%Y%m%d%H%M%S)" "$1" "$2" "$3" >> "$SBMON_HISTORY_FILE"
    chmod 0644 "$SBMON_HISTORY_FILE" 2>/dev/null || true
}

sbmon_prune_releases() {
    # R4.1: retention = ACTUAL RELEASE-DIRECTORY AGE (creation chronology),
    # fully decoupled from releases.history. History is the audit record and
    # the rollback-target source ONLY -- it must not also rank physical
    # trees: first-seen order misrepresents rolled-back releases (A install,
    # B, C, A rollback, D => A is the OLDEST tree, not a recent one) and
    # failed-candidate trees (never committed) would otherwise sort last.
    # A directory's mtime is the single age fact shared by successful
    # releases and failed candidates. Rollback activation does NOT mutate
    # release-tree age (immutable artifact -- rollback only flips the
    # symlink, it never re-creates the tree).
    #
    # Live protection (R4.1-3): the live release is never pruned regardless
    # of age; the loop keeps searching for the next-oldest eligible victim
    # until the retention count is met or only the live release remains (a
    # naive "skip live in the first N" would retain KEEP+1 trees).
    #
    # history is never rewritten here: pruned releases keep their commit
    # records; default rollback skips history entries whose directory is gone.
    local live
    live="$(sbmon_current_release_id)"
    local -a ordered=()
    local d
    # -type d excludes .switch-tmp (a symlink) and releases.history (a file);
    # .staging-* intermediates are not retention candidates.
    while IFS= read -r d; do
        [ -n "$d" ] || continue
        case "$d" in .staging-*) continue ;; esac
        ordered+=("$d")
    done < <(find "$SBMON_RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %f\n' 2>/dev/null | sort -n | cut -d' ' -f2-)
    local total="${#ordered[@]}"
    local keep="$SBMON_KEEP_RELEASES"
    local i id
    for (( i = 0; i < total && total > keep; i++ )); do
        id="${ordered[$i]}"   # oldest -> newest
        [ "$id" = "$live" ] && continue
        sbmon_info "清理旧 release: $id"
        rm -rf -- "${SBMON_RELEASES_DIR:?}/$id"   # :? guard: never expand empty -> /
        total=$(( total - 1 ))
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

sbmon_install_unit() { # rc 0 ok / 1 failed (R3-7: never exits inside a transaction)
    local rendered
    rendered="$(sbmon_render_unit)" || return 1
    if [ -e "$SBMON_UNIT_FILE" ]; then
        if [ "$(cat "$SBMON_UNIT_FILE" 2>/dev/null)" = "$rendered" ]; then
            sbmon_info "systemd unit 无变化"
            return 0
        fi
        cp -a -- "$SBMON_UNIT_FILE" "$SBMON_UNIT_FILE.bak.$(date +%Y%m%d%H%M%S)" || return 1
        sbmon_warn "systemd unit 已存在且内容变化，已备份旧 unit 后覆盖"
    fi
    # P3: atomic unit install (same-filesystem temp -> rename); readers of
    # the unit never observe a half-written file.
    if ! sbmon_atomic_write "$SBMON_UNIT_FILE" 0644 <<< "$rendered"; then
        sbmon_warn "unit 原子写入失败"
        return 1
    fi   # root:root, no group chgrp
    # shellcheck disable=SC2034  # consumed by the caller (install-monitor.sh)
    SBMON_UNIT_CHANGED=1
    sbmon_systemctl daemon-reload || return 1
}

sbmon_systemctl() {
    "$SBMON_SYSTEMCTL" "$@"
}

sbmon_service_restart() { sbmon_systemctl restart "$SBMON_SERVICE_NAME"; }
sbmon_service_enable_now() { sbmon_systemctl enable --now "$SBMON_SERVICE_NAME"; }
sbmon_service_enable() { sbmon_systemctl enable "$SBMON_SERVICE_NAME"; }
sbmon_service_stop() { sbmon_systemctl stop "$SBMON_SERVICE_NAME"; }
sbmon_service_enabled() { # rc 0 = enabled (explicit fact, never inferred)
    sbmon_systemctl is-enabled "$SBMON_SERVICE_NAME" >/dev/null 2>&1
}
# R4-2: the old stop_disable helper swallowed errors (|| true) and was a
# trap for future callers. Idempotency must come from CHECKING state first,
# never from ignoring failures. Uninstall uses the strict sequence inline.
sbmon_service_stop_strict() {
    sbmon_systemctl stop "$SBMON_SERVICE_NAME"
}
sbmon_service_disable_strict() {
    sbmon_systemctl disable "$SBMON_SERVICE_NAME"
}

# ---------------------------------------------------------------------------
# Health (delegates to the deployed probe so prod and tests run the same code)
# ---------------------------------------------------------------------------
sbmon_health_cmd() { printf '%s/bin/monitor-health\n' "$SBMON_APP_LINK"; }

sbmon_health_json() {
    local probe
    probe="$(sbmon_health_cmd)"
    [ -x "$probe" ] || { printf '{"error":"probe missing"}'; return 1; }
    # P1: the data root is an explicit contract -- the probe must never
    # infer it from the caller's working directory.
    "$probe" "$(sbmon_conf_file)" "$SBMON_STATE_ROOT" 2>/dev/null || true   # degraded(2)/unhealthy(1) still print JSON
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
