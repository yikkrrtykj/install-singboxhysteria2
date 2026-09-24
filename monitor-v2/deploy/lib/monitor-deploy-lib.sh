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
# Compatibility preflight (capability detection -- never /etc/os-release
# version branching; supported baselines: Ubuntu 22.04 / 24.04 / 26.04 LTS).
# Every mutating command fails CLOSED on a missing required dependency,
# BEFORE any filesystem/service mutation, with a single clear diagnostic.
# Required set (deployment/canary tooling actually used by this library and
# its callers): python3 systemctl journalctl jq ss flock stat sha256sum
# mktemp -- the runtime shims use their own MINIMAL sets (monitor-env.sh).
# SBMON_REQUIRED_COMMANDS may override the extra-command set ONLY behind the
# explicit test-only gate SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1
# (SBMON_FIXTURE deliberately does NOT unlock it: non-root production hosts
# must not bypass the preflight either). A production invocation that sets
# the override WITHOUT the gate is refused (fail-closed), so the preflight
# can never be bypassed. The configured wrappers
# (SBMON_PYTHON3 / SBMON_SYSTEMCTL / SBMON_FLOCK) are always checked as
# themselves, since those are the exact binaries the deployment executes.
# ---------------------------------------------------------------------------
sbmon_required_command_list() { # -> prints the list; rc 1 = override refused (message on stderr)
    printf '%s\n' "$SBMON_PYTHON3" "$SBMON_SYSTEMCTL" "$SBMON_FLOCK"
    if [ "${SBMON_REQUIRED_COMMANDS+x}" = x ]; then
        # The gate MUST be judged in the caller's context (a die/exit inside
        # the process substitution would only kill the subshell and silently
        # skip the preflight -- exactly the bypass this check prevents).
        # ONLY the explicit test-only gate unlocks the override; SBMON_FIXTURE
        # deliberately does NOT (non-root production/dev hosts must not be
        # able to bypass the preflight either).
        if [ "${SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE:-0}" != "1" ]; then
            printf '[sbmon] SBMON_REQUIRED_COMMANDS 覆写被拒绝（仅限显式测试门 SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1；生产预检使用必需命令全集）\n' >&2
            return 1
        fi
        # shellcheck disable=SC2086  # intentional word split of the gated override list
        printf '%s\n' ${SBMON_REQUIRED_COMMANDS}
    else
        printf '%s\n' journalctl jq ss stat sha256sum mktemp
    fi
}

sbmon_preflight_commands() {
    local missing="" cmd list_text
    # Capture in the PARENT context: an rc 1 here is a refused production
    # bypass attempt, never an empty list.
    if ! list_text="$(sbmon_required_command_list)"; then
        sbmon_die "命令预检配置被拒绝（生产环境不得以 SBMON_REQUIRED_COMMANDS 绕过必需命令预检）：fail-closed，未做任何更改"
    fi
    while IFS= read -r cmd; do
        [ -n "$cmd" ] || continue
        case "$cmd" in
            */*) [ -x "$cmd" ] || missing="$missing $cmd" ;;
            *)   command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd" ;;
        esac
    done <<< "$list_text"
    if [ -n "$missing" ]; then
        sbmon_die "缺少必需依赖命令:${missing}（preflight fail-closed，未做任何更改；请安装提供这些命令的软件包）"
    fi
}

# Environment diagnostics for deploy/canary records -- NO secrets, no conf
# values, no paths that could carry sensitive material.
sbmon_record_environment() {
    if [ -r /etc/os-release ]; then
        local os_id os_ver
        os_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"' || true)"
        os_ver="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '"' || true)"
        sbmon_info "environment os=${os_id:-unknown} ${os_ver:-unknown}"
    else
        sbmon_info "environment os-release unreadable"
    fi
    "$SBMON_PYTHON3" --version 2>&1 | sed 's/^/[sbmon] environment /' || true
    "$SBMON_SYSTEMCTL" --version 2>/dev/null | head -n1 | sed 's/^/[sbmon] environment /' || true
    if command -v ssh >/dev/null 2>&1; then
        ssh -V 2>&1 | sed 's/^/[sbmon] environment /' || true
    fi
    sbmon_info "environment kernel=$(uname -r)"
    return 0
}

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
    cp -- "$DEPLOY_DIR/app-bin/monitor-contract-probe" "$staged/bin/monitor-contract-probe"
    cp -- "$DEPLOY_DIR/app-bin/monitor-env.sh" "$staged/lib/monitor-env.sh"

    # PR-2B: the sbox-journal-reader runtime is bundled INTO the immutable
    # release tree under the frozen explicit manifest (12 modules + entry
    # wrapper + unit template). $SBOXJR_LIB_DIR is only ever a symlink into
    # a release's libexec dir, so release rollback/restaging keeps the
    # reader code, the wrapper and the unit template version-coherent.
    # NEVER cp -R the source directory. A source tree WITHOUT
    # journal_reader/ (pre-reader baseline) stages no libexec at all (INERT).
    jr_staged=0
    local jr_libexec="$staged/$SBOXJR_RELEASE_LIBEXEC_REL"
    if sbmon_sboxjr_source_present; then
        mkdir -p "$jr_libexec/journal_reader"
        local jf
        for jf in "${SBOXJR_MODULE_FILES[@]}"; do
            [ -f "$SBMON_REPO_MONITOR_DIR/journal_reader/$jf" ] \
                || sbmon_die "缺少 journal_reader 模块 $jf：fail-closed"
            cp -- "$SBMON_REPO_MONITOR_DIR/journal_reader/$jf" "$jr_libexec/journal_reader/$jf"
        done
        [ -f "$DEPLOY_DIR/app-bin/sbox-journal-reader" ] || sbmon_die "缺少 reader 入口 wrapper：fail-closed"
        cp -- "$DEPLOY_DIR/app-bin/sbox-journal-reader" "$jr_libexec/sbox-journal-reader"
        [ -f "$DEPLOY_DIR/$SBOXJR_TEMPLATE_NAME" ] || sbmon_die "缺少 reader unit 模板：fail-closed"
        cp -- "$DEPLOY_DIR/$SBOXJR_TEMPLATE_NAME" "$jr_libexec/$SBOXJR_TEMPLATE_NAME"
        jr_staged=1
    fi

    printf '%s\n' "$version" > "$staged/VERSION"

    # Validate BEFORE it can become live: python syntax for the WHOLE staged
    # runtime (collector, api_bridge, webapp, web/*.py) + shell syntax for
    # the shims. JS syntax is a CI/development gate -- Node.js is never a
    # production installer dependency.
    local -a py_targets=(
        "$staged/app/monitor-v2/collector.py"
        "$staged/app/monitor-v2/webapp.py"
        "$staged/app/monitor-v2/api_bridge/"*.py
        "$staged/app/monitor-v2/web/"*.py)
    local -a sh_targets=("$staged/bin/monitor-service" "$staged/bin/monitor-health"
        "$staged/bin/monitor-contract-probe" "$staged/lib/monitor-env.sh")
    if [ "$jr_staged" = 1 ]; then
        py_targets+=("$jr_libexec/journal_reader/"*.py)
        sh_targets+=("$jr_libexec/sbox-journal-reader")
    fi
    "$SBMON_PYTHON3" -m py_compile \
        "${py_targets[@]}" >/dev/null 2>&1 \
        || { rm -rf -- "$staged"; sbmon_die "staged python 代码校验失败，放弃发布"; }
    bash -n "${sh_targets[@]}" \
        || { rm -rf -- "$staged"; sbmon_die "staged shell 脚本校验失败，放弃发布"; }

    find "$staged" -type d -exec chmod 0755 {} +
    find "$staged" -type f -exec chmod 0644 {} +
    find "$staged" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    chmod 0755 "$staged/bin/monitor-service" "$staged/bin/monitor-health" \
        "$staged/bin/monitor-contract-probe"
    [ "$jr_staged" = 1 ] && chmod 0755 "$jr_libexec/sbox-journal-reader"

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
    # PR-2B: the release the READER runtime link points into is live too --
    # pruning it would leave $SBOXJR_LIB_DIR dangling (the wrapper fails
    # closed with staged_tree_missing at next start, and rollback to that
    # release would be impossible).
    # Review round (provenance): an unreadable/illegal link means the live
    # reader release cannot be identified -- pruning anything then could
    # delete it. Fail closed and demand human handling instead of guessing.
    local jr_live
    jr_live="$(sbmon_sboxjr_runtime_linked_id)" \
        || sbmon_die "拒绝 prune：reader 运行时链接 provenance 非法（见上），无法确定受保护的 release；需人工处理"
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
        [ -n "$jr_live" ] && [ "$id" = "$jr_live" ] && continue
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

# ---------------------------------------------------------------------------
# sbox-journal-reader (issue #33 P2, PR-2A helpers / PR-2B activation) --
# ACTIVATED HELPER SECTION.
#
# PR-2A shipped these helpers with ZERO call sites (DARK). PR-2B (Coding E,
# deploy/activation lane) wires them into the install-monitor.sh
# transaction: every sbmon_sboxjr_* function is still EXPLICITLY NAMED and
# reachable only through the reviewed installer paths (install/upgrade via
# sbmon_sboxjr_converge, rollback via the same converge in keep-prestate
# mode, uninstall via the teardown in install-monitor.sh). tests/
# test-monitor-v2-jr.sh statically asserts that no other surface (health /
# status / web-setup / collector) activates the reader.
#
# R7 frozen identity contract: the ONLY accepted journal-read model is the
# dedicated sbox-jr system user (nologin shell, /nonexistent home) plus OS
# group membership systemd-journal. A partial or divergent identity is a
# preflight STOP before ANY mutation -- there is deliberately NO root
# fallback and NO sboxweb read path anywhere in this section.
# ---------------------------------------------------------------------------
SBOXJR_USER="${SBOXJR_USER:-sbox-jr}"
SBOXJR_GROUP="${SBOXJR_GROUP:-sbox-jr}"
SBOXJR_JOURNAL_GROUP="${SBOXJR_JOURNAL_GROUP:-systemd-journal}"
SBOXJR_DATA_ROOT="${SBOXJR_DATA_ROOT:-/var/lib/sbox-journal}"
SBOXJR_STATE_DIR="${SBOXJR_STATE_DIR:-$SBOXJR_DATA_ROOT/state}"
SBOXJR_OUT_DIR="${SBOXJR_OUT_DIR:-$SBOXJR_DATA_ROOT/out}"
SBOXJR_LIB_DIR="${SBOXJR_LIB_DIR:-/usr/local/lib/singbox-journal-reader}"
SBOXJR_SERVICE_NAME="${SBOXJR_SERVICE_NAME:-singbox-journal-reader}"
SBOXJR_UNIT_FILE="${SBOXJR_UNIT_FILE:-/etc/systemd/system/$SBOXJR_SERVICE_NAME.service}"
SBOXJR_WATCHED_UNIT="${SBOXJR_WATCHED_UNIT:-sing-box.service}"
SBOXJR_RUNUSER="${SBOXJR_RUNUSER:-runuser}"
SBMON_SYSTEMD_ANALYZE="${SBMON_SYSTEMD_ANALYZE:-systemd-analyze}"

# Reader runtime lives INSIDE the immutable release tree
# (<release>/libexec/sbox-journal-reader) and /usr/local/lib/... is a single
# symlink flipped atomically -- so a Monitor release rollback can restore a
# byte-compatible reader runtime/unit-template with it (Coding E PR-2B).
SBOXJR_RELEASE_LIBEXEC_REL="libexec/sbox-journal-reader"
SBOXJR_TEMPLATE_NAME="singbox-journal-reader.service.in"
# Explicit 12+1+1 manifest (PR-2A frozen allowlist + wrapper + unit
# template). NEVER a directory-wildcard copy: new repo files only reach
# production by being named here AND in tests/test-monitor-v2-jr-deploy.sh.
SBOXJR_MODULE_FILES=(__init__.py codes.py cursor.py journal_time.py
    normalize.py classifier.py fingerprint.py eligibility.py schema.py
    state.py reader.py ingest_contract.py)

sboxjr_log() { printf '[sbjr-deploy] %s\n' "$*"; }
sboxjr_warn() { printf '[sbjr-deploy] WARNING: %s\n' "$*" >&2; }
sboxjr_die() { printf '[sbjr-deploy] ERROR: %s\n' "$*" >&2; return 1; }

# EXACT-identity validation of the sbox-jr account (R7, hardened by review
# #46 B3): nologin shell AND home /nonexistent AND primary group == sbox-jr
# AND effective group set EXACTLY {sbox-jr, systemd-journal} -- a missing
# group and an extra group both refuse. Refusals name only the offending
# FIELD (never values), return nonzero, and mutate nothing. Never silently
# "converged" by a root-side repair here.
sbmon_sboxjr_validate_identity() {
    if [ "$SBMON_FIXTURE" = "1" ]; then
        sboxjr_log "fixture: 身份校验跳过（真实语义由 PATH 桩 + 根 Linux 门负责）"
        return 0
    fi
    local pw shell home gid gname got want
    pw="$(getent passwd "$SBOXJR_USER" 2>/dev/null)" || {
        sboxjr_die "field=user_exists: 用户 $SBOXJR_USER 不存在：先执行 ensure，绝不回退 root/sboxweb"
        return 1
    }
    shell="$(printf '%s\n' "$pw" | cut -d: -f7)"
    home="$(printf '%s\n' "$pw" | cut -d: -f6)"
    gid="$(printf '%s\n' "$pw" | cut -d: -f4)"
    case "$shell" in
        /usr/sbin/nologin|/sbin/nologin) ;;
        *)
            sboxjr_die "field=shell: $SBOXJR_USER shell 非 nologin（期望拒绝登录身份）"
            return 1
            ;;
    esac
    if [ "$home" != "/nonexistent" ]; then
        sboxjr_die "field=home: $SBOXJR_USER home 非 /nonexistent"
        return 1
    fi
    gname="$(getent group "$gid" 2>/dev/null | cut -d: -f1)"
    if [ "$gname" != "$SBOXJR_GROUP" ]; then
        sboxjr_die "field=primary_group: $SBOXJR_USER 主组非 $SBOXJR_GROUP"
        return 1
    fi
    got="$(id -nG "$SBOXJR_USER" 2>/dev/null | tr ' ' '\n' \
           | grep -v '^$' | LC_ALL=C sort -u | tr '\n' ' ')"
    want="$(printf '%s\n' "$SBOXJR_GROUP" "$SBOXJR_JOURNAL_GROUP" \
            | LC_ALL=C sort -u | tr '\n' ' ')"
    if [ "$got" != "$want" ]; then
        sboxjr_die "field=group_set: $SBOXJR_USER 有效组集不恰为 {$SBOXJR_GROUP, $SBOXJR_JOURNAL_GROUP}（缺组或多组均拒绝）"
        return 1
    fi
    return 0
}

# Create the identity ONLY when the USER IS COMPLETELY ABSENT (review #46
# B3 order): an existing account is exact-validated with ZERO mutation --
# including zero groupadd -- even before/around any group work; only the
# absent-user branch may create group/user/membership, then re-validates
# the exact final shape.
sbmon_sboxjr_ensure_identity() {
    if [ "$SBMON_FIXTURE" = "1" ]; then
        sboxjr_log "fixture: 确认身份存在（跳过真实 useradd/usermod）: $SBOXJR_USER"
        return 0
    fi
    if getent passwd "$SBOXJR_USER" >/dev/null 2>&1; then
        # EXISTING user: validate immediately; mutate NOTHING on any path.
        if sbmon_sboxjr_validate_identity; then
            sboxjr_log "既有身份 $SBOXJR_USER 精确合规（零变更）"
            return 0
        fi
        return 1
    fi
    if ! getent group "$SBOXJR_GROUP" >/dev/null 2>&1; then
        groupadd --system "$SBOXJR_GROUP" || return 1
    fi
    useradd --system --gid "$SBOXJR_GROUP" --home-dir /nonexistent \
        --no-create-home --shell /usr/sbin/nologin "$SBOXJR_USER" || return 1
    usermod -aG "$SBOXJR_JOURNAL_GROUP" "$SBOXJR_USER" || return 1
    sboxjr_log "已创建系统身份 $SBOXJR_USER（nologin, /nonexistent, 主组 $SBOXJR_GROUP, +$SBOXJR_JOURNAL_GROUP）"
    sbmon_sboxjr_validate_identity
}

# Data tree boundary (mirrors the monitor service-owned-tree rules):
#   <root>          root:sbox-jr 0750 -- root-controlled parent only.
#   <root>/state    0700 sbox-jr      -- reader-private (cursor state and
#                   the fingerprint key): the web identity must NOT read it.
#   <root>/out      2750 sbox-jr:sboxweb -- the exchange group is exactly
#                   the Monitor READ side; setgid keeps reader-created
#                   0640 files group-readable without any chown race.
# Root only creates/converges directories whose PARENT it owns; it never
# recurses and never follows a symlink.
sbmon_sboxjr_ensure_data_tree() {
    local d
    for d in "$SBOXJR_DATA_ROOT" "$SBOXJR_STATE_DIR" "$SBOXJR_OUT_DIR"; do
        if [ -L "$d" ]; then
            sboxjr_die "$d 是符号链接：fail-closed，未做任何变更"
            return 1
        fi
        if [ -e "$d" ] && [ ! -d "$d" ]; then
            sboxjr_die "$d 已存在但不是目录：fail-closed，未做任何变更"
            return 1
        fi
        mkdir -p -- "$d" || return 1
        if [ -L "$d" ] || [ ! -d "$d" ]; then
            sboxjr_die "$d 不是真实目录：fail-closed"
            return 1
        fi
    done
    if [ "$SBMON_FIXTURE" = "1" ]; then
        return 0
    fi
    chown "root:$SBOXJR_GROUP" "$SBOXJR_DATA_ROOT" || return 1
    chmod 0750 "$SBOXJR_DATA_ROOT" || return 1
    chown "$SBOXJR_USER:$SBOXJR_GROUP" "$SBOXJR_STATE_DIR" || return 1
    chmod 0700 "$SBOXJR_STATE_DIR" || return 1
    chown "$SBOXJR_USER:${SBMON_GROUP:-sboxweb}" "$SBOXJR_OUT_DIR" || return 1
    chmod 2750 "$SBOXJR_OUT_DIR" || return 1
    return 0
}

# ---------------------------------------------------------------------------
# Runtime link + unit (same render / verify-before-install / atomic-switch
# discipline as the monitor unit). PR-2B adds the activation-side helpers;
# enable/start run ONLY inside sbmon_sboxjr_converge below, which the
# installer transaction owns.
# ---------------------------------------------------------------------------
sbmon_sboxjr_release_runtime_dir() { # <release-id> -> prints <release>/libexec/sbox-journal-reader
    printf '%s/%s/%s\n' "$SBMON_RELEASES_DIR" "$1" "$SBOXJR_RELEASE_LIBEXEC_REL"
}

# Tri-state link provenance decoder (Coding E review round):
#   (1) $SBOXJR_LIB_DIR is NOT a symlink -> prints nothing, rc 0: the
#       runtime has never been linked (normal pre-activation state).
#   (2) symlink whose target is EXACTLY the canonical release runtime shape
#       "$SBMON_RELEASES_DIR/<release-id>/$SBOXJR_RELEASE_LIBEXEC_REL"
#       (single-component release id, target passes the manifest audit)
#       -> prints the exact release id, rc 0.
#   (3) ANY other symlink (foreign path -- even one whose suffix happens to
#       match, wrong depth, wrong suffix, broken link, manifest violation)
#       -> rc 1 with a loud human-action diagnostic and NOTHING on stdout.
#       Callers must fail closed; the link is never guessed into a release
#       id nor silently treated as absent.
sbmon_sboxjr_runtime_linked_id() { # -> release id | rc1 = illegal provenance
    [ -L "$SBOXJR_LIB_DIR" ] || return 0
    local t rel id
    t="$(readlink -- "$SBOXJR_LIB_DIR")" \
        || { sboxjr_die "无法读取 reader 运行时链接目标: $SBOXJR_LIB_DIR；需人工处理"; return 1; }
    rel="${t#"$SBMON_RELEASES_DIR"/}"
    if [ "$rel" = "$t" ] || [ -z "$rel" ]; then
        sboxjr_die "reader 运行时链接指向 releases 根之外（$t）：provenance 非法，需人工处理（fail-closed）"
        return 1
    fi
    id="${rel%/"$SBOXJR_RELEASE_LIBEXEC_REL"}"
    case "$id" in
        "$rel"|""|*/*)
            sboxjr_die "reader 运行时链接形状非 <release-id>/$SBOXJR_RELEASE_LIBEXEC_REL（$t）：provenance 非法，需人工处理（fail-closed）"
            return 1 ;;
    esac
    sbmon_sboxjr_audit_runtime "$SBMON_RELEASES_DIR/$id/$SBOXJR_RELEASE_LIBEXEC_REL" \
        || { sboxjr_die "reader 运行时链接目标未通过 manifest 审计（$t）：需人工处理（fail-closed）"; return 1; }
    printf '%s\n' "$id"
}

# Strict allowlist audit of a staged reader runtime tree: the 12+1+1
# manifest EXACTLY -- missing OR unexpected files/dirs fail closed. This is
# the gate that keeps "new file in repo" out of production until the
# manifest AND its tests are consciously updated together.
sbmon_sboxjr_audit_runtime() { # <runtime-dir> rc only
    local dir="$1"
    if [ -L "$dir" ]; then
        sboxjr_die "reader runtime 目录本身是符号链接: $dir"
        return 1
    fi
    if [ ! -d "$dir" ]; then
        sboxjr_die "reader runtime 目录不存在: $dir"
        return 1
    fi
    local want_top got want_mod
    want_top="$(printf '%s\n' journal_reader "$SBOXJR_TEMPLATE_NAME" sbox-journal-reader | LC_ALL=C sort)"
    got="$(find "$dir" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | LC_ALL=C sort)"
    if [ "$got" != "$want_top" ]; then
        sboxjr_die "reader runtime 顶层文件集偏离 12+1+1 manifest（多余或缺失均 fail-closed）: $dir"
        return 1
    fi
    want_mod="$(printf '%s\n' "${SBOXJR_MODULE_FILES[@]}" | LC_ALL=C sort)"
    got="$(find "$dir/journal_reader" -mindepth 1 -maxdepth 1 -printf '%f\n' 2>/dev/null | LC_ALL=C sort)"
    if [ "$got" != "$want_mod" ]; then
        sboxjr_die "journal_reader/ 文件集不恰为 12 模块 manifest：fail-closed: $dir"
        return 1
    fi
    if [ ! -f "$dir/sbox-journal-reader" ]; then
        sboxjr_die "reader 入口 wrapper 缺失: $dir"
        return 1
    fi
    return 0
}

# Flip $SBOXJR_LIB_DIR (a symlink) atomically onto a release's staged
# reader runtime. rc only -- never exits (R3-7).
sbmon_sboxjr_link_runtime() { # <release-id>
    local id="$1"
    [ -n "$id" ] || { sboxjr_die "link_runtime: release id 为空"; return 1; }
    local target_dir
    target_dir="$(sbmon_sboxjr_release_runtime_dir "$id")"
    sbmon_sboxjr_audit_runtime "$target_dir" || return 1
    if [ -L "$SBOXJR_LIB_DIR" ]; then
        if [ "$(readlink "$SBOXJR_LIB_DIR")" = "$target_dir" ]; then
            sboxjr_log "reader 运行时代码无变化（release $id）"
            return 0
        fi
    elif [ -e "$SBOXJR_LIB_DIR" ]; then
        sboxjr_die "$SBOXJR_LIB_DIR 已存在且不是符号链接（PR-2A 直拷时代遗留？）：请人工处理后重试；fail-closed"
        return 1
    fi
    local parent tmp
    parent="$(dirname -- "$SBOXJR_LIB_DIR")"
    mkdir -p -- "$parent" || return 1
    tmp="$SBOXJR_LIB_DIR.switch.$$"
    rm -f -- "$tmp" || return 1
    ln -s -- "$target_dir" "$tmp" || { rm -f -- "$tmp"; return 1; }
    if ! mv -T -- "$tmp" "$SBOXJR_LIB_DIR"; then
        rm -f -- "$tmp" 2>/dev/null || true
        sboxjr_die "reader 运行时符号链接原子切换失败"
        return 1
    fi
    sboxjr_log "reader 运行时已链接到 release $id"
    return 0
}

sbmon_sboxjr_unlink_runtime() { # remove ONLY the symlink itself; rc only
    if [ -L "$SBOXJR_LIB_DIR" ]; then
        rm -f -- "$SBOXJR_LIB_DIR" || return 1
        sboxjr_log "reader 运行时链接已移除"
    elif [ -e "$SBOXJR_LIB_DIR" ]; then
        sboxjr_die "$SBOXJR_LIB_DIR 不是符号链接：拒绝删除真实目录（fail-closed）"
        return 1
    fi
    return 0
}

sbmon_sboxjr_render_unit() { # -> rendered unit on stdout
    # Version coherence: render from the runtime tree that is actually
    # linked (its bundled template), falling back to the repo template
    # only when no runtime has been linked yet.
    local tpl
    if [ -f "$SBOXJR_LIB_DIR/$SBOXJR_TEMPLATE_NAME" ]; then
        tpl="$SBOXJR_LIB_DIR/$SBOXJR_TEMPLATE_NAME"
    else
        tpl="$DEPLOY_DIR/$SBOXJR_TEMPLATE_NAME"
    fi
    [ -f "$tpl" ] || { sboxjr_die "reader unit 模板不存在: $tpl" >&2; return 1; }
    sed -e "s|@SBJR_USER@|$SBOXJR_USER|g" \
        -e "s|@SBJR_GROUP@|$SBOXJR_GROUP|g" \
        -e "s|@SBJR_LIBEXEC@|$SBOXJR_LIB_DIR|g" \
        -e "s|@SBJR_DATA_ROOT@|$SBOXJR_DATA_ROOT|g" \
        -e "s|@SBJR_WATCHED_UNIT@|$SBOXJR_WATCHED_UNIT|g" \
        "$tpl"
}

# §7 gate: systemd-analyze verify on the RENDERED unit BEFORE it can be
# installed. Missing verifier is fail-closed outside the fixture (there is
# deliberately no "skip and hope" path on a production host).
sbmon_sboxjr_verify_unit() { # <rendered-unit-file> rc only
    local unit="$1"
    if ! command -v "$SBMON_SYSTEMD_ANALYZE" >/dev/null 2>&1; then
        if [ "$SBMON_FIXTURE" = "1" ]; then
            sboxjr_log "fixture: systemd-analyze 缺席，verify 语义由 PATH 桩 + 根 Linux 门承担"
            return 0
        fi
        sboxjr_die "缺少 $SBMON_SYSTEMD_ANALYZE：unit 无法验证，拒绝 install/enable/start（fail-closed）"
        return 1
    fi
    if ! "$SBMON_SYSTEMD_ANALYZE" verify "$unit" >&2; then
        sboxjr_die "systemd-analyze verify 未通过：拒绝 install/enable/start（fail-closed）"
        return 1
    fi
    sboxjr_log "unit 通过 systemd-analyze verify"
    return 0
}

SBOXJR_UNIT_CHANGED=0

sbmon_sboxjr_install_unit() { # rc 0 ok / 1 failed; NEVER enables or starts
    local rendered vtmp vdir
    rendered="$(sbmon_sboxjr_render_unit)" || return 1
    vdir="$(dirname -- "$SBOXJR_UNIT_FILE")"
    [ -d "$vdir" ] || { sboxjr_die "unit 目录不存在: $vdir"; return 1; }
    # Leading dot keeps the transient file invisible to the unit loader;
    # the .service suffix gives systemd-analyze verify a valid unit name.
    vtmp="$vdir/.jr-verify.$$.service"
    if [ -e "$vtmp" ]; then
        sboxjr_die "verify 临时文件已存在: $vtmp"
        return 1
    fi
    if ! printf '%s\n' "$rendered" > "$vtmp"; then
        rm -f -- "$vtmp"
        sboxjr_die "verify 临时文件写入失败"
        return 1
    fi
    if ! sbmon_sboxjr_verify_unit "$vtmp"; then
        rm -f -- "$vtmp"
        return 1
    fi
    rm -f -- "$vtmp"
    if [ -e "$SBOXJR_UNIT_FILE" ]; then
        if [ "$(cat "$SBOXJR_UNIT_FILE" 2>/dev/null)" = "$rendered" ]; then
            sboxjr_log "unit 无变化"
            return 0
        fi
        cp -a -- "$SBOXJR_UNIT_FILE" "$SBOXJR_UNIT_FILE.bak.$(date +%Y%m%d%H%M%S)" || return 1
        sboxjr_warn "unit 已存在且内容变化，已备份旧 unit 后覆盖"
    fi
    if ! sbmon_atomic_write "$SBOXJR_UNIT_FILE" 0644 <<< "$rendered"; then
        sboxjr_warn "unit 原子写入失败"
        return 1
    fi
    # shellcheck disable=SC2034  # consumed by sbmon_sboxjr_converge
    SBOXJR_UNIT_CHANGED=1
    sbmon_systemctl daemon-reload || return 1
}

# ---------------------------------------------------------------------------
# Reader service-state helpers. Naming mirrors the monitor helpers:
# idempotency comes from CHECKING state first, never from swallowing
# failures (R4-2).
# ---------------------------------------------------------------------------
sbmon_sboxjr_service_active() {
    sbmon_systemctl is-active --quiet "$SBOXJR_SERVICE_NAME" 2>/dev/null
}
sbmon_sboxjr_service_enabled() {
    sbmon_systemctl is-enabled "$SBOXJR_SERVICE_NAME" >/dev/null 2>&1
}
sbmon_sboxjr_service_restart()    { sbmon_systemctl restart "$SBOXJR_SERVICE_NAME"; }
sbmon_sboxjr_service_enable()     { sbmon_systemctl enable "$SBOXJR_SERVICE_NAME"; }
sbmon_sboxjr_service_enable_now() { sbmon_systemctl enable --now "$SBOXJR_SERVICE_NAME"; }
sbmon_sboxjr_service_stop()       { sbmon_systemctl stop "$SBOXJR_SERVICE_NAME"; }
sbmon_sboxjr_service_disable()    { sbmon_systemctl disable "$SBOXJR_SERVICE_NAME"; }
sbmon_wait_sboxjr_active() {
    local deadline=$(( SECONDS + SBMON_HEALTH_TIMEOUT ))
    while (( SECONDS < deadline )); do
        if sbmon_sboxjr_service_active; then return 0; fi
        sleep 1
    done
    return 1
}

# Non-mutating postcondition probe: the reader identity's EFFECTIVE groups
# carry $SBOXJR_JOURNAL_GROUP (that membership, not any root-side reading,
# is what grants journal access). Runs as the reader identity via runuser.
sbmon_sboxjr_readability_probe() {
    if [ "$SBMON_FIXTURE" = "1" ]; then
        sboxjr_log "fixture: 可读性探针跳过（真实语义由根 Linux CI 门保证）"
        return 0
    fi
    if ! command -v "$SBOXJR_RUNUSER" >/dev/null 2>&1; then
        sboxjr_die "缺少 runuser，无法执行身份探针"
        return 1
    fi
    if ! "$SBOXJR_RUNUSER" -u "$SBOXJR_USER" -- id -nG 2>/dev/null \
        | tr ' ' '\n' | grep -Fxq "$SBOXJR_JOURNAL_GROUP"; then
        sboxjr_die "$SBOXJR_USER 有效组缺少 $SBOXJR_JOURNAL_GROUP"
        return 1
    fi
    return 0
}

# ---------------------------------------------------------------------------
# PR-2B ACTIVATION TRANSACTION -- reader activation is installer-owned.
#
# Contract (Coding E, issue #33 P2 PR-2B):
#   preflight -> exact identity -> directories -> runtime link (release
#   libexec) -> unit render -> systemd verify -> unit install ->
#   enable/start -> health proof
# Every step RETURNS nonzero on failure (never exits, R3-7); the caller in
# install-monitor.sh owns rollback. sbmon_sboxjr_restore_prestate is the
# single inverse: it re-establishes the captured active/enabled/unit/
# runtime-link/identity-created facts.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Reader transaction inert rule (PR-2B, tightened by review #54 B4): a FORMAL
# install/upgrade whose source tree does not ship journal_reader/ is refused
# BEFORE any staging or mutation. §3 makes "the release carries and imports the
# ingest contract" part of the definition of a release, so a top-level install
# that silently ends with contract_available=false is not a successful
# deployment -- it is the exact mixed-version half-state this branch exists to
# make unreachable, just reached by omission instead of by ordering.
#
# A wholly-absent payload is therefore treated exactly like a partial one (the
# manifest gate below already refuses that): same fail-closed class, same zero
# side effects. The only way to keep the old INERT behavior is to SAY SO:
# SBMON_ALLOW_INERT_BASELINE=1 is a declaration that this run models a
# pre-PR-2B baseline (the packaging fixtures and the legacy no-libexec release
# used as a rollback target). Production code never sets it; the low-level
# staging/converge inert paths remain so that such a baseline can still be
# staged, audited and rolled back.
# ---------------------------------------------------------------------------
sbmon_sboxjr_source_present() { # rc 0 = source tree ships journal_reader/
    [ -d "$SBMON_REPO_MONITOR_DIR/journal_reader" ]
}

sbmon_sboxjr_deployed() { # rc 0 = this host has (or had) an activated reader
    [ -e "$SBOXJR_UNIT_FILE" ] || [ -L "$SBOXJR_LIB_DIR" ] \
        || sbmon_sboxjr_service_active || sbmon_sboxjr_service_enabled
}

# Non-mutating precondition gate (fresh install / upgrade). A wrong-shaped
# PRE-EXISTING identity stops the whole command here, before ANY staging or
# mutation, with zero side effects (§3: never "quietly fix" an alien sbox-jr).
sbmon_sboxjr_activation_preflight() {
    # Provenance gate runs FIRST, even on the inert baseline: an illegal
    # $SBOXJR_LIB_DIR symlink (foreign target, wrong shape, broken, failed
    # audit) must refuse the whole command before ANY mutation and demand
    # human handling -- never guessed, never silently treated as absent.
    sbmon_sboxjr_runtime_linked_id >/dev/null \
        || sbmon_die "reader 运行时链接 provenance 非法：拒绝继续（fail-closed，未做任何变更，需人工处理）"
    if ! sbmon_sboxjr_source_present; then
        if [ "${SBMON_ALLOW_INERT_BASELINE:-0}" = "1" ]; then
            sbmon_warn "显式声明的 pre-PR-2B legacy 基线（SBMON_ALLOW_INERT_BASELINE=1）：reader 零激活，仅用于建模历史 release"
            return 0
        fi
        sbmon_die "源树缺少 journal_reader/ 载荷：正式 release 必须携带并可导入 ingest contract（PR-2B §3），拒绝以 contract_available=false 完成部署（fail-closed，未做任何变更）；确需建模 pre-PR-2B 基线时请显式设置 SBMON_ALLOW_INERT_BASELINE=1"
    fi
    [ -f "$DEPLOY_DIR/$SBOXJR_TEMPLATE_NAME" ] || sbmon_die "缺少 reader unit 模板: $DEPLOY_DIR/$SBOXJR_TEMPLATE_NAME"
    [ -f "$DEPLOY_DIR/app-bin/sbox-journal-reader" ] || sbmon_die "缺少 reader 入口 wrapper"
    local jf
    for jf in "${SBOXJR_MODULE_FILES[@]}"; do
        [ -f "$SBMON_REPO_MONITOR_DIR/journal_reader/$jf" ] \
            || sbmon_die "缺少 journal_reader 模块源文件: $jf（manifest 与源树不一致，fail-closed）"
    done
    if [ "$SBMON_FIXTURE" != "1" ]; then
        command -v getent >/dev/null 2>&1 \
            || sbmon_die "缺少 getent：sbox-jr 身份无法精确校验（fail-closed，未做任何变更）"
        command -v "$SBMON_SYSTEMD_ANALYZE" >/dev/null 2>&1 \
            || sbmon_die "缺少 $SBMON_SYSTEMD_ANALYZE：reader unit 无法验证（fail-closed，未做任何变更）"
        command -v "$SBOXJR_RUNUSER" >/dev/null 2>&1 \
            || sbmon_die "缺少 $SBOXJR_RUNUSER：journal 可读性无法证明（fail-closed，未做任何变更）"
        if getent passwd "$SBOXJR_USER" >/dev/null 2>&1; then
            sbmon_sboxjr_validate_identity \
                || sbmon_die "既有 $SBOXJR_USER 身份形状不符（见上）：fail-closed，未做任何变更"
        fi
    fi
}

# Transaction pre-state facts (call under the deploy lock, BEFORE any
# mutation of this transaction).
SBOXJR_PRE_ACTIVE=0
SBOXJR_PRE_ENABLED=0
SBOXJR_PRE_UNIT_EXISTED=0
SBOXJR_PRE_UNIT_BACKUP=""
SBOXJR_PRE_LINK_ID=""
SBOXJR_PRE_USER_EXISTED=1
SBOXJR_PRE_GROUP_EXISTED=1

sbmon_sboxjr_capture_prestate() {
    SBOXJR_PRE_ACTIVE=0
    SBOXJR_PRE_ENABLED=0
    SBOXJR_PRE_UNIT_EXISTED=0
    SBOXJR_PRE_UNIT_BACKUP=""
    SBOXJR_PRE_LINK_ID="$(sbmon_sboxjr_runtime_linked_id)" \
        || { sboxjr_warn "reader 预状态捕获：运行时链接 provenance 非法，拒绝开始事务（需人工处理）"; return 1; }
    if sbmon_sboxjr_service_active; then SBOXJR_PRE_ACTIVE=1; fi
    if sbmon_sboxjr_service_enabled; then SBOXJR_PRE_ENABLED=1; fi
    if [ -e "$SBOXJR_UNIT_FILE" ]; then
        SBOXJR_PRE_UNIT_EXISTED=1
        SBOXJR_PRE_UNIT_BACKUP="$(mktemp "$(dirname -- "$SBOXJR_UNIT_FILE")/.jr-pretxn.XXXXXX")" \
            || sbmon_die "reader unit 预状态备份创建失败"
        cp -a -- "$SBOXJR_UNIT_FILE" "$SBOXJR_PRE_UNIT_BACKUP" \
            || sbmon_die "reader unit 预状态备份失败"
    fi
    if [ "$SBMON_FIXTURE" = "1" ]; then
        return 0
    fi
    SBOXJR_PRE_USER_EXISTED=0
    SBOXJR_PRE_GROUP_EXISTED=0
    if getent passwd "$SBOXJR_USER" >/dev/null 2>&1; then SBOXJR_PRE_USER_EXISTED=1; fi
    if getent group "$SBOXJR_GROUP" >/dev/null 2>&1; then SBOXJR_PRE_GROUP_EXISTED=1; fi
}

# Post-activation health proof (§17). Mockable facts (systemd state via the
# configured systemctl wrapper, identity via getent/id, journal-group via
# the runuser probe) are HARD here. Process-level PID/proc identity and the
# heartbeat cycle are proven on the real machine by
# tests/journal-reader/test-jr-live.sh; this gate degrades them to
# presence-consistency checks only (never a silent pass of the whole proof).
#
# TWO INDEPENDENT AXES (review #54 B5): RUNTIME health -- the process is
# actually running and can read the journal -- and the BOOT-ENABLE fact -- it
# comes back on its own after a reboot. Conflating them means a host whose
# reader is deliberately active-but-disabled can never complete a
# keep-prestate transaction: the proof would "repair" the very intent it was
# told to preserve, and the rollback would fail forever instead of once. So
# the WANTED enable state is a parameter, never a hard-coded 1:
#   want_enabled=1 (default, forward activation) -> enabled is required;
#   want_enabled=0 (keep-prestate)               -> enabled is DRIFT and fails.
# Either way one of the two axes is always proven, so nothing is weakened --
# what moves is which value that axis must hold.
sbmon_sboxjr_health_proof() { # [want_enabled 0|1] (default 1)
    local want_enabled="${1:-1}"
    sbmon_sboxjr_service_active || { sboxjr_warn "健康证明：reader 服务非 active"; return 1; }
    if [ "$want_enabled" = "1" ]; then
        if ! sbmon_sboxjr_service_enabled; then
            sboxjr_warn "健康证明：reader 服务未 enabled（重启后不会自起）"
            return 1
        fi
    elif sbmon_sboxjr_service_enabled; then
        sboxjr_warn "健康证明：事务前为 disabled，boot-enable 事实已漂移（现在被 enabled）"
        return 1
    fi
    sbmon_sboxjr_readability_probe || return 1
    if [ "$SBMON_FIXTURE" = "1" ]; then
        return 0
    fi
    sbmon_sboxjr_validate_identity || { sboxjr_warn "健康证明：身份在激活后发生漂移"; return 1; }
    local hb="$SBOXJR_OUT_DIR/hb"
    if [ -L "$hb" ]; then
        sboxjr_warn "健康证明：heartbeat 路径是符号链接（契约违规）"
        return 1
    fi
    if [ -e "$hb" ] && [ ! -f "$hb" ]; then
        sboxjr_warn "健康证明：heartbeat 不是普通文件"
        return 1
    fi
    # An absent hb only means the first poll cycle has not completed yet;
    # heartbeat CONTENT/age is the Monitor-derived staleness contract and is
    # proven live, not here.
    return 0
}

# Forward convergence. <new-release-id> may be empty (noop/repair without
# relink is then a state RE-PROOF, not a restart). <no_start>=1 deploys
# files/unit only. <keep_prestate>=1 (rollback path) preserves the reader's
# captured active/enabled facts instead of forcing running+enabled; with
# keep=0 the terminal contract is enabled AND active.
sbmon_sboxjr_converge() { # <new_id|''> <no_start 0|1> <keep_prestate 0|1>
    local new_id="$1" no_start="$2" keep="$3"
    if ! sbmon_sboxjr_source_present && ! sbmon_sboxjr_deployed; then
        sboxjr_log "reader INERT：源树无 journal_reader/ 且从未激活（零变更、零启动）"
        return 0
    fi
    local runtime_changed=0
    sbmon_sboxjr_ensure_identity || { sboxjr_warn "reader 身份收敛失败"; return 1; }
    sbmon_sboxjr_ensure_data_tree || { sboxjr_warn "reader 数据目录收敛失败"; return 1; }
    if [ -n "$new_id" ]; then
        sbmon_sboxjr_link_runtime "$new_id" || { sboxjr_warn "reader 运行时链接切换失败"; return 1; }
        runtime_changed=1
    fi
    SBOXJR_UNIT_CHANGED=0
    sbmon_sboxjr_install_unit || { sboxjr_warn "reader unit 验证/安装失败（未 enable/未 start）"; return 1; }
    if [ "$no_start" = "1" ]; then
        sboxjr_log "--no-start：跳过 reader 服务启动（仅部署文件）"
        return 0
    fi
    local want_active="$SBOXJR_PRE_ACTIVE" want_enabled="$SBOXJR_PRE_ENABLED"
    if [ "$keep" != "1" ]; then
        want_active=1
        want_enabled=1
    fi
    if sbmon_sboxjr_service_active; then
        if [ "$runtime_changed" = "1" ] || [ "$SBOXJR_UNIT_CHANGED" = "1" ]; then
            sbmon_info "重启 singbox-journal-reader（仅 reader；不触碰 sing-box / Monitor 之外服务）"
            sbmon_sboxjr_service_restart || { sboxjr_warn "reader 重启失败"; return 1; }
        fi
    elif [ "$want_active" = "1" ]; then
        sbmon_info "启用并启动 singbox-journal-reader"
        sbmon_sboxjr_service_enable_now || { sboxjr_warn "reader enable/start 失败"; return 1; }
    fi
    if [ "$want_active" = "1" ]; then
        sbmon_wait_sboxjr_active || { sboxjr_warn "reader 未在 ${SBMON_HEALTH_TIMEOUT}s 内 active"; return 1; }
    elif sbmon_sboxjr_service_active; then
        sboxjr_warn "reader 保持策略要求 inactive，但服务仍在运行"; return 1
    fi
    local now_enabled=0
    if sbmon_sboxjr_service_enabled; then now_enabled=1; fi
    if [ "$now_enabled" != "$want_enabled" ]; then
        if [ "$want_enabled" = "1" ]; then
            sbmon_sboxjr_service_enable || { sboxjr_warn "reader enable 补偿失败"; return 1; }
        else
            sbmon_sboxjr_service_disable || { sboxjr_warn "reader disable 补偿失败"; return 1; }
        fi
        now_enabled=0
        if sbmon_sboxjr_service_enabled; then now_enabled=1; fi
        if [ "$now_enabled" != "$want_enabled" ]; then
            sboxjr_warn "reader enabled 状态漂移（want=$want_enabled got=$now_enabled）"
            return 1
        fi
    fi
    if [ "$want_active" = "1" ]; then
        # B5: the proof is told WHICH boot-enable fact this transaction must
        # leave behind -- the forward contract's 1, or the host's preserved 0.
        sbmon_sboxjr_health_proof "$want_enabled" || return 1
    fi
    sboxjr_log "reader 收敛完成（active=$( [ "$want_active" = 1 ] && printf yes || printf kept-inactive) enabled=$want_enabled）"
    return 0
}

# Single inverse of the reader transaction: restores the captured
# active/enabled/unit/runtime/identity-created facts. Any failed restore
# step is CRITICAL (exit 2): the caller is already inside a failure path.
#
# ORDER IS THE CONTRACT (review #54 B1 + B6): THE PROCESS NEVER OUTLIVES ITS
# CODE, AND ITS CODE IS NEVER DISMANTLED UNDERNEATH IT. What "last" means is
# decided by the CAPTURED prestate, not by the current one:
#
#   PRE_ACTIVE=1 -- the reader ran before this transaction, so restore must put
#   it back to running. The unit file and the runtime link are restored FIRST
#   and the restart is the LAST service action. Restarting first would let a
#   failed N->N+1 upgrade restart the reader on the N+1 runtime and then merely
#   repoint the symlink at N: both live links would read "N" while the RUNNING
#   process is still N+1 -- the exact mixed-version state this contract exists
#   to forbid, and one no link-based assertion can detect afterwards.
#
#   PRE_ACTIVE=0 -- the prestate is "not running", but the candidate may have
#   been started by this very transaction and a LATER step failed (enable
#   succeeded partially, health proof drifted, ...). Dismantling the unit and
#   removing the runtime link first would tear the ground out from under a live
#   process and only then stop it, so for this branch the stop (plus the
#   verify-inactive proof) is the FIRST action. Either way the branch ends by
#   re-asserting the prestate fact, so no path can leave the candidate running.
#
# The boot-enable fact sits with the CODE group (before the link) rather than
# after it: plain `enable`/`disable` never start or stop a running process, so
# they cannot load candidate code, while a failed link step must not be able to
# strand an uncompensated `enable`.
sbmon_sboxjr_restore_prestate() {
    sbmon_warn "恢复 reader 事务前状态（服务状态 → unit + enable 事实 + 运行时链接 → 本次新建身份；顺序按事务前 active 事实分支）"
    if [ "$SBOXJR_PRE_ACTIVE" != "1" ] && sbmon_sboxjr_service_active; then
        # B6: quiesce the candidate BEFORE anything of its own code/unit goes away.
        if ! sbmon_sboxjr_service_stop; then
            sbmon_critical "reader 回滚：stop 失败（事务前 inactive，但候选进程仍在运行）；需要人工处理"
        fi
        if sbmon_sboxjr_service_active; then
            sbmon_critical "reader 回滚：服务仍处于运行状态（事务前 inactive）；需要人工处理"
        fi
    fi
    local unit_touched=0
    if [ "$SBOXJR_PRE_UNIT_EXISTED" = "1" ]; then
        if [ ! -f "$SBOXJR_PRE_UNIT_BACKUP" ] \
           || ! sbmon_atomic_write "$SBOXJR_UNIT_FILE" 0644 < "$SBOXJR_PRE_UNIT_BACKUP"; then
            sbmon_critical "reader 回滚：unit 恢复失败（备份缺失或写入异常）；需要人工处理"
        fi
        unit_touched=1
    else
        if [ -e "$SBOXJR_UNIT_FILE" ]; then
            if ! rm -f -- "$SBOXJR_UNIT_FILE"; then
                sbmon_critical "reader 回滚：候选 unit 删除失败；需要人工处理"
            fi
            unit_touched=1
        fi
    fi
    rm -f -- "$SBOXJR_PRE_UNIT_BACKUP" 2>/dev/null || true
    SBOXJR_PRE_UNIT_BACKUP=""
    if [ "$unit_touched" = "1" ]; then
        if ! sbmon_systemctl daemon-reload; then
            sbmon_critical "reader 回滚：daemon-reload 失败；systemd 状态可能不一致，需要人工处理"
        fi
    fi
    if [ "$SBOXJR_PRE_ENABLED" = "1" ]; then
        if ! sbmon_sboxjr_service_enabled; then
            if ! sbmon_sboxjr_service_enable; then
                sbmon_critical "reader 回滚：enable 恢复失败；需要人工处理"
            fi
        fi
    else
        if sbmon_sboxjr_service_enabled; then
            if ! sbmon_sboxjr_service_disable; then
                sbmon_critical "reader 回滚：disable 恢复失败（可能残留 enabled 状态）；需要人工处理"
            fi
        fi
    fi
    if [ -n "$SBOXJR_PRE_LINK_ID" ]; then
        if [ "$(sbmon_sboxjr_runtime_linked_id)" != "$SBOXJR_PRE_LINK_ID" ]; then
            if [ ! -d "$(sbmon_sboxjr_release_runtime_dir "$SBOXJR_PRE_LINK_ID")" ]; then
                sbmon_critical "reader 回滚：事务前运行时 release（$SBOXJR_PRE_LINK_ID）目录已不存在，无法恢复链接；需要人工处理"
            fi
            if ! sbmon_sboxjr_link_runtime "$SBOXJR_PRE_LINK_ID"; then
                sbmon_critical "reader 回滚：运行时链接恢复失败（$SBOXJR_PRE_LINK_ID）；需要人工处理"
            fi
        fi
    else
        if ! sbmon_sboxjr_unlink_runtime; then
            sbmon_critical "reader 回滚：运行时链接移除失败；需要人工处理"
        fi
    fi
    # LAST for the active prestate: the process is (re)started only now that the
    # prestate code + unit are back in place, so a restart can never load the
    # failed candidate. For the inactive prestate this block only RE-ASSERTS the
    # fact (the stop already happened up front, before any teardown).
    if [ "$SBOXJR_PRE_ACTIVE" = "1" ]; then
        if ! sbmon_sboxjr_service_restart; then
            sbmon_critical "reader 回滚：restart 失败（事务前 active）；需要人工处理"
        fi
        if ! sbmon_wait_sboxjr_active; then
            sbmon_critical "reader 回滚：服务未恢复 active（事务前 active）；需要人工检查 journalctl -u $SBOXJR_SERVICE_NAME"
        fi
    else
        if sbmon_sboxjr_service_active; then
            # Nothing in this restore may start the reader, so reaching here
            # active means an outside actor did; it is still put down, never
            # left running on top of a torn-down unit/runtime.
            if ! sbmon_sboxjr_service_stop; then
                sbmon_critical "reader 回滚：stop 失败（事务前 inactive）；需要人工处理"
            fi
            if sbmon_sboxjr_service_active; then
                sbmon_critical "reader 回滚：服务仍处于运行状态（事务前 inactive）；需要人工处理"
            fi
        fi
    fi
    # Identity: only an account THIS transaction created is removed again
    # (never delete a pre-existing user/group -- those are restore-only facts).
    if [ "$SBMON_FIXTURE" != "1" ]; then
        if [ "$SBOXJR_PRE_USER_EXISTED" = "0" ] && getent passwd "$SBOXJR_USER" >/dev/null 2>&1; then
            if ! userdel -- "$SBOXJR_USER"; then
                sbmon_critical "reader 回滚：本次创建的用户删除失败（$SBOXJR_USER）；需要人工处理"
            fi
        fi
        if [ "$SBOXJR_PRE_GROUP_EXISTED" = "0" ] && getent group "$SBOXJR_GROUP" >/dev/null 2>&1; then
            if ! getent passwd | grep -q ":$SBOXJR_GROUP:"; then
                if ! groupdel -- "$SBOXJR_GROUP" 2>/dev/null; then
                    sbmon_warn "reader 回滚：本次创建的组 $SBOXJR_GROUP 删除失败（可能仍有成员）；请人工复核"
                fi
            fi
        fi
    fi
    sbmon_warn "sbox-journal-reader 激活前状态恢复完成（active=$SBOXJR_PRE_ACTIVE enabled=$SBOXJR_PRE_ENABLED unit=$([ "$SBOXJR_PRE_UNIT_EXISTED" = 1 ] && printf restored || printf removed) runtime=${SBOXJR_PRE_LINK_ID:-<none>}）"
}
