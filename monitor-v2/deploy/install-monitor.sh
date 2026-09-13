#!/usr/bin/env bash
# install-monitor.sh -- Monitor v2 deployment entrypoint (skeleton track).
#
# Commands:
#   install [--repair] [--allow-downgrade] [--no-start]   converge to repo VERSION
#   upgrade                                               = install (refuses when absent)
#   rollback [release-id]                                 flip back, restart monitor only
#   history                                               release history
#   health                                                print separated health JSON
#   status                                                version + dirs + unit state
#   uninstall [--purge-state] [--purge-config] [--purge-backups]
#
# Guarantees (enforced by tests/test-monitor-packaging.sh):
#   * NEVER reads or writes the proxy tree (/root/sbox, sbconfig_server.json);
#   * NEVER touches firewall tooling; web stays on 127.0.0.1:9191 by default;
#   * NEVER restarts/reloads sing-box -- only singbox-monitor.service;
#   * re-runs never overwrite monitor.conf, auth, access or state data.
set -Eeuo pipefail

DEPLOY_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/monitor-deploy-lib.sh
source "$DEPLOY_DIR/lib/monitor-deploy-lib.sh"

OPT_REPAIR=0
OPT_ALLOW_DOWNGRADE=0
OPT_NO_START=0
OPT_PURGE_STATE=0
OPT_PURGE_CONFIG=0
OPT_PURGE_BACKUPS=0

usage() {
    cat <<'EOF'
用法: install-monitor.sh <command> [flags]

commands:
  install [--repair] [--allow-downgrade] [--no-start]   收敛到仓库 VERSION（幂等）
  upgrade                                               等价 install（未安装则拒绝）
  rollback [release-id]                                 回滚 release（只重启 monitor）
  history                                               release 历史
  health                                                输出分离式健康 JSON
  status                                                版本 + 目录 + 服务状态
  uninstall [--purge-state] [--purge-config] [--purge-backups]
                                                        卸载（默认保留状态/配置/备份）
EOF
}

parse_flags() { # parse_flags <cmd> "$@"
    local cmd="$1"; shift
    while (($# > 0)); do
        case "$1" in
            --repair)          OPT_REPAIR=1 ;;
            --allow-downgrade) OPT_ALLOW_DOWNGRADE=1 ;;
            --no-start)        OPT_NO_START=1 ;;
            --purge-state)     OPT_PURGE_STATE=1 ;;
            --purge-config)    OPT_PURGE_CONFIG=1 ;;
            --purge-backups)   OPT_PURGE_BACKUPS=1 ;;
            *) sbmon_die "$cmd: 未知参数 $1" ;;
        esac
        shift
    done
}

# ---------------------------------------------------------------------------
# F4: unified dispatcher -- every mutating command runs
# "acquire lock -> precondition -> decision -> mutation" under ONE lock.
# Precondition reads happen INSIDE the lock (no TOCTOU between
# "upgrade checks installed" and a concurrent uninstall).
# ---------------------------------------------------------------------------
sbmon_with_deploy_lock() { # sbmon_with_deploy_lock <locked-fn> [args...]
    local fn="$1"; shift
    sbmon_acquire_deploy_lock
    "$fn" "$@"
}

# ---------------------------------------------------------------------------
# P3/F2: deployment transaction -- release + unit + service state
# (active AND enabled) are rolled back TOGETHER.
# ---------------------------------------------------------------------------
sbmon_txn_rollback() { # <old_id> <old_unit_backup|''> <old_unit_existed> <old_active> <old_enabled>
    local old_id="$1" old_unit_backup="$2" old_unit_existed="$3" old_active="$4" old_enabled="$5"
    sbmon_warn "部署门未通过：开始恢复事务前状态（release + unit + 服务）"

    if [ -n "$old_id" ]; then
        if ! sbmon_activate_release "$old_id"; then
            rm -f -- "$old_unit_backup" 2>/dev/null || true
            sbmon_critical "release 回滚失败（$old_id 激活异常）；系统处于混合状态，需要人工处理"
        fi
    fi

    if [ "$old_unit_existed" = 1 ]; then
        if [ ! -f "$old_unit_backup" ]            || ! sbmon_atomic_write "$SBMON_UNIT_FILE" 0644 < "$old_unit_backup"; then
            rm -f -- "$old_unit_backup" 2>/dev/null || true
            sbmon_critical "unit 恢复失败（备份缺失或写入失败）；需要人工处理"
        fi
    else
        # R4-1: removal of the candidate unit is a restoration step -- a
        # failure must be CRITICAL, never a silent set -e exit.
        if ! rm -f -- "$SBMON_UNIT_FILE"; then
            sbmon_critical "unit 删除失败（candidate unit 无法移除）；需要人工处理"
        fi
    fi
    rm -f -- "$old_unit_backup" 2>/dev/null || true   # temp bookkeeping, not a state restore step

    if ! sbmon_systemctl daemon-reload; then
        sbmon_critical "回滚后 daemon-reload 失败；systemd 状态可能不一致，需要人工处理"
    fi

    # F2: restore the recorded enabled state explicitly (never inferred).
    if [ "$old_enabled" = 1 ]; then
        if ! sbmon_service_enable; then
            sbmon_critical "回滚后 enable 恢复失败（事务前 enabled）；需要人工处理"
        fi
    else
        if ! sbmon_systemctl disable "$SBMON_SERVICE_NAME"; then
            sbmon_critical "回滚后 disable 恢复失败（事务前 disabled）；需要人工处理"
        fi
    fi

    # F2: restore the recorded active state explicitly.
    if [ "$old_active" = 1 ]; then
        if ! sbmon_service_restart; then
            sbmon_critical "回滚后服务重启失败（旧 release/unit 已恢复但服务未运行）；需要人工处理"
        fi
        if ! sbmon_wait_service_active; then
            sbmon_critical "回滚后服务未恢复 active；旧 release/unit 已就位，需要人工检查 journalctl -u $SBMON_SERVICE_NAME"
        fi
    else
        # R4-1: stop is a restoration step -- failure is CRITICAL, never a
        # silent set -e exit.
        if ! sbmon_service_stop; then
            sbmon_critical "回滚后服务停止失败（事务前为 inactive）；需要人工处理"
        fi
        if sbmon_service_active; then
            sbmon_critical "回滚后服务仍处于运行状态（事务前为 inactive）；需要人工处理"
        fi
    fi

    sbmon_warn "事务前状态已恢复（release=${old_id:-<none>} unit=$([ "$old_unit_existed" = 1 ] && printf restored || printf removed) service_active=$old_active service_enabled=$old_enabled）"
}

# F2/R3-3: fresh-install failure has NO pre-state to restore. Contract
# (README §5): remove the live symlink and the newly created unit (never
# leave an active release or an enabled broken service), keep the immutable
# release tree for diagnosis, end disabled + inactive. R3-3: NO step is
# allowed to swallow errors -- only when every restore step succeeded may
# the function claim "restored to uninstalled state"; any failure is
# CRITICAL exit 2.
sbmon_fresh_failure_cleanup() {
    sbmon_warn "首次部署启动失败：清理激活链接与 unit（release 树保留以便排查）"
    if ! sbmon_service_stop; then
        sbmon_critical "首次部署失败清理：stop 失败"
    fi
    if ! sbmon_systemctl disable "$SBMON_SERVICE_NAME"; then
        sbmon_critical "首次部署失败清理：disable 失败，可能残留 enabled 状态"
    fi
    if ! rm -rf -- "$SBMON_APP_LINK"; then   # symlink itself; never descends into the release tree
        sbmon_critical "首次部署失败清理：live 链接删除失败"
    fi
    if ! rm -f -- "$SBMON_UNIT_FILE"; then
        sbmon_critical "首次部署失败清理：unit 删除失败"
    fi
    if ! sbmon_systemctl daemon-reload; then
        sbmon_critical "首次部署失败清理：daemon-reload 失败；systemd 状态可能不一致"
    fi
    if sbmon_service_active; then
        sbmon_critical "首次部署失败清理：服务仍处于运行状态"
    fi
    if sbmon_service_enabled; then
        sbmon_critical "首次部署失败清理：服务仍处于 enabled 状态"
    fi
    sbmon_warn "已恢复到未安装状态（disabled + inactive）；排查请查看 journalctl -u $SBMON_SERVICE_NAME"
}

cmd_install() { # F4: lock -> precondition -> decision -> mutation, all in one lock
    parse_flags install "$@"
    sbmon_with_deploy_lock _cmd_install_locked install "$@"
}

cmd_upgrade() { # F4: precondition is checked INSIDE the deploy lock and can
    #            never degrade into a fresh install.
    parse_flags upgrade "$@"
    sbmon_with_deploy_lock _cmd_install_locked upgrade "$@"
}

# R3-1: forward apply. Every step that touches live deployment state
# returns nonzero on failure -- nothing in here may exit (R3-7); the caller
# (transaction handler in _cmd_install_locked) owns rollback.
sbmon_apply_candidate() { # <new_id-or-empty> <was_active> <no_start>
    local new_id="$1" was_active="$2" no_start="$3"
    if [ -n "$new_id" ]; then
        sbmon_activate_release "$new_id" || { sbmon_warn "release 激活失败"; return 1; }
    fi
    # Unit converge runs on EVERY path (incl. noop): template changes must
    # apply even when the app version is unchanged. Atomic write (P3).
    SBMON_UNIT_CHANGED=0
    sbmon_install_unit || { sbmon_warn "unit 应用失败"; return 1; }
    [ "$no_start" = 1 ] && { sbmon_info "--no-start：跳过服务启动（仅部署文件）"; return 0; }
    if [ "$was_active" = 1 ]; then
        if [ -n "$new_id" ] || [ "$SBMON_UNIT_CHANGED" = 1 ]; then
            sbmon_info "重启监控服务（仅 singbox-monitor，不触碰 sing-box）"
            if ! sbmon_service_restart; then
                sbmon_warn "服务重启失败"
                return 1
            fi
            if ! sbmon_wait_service_active; then
                sbmon_warn "服务未在 ${SBMON_HEALTH_TIMEOUT}s 内激活"
                return 1
            fi
            sbmon_info "服务已激活"
        fi
    else
        sbmon_info "启用并启动 singbox-monitor"
        if ! sbmon_service_enable_now; then
            sbmon_warn "candidate 启动失败"
            return 1
        fi
        if ! sbmon_wait_service_active; then
            sbmon_warn "服务未在 ${SBMON_HEALTH_TIMEOUT}s 内激活"
            return 1
        fi
        sbmon_info "服务已激活"
    fi
    return 0
}

_cmd_install_locked() { # <install|upgrade> [flags...]
    local MODE="$1"; shift
    parse_flags install "$@"

    # --- precheck: fail closed BEFORE touching the filesystem ---
    command -v "$SBMON_PYTHON3" >/dev/null 2>&1         || sbmon_die "缺少依赖 python3（预检失败，未做任何更改）"
    command -v "$SBMON_SYSTEMCTL" >/dev/null 2>&1         || sbmon_die "缺少依赖 systemctl（预检失败，未做任何更改）"
    [ -f "$DEPLOY_DIR/singbox-monitor.service.in" ] || sbmon_die "缺少 unit 模板"
    [ -d "$SBMON_REPO_MONITOR_DIR" ] || sbmon_die "缺少 monitor-v2 源目录: $SBMON_REPO_MONITOR_DIR"

    # F4: precondition re-check under the lock. A concurrent uninstall may
    # have completed between the CLI call and this point -- upgrade must
    # fail here, never fall through to a fresh install.
    local current_id_pre
    current_id_pre="$(sbmon_current_release_id)"
    if [ "$MODE" = "upgrade" ] && [ -z "$current_id_pre" ]; then
        sbmon_die "升级前置检查（锁内）：当前未安装 Monitor；绝不退化为全新安装"
    fi

    local repo_version current_version current_id
    repo_version="$(sbmon_repo_version)"
    current_id="$(sbmon_current_release_id)"
    current_version="$(sbmon_current_version)"

    sbmon_ensure_group
    sbmon_ensure_user
    sbmon_create_layout
    sbmon_write_default_conf
    sbmon_repair_conf_perms
    # P6: fail-closed secret delivery BEFORE any release change; failure
    # aborts the whole install with nothing staged.
    sbmon_sync_api_secret

    if [ -e "$SBMON_APP_LINK" ] && [ ! -L "$SBMON_APP_LINK" ]; then
        sbmon_die "$SBMON_APP_LINK 已存在且不是符号链接；请手工迁移后重试（fail-closed）"
    fi

    local action="install"
    if [ -z "$current_id" ]; then
        action="fresh"
    elif [ "$current_version" = "$repo_version" ]; then
        action="noop"
    elif sbmon_version_ge "$repo_version" "$current_version"; then
        action="upgrade"
    elif [ "$OPT_ALLOW_DOWNGRADE" = 1 ]; then
        action="downgrade"
    else
        sbmon_die "仓库版本 $repo_version 低于已安装版本 $current_version；回退请用 rollback 或 --allow-downgrade"
    fi

    if [ "$action" = "noop" ] && [ "$OPT_REPAIR" = 0 ]; then
        sbmon_info "已安装且版本一致（$repo_version）：仅修复权限，不改代码/配置/状态"
    elif [ "$action" = "noop" ]; then
        action="repair"
    fi

    # --- transaction state (P3/F2): captured before anything is mutated ---
    local was_active=0
    if sbmon_service_active; then was_active=1; fi
    local old_enabled=0
    if sbmon_service_enabled; then old_enabled=1; fi
    local old_unit_existed=0
    local old_unit_backup=""
    if [ -e "$SBMON_UNIT_FILE" ]; then
        old_unit_existed=1
        old_unit_backup="$(mktemp "$(dirname -- "$SBMON_UNIT_FILE")/.pretxn.XXXXXX")"
        cp -a -- "$SBMON_UNIT_FILE" "$old_unit_backup"
    fi

    local new_id=""
    if [ "$action" = "fresh" ] || [ "$action" = "upgrade" ] || [ "$action" = "repair" ] || [ "$action" = "downgrade" ]; then
        # F1: history is a COMMIT record, not an intent record. The entry is
        # written ONLY after the service gate passes; failed/rolled-back
        # candidates never become rollback targets. Staging mutates nothing
        # live, so its failure may still die (precondition-class).
        new_id="$(sbmon_stage_release "$repo_version")"
    fi

    # R3-1: EVERY forward-apply step after pre-state capture -- release
    # activation, unit atomic write, daemon-reload, restart/enable, and the
    # active gate -- runs inside sbmon_apply_candidate, which only RETURNS
    # nonzero (never exits). Any failure enters the same rollback path here.
    if ! sbmon_apply_candidate "$new_id" "$was_active" "$OPT_NO_START"; then
        sbmon_warn "candidate 部署失败，进入事务回滚"
        if [ "$old_unit_existed" = 1 ] || [ -n "$current_id" ]; then
            sbmon_txn_rollback "$current_id" "$old_unit_backup" "$old_unit_existed" "$was_active" "$old_enabled"
        else
            rm -f -- "$old_unit_backup" 2>/dev/null || true
            sbmon_fresh_failure_cleanup
        fi
        return 1
    fi

    local release_changed=0
    if [ -n "$new_id" ]; then
        release_changed=1
    fi

    # F1: gate PASSED -> the candidate is now a committed deployment.
    if [ "$release_changed" = 1 ]; then
        sbmon_record_history "$new_id" "$repo_version" "$action"
        sbmon_prune_releases
    fi
    rm -f -- "$old_unit_backup" 2>/dev/null || true

    sbmon_report_health
    sbmon_info "install 完成（action=$action version=$repo_version）"
}

cmd_rollback() { # rollback [release-id]
    # F4: lock -> precondition -> mutation, single acquisition, no nesting.
    sbmon_with_deploy_lock _cmd_rollback_locked "$@"
}

# R3-2: apply a rollback target and bring the service to the required
# state; returns nonzero on ANY failure (never exits, R3-7). The caller
# owns restoring the original release.
sbmon_apply_rollback_target() { # <target-id> <orig_active> <orig_enabled>
    local target="$1" orig_active="$2" orig_enabled="$3"
    sbmon_activate_release "$target" || { sbmon_warn "rollback: target 激活失败"; return 1; }
    if [ "$orig_active" = 1 ]; then
        if ! sbmon_service_restart; then
            sbmon_warn "rollback: 服务重启失败"
            return 1
        fi
        if ! sbmon_wait_service_active; then
            sbmon_warn "rollback: 服务未在 ${SBMON_HEALTH_TIMEOUT}s 内激活"
            return 1
        fi
    else
        # product contract: rollback keeps the ORIGINAL active state; an
        # inactive service stays inactive on the target release.
        if ! sbmon_service_stop; then
            sbmon_warn "rollback: 服务停止失败"
            return 1
        fi
        if sbmon_service_active; then
            sbmon_warn "rollback: 服务未停止"
            return 1
        fi
    fi
    # enabled state is untouched by activate/restart/stop; verify it still
    # matches the captured original (defensive, fail-closed).
    local now_enabled=0
    if sbmon_service_enabled; then now_enabled=1; fi
    if [ "$now_enabled" != "$orig_enabled" ]; then
        sbmon_warn "rollback: enabled 状态漂移（want=$orig_enabled got=$now_enabled）"
        return 1
    fi
    return 0
}

# R3-2: restore the original release after a failed rollback target apply.
# Failure here is irrecoverable -> CRITICAL.
sbmon_restore_original_after_rollback() { # <orig_id> <orig_active> <orig_enabled>
    local orig_id="$1" orig_active="$2" orig_enabled="$3"
    if ! sbmon_activate_release "$orig_id"; then
        sbmon_critical "rollback 恢复失败：原 release 激活异常（$orig_id）；需要人工处理"
    fi
    if [ "$orig_enabled" = 1 ]; then
        if ! sbmon_service_enable; then
            sbmon_critical "rollback 恢复失败：enable 恢复失败；需要人工处理"
        fi
    else
        if ! sbmon_systemctl disable "$SBMON_SERVICE_NAME"; then
            sbmon_critical "rollback 恢复失败：disable 恢复失败；需要人工处理"
        fi
    fi
    if [ "$orig_active" = 1 ]; then
        if ! sbmon_service_restart; then
            sbmon_critical "rollback 恢复失败：原 release 重启失败；需要人工处理"
        fi
        if ! sbmon_wait_service_active; then
            sbmon_critical "rollback 恢复失败：原 release 未恢复 active；需要人工检查 journalctl -u $SBMON_SERVICE_NAME"
        fi
    else
        if ! sbmon_service_stop; then
            sbmon_critical "rollback 恢复失败：服务停止失败；需要人工处理"
        fi
        if sbmon_service_active; then
            sbmon_critical "rollback 恢复失败：服务仍处于运行状态（事务前 inactive）"
        fi
    fi
}

_cmd_rollback_locked() { # [release-id]   (F4: runs under the deploy lock)
    local target="${1:-}"
    [ -L "$SBMON_APP_LINK" ] || sbmon_die "当前没有已激活的 release"
    local current
    current="$(sbmon_current_release_id)"
    if [ -z "$target" ]; then
        target="$(awk -v cur="$current" '$2 != cur { print $2 }' "$SBMON_HISTORY_FILE" 2>/dev/null | tail -n 1)"
        [ -n "$target" ] || sbmon_die "history 中没有可回滚的 release"
    fi
    [ -d "$SBMON_RELEASES_DIR/$target" ] || sbmon_die "release 不存在: $target"

    # R3-2: capture the full pre-state BEFORE touching anything.
    local orig_active=0 orig_enabled=0
    if sbmon_service_active; then orig_active=1; fi
    if sbmon_service_enabled; then orig_enabled=1; fi

    sbmon_info "回滚: $current -> $target"
    if ! sbmon_apply_rollback_target "$target" "$orig_active" "$orig_enabled"; then
        sbmon_warn "rollback target 未能健康应用：恢复原 release $current"
        if sbmon_restore_original_after_rollback "$current" "$orig_active" "$orig_enabled"; then
            sbmon_warn "已恢复到原 release（rollback 未完成）；未写入任何 history"
        else
            sbmon_critical "rollback 恢复亦失败（见上方 CRITICAL）"
        fi
        return 1
    fi
    # F1: history is a commit record -- recorded only after the rollback
    # target is activated AND the service state is verified.
    sbmon_record_history "$target" "$(tr -d ' \t\r\n' < "$SBMON_RELEASES_DIR/$target/VERSION")" "rollback"
    sbmon_info "回滚完成"
    sbmon_report_health
}

cmd_history() {
    if [ -r "$SBMON_HISTORY_FILE" ]; then
        cat "$SBMON_HISTORY_FILE"
    else
        sbmon_info "（无历史记录）"
    fi
}

cmd_health() {
    local probe
    probe="$(sbmon_health_cmd)"
    [ -x "$probe" ] || sbmon_die "health probe 不存在（未安装？）: $probe"
    # P1: explicit conf + state-root contract; the probe never infers the
    # state path from the caller's working directory.
    exec "$probe" "$(sbmon_conf_file)" "$SBMON_STATE_ROOT/state" "$@"
}

cmd_status() {
    local current_id current_version
    current_id="$(sbmon_current_release_id)"
    current_version="$(sbmon_current_version)"
    sbmon_info "安装状态:"
    printf '  version: %s\n' "${current_version:-<未安装>}"
    printf '  release: %s\n' "${current_id:-<none>}"
    printf '  app:     %s\n' "$SBMON_APP_LINK"
    printf '  state:   %s\n' "$SBMON_STATE_ROOT"
    printf '  conf:    %s\n' "$(sbmon_conf_file)"
    printf '  unit:    %s\n' "$SBMON_UNIT_FILE"
    if [ -x "$(sbmon_health_cmd)" ]; then
        sbmon_report_health
    fi
}

sbmon_report_health() {
    local json
    json="$(sbmon_health_json)"
    sbmon_info "health: $json"
}

cmd_uninstall() {
    parse_flags uninstall "$@"
    sbmon_with_deploy_lock _cmd_uninstall_locked
}

_cmd_uninstall_locked() { # F4: runs under the deploy lock
    sbmon_info "卸载 Monitor（仅 Monitor；不触碰 sing-box / 代理凭据 / 配置）"
    # R4-2: idempotency comes from CHECKING state, never from swallowing
    # errors. Already-absent states are fine; a FAILED stop/disable aborts
    # BEFORE any destructive deletion.
    if sbmon_service_active; then
        if ! sbmon_service_stop_strict; then
            sbmon_die "服务停止失败：拒绝在 Monitor 运行时删除部署文件"
        fi
    fi
    if sbmon_service_enabled; then
        if ! sbmon_service_disable_strict; then
            sbmon_die "服务 disable 失败：拒绝在 enabled 状态下删除部署文件"
        fi
    fi
    # Final proof BEFORE deleting anything.
    if sbmon_service_active; then
        sbmon_critical "卸载前校验失败：服务仍处于运行状态"
    fi
    if sbmon_service_enabled; then
        sbmon_critical "卸载前校验失败：服务仍处于 enabled 状态"
    fi
    if [ -e "$SBMON_UNIT_FILE" ]; then
        if ! rm -f -- "$SBMON_UNIT_FILE"; then
            sbmon_critical "unit 删除失败（卸载已开始，处于部分删除状态）；需要人工处理"
        fi
        if ! sbmon_systemctl daemon-reload; then
            sbmon_critical "卸载后 daemon-reload 失败（unit 已删除，处于部分卸载状态）；需要人工处理"
        fi
    fi
    if ! rm -rf -- "$SBMON_APP_LINK"; then   # symlink itself; never descends into the release tree
        sbmon_critical "app 链接删除失败（部分卸载状态）；需要人工处理"
    fi
    if ! rm -rf -- "$SBMON_RELEASES_DIR"; then
        sbmon_critical "release 树删除失败（部分卸载状态）；需要人工处理"
    fi
    if [ "$OPT_PURGE_STATE" = 1 ]; then
        sbmon_info "--purge-state: 删除 $SBMON_STATE_ROOT（auth/access/state）"
        rm -rf -- "$SBMON_STATE_ROOT"
    else
        sbmon_info "保留状态目录（auth/access/state）: $SBMON_STATE_ROOT（--purge-state 可删除）"
    fi
    if [ "$OPT_PURGE_CONFIG" = 1 ]; then
        sbmon_info "--purge-config: 删除 $SBMON_CONF_DIR"
        rm -rf -- "$SBMON_CONF_DIR"
    else
        sbmon_info "保留配置目录: $SBMON_CONF_DIR（--purge-config 可删除）"
    fi
    if [ "$OPT_PURGE_BACKUPS" = 1 ]; then
        rm -rf -- "$SBMON_BACKUP_ROOT"
    else
        sbmon_info "保留备份目录: $SBMON_BACKUP_ROOT"
    fi
    sbmon_info "Monitor 卸载完成"
}

main() {
    local cmd="${1:-}"
    [ -n "$cmd" ] || { usage; exit 1; }
    shift
    case "$cmd" in
        install)   cmd_install "$@" ;;
        upgrade)   cmd_upgrade "$@" ;;
        rollback)  cmd_rollback "$@" ;;
        history)   cmd_history ;;
        health)    cmd_health "$@" ;;
        status)    cmd_status ;;
        uninstall) cmd_uninstall "$@" ;;
        -h|--help) usage ;;
        *) usage; sbmon_die "未知命令: $cmd" ;;
    esac
}

main "$@"
