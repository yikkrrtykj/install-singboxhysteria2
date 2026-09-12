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
# P3: deployment transaction -- release + unit are rolled back TOGETHER.
# ---------------------------------------------------------------------------
sbmon_txn_rollback() { # <old_id> <old_unit_backup|''> <old_unit_existed> <old_active>
    local old_id="$1" old_unit_backup="$2" old_unit_existed="$3" old_active="$4"
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
        rm -f -- "$SBMON_UNIT_FILE"
    fi
    rm -f -- "$old_unit_backup" 2>/dev/null || true

    if ! sbmon_systemctl daemon-reload; then
        sbmon_critical "回滚后 daemon-reload 失败；systemd 状态可能不一致，需要人工处理"
    fi

    if [ "$old_active" = 1 ]; then
        if ! sbmon_service_restart; then
            sbmon_critical "回滚后服务重启失败（旧 release/unit 已恢复但服务未运行）；需要人工处理"
        fi
        if ! sbmon_wait_service_active; then
            sbmon_critical "回滚后服务未恢复 active；旧 release/unit 已就位，需要人工检查 journalctl -u $SBMON_SERVICE_NAME"
        fi
    else
        sbmon_service_stop_disable
        if sbmon_service_active; then
            sbmon_critical "回滚后服务仍处于运行状态（事务前为 inactive）；需要人工处理"
        fi
    fi

    sbmon_warn "事务前状态已恢复（release=${old_id:-<none>} unit=$([ "$old_unit_existed" = 1 ] && printf restored || printf removed) service_active=$old_active）"
}

cmd_install() {
    parse_flags install "$@"

    # --- precheck: fail closed BEFORE touching the filesystem ---
    command -v "$SBMON_PYTHON3" >/dev/null 2>&1         || sbmon_die "缺少依赖 python3（预检失败，未做任何更改）"
    command -v "$SBMON_SYSTEMCTL" >/dev/null 2>&1         || sbmon_die "缺少依赖 systemctl（预检失败，未做任何更改）"
    [ -f "$DEPLOY_DIR/singbox-monitor.service.in" ] || sbmon_die "缺少 unit 模板"
    [ -d "$SBMON_REPO_MONITOR_DIR" ] || sbmon_die "缺少 monitor-v2 源目录: $SBMON_REPO_MONITOR_DIR"

    # P4: serialize ALL mutations. Every step below (user/dirs/conf/secret/
    # stage/unit/flip/restart/rollback/prune/history) runs under this lock;
    # a busy/unavailable lock aborts before any mutation (fail-closed).
    sbmon_acquire_deploy_lock

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

    # --- transaction state (P3): captured before anything is mutated ---
    local was_active=0
    if sbmon_service_active; then was_active=1; fi
    local old_unit_existed=0
    local old_unit_backup=""
    if [ -e "$SBMON_UNIT_FILE" ]; then
        old_unit_existed=1
        old_unit_backup="$(mktemp "$(dirname -- "$SBMON_UNIT_FILE")/.pretxn.XXXXXX")"
        cp -a -- "$SBMON_UNIT_FILE" "$old_unit_backup"
    fi

    local new_id=""
    if [ "$action" = "fresh" ] || [ "$action" = "upgrade" ] || [ "$action" = "repair" ] || [ "$action" = "downgrade" ]; then
        new_id="$(sbmon_stage_release "$repo_version")"
        sbmon_record_history "$new_id" "$repo_version" "$action"
        sbmon_activate_release "$new_id"
    fi

    # Unit converge runs on EVERY path (incl. noop): template changes must
    # apply even when the app version is unchanged. Atomic write (P3).
    SBMON_UNIT_CHANGED=0
    sbmon_install_unit

    local release_changed=0
    if [ -n "$new_id" ]; then
        release_changed=1
    fi

    if [ "$OPT_NO_START" = 1 ]; then
        sbmon_info "--no-start：跳过服务启动（仅部署文件）"
    elif [ "$was_active" = 1 ]; then
        if [ "$release_changed" = 1 ] || [ "$SBMON_UNIT_CHANGED" = 1 ]; then
            sbmon_info "重启监控服务（仅 singbox-monitor，不触碰 sing-box）"
            if sbmon_service_restart && sbmon_wait_service_active; then
                sbmon_info "服务已激活"
            else
                sbmon_warn "服务未在 ${SBMON_HEALTH_TIMEOUT}s 内激活"
                if [ "$old_unit_existed" = 1 ] || [ -n "$current_id" ]; then
                    sbmon_txn_rollback "$current_id" "$old_unit_backup" "$old_unit_existed" 1
                else
                    rm -f -- "$old_unit_backup" 2>/dev/null || true
                    sbmon_warn "无事务前状态可回滚（首次部署），unit 保留以便排查"
                fi
                return 1
            fi
        fi
    else
        sbmon_info "启用并启动 singbox-monitor"
        if ! sbmon_service_enable_now; then
            sbmon_warn "服务启动失败：unit 已保留以便排查（journalctl -u $SBMON_SERVICE_NAME）"
            return 1
        fi
        if ! sbmon_wait_service_active; then
            sbmon_warn "服务未在 ${SBMON_HEALTH_TIMEOUT}s 内激活，请检查 journalctl -u $SBMON_SERVICE_NAME"
            return 1
        fi
        sbmon_info "服务已激活"
    fi

    if [ "$release_changed" = 1 ]; then
        sbmon_prune_releases
    fi
    rm -f -- "$old_unit_backup" 2>/dev/null || true

    sbmon_report_health
    sbmon_info "install 完成（action=$action version=$repo_version）"
}

cmd_upgrade() {
    if [ -z "$(sbmon_current_release_id)" ]; then
        sbmon_die "尚未安装 Monitor；请先运行 install"
    fi
    cmd_install "$@"
}

cmd_rollback() { # rollback [release-id]
    sbmon_acquire_deploy_lock   # P4: rollback mutates release/unit/service
    local target="${1:-}"
    [ -L "$SBMON_APP_LINK" ] || sbmon_die "当前没有已激活的 release"
    local current
    current="$(sbmon_current_release_id)"
    if [ -z "$target" ]; then
        target="$(awk -v cur="$current" '$2 != cur { print $2 }' "$SBMON_HISTORY_FILE" 2>/dev/null | tail -n 1)"
        [ -n "$target" ] || sbmon_die "history 中没有可回滚的 release"
    fi
    [ -d "$SBMON_RELEASES_DIR/$target" ] || sbmon_die "release 不存在: $target"
    sbmon_info "回滚: $current -> $target"
    sbmon_activate_release "$target"
    sbmon_record_history "$target" "$(tr -d ' \t\r\n' < "$SBMON_RELEASES_DIR/$target/VERSION")" "rollback"
    sbmon_service_restart
    if sbmon_wait_service_active; then
        sbmon_info "回滚完成，服务已激活"
        sbmon_report_health
    else
        sbmon_warn "回滚后服务未激活，请检查 journalctl -u $SBMON_SERVICE_NAME"
        return 1
    fi
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
    sbmon_acquire_deploy_lock   # P4: uninstall mutates unit/releases/state
    sbmon_info "卸载 Monitor（仅 Monitor；不触碰 sing-box / 代理凭据 / 配置）"
    sbmon_service_stop_disable
    if [ -e "$SBMON_UNIT_FILE" ]; then
        rm -f -- "$SBMON_UNIT_FILE"
        sbmon_systemctl daemon-reload
    fi
    rm -rf -- "$SBMON_APP_LINK"   # symlink itself; never descends into the release tree
    rm -rf -- "$SBMON_RELEASES_DIR"
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
