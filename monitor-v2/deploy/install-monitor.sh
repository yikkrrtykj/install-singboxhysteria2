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
                                                        （含 journal-reader 激活事务：
                                                        身份/目录/运行时/unit/启动，
                                                        任一步失败整体回滚）
  upgrade                                               等价 install（未安装则拒绝）
  rollback [release-id]                                 回滚 release（只重启 monitor +
                                                        reader 运行时/状态按事务前恢复；
                                                        绝不触碰 sing-box / sbox-cm）
  web-setup                                             以 sboxweb 身份运行已评审的
                                                        webapp.py setup（交互式；
                                                        白名单/口令/恢复键）
  history                                               release 历史
  health                                                输出分离式健康 JSON（只读）
  status                                                版本 + 目录 + 服务状态（只读）
  uninstall [--purge-state] [--purge-config] [--purge-backups]
                                                        卸载 Monitor + reader（unit/运行时
                                                        移除；reader 状态/输出与身份默认
                                                        保留，--purge-state 一并清除数据）
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
    sbmon_preflight_commands   # capability detection (python3/systemctl/journalctl/jq/ss/flock/stat/sha256sum/mktemp)
    sbmon_record_environment   # diagnostics only (no secrets)
    [ -f "$DEPLOY_DIR/singbox-monitor.service.in" ] || sbmon_die "缺少 unit 模板"
    [ -d "$SBMON_REPO_MONITOR_DIR" ] || sbmon_die "缺少 monitor-v2 源目录: $SBMON_REPO_MONITOR_DIR"
    # PR-2B: reader activation gate -- non-mutating. A wrong-shaped existing
    # sbox-jr identity or a missing verify/readability tool stops the WHOLE
    # command here, before any staging (spec §3: never "quietly fix").
    sbmon_sboxjr_activation_preflight

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
    # PR-2B: reader transaction pre-state (active/enabled/unit/runtime-link/
    # identity-created), captured under the same deploy lock BEFORE any
    # mutation of this transaction.
    sbmon_sboxjr_capture_prestate

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
    # PR-2B: the reader activation transaction is part of the SAME gate:
    # monitor first (primary product), then the reader producer service;
    # a reader failure rolls the whole deployment back (no Monitor-new /
    # reader-half state can be committed).
    local deploy_rc=0
    if ! sbmon_apply_candidate "$new_id" "$was_active" "$OPT_NO_START"; then
        deploy_rc=1
    elif ! sbmon_sboxjr_converge "$new_id" "$OPT_NO_START" 0; then
        deploy_rc=1
    fi
    if [ "$deploy_rc" != 0 ]; then
        sbmon_warn "candidate 部署失败，进入事务回滚"
        sbmon_sboxjr_restore_prestate
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
    rm -f -- "$SBOXJR_PRE_UNIT_BACKUP" 2>/dev/null || true

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
    sbmon_preflight_commands   # fail closed BEFORE any mutation
    local target="${1:-}"
    [ -L "$SBMON_APP_LINK" ] || sbmon_die "当前没有已激活的 release"
    local current
    current="$(sbmon_current_release_id)"
    if [ -z "$target" ]; then
        # R4-3: default target = NEWEST history entry that (a) is not the
        # current release and (b) still has a release directory. History is
        # a durable commit record -- pruned releases keep their entries and
        # are skipped here, never rewritten.
        target=""
        if [ -r "$SBMON_HISTORY_FILE" ]; then
            local hid
            while read -r _ hid _; do
                [ -n "$hid" ] || continue
                [ "$hid" = "$current" ] && continue
                [ -d "$SBMON_RELEASES_DIR/$hid" ] || continue
                target="$hid"
                break
            done < <(tac "$SBMON_HISTORY_FILE")
        fi
        [ -n "$target" ] || sbmon_die "history 中没有仍保留的可回滚 release（全部已被 retention 清理）"
    fi
    [ -d "$SBMON_RELEASES_DIR/$target" ] || sbmon_die "release 不存在: $target"

    # PR-2B reader compatibility gate (BEFORE any mutation): once the reader
    # has been activated, its runtime/unit-template live INSIDE the release
    # tree, so a rollback target must carry them -- otherwise Monitor would
    # roll back while the reader keeps running incompatible code (the exact
    # mixed-version state this contract forbids). A never-activated reader
    # (pre-PR-2B dark state) stays untouched by rollback.
    local reader_deployed=0
    if [ -e "$SBOXJR_UNIT_FILE" ] || [ -L "$SBOXJR_LIB_DIR" ] \
       || sbmon_sboxjr_service_active || sbmon_sboxjr_service_enabled; then
        reader_deployed=1
    fi
    if [ "$reader_deployed" = 1 ] \
       && [ ! -d "$(sbmon_sboxjr_release_runtime_dir "$target")" ]; then
        sbmon_die "回滚目标 $target 不含 reader 运行时（pre-PR-2B release）：reader 已激活时拒绝回滚，避免 Monitor/reader 混版本；fail-closed，未做任何变更"
    fi

    # R3-2: capture the full pre-state BEFORE touching anything.
    local orig_active=0 orig_enabled=0
    if sbmon_service_active; then orig_active=1; fi
    if sbmon_service_enabled; then orig_enabled=1; fi
    sbmon_sboxjr_capture_prestate

    sbmon_info "回滚: $current -> $target"
    local rollback_rc=0
    if ! sbmon_apply_rollback_target "$target" "$orig_active" "$orig_enabled"; then
        rollback_rc=1
    elif [ "$reader_deployed" = 1 ] && ! sbmon_sboxjr_converge "$target" 0 1; then
        sbmon_warn "rollback: reader 运行时/unit 收敛失败"
        rollback_rc=2
    fi
    if [ "$rollback_rc" != 0 ]; then
        sbmon_warn "rollback target 未能健康应用：恢复原 release $current"
        if [ "$rollback_rc" = 2 ]; then
            sbmon_sboxjr_restore_prestate
        else
            rm -f -- "$SBOXJR_PRE_UNIT_BACKUP" 2>/dev/null || true
        fi
        if sbmon_restore_original_after_rollback "$current" "$orig_active" "$orig_enabled"; then
            sbmon_warn "已恢复到原 release（rollback 未完成）；未写入任何 history"
        else
            sbmon_critical "rollback 恢复亦失败（见上方 CRITICAL）"
        fi
        return 1
    fi
    rm -f -- "$SBOXJR_PRE_UNIT_BACKUP" 2>/dev/null || true
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

# ---------------------------------------------------------------------------
# R1-8 / R1.1-B,E: web-setup -- run the already-reviewed E2 `webapp.py setup`
# AS THE SERVICE IDENTITY so auth.json / access.json are never root-owned.
#   * under the deployment lock (F4);
#   * E: the setup runs in an EXPLICIT CLEAN environment (`env -i`): only
#     HOME (the data root), a fixed approved PATH and SSH_CONNECTION are
#     forwarded. The caller's environment is NOT inherited (no BOX_API_SECRET,
#     no token/cookie, no arbitrary env); the python binary is resolved by
#     root first (`command -v`) and passed as an absolute path;
#   * SSH_CONNECTION is the only data value forwarded (E2 uses it to OFFER the
#     current SSH source /32|/128 -- it never auto-adds without confirmation);
#   * fully interactive: the password prompt and the one-time recovery-key
#     display stay on the terminal; no plaintext password is accepted or
#     echoed non-interactively; neither password nor recovery key is ever
#     written to the argv, the environment, the journal or the installer log;
#   * B: after setup, NO root-side chown/chmod of auth.json / access.json (or
#     any service-owned child). The installer only runs a NON-DESTRUCTIVE
#     postcondition check; a mismatch fails closed with a manual-fix hint --
#     it never "rescues" root-owned data automatically;
#   * if the monitor service WAS active, restart ONLY singbox-monitor so a
#     process started with auth=None reloads the fresh AuthStore;
#     sing-box is never touched;
#   * never run automatically as part of unattended install.
# ---------------------------------------------------------------------------
cmd_web_setup() {
    sbmon_with_deploy_lock _cmd_web_setup_locked
}

# Non-sensitive post-setup access hint (operator UX only). By contract this
# NEVER prints or infers the server public IP, NEVER prints secrets, NEVER
# auto-adds whitelist entries and NEVER touches firewall/sshd configuration.
sbmon_print_web_access_hint() {
    cat <<'EOF'

Dashboard listens on loopback only:
  127.0.0.1:9191

From your workstation:
  ssh -L 19191:127.0.0.1:9191 root@<server>

Then open:
  http://127.0.0.1:19191

Note: 127.0.0.1 and ::1 are implicitly allowed, so SSH port-forward access
does NOT require adding your public SSH source IP to the Monitor whitelist
(the tunneled browser connection appears to Monitor as loopback). If you
answered "n" during setup and no whitelist entry was ever written,
access.json may not exist -- that is not an error.
EOF
}

_cmd_web_setup_locked() {
    local release_id webapp
    release_id="$(sbmon_current_release_id)"
    [ -n "$release_id" ] || sbmon_die "web-setup: 当前没有已激活的 release（先 install）"
    webapp="$SBMON_RELEASES_DIR/$release_id/app/monitor-v2/webapp.py"
    [ -f "$webapp" ] || sbmon_die "web-setup: 当前 release 缺少 webapp.py（release 布局异常）：fail-closed"

    local ssh_conn="${SSH_CONNECTION:-}"
    local was_active=0
    if sbmon_service_active; then was_active=1; fi

    # E: build the explicit clean environment ONCE (never inherit the caller).
    local -a setup_env=(env -i \
        HOME="$SBMON_STATE_ROOT" \
        PATH=/usr/sbin:/usr/bin:/sbin:/bin)
    if [ -n "$ssh_conn" ]; then
        setup_env+=("SSH_CONNECTION=$ssh_conn")
    fi

    local rc=0
    if [ "$SBMON_FIXTURE" = "1" ]; then
        # Fixture/non-root test runs execute directly (same reviewed code),
        # still under the same clean environment contract.
        "${setup_env[@]}" "$SBMON_PYTHON3" "$webapp" setup \
            --data-dir "$SBMON_STATE_ROOT" || rc=$?
    else
        command -v "$SBMON_SUDO" >/dev/null 2>&1 \
            || sbmon_die "web-setup: 缺少 sudo，无法以 $SBMON_USER 运行 setup：fail-closed"
        # E: resolve the interpreter as root, then exec it by absolute path
        # inside the clean env (the fixed PATH does not have to contain it).
        local pybin
        pybin="$(command -v "$SBMON_PYTHON3")" \
            || sbmon_die "web-setup: 找不到 python3（$SBMON_PYTHON3）：fail-closed"
        # -n: non-interactive sudo (fail instead of prompting for a root
        # password mid-setup). stdin/stdout/stderr/TTY stay attached.
        "$SBMON_SUDO" -n -u "$SBMON_USER" -- "${setup_env[@]}" \
            "$pybin" "$webapp" setup \
            --data-dir "$SBMON_STATE_ROOT" || rc=$?
    fi
    if [ "$rc" != 0 ]; then
        # B: honest failure message. E2 setup performs several persistence
        # steps; a later-step failure does NOT prove earlier steps wrote
        # nothing, so we never claim the data is byte-identical/unchanged.
        sbmon_warn "web setup 失败（rc=$rc）；setup 可能已完成部分持久化写入，请检查 $SBMON_STATE_ROOT/auth.json 与 access.json 后重试；Monitor 未因本次失败自动重启。"
        return "$rc"
    fi

    # B: NO root-side privileged mutation of service-owned children. Ownership
    # and mode of the data root / auth.json / access.json are guaranteed by
    # E2 storage/setup itself; here we only VERIFY (never chown/chmod).
    if ! sbmon_verify_service_owned_tree; then
        sbmon_warn "web setup 后置校验失败：未重启 Monitor；请按上方提示人工修复数据根/auth.json/access.json 权限后重试"
        return 1
    fi
    sbmon_info "web setup 完成（auth.json / access.json 位于 $SBMON_STATE_ROOT，属主 $SBMON_USER）"
    sbmon_print_web_access_hint

    if [ "$was_active" = 1 ]; then
        sbmon_info "重启 singbox-monitor 以加载新创建的 AuthStore（仅 Monitor，不触碰 sing-box）"
        if ! sbmon_service_restart; then
            sbmon_warn "web setup 后服务重启失败"
            return 1
        fi
        if ! sbmon_wait_service_active; then
            sbmon_warn "web setup 后服务未恢复 active"
            return 1
        fi
    else
        sbmon_info "服务此前未运行：不启动（web-setup 不改变服务状态）"
    fi
    return 0
}

cmd_health() {
    local probe
    probe="$(sbmon_health_cmd)"
    [ -x "$probe" ] || sbmon_die "health probe 不存在（未安装？）: $probe"
    # P1: explicit conf + data-root contract; the probe never infers the
    # state path from the caller's working directory.
    exec "$probe" "$(sbmon_conf_file)" "$SBMON_STATE_ROOT" "$@"
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
    # PR-2B reader facts -- READ-ONLY by contract (statically asserted: no
    # enable/start/converge/ensure may ever appear in this command body).
    printf '  jr unit:    %s\n' "$SBOXJR_UNIT_FILE"
    local jr_state="inactive" jr_boot="disabled"
    if sbmon_sboxjr_service_active; then jr_state=active; fi
    if sbmon_sboxjr_service_enabled; then jr_boot=enabled; fi
    printf '  jr state:   %s/%s\n' "$jr_state" "$jr_boot"
    printf '  jr runtime: %s\n' "$( [ -L "$SBOXJR_LIB_DIR" ] && readlink "$SBOXJR_LIB_DIR" || printf '<none>' )"
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
    sbmon_preflight_commands   # fail closed BEFORE any mutation
    sbmon_info "卸载 Monitor + journal-reader（仅两者；不触碰 sing-box / sbox-cm / 代理凭据 / 配置）"
    # R4-2: idempotency comes from CHECKING state, never from swallowing
    # errors. Already-absent states are fine; a FAILED stop/disable aborts
    # BEFORE any destructive deletion.
    # PR-2B: the reader is dismantled FIRST (its runtime lives inside the
    # release tree that is deleted below). Default retention mirrors the
    # Monitor: unit + runtime link go, identity + reader state/output data
    # stay unless --purge-state is given explicitly.
    if sbmon_sboxjr_service_active; then
        if ! sbmon_sboxjr_service_stop; then
            sbmon_die "reader 服务停止失败：拒绝在 reader 运行时删除部署文件"
        fi
    fi
    if sbmon_sboxjr_service_enabled; then
        if ! sbmon_sboxjr_service_disable; then
            sbmon_die "reader 服务 disable 失败：拒绝在 enabled 状态下删除部署文件"
        fi
    fi
    if sbmon_sboxjr_service_active; then
        sbmon_critical "卸载前校验失败：reader 仍处于运行状态"
    fi
    if sbmon_sboxjr_service_enabled; then
        sbmon_critical "卸载前校验失败：reader 仍处于 enabled 状态"
    fi
    if [ -e "$SBOXJR_UNIT_FILE" ]; then
        if ! rm -f -- "$SBOXJR_UNIT_FILE"; then
            sbmon_critical "reader unit 删除失败（卸载已开始，处于部分删除状态）；需要人工处理"
        fi
        if ! sbmon_systemctl daemon-reload; then
            sbmon_critical "reader unit 删除后 daemon-reload 失败；需要人工处理"
        fi
    fi
    if ! sbmon_sboxjr_unlink_runtime; then
        sbmon_critical "reader 运行时链接删除失败（拒绝经它删除真实目录）；需要人工处理"
    fi
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
        sbmon_info "--purge-state: 删除 $SBMON_STATE_ROOT（auth/access/state）与 $SBOXJR_DATA_ROOT（reader cursor/state/输出）"
        rm -rf -- "$SBMON_STATE_ROOT"
        rm -rf -- "$SBOXJR_DATA_ROOT"
    else
        sbmon_info "保留状态目录（auth/access/state）: $SBMON_STATE_ROOT（--purge-state 可删除）"
        sbmon_info "保留 reader 诊断数据（cursor/state/exchange）: $SBOXJR_DATA_ROOT（--purge-state 可删除）"
    fi
    sbmon_info "保留系统身份 $SBOXJR_USER/$SBMON_USER（卸载从不删除账号；如需清除请人工 userdel）"
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
        web-setup) cmd_web_setup "$@" ;;
        history)   cmd_history ;;
        health)    cmd_health "$@" ;;
        status)    cmd_status ;;
        uninstall) cmd_uninstall "$@" ;;
        -h|--help) usage ;;
        *) usage; sbmon_die "未知命令: $cmd" ;;
    esac
}

main "$@"
