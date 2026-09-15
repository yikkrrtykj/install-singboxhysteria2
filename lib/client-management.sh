#!/usr/bin/env bash
# Canonical shared transaction primitives for CLI + future E3 sbox-cm.
#
# This file is intentionally function-only: sourcing it performs no mutation.
# Callers provide the existing install.sh environment/functions such as
# warning/info/candidate_problems and SB_* paths. There must be exactly ONE
# copy of these primitives in the repository; install.sh sources this library
# and the future privileged helper will source the same file.

# ---------------------------------------------------------------- transaction result --
# The legacy CLI keeps the historical 0/1 function return contract. E3 can read
# the structured result after commit_server_config via cm_transaction_result_json.
# Values are deliberately non-sensitive: no UUID/password/secret/key material.
cm_transaction_reset() {
    CM_TX_PHASE="parse"
    CM_TX_CHANGED=false
    CM_TX_RELOAD_PERFORMED=false
    CM_TX_ROLLBACK_ATTEMPTED=false
    CM_TX_ROLLBACK_OK=null
    CM_TX_HEALTH_VERIFIED=false
    CM_TX_BACKUP_PATH=""
}

cm_transaction_result_json() {
    jq -cn \
      --arg phase "${CM_TX_PHASE:-parse}" \
      --argjson changed "${CM_TX_CHANGED:-false}" \
      --argjson reload_performed "${CM_TX_RELOAD_PERFORMED:-false}" \
      --argjson rollback_attempted "${CM_TX_ROLLBACK_ATTEMPTED:-false}" \
      --argjson rollback_ok "${CM_TX_ROLLBACK_OK:-null}" \
      --argjson health_verified "${CM_TX_HEALTH_VERIFIED:-false}" \
      --arg backup_path "${CM_TX_BACKUP_PATH:-}" '
      {
        phase: $phase,
        changed: $changed,
        reload_performed: $reload_performed,
        rollback_attempted: $rollback_attempted,
        rollback_ok: $rollback_ok,
        health_verified: $health_verified,
        backup_path: (if $backup_path == "" then null else $backup_path end)
      }
    '
}

cm_transaction_reset

# ---------------------------------------------------------------- global lock --
# Seconds to wait for the exclusive config lock before aborting. Web/E3 helpers
# MUST run with a finite timeout; the CLI default stays 15 seconds.
SB_LOCK_TIMEOUT="${SB_LOCK_TIMEOUT:-15}"

# Runs "$@" while holding the exclusive config lock (fd 9). FAIL-CLOSED: a
# missing flock binary, lock directory/open failure, acquire error or timeout
# aborts before the callback executes. Callers must never nest this function.
with_client_lock() {
    if ! command -v flock >/dev/null 2>&1; then
        warning "flock 不可用，无法安全地序列化配置修改，操作已中止（fail-closed）"
        return 1
    fi
    if ! mkdir -p "$(dirname "$SB_LOCK_FILE")" 2>/dev/null; then
        warning "无法创建锁目录 $(dirname "$SB_LOCK_FILE")，操作已中止（fail-closed）"
        return 1
    fi
    if ! exec 9>>"$SB_LOCK_FILE" 2>/dev/null; then
        warning "无法打开配置锁文件 $SB_LOCK_FILE，操作已中止（fail-closed）"
        return 1
    fi
    if ! flock -w "$SB_LOCK_TIMEOUT" 9 2>/dev/null; then
        warning "配置锁 $SB_LOCK_FILE 获取失败或超时（${SB_LOCK_TIMEOUT}s），操作已中止（fail-closed）"
        exec 9>&- 2>/dev/null
        return 1
    fi
    "$@"
    local rc=$?
    exec 9>&- 2>/dev/null
    return $rc
}

# ------------------------------------------------------------ runtime reload/health --
reload_running_singbox() {
    if systemctl is-active --quiet sing-box 2>/dev/null; then
        systemctl reload sing-box || return 1
    elif pgrep -x sing-box >/dev/null 2>&1; then
        kill -HUP "$(pgrep -o -x sing-box)" || return 1
    fi
    return 0
}

reload_health_ok() {
    sleep 1
    if systemctl is-active --quiet sing-box 2>/dev/null; then return 0; fi
    pgrep -x sing-box >/dev/null 2>&1
}

# --------------------------------------------------------------- atomic restore --
# Caller holds with_client_lock. Exact backup bytes are copied to a unique temp
# in the target directory, hardened to the requested mode, atomically renamed,
# then verified byte-for-byte. Config/state callers omit <mode> and get 0600;
# the Phase-D binary rollback passes 0755. This is the ONE restore primitive for
# both generic config transactions and the Phase-D paired transaction.
restore_file_atomically() { # <backup> <live> [mode=0600]
    local backup="$1" live="$2" mode="${3:-0600}" tmp=""
    if [ -z "$backup" ] || [ -z "$live" ]; then
        warning "restore_file_atomically: 参数不能为空"
        return 1
    fi
    case "$mode" in
        0600|0644|0755) : ;;
        *) warning "restore_file_atomically: 非法目标权限 $mode"; return 1 ;;
    esac
    if [ -L "$backup" ] || [ ! -f "$backup" ]; then
        warning "备份不是普通文件（缺失或符号链接），拒绝恢复: $backup"
        return 1
    fi
    if ! tmp="$(mktemp "${live}.restore.XXXXXX" 2>/dev/null)"; then
        warning "创建恢复临时文件失败（需与目标同目录）: ${live}.restore.XXXXXX"
        return 1
    fi
    if ! cp -a "$backup" "$tmp" 2>/dev/null; then
        warning "写入恢复临时文件失败: $tmp"
        rm -f "$tmp"
        return 1
    fi
    if ! chmod "$mode" "$tmp" 2>/dev/null; then
        warning "恢复临时文件权限设置为 $mode 失败: $tmp"
        rm -f "$tmp"
        return 1
    fi
    if ! mv -f "$tmp" "$live" 2>/dev/null; then
        warning "恢复文件原子替换失败: $live"
        rm -f "$tmp"
        return 1
    fi
    if ! cmp -s "$backup" "$live" 2>/dev/null; then
        warning "恢复校验失败：$live 与备份 $backup 内容不一致"
        return 1
    fi
    return 0
}

# ------------------------------------------------------------ candidate/backup paths --
new_candidate_path() {
    mktemp "${SB_SERVER_CONFIG}.candidate.XXXXXX" 2>/dev/null
}

new_backup_path() {
    mktemp "${SB_SERVER_CONFIG}.bak.$(date +%Y%m%d-%H%M%S).XXXXXX" 2>/dev/null
}

# ----------------------------------------------------------- canonical commit engine --
# The caller MUST already hold with_client_lock. Existing CLI behavior stays 0/1;
# the non-sensitive structured state is available through cm_transaction_result_json.
commit_server_config() { # <candidate> <description>
    local candidate="$1" description="${2:-server config update}"
    local backup_path was_running problems

    cm_transaction_reset
    CM_TX_PHASE="candidate"

    [ -f "$candidate" ] || { warning "candidate 不存在: $candidate"; return 1; }

    if ! problems="$(candidate_problems "$candidate")"; then
        warning "candidate 结构审计执行失败（$description），正式配置未修改"
        rm -f "$candidate"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "candidate 结构一致性检查失败（$description），正式配置未修改:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        rm -f "$candidate"
        return 1
    fi

    CM_TX_PHASE="check"
    if ! "$SB_SING_BOX_BIN" check -c "$candidate" >/dev/null 2>&1; then
        warning "sing-box check 未通过（$description），正式配置未修改"
        rm -f "$candidate"
        return 1
    fi

    if systemctl is-active --quiet sing-box 2>/dev/null; then
        was_running=systemd
    elif pgrep -x sing-box >/dev/null 2>&1; then
        was_running=manual
    else
        was_running=no
    fi

    CM_TX_PHASE="backup"
    backup_path="$(new_backup_path)" || {
        warning "创建备份文件失败（$description），正式配置未修改"
        rm -f "$candidate"
        return 1
    }
    CM_TX_BACKUP_PATH="$backup_path"

    cp -a "$SB_SERVER_CONFIG" "$backup_path" || {
        warning "备份正式配置失败（$description），正式配置未修改"
        rm -f "$candidate"
        return 1
    }
    if ! chmod 0600 "$backup_path" 2>/dev/null; then
        warning "备份文件权限收紧为 0600 失败（$description），正式配置未修改"
        rm -f "$backup_path" "$candidate"
        CM_TX_BACKUP_PATH=""
        return 1
    fi

    CM_TX_PHASE="replace"
    if ! mv -f "$candidate" "$SB_SERVER_CONFIG"; then
        warning "原子替换失败（$description），已保留备份: $backup_path"
        rm -f "$candidate"
        return 1
    fi
    CM_TX_CHANGED=true

    if [ "$was_running" != "no" ]; then
        CM_TX_PHASE="reload"
        CM_TX_RELOAD_PERFORMED=true
        if reload_running_singbox; then
            CM_TX_PHASE="health"
            if reload_health_ok; then
                CM_TX_HEALTH_VERIFIED=true
                info "配置已提交并重载成功: $description"
                info "上一份配置备份: $backup_path"
                return 0
            fi
        fi

        warning "reload 后健康检查失败（$description），自动回滚..."
        CM_TX_PHASE="rollback"
        CM_TX_ROLLBACK_ATTEMPTED=true
        if ! restore_file_atomically "$backup_path" "$SB_SERVER_CONFIG" 0600; then
            CM_TX_PHASE="rollback_manual"
            CM_TX_ROLLBACK_OK=false
            warning "回滚恢复失败，请立即人工介入！备份: $backup_path"
            return 1
        fi
        CM_TX_ROLLBACK_OK=true
        CM_TX_CHANGED=false

        if reload_running_singbox && reload_health_ok; then
            CM_TX_HEALTH_VERIFIED=true
            warning "已回滚并重新加载上一份配置: $backup_path"
        else
            # Disk bytes are restored, but rollback is not operationally
            # complete until the previous runtime is confirmed healthy.
            CM_TX_PHASE="rollback_manual"
            CM_TX_ROLLBACK_OK=false
            warning "已回滚配置文件，但服务未能确认恢复，请立即人工检查！备份: $backup_path"
        fi
        return 1
    fi

    info "配置已提交（当前无运行中的 sing-box 进程，跳过 reload）: $description"
    info "上一份配置备份: $backup_path"
    return 0
}
