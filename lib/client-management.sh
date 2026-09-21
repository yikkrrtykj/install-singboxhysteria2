#!/usr/bin/env bash
# Canonical shared client-management + transaction library.
#
# This file is intentionally function-only: sourcing it performs no mutation.
# It is the SINGLE canonical source of the client-management semantics shared by
# BOTH writers:
#
#     install.sh (root CLI)
#                 \
#                  -> lib/client-management.sh   (this file)
#                 /
#     sbox-cm transaction worker
#
# There must be exactly ONE copy of every primitive below in the repository.
# install.sh sources this library and binds itself to the reviewed bytes via an
# embedded SHA-256 pin; the privileged worker sources the very same file.
#
# Callers must provide the CLI/logging surface (warning/info); everything else
# (paths, inbound tags, name rules) has a self-sufficient default so the library
# is usable by a non-interactive root worker with a clean environment.
#
# E3 M1: this file MUST NOT print credential material, MUST NOT place
# credential material into argv, and MUST NOT write it to any file. See the
# "planned credentials" section for the only sanctioned credential path.

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

# --------------------------------------------------------- canonical configuration --
# Self-sufficient defaults: the CLI exports its own (identical) values before
# sourcing; the privileged worker sets production constants explicitly and
# rejects environment injection. A caller may override any of these.
SB_SERVER_CONFIG="${SB_SERVER_CONFIG:-/root/sbox/sbconfig_server.json}"
SB_STATE_FILE="${SB_STATE_FILE:-/root/sbox/config}"
SB_CLIENTS_DIR="${SB_CLIENTS_DIR:-/root/sbox/clients}"
SB_SING_BOX_BIN="${SB_SING_BOX_BIN:-/root/sbox/sing-box}"
SB_LOCK_FILE="${SB_LOCK_FILE:-/root/sbox/config.lock}"

# The name "legacy" is RESERVED (pre-Phase-C shared account): it is never
# created by "add" and never removed by "delete" in this version.
RESERVED_CLIENT_NAME="${RESERVED_CLIENT_NAME:-legacy}"
# NOTE: assigned with an explicit test, not ${VAR:-...}: the default value
# itself contains "}" (the {0,31} quantifier), which would terminate a
# parameter expansion early.
if [ -z "${CLIENT_NAME_PATTERN:-}" ]; then
    CLIENT_NAME_PATTERN='^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$'
fi
REALITY_INBOUND_TAG="${REALITY_INBOUND_TAG:-vless-in}"
HY2_INBOUND_TAG="${HY2_INBOUND_TAG:-hy2-in}"

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
# Every external substep is BOUNDED (rev5 M1 deadline revision): there is no
# whole-op kill timer anywhere (a post-intent mutation must never be aborted),
# so the only protection against a hung subcommand is a per-subcommand timeout.
# `timeout` is used only for EXTERNAL commands: shell functions (the shim
# surface the test suites inject, and anything a caller overrides) must still
# resolve in-process -- `timeout` would exec a subshell where functions do not
# exist and silently break every shim.
cm_bounded() { # <seconds> <command...>
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1 && ! declare -F -- "$1" >/dev/null 2>&1; then
        timeout "$secs" "$@"
    else
        "$@"
    fi
}

reload_running_singbox() {
    if cm_bounded "${SB_SYSTEMCTL_TIMEOUT:-30}" systemctl is-active --quiet sing-box 2>/dev/null; then
        cm_bounded "${SB_RELOAD_TIMEOUT:-60}" systemctl reload sing-box || return 1
    elif pgrep -x sing-box >/dev/null 2>&1; then
        kill -HUP "$(pgrep -o -x sing-box)" || return 1
    fi
    return 0
}

reload_health_ok() {
    sleep 1
    if cm_bounded "${SB_SYSTEMCTL_TIMEOUT:-30}" systemctl is-active --quiet sing-box 2>/dev/null; then return 0; fi
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
#
# Durable phase journal hook (E3 M1 review B1): when the caller sets
# CM_TX_JOURNAL_HOOK to a function name, that function is invoked
#     cm_journal_hook <phase> <backup_path>
# BEFORE each phase's irreversible action -- critically BEFORE the mv in
# 'replace' -- so a crash at ANY point leaves a journal from which startup
# reconciliation can prove a safe state (disk-new -> reload; unhealthy ->
# restore backup). The hook must be durable (fsync) before returning 0. A hook
# failure is FAIL-CLOSED: the transaction aborts (pre-replace: zero mutation;
# post-replace: routed into the normal rollback path).
cm_tx_journal_phase() { # <phase>
    CM_TX_PHASE="$1"
    if [ -n "${CM_TX_JOURNAL_HOOK:-}" ]; then
        "$CM_TX_JOURNAL_HOOK" "$1" "${CM_TX_BACKUP_PATH:-}" || return 1
    fi
    return 0
}

commit_server_config() { # <candidate> <description>
    local candidate="$1" description="${2:-server config update}"
    local backup_path was_running problems tx_bad

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

    if ! cm_tx_journal_phase "check"; then
        rm -f "$candidate"
        return 1
    fi
    if ! cm_bounded "${SB_CHECK_TIMEOUT:-60}" "$SB_SING_BOX_BIN" check -c "$candidate" >/dev/null 2>&1; then
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
    if ! cm_tx_journal_phase "backup"; then
        rm -f "$backup_path" "$candidate"
        CM_TX_BACKUP_PATH=""
        return 1
    fi

    # The critical durable boundary: the journal MUST already say
    # phase=replace + backup_path on stable storage BEFORE the live file moves.
    if ! cm_tx_journal_phase "replace"; then
        rm -f "$candidate"
        return 1
    fi
    if ! mv -f "$candidate" "$SB_SERVER_CONFIG"; then
        warning "原子替换失败（$description），已保留备份: $backup_path"
        rm -f "$candidate"
        return 1
    fi
    CM_TX_CHANGED=true

    if [ "$was_running" != "no" ]; then
        tx_bad=false
        CM_TX_RELOAD_PERFORMED=true
        if ! cm_tx_journal_phase "reload"; then
            tx_bad=true
        elif ! reload_running_singbox; then
            tx_bad=true
        elif ! cm_tx_journal_phase "health"; then
            tx_bad=true
        elif ! reload_health_ok; then
            tx_bad=true
        fi
        if [ "$tx_bad" != "true" ]; then
            CM_TX_HEALTH_VERIFIED=true
            info "配置已提交并重载成功: $description"
            info "上一份配置备份: $backup_path"
            return 0
        fi

        warning "reload 后健康检查失败（$description），自动回滚..."
        CM_TX_ROLLBACK_ATTEMPTED=true
        # Journal the rollback intent best-effort: the restore itself matters
        # more than the record, and a failed journal write must not skip it.
        cm_tx_journal_phase "rollback" || warning "回滚前 journal 写入失败（回滚照常执行）"
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

# ============================================================================
# M1-A0: canonical client-management semantics (moved verbatim out of install.sh)
# These were previously defined in install.sh, which forced every other writer
# (the privileged worker) to either source the whole installer or copy them.
# There is now exactly ONE definition of each.
# ============================================================================

validate_client_name() { # validate_client_name <name> -> rc 0 if allowed
    local name="$1"
    [ -n "$name" ] || return 1
    [[ "$name" =~ $CLIENT_NAME_PATTERN ]] || return 1
    return 0
}

get_reality_client_names() { # [config] -> one name per line ("" = unnamed user)
    jq -r --arg tag "$REALITY_INBOUND_TAG" \
        '.inbounds[] | select(.tag == $tag) | .users[]? | (.name // "")' \
        "${1:-$SB_SERVER_CONFIG}" 2>/dev/null | tr -d '\r'
}

get_hy2_client_names() { # [config] -> one name per line ("" = unnamed user)
    jq -r --arg tag "$HY2_INBOUND_TAG" \
        '.inbounds[] | select(.tag == $tag) | .users[]? | (.name // "")' \
        "${1:-$SB_SERVER_CONFIG}" 2>/dev/null | tr -d '\r'
}

# Structural precheck only: root must be an object, .inbounds must exist and be
# an array, vless-in/hy2-in must each appear EXACTLY once, and their users
# field must exist and be an array. Deliberately separate from the identity
# audit: legacy migration must accept users WITHOUT names, so it runs only
# this check before counting unnamed users. The jq exit code propagates to the
# function: any runtime error means FAIL, never "no problems".
client_structure_problems() { # client_structure_problems <config> -> prints problem lines
    jq -r '
      if (type != "object") then ["配置根节点不是 object"]
      elif ((.inbounds // null) | type) != "array" then
        (if (.inbounds // null) == null then ["缺少 inbounds 字段"] else ["inbounds 不是数组"] end)
      else
        (
          ([.inbounds[] | select(.tag == "vless-in")]) as $ri |
          ([.inbounds[] | select(.tag == "hy2-in")]) as $hi |
          ([]
            + (if ($ri | length) == 0 then ["缺少 vless-in 入站"] else [] end)
            + (if ($ri | length) > 1 then ["vless-in 入站数量不是 1（实际 \($ri | length) 个）"] else [] end)
            + (if ($hi | length) == 0 then ["缺少 hy2-in 入站"] else [] end)
            + (if ($hi | length) > 1 then ["hy2-in 入站数量不是 1（实际 \($hi | length) 个）"] else [] end)
            + (if ($ri | length) == 1 then
                 (if ($ri[0] | has("users") | not) then ["vless-in 缺少 users 字段"]
                  elif (($ri[0].users) | type) != "array" then ["vless-in 的 users 不是数组"]
                  else [] end)
               else [] end)
            + (if ($hi | length) == 1 then
                 (if ($hi[0] | has("users") | not) then ["hy2-in 缺少 users 字段"]
                  elif (($hi[0].users) | type) != "array" then ["hy2-in 的 users 不是数组"]
                  else [] end)
               else [] end)
          )
        )
      end | .[]
    ' "$1" 2>/dev/null
}

# Full identity audit: structure first, then the per-user rules. FAIL-CLOSED:
# a jq/runtime error inside either stage is an audit FAILURE, never "no
# problems found" -- callers must check this function's exit code, not just
# its stdout.
candidate_problems() { # candidate_problems <config> -> prints problem lines (empty = OK)
    local structural
    structural="$(client_structure_problems "$1")" || return $?
    if [ -n "$structural" ]; then
        printf '%s\n' "$structural"
        return 0
    fi
    jq -r '
      ([.inbounds[] | select(.tag == "vless-in")][0].users) as $ru |
      ([.inbounds[] | select(.tag == "hy2-in")][0].users) as $hu |
      ([ $ru[] | .name // "" ]) as $rn |
      ([ $hu[] | .name // "" ]) as $hn |
      ([ $ru[] | .uuid // "" ]) as $rid |
      ([ $hu[] | .password // "" ]) as $hp |
      ([ $ru[] | .flow // "" ]) as $rf |
      ([]
        + (if ($rn | index("")) != null then ["vless-in 存在没有 name 的用户"] else [] end)
        + (if ($hn | index("")) != null then ["hy2-in 存在没有 name 的用户"] else [] end)
        + (if ($rn | sort) == ($hn | sort) then [] else ["Reality 与 HY2 的 name 集合不一致"] end)
        + (if ($rn | length) == ($rn | unique | length) then [] else ["vless-in 存在重复 name"] end)
        + (if ($hn | length) == ($hn | unique | length) then [] else ["hy2-in 存在重复 name"] end)
        + (if ($rid | index("")) != null then ["vless-in 存在没有 uuid 的用户"] else [] end)
        + (if ($hp | index("")) != null then ["hy2-in 存在没有 password 的用户"] else [] end)
        + (if ($rid | length) == ($rid | unique | length) then [] else ["vless-in 存在重复 uuid"] end)
        + (if ($hp | length) == ($hp | unique | length) then [] else ["hy2-in 存在重复 password"] end)
        + (if ($rf | all(. == "xtls-rprx-vision")) then [] else ["vless-in 存在 flow 不等于 xtls-rprx-vision 的用户"] end)
      )[]
    ' "$1" 2>/dev/null
}

audit_client_consistency() { # audit_client_consistency [config] -> table + rc
    local cfg="${1:-$SB_SERVER_CONFIG}" problems rn hn union name r h p
    if [ ! -f "$cfg" ]; then
        warning "服务端配置不存在: $cfg"
        return 1
    fi
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    # FAIL-CLOSED: a jq/runtime error inside the audit is an audit failure,
    # never equivalent to "no problems found".
    if ! problems="$(candidate_problems "$cfg")"; then
        warning "客户端结构审计执行失败: $cfg"
        return 1
    fi
    rn="$(get_reality_client_names "$cfg")"
    hn="$(get_hy2_client_names "$cfg")"
    printf '%-16s %-12s %s\n' "NAME" "REALITY" "HY2"
    union="$(printf '%s\n%s\n' "$rn" "$hn" | sed '/^$/d' | sort -u)"
    while IFS= read -r name; do
        [ -n "$name" ] || continue
        r="MISSING"; h="MISSING"
        grep -qxF "$name" <<<"$rn" && r="OK"
        grep -qxF "$name" <<<"$hn" && h="OK"
        printf '%-16s %-12s %s\n' "$name" "$r" "$h"
    done <<< "$union"
    if [ -n "$problems" ]; then
        warning "客户端一致性检查发现问题:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    info "客户端一致性检查通过（Reality 与 HY2 的 name 集合完全一致）"
    return 0
}

client_name_exists() { # client_name_exists <name> [config] -> rc 0 if present in either inbound
    local name="$1" cfg="${2:-$SB_SERVER_CONFIG}"
    grep -qxF "$name" <(get_reality_client_names "$cfg") ||
        grep -qxF "$name" <(get_hy2_client_names "$cfg")
}

get_client_credentials() { # get_client_credentials <name> [config] -> "uuid\npassword"
    local name="$1" cfg="${2:-$SB_SERVER_CONFIG}" uuid password
    uuid="$(jq -r --arg name "$name" --arg tag "$REALITY_INBOUND_TAG" '
        .inbounds[] | select(.tag == $tag) | .users[]? | select(.name == $name) | .uuid // ""
    ' "$cfg" 2>/dev/null)"
    password="$(jq -r --arg name "$name" --arg tag "$HY2_INBOUND_TAG" '
        .inbounds[] | select(.tag == $tag) | .users[]? | select(.name == $name) | .password // ""
    ' "$cfg" 2>/dev/null)"
    [ -n "$uuid" ] && [ -n "$password" ] || return 1
    printf '%s\n%s\n' "$uuid" "$password"
}

# ============================================================================
# M4-A: canonical Mihomo/Clash Meta client YAML renderer (single source).
#
# Pure renderer: prints the client YAML to stdout and writes NOTHING
# anywhere -- no temp file, no log line, no diagnostic. Credential material
# never enters argv/env: jq reads the config file directly and the values
# travel through shell memory into this shell's own heredoc expansion only.
#
# install.sh `generate_client_configuration` and the privileged sbox-cm
# `client.export` op MUST render through this exact copy; the byte-identical
# regressions pin the output against the historical template.
# Failures are silent (rc only) -- the caller owns user-facing messages.
# ============================================================================
cm_render_client_mihomo_yaml() { # <name> [config] -> mihomo YAML on stdout
    local name="$1" cfg="${2:-$SB_SERVER_CONFIG}"
    local creds uuid password reality_uuid hy_password
    local server_ip public_key reality_port reality_server_name short_id
    local hy_port hy_server_name ishopping hy_hopping_start hy_hopping_end
    local hy_clash_port_yaml formatted_range=""

    validate_client_name "$name" || return 1
    [ -f "$cfg" ] || return 1
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        return 1
    fi
    if ! creds="$(get_client_credentials "$name" "$cfg")"; then
        return 1
    fi
    uuid="$(printf '%s\n' "$creds" | sed -n '1p')"
    password="$(printf '%s\n' "$creds" | sed -n '2p')"

    # State facts use the same frozen parsing as the historical CLI renderer.
    server_ip="$(grep -o "SERVER_IP='[^']*'" "$SB_STATE_FILE" 2>/dev/null | awk -F"'" '{print $2}')"
    public_key="$(grep -o "PUBLIC_KEY='[^']*'" "$SB_STATE_FILE" 2>/dev/null | awk -F"'" '{print $2}')"
    reality_port="$(jq -r --arg tag "$REALITY_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .listen_port' "$cfg")"
    reality_server_name="$(jq -r --arg tag "$REALITY_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .tls.server_name' "$cfg")"
    short_id="$(jq -r --arg tag "$REALITY_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .tls.reality.short_id[0]' "$cfg")"
    hy_port="$(jq -r --arg tag "$HY2_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .listen_port' "$cfg")"
    hy_server_name="$(grep -o "HY_SERVER_NAME='[^']*'" "$SB_STATE_FILE" 2>/dev/null | awk -F"'" '{print $2}')"
    ishopping="$(grep '^HY_HOPPING=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)"
    hy_hopping_start="$(grep '^HY_HOPPING_START=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)"
    hy_hopping_end="$(grep '^HY_HOPPING_END=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)"
    hy_clash_port_yaml="    port: $hy_port"
    if [ "$ishopping" = "TRUE" ] &&
       [[ "$hy_hopping_start" =~ ^[0-9]+$ ]] &&
       [[ "$hy_hopping_end" =~ ^[0-9]+$ ]]; then
        formatted_range="${hy_hopping_start}-${hy_hopping_end}"
        hy_clash_port_yaml="    port: $hy_port
    ports: ${formatted_range}
    hop-interval: 30"
    fi

    # Reality/HY2 credentials exist ONLY transiently inside shell memory; the
    # expansion below is the one intended delivery into the rendered config.
    reality_uuid="$uuid"
    hy_password="$password"
    cat << EOF
mixed-port: 7897
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
unified-delay: true
ipv6: true
profile:
  store-selected: true
  store-fake-ip: true
dns:
  enable: true
  listen: "0.0.0.0:53"
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver:
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

tun:
  enable: true
  stack: mixed
  device: Mihomo
  mtu: 1420
  auto-route: true
  auto-redirect: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53

proxies:
  - name: Reality
    type: vless
    server: $server_ip
    port: $reality_port
    uuid: $reality_uuid
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: $reality_server_name
    client-fingerprint: chrome
    reality-opts:
      public-key: $public_key
      short-id: $short_id

  - name: Hysteria2
    type: hysteria2
    server: $server_ip
${hy_clash_port_yaml}
    password: $hy_password
    up: "300 Mbps"
    down: "300 Mbps"
    sni: $hy_server_name
    skip-cert-verify: true
    alpn:
      - h3

proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - Reality
      - Hysteria2
      - 自动选择
      - DIRECT

  - name: 自动选择
    type: url-test
    proxies:
      - Reality
      - Hysteria2
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 50


rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择

EOF
    return 0
}

# ============================================================================
# M1-A: planned credential transaction interface
#
# The E3 path MUST NOT build candidates with `jq --arg uuid/--arg password`:
# those values land in the jq process argv (/proc/<pid>/cmdline). The contract
# below keeps credential material inside the privileged worker's own process
# tree -- memory, or an anonymous pipe / inherited private FD -- and never in
# argv, env, stdout, stderr, a temp file, the journal, or any audit stream.
#
# Byte-level digest definition (fixed, single implementation):
#     digest = SHA256(uuid + "\n" + password)
# planned_cred_digest / old_cred_digest / current_cred_digest ALL come from
# cm_cred_digest_of, so no caller can invent a different concatenation.
# ============================================================================

# Raw digest primitive. Reads the exact bytes to hash from STDIN (never argv),
# writes the lowercase hex digest to stdout.
cm_cred_digest() {
    local out=""
    if command -v sha256sum >/dev/null 2>&1; then
        out="$(sha256sum)" || return 1
    elif command -v openssl >/dev/null 2>&1; then
        out="$(openssl dgst -sha256 -r)" || return 1
    else
        return 1
    fi
    out="${out%% *}"
    [ -n "$out" ] || return 1
    printf '%s\n' "$out"
}

# The ONE canonical credential digest. Inputs are function arguments (never
# argv of an external process); the value is piped through the raw primitive.
cm_cred_digest_of() { # <uuid> <password> -> sha256(uuid + "\n" + password)
    local uuid="${1:-}" password="${2:-}"
    [ -n "$uuid" ] && [ -n "$password" ] || return 1
    printf '%s\n%s' "$uuid" "$password" | cm_cred_digest
}

# Generate a planned credential. Deliberately emits NOTHING on stdout: the
# values are held in the caller's own shell memory (CM_PLAN_UUID /
# CM_PLAN_PASSWORD) until they are either committed or forgotten.
cm_plan_client_credential() {
    CM_PLAN_UUID=""
    CM_PLAN_PASSWORD=""
    CM_PLAN_UUID="$("$SB_SING_BOX_BIN" generate uuid)" || { cm_cred_forget; return 1; }
    CM_PLAN_PASSWORD="$("$SB_SING_BOX_BIN" generate rand --hex 16)" || { cm_cred_forget; return 1; }
    if [ -z "$CM_PLAN_UUID" ] || [ -z "$CM_PLAN_PASSWORD" ]; then
        cm_cred_forget
        return 1
    fi
    return 0
}

# Drop planned credential material from shell memory.
cm_cred_forget() {
    unset CM_PLAN_UUID CM_PLAN_PASSWORD 2>/dev/null || true
    return 0
}

# Build an add candidate from an ALREADY PLANNED credential set delivered as a
# JSON object over an inherited FD:
#     {"uuid":"<uuid>","password":"<password>"}
#
# jq receives the live config through --slurpfile (a path, not a value) and the
# credential object as its MAIN INPUT over the FD; therefore the jq argv
# contains no credential material. The FD is expected to be the read end of an
# anonymous pipe created by the caller (process substitution / pipe), never a
# regular file on disk.
cm_add_candidate_planned() { # <live_cfg> <name> <out> [cred_fd=8]
    local cfg="$1" name="$2" out="$3" fd="${4:-8}"
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    jq --slurpfile cfg "$cfg" --arg name "$name" '
      . as $cred
      | if (($cred | type) != "object")
           or (($cred.uuid | type) != "string") or ($cred.uuid == "")
           or (($cred.password | type) != "string") or ($cred.password == "")
        then error("planned credential shape invalid")
        else
          $cfg[0]
          | (.inbounds[] | select(.tag == "vless-in") | .users) +=
              [{"name": $name, "uuid": $cred.uuid, "flow": "xtls-rprx-vision"}]
          | (.inbounds[] | select(.tag == "hy2-in") | .users) +=
              [{"name": $name, "password": $cred.password}]
        end
    ' <&"$fd" > "$out"
}

# Build a delete candidate. Carries no credential material at all.
cm_delete_candidate() { # <live_cfg> <name> <out>
    local cfg="$1" name="$2" out="$3"
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    jq --arg name "$name" '
      (.inbounds[] | select(.tag == "vless-in") | .users) |=
        map(select(.name != $name)) |
      (.inbounds[] | select(.tag == "hy2-in") | .users) |=
        map(select(.name != $name))
    ' "$cfg" > "$out"
}

# Current credential digest of an existing client, computed from the LIVE
# config in the caller's head. Same primitive as planned_cred_digest.
cm_old_cred_digest() { # <cfg> <name> -> sha256 hex
    local cfg="$1" name="$2" uuid="" password=""
    local -a lines=()
    mapfile -t lines < <(get_client_credentials "$name" "$cfg") || return 1
    [ "${#lines[@]}" -ge 2 ] || return 1
    uuid="${lines[0]}"; password="${lines[1]}"
    cm_cred_digest_of "$uuid" "$password"
}

# Digest of the CURRENTLY planned credential set (see cm_plan_client_credential).
# Same primitive as every other credential digest: no caller may self-concatenate.
cm_planned_cred_digest() {
    if [ -z "${CM_PLAN_UUID:-}" ] || [ -z "${CM_PLAN_PASSWORD:-}" ]; then
        return 1
    fi
    cm_cred_digest_of "$CM_PLAN_UUID" "$CM_PLAN_PASSWORD"
}

# Render an add candidate from the CURRENTLY planned credential set. The
# credential set travels over an anonymous pipe owned by this shell; the
# subscript inherits the values from memory, and nothing touches argv or disk.
cm_render_planned_candidate() { # <live_cfg> <name> <out>
    local cfg="$1" name="$2" out="$3"
    if [ -z "${CM_PLAN_UUID:-}" ] || [ -z "${CM_PLAN_PASSWORD:-}" ]; then
        warning "planned credential 尚未生成"
        return 1
    fi
    exec 8< <(printf '{"uuid":"%s","password":"%s"}' "$CM_PLAN_UUID" "$CM_PLAN_PASSWORD")
    if ! cm_add_candidate_planned "$cfg" "$name" "$out" 8; then
        exec 8<&- 2>/dev/null || true
        return 1
    fi
    exec 8<&- 2>/dev/null || true
    return 0
}

# Convenience composition for callers that do not need to interleave a durable
# ledger intent (i.e. the interactive CLI). The privileged worker deliberately
# uses the three primitives above separately so it can order
# plan -> digest -> durable intent -> candidate.
# Sets:
#     CM_ADD_CANDIDATE     path of the candidate (0600, same dir as live config)
#     CM_PLAN_CRED_DIGEST  sha256(uuid + "\n" + password)
# Credential material is forgotten before returning.
cm_add_client_candidate_planned() { # <name> -> sets CM_ADD_CANDIDATE / CM_PLAN_CRED_DIGEST
    local name="$1"
    CM_ADD_CANDIDATE=""
    CM_PLAN_CRED_DIGEST=""
    cm_plan_client_credential || { warning "生成客户端凭据失败"; return 1; }
    # Deliberate output, not an internal: CM_PLAN_CRED_DIGEST is the digest of
    # the credential set this call has just planned, for callers that want to
    # journal it. Nothing inside this library consumes it.
    # shellcheck disable=SC2034
    CM_PLAN_CRED_DIGEST="$(cm_planned_cred_digest)" || {
        warning "计算凭据摘要失败"
        cm_cred_forget
        return 1
    }
    CM_ADD_CANDIDATE="$(new_candidate_path)" || {
        warning "创建 candidate 失败"
        cm_cred_forget
        return 1
    }
    if ! cm_render_planned_candidate "$SB_SERVER_CONFIG" "$name" "$CM_ADD_CANDIDATE"; then
        warning "生成 add candidate 失败"
        rm -f "$CM_ADD_CANDIDATE"
        CM_ADD_CANDIDATE=""
        cm_cred_forget
        return 1
    fi
    cm_cred_forget
    return 0
}
