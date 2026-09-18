#!/usr/bin/env bash
# install-sbox-cm.sh -- deploy the sbox-cm privileged execution plane (E3 M1).
#
# M1 is NOT an activation. `install` converges the files and the units but
# leaves both units DISABLED and INACTIVE: the default safe state is "capability
# present, management plane closed". Enabling is an explicit, separate action.
#
# Guarantees:
#   * never touches sbconfig_server.json / sing-box / its unit;
#   * never enables or starts the units implicitly;
#   * disabling the plane stops BOTH the socket and the service -- stopping the
#     service alone is NOT enough, because the socket would restart it;
#   * never removes /var/lib/sbox-cm unless --purge-state is given.
#
# Commands:
#   install [--enable]     stage files + units (disabled/inactive by default)
#   enable                 enable --now socket + service (opens the channel)
#   disable                stop + disable socket AND service (closes it)
#   uninstall [--purge-state]
#   status
#   reconcile              run startup reconciliation once, report the result
#
# Fixture/test overrides: SBXCM_PREFIX, SBXCM_LIBEXEC, SBXCM_UNIT_DIR,
# SBXCM_SYSTEMCTL, SBXCM_GROUP, SB_CM_STATE_DIR, SBXCM_DEPLOY_DIR.

set -uo pipefail

DEPLOY_DIR="${SBXCM_DEPLOY_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)}"
SRC_DIR="$(cd -- "$DEPLOY_DIR/.." && pwd)"

PREFIX="${SBXCM_PREFIX:-}"
LIBEXEC="${SBXCM_LIBEXEC:-/usr/local/lib/sbox-cm}"
UNIT_DIR="${SBXCM_UNIT_DIR:-/etc/systemd/system}"
STATE_DIR="${SB_CM_STATE_DIR:-/var/lib/sbox-cm}"
SYSTEMCTL="${SBXCM_SYSTEMCTL:-systemctl}"
GROUP="${SBXCM_GROUP:-sboxweb}"
SOCKET_UNIT="sbox-cm.socket"
SERVICE_UNIT="sbox-cm.service"

tgt() { printf '%s%s' "${PREFIX%/}" "$1"; }

warn() { printf '[sbox-cm-deploy] %s\n' "$*" >&2; }
die()  { warn "$*"; exit 1; }

need_file() { [ -f "$1" ] || die "缺少文件: $1"; }

# ------------------------------------------------------------------ install --
render_unit() { # <template> <destination>
    local tmpl="$1" dest="$2" tmp
    need_file "$tmpl"
    mkdir -p -- "$(dirname -- "$dest")" || die "无法创建 unit 目录"
    tmp="$(mktemp "$(dirname -- "$dest")/.sbox-cm-unit.XXXXXX")" || die "无法创建临时 unit"
    sed -e "s|@SBXCM_GROUP@|$GROUP|g" -e "s|@SBXCM_LIBEXEC@|${LIBEXEC%/}|g" \
        "$tmpl" > "$tmp" || { rm -f -- "$tmp"; die "unit 渲染失败: $tmpl"; }
    chmod 0644 "$tmp" || { rm -f -- "$tmp"; die "unit 权限设置失败"; }
    if ! mv -f -- "$tmp" "$dest"; then
        rm -f -- "$tmp"
        die "unit 原子写入失败: $dest"
    fi
}

cmd_install() {
    local enable_now=0
    while (($# > 0)); do
        case "$1" in
            --enable) enable_now=1 ;;
            *) die "未知参数: $1" ;;
        esac
        shift
    done

    local dest_libexec dest_units
    dest_libexec="$(tgt "$LIBEXEC")"
    dest_units="$(tgt "$UNIT_DIR")"

    need_file "$SRC_DIR/sbox-cm"
    need_file "$SRC_DIR/sbox-cm-ops"
    need_file "$SRC_DIR/../lib/client-management.sh"
    need_file "$SRC_DIR/../lib/sbox-cm-state.sh"

    mkdir -p -- "$dest_libexec/lib" "$dest_units" "$STATE_DIR" || die "无法创建目标目录"
    chmod 0700 -- "$STATE_DIR" 2>/dev/null || true
    # Fail-closed ownership (E3 M1 review B8): a pre-existing state directory
    # owned by anyone else must never keep that owner (the ledger/audit are
    # root-only). Real installs run as root; sandboxed test prefixes skip this.
    if [ -z "${SBXCM_PREFIX:-}" ] && [ "$(id -u 2>/dev/null)" = "0" ]; then
        chown root:root "$STATE_DIR" 2>/dev/null \
            || die "无法将状态目录 chown 为 root:root（fail-closed）"
        [ "$(stat -c '%u %g' "$STATE_DIR" 2>/dev/null)" = "0 0" ] \
            || die "状态目录所有权不是 root:root（fail-closed）"
    fi

    install -m 0755 "$SRC_DIR/sbox-cm" "$dest_libexec/sbox-cm" || die "安装 sbox-cm 失败"
    install -m 0755 "$SRC_DIR/sbox-cm-ops" "$dest_libexec/sbox-cm-ops" || die "安装 sbox-cm-ops 失败"
    install -m 0644 "$SRC_DIR/../lib/client-management.sh" \
        "$dest_libexec/lib/client-management.sh" || die "安装共享库失败"
    install -m 0644 "$SRC_DIR/../lib/sbox-cm-state.sh" \
        "$dest_libexec/lib/sbox-cm-state.sh" || die "安装状态库失败"

    render_unit "$DEPLOY_DIR/sbox-cm.socket.in" "$dest_units/$SOCKET_UNIT"
    render_unit "$DEPLOY_DIR/sbox-cm.service.in" "$dest_units/$SERVICE_UNIT"

    "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || warn "daemon-reload 失败"

    warn "已安装（units 默认 disabled + inactive：默认安全态，管理面未开启）"
    warn "  libexec : $dest_libexec"
    warn "  units   : $dest_units/$SOCKET_UNIT, $dest_units/$SERVICE_UNIT"
    warn "  state   : $STATE_DIR"
    if [ "$enable_now" = "1" ]; then
        cmd_enable
    fi
    return 0
}

# ------------------------------------------------------------------- enable --
# Enablement is SOCKET-ONLY. The service unit carries no independent enable
# requirement: systemd pulls it up on the first accepted connection, which keeps
# boot-time surface at "a listening socket, not a running root daemon". An
# operator MAY additionally `systemctl enable sbox-cm.service` as an explicit,
# documented opt-in (the unit keeps its [Install] section for that), but this
# script never does it.
cmd_enable() {
    "$SYSTEMCTL" enable --now "$SOCKET_UNIT" >/dev/null 2>&1 \
        || die "enable 失败（$SOCKET_UNIT）"
    warn "privileged plane 已开启（$SOCKET_UNIT enabled/active；service 由 socket activation 按需拉起）"
    return 0
}

# ------------------------------------------------------------------ disable --
# Stopping the SERVICE alone does not close the plane: the socket would start it
# again on the next connection. Rollback order is therefore:
#     stop socket -> stop service -> disable socket -> disable service (iff it
#     was enabled) -- so a disabled plane cannot be re-armed by anything.
cmd_disable() {
    local rc=0 svc_enabled
    svc_enabled="$("$SYSTEMCTL" is-enabled "$SERVICE_UNIT" 2>/dev/null || true)"
    "$SYSTEMCTL" stop "$SOCKET_UNIT"    >/dev/null 2>&1 || rc=1
    "$SYSTEMCTL" stop "$SERVICE_UNIT"   >/dev/null 2>&1 || rc=1
    "$SYSTEMCTL" disable "$SOCKET_UNIT" >/dev/null 2>&1 || rc=1
    if [ "$svc_enabled" = "enabled" ]; then
        "$SYSTEMCTL" disable "$SERVICE_UNIT" >/dev/null 2>&1 || rc=1
    fi
    [ "$rc" = "0" ] || die "disable 未完全成功：请人工检查 $SOCKET_UNIT / $SERVICE_UNIT"
    warn "privileged plane 已关闭（socket + service stopped；socket 已 disable）"
    return 0
}

# ---------------------------------------------------------------- uninstall --
cmd_uninstall() {
    local purge_state=0
    while (($# > 0)); do
        case "$1" in
            --purge-state) purge_state=1 ;;
            *) die "未知参数: $1" ;;
        esac
        shift
    done

    cmd_disable || warn "disable 未完全成功，继续卸载"

    local dest_libexec dest_units
    dest_libexec="$(tgt "$LIBEXEC")"
    dest_units="$(tgt "$UNIT_DIR")"

    case "$dest_libexec" in
        ""|"/") die "拒绝删除空路径（fail-closed）" ;;
    esac

    rm -f -- "$dest_units/$SOCKET_UNIT" "$dest_units/$SERVICE_UNIT" 2>/dev/null || true
    rm -rf -- "$dest_libexec" 2>/dev/null || die "删除 $dest_libexec 失败"
    "$SYSTEMCTL" daemon-reload >/dev/null 2>&1 || warn "daemon-reload 失败"

    if [ "$purge_state" = "1" ]; then
        case "$STATE_DIR" in
            ""|"/") die "拒绝删除空状态路径（fail-closed）" ;;
        esac
        rm -rf -- "$STATE_DIR" 2>/dev/null || die "删除 $STATE_DIR 失败"
        warn "已删除运行时状态: $STATE_DIR"
    else
        warn "保留运行时状态（ledger/journal/audit/marker）: $STATE_DIR"
    fi
    warn "sbox-cm 已卸载"
    return 0
}

# ------------------------------------------------------------------- status --
# Read-ONLY. This is the deployment/operator CLI status, NOT the RPC
# management.status. Neither of them may trigger reconciliation or any repair:
# reconciliation runs exactly once, in the daemon's startup path, before the
# first request is served. Here we only surface the durable reconcile state.
cmd_status() {
    printf 'libexec      : %s\n' "$(tgt "$LIBEXEC")"
    printf 'socket unit  : %s\n' "$(tgt "$UNIT_DIR")/$SOCKET_UNIT"
    printf 'service unit : %s\n' "$(tgt "$UNIT_DIR")/$SERVICE_UNIT"
    printf 'state dir    : %s\n' "$STATE_DIR"
    if [ -f "$STATE_DIR/degraded.json" ]; then
        printf 'reconcile    : %s\n' \
            "$(jq -r '.reconcile // "manual_intervention"' "$STATE_DIR/degraded.json" 2>/dev/null || printf manual_intervention)"
        warn "helper 处于 degraded：状态无法被证明安全，需 root 修复后手动 reconcile"
    else
        printf 'reconcile    : clean\n'
    fi
    local unit state
    for unit in "$SOCKET_UNIT" "$SERVICE_UNIT"; do
        state="$("$SYSTEMCTL" is-active "$unit" 2>/dev/null || true)"
        printf '%-13s: active=%s' "$unit" "${state:-unknown}"
        state="$("$SYSTEMCTL" is-enabled "$unit" 2>/dev/null || true)"
        printf ' enabled=%s\n' "${state:-unknown}"
    done
    return 0
}

# ---------------------------------------------------------------- reconcile --
cmd_reconcile() {
    local dest_libexec
    dest_libexec="$(tgt "$LIBEXEC")"
    [ -x "$dest_libexec/sbox-cm" ] || die "未安装: $dest_libexec/sbox-cm"
    exec "$dest_libexec/sbox-cm" reconcile
}

# ------------------------------------------------------------------ recover --
# active_stale recovery: the ONLY sanctioned path is this root CLI. Operators
# must never hand-delete the marker file.
cmd_recover() {
    local dest_libexec
    dest_libexec="$(tgt "$LIBEXEC")"
    [ -x "$dest_libexec/sbox-cm" ] || die "未安装: $dest_libexec/sbox-cm"
    warn "root recovery: mgmt-deactivate（删除激活标记并写审计；不手工 rm 标记文件）"
    exec "$dest_libexec/sbox-cm" mgmt-deactivate
}

usage() {
    cat <<'EOF'
用法: install-sbox-cm.sh <command> [flags]
  install [--enable]          部署文件与 units（默认 disabled/inactive）
  enable                      开启特权通道（socket + service）
  disable                     关闭特权通道（socket + service 同时停止并 disable）
  uninstall [--purge-state]   卸载（默认保留运行时状态）
  status                      路径 + 单元状态
  reconcile                   运行一次启动调和
  recover                     active_stale 恢复（root CLI mgmt-deactivate）
EOF
}

main() {
    local cmd="${1:-}"
    [ -n "$cmd" ] || { usage; exit 1; }
    shift
    case "$cmd" in
        install)   cmd_install "$@" ;;
        enable)    cmd_enable ;;
        disable)   cmd_disable ;;
        uninstall) cmd_uninstall "$@" ;;
        status)    cmd_status ;;
        reconcile) cmd_reconcile ;;
        recover)   cmd_recover ;;
        -h|--help) usage ;;
        *) usage; die "未知命令: $cmd" ;;
    esac
}

main "$@"
