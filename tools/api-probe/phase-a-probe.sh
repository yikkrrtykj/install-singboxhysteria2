#!/usr/bin/env bash
# Phase A - sing-box official API feasibility probe.
#
# Manual diagnostic tool. It is NOT part of the installer, NOT part of Monitor v2
# and is never installed on user servers automatically. See README.md.
#
# Every mode only ever writes inside PROBE_ROOT (default /root/sbox-probe) and
# never stops, restarts, reconfigures or firewalls the production sing-box.
#
# Usage:
#   phase-a-probe.sh prepare    # generate keys/users/certs/configs, run check, start nothing
#   phase-a-probe.sh run        # start the independent probe (and throwaway clients), run the
#                               # local test matrix, collect evidence, analyse, then stop
#   phase-a-probe.sh collect    # snapshot a running probe again (e.g. after external clients)
#   phase-a-probe.sh status     # show probe state
#   phase-a-probe.sh cleanup    # stop probe-owned processes and remove PROBE_ROOT
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"

PROBE_ROOT="${PROBE_ROOT:-/root/sbox-probe}"
REALITY_PORT="${REALITY_PORT:-18443}"
HY2_PORT="${HY2_PORT:-18444}"
CLASH_PORT="${CLASH_PORT:-19090}"
SINK_PORT="${SINK_PORT:-18080}"
SOCKS_AR="${SOCKS_AR:-18081}"
SOCKS_AH="${SOCKS_AH:-18082}"
SOCKS_BR="${SOCKS_BR:-18083}"
SOCKS_BH="${SOCKS_BH:-18084}"
EXPOSE="${EXPOSE:-0}"
PUBLIC_IP="${PUBLIC_IP:-}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-67108864}"
TRANSFER_RATE="${TRANSFER_RATE:-4194304}"
KEEP="${KEEP:-0}"
LABEL="${LABEL:-}"
CMD=""

usage() {
  cat <<'EOF'
Phase A - sing-box official API feasibility probe (manual diagnostic tool)

  prepare   生成 probe 密钥/用户/证书/配置并执行 sing-box check，不启动任何进程
  run       以独立进程启动 probe（顺带启动一次性客户端与 sink），跑本机测试矩阵，
            采集 evidence 并分析，默认结束后停止 probe 自己的进程
  collect   对正在运行的 probe 再取一次快照（例如外部客户端测完之后）
  status    显示 probe 状态
  cleanup   只停止 probe 自己的进程并删除 PROBE_ROOT

选项:
  --probe-root DIR     探针目录（默认 /root/sbox-probe）
  --reality-port N     probe Reality 端口（默认 18443）
  --hy2-port N         probe HY2 端口（默认 18444）
  --clash-port N       Clash API 端口，仅绑定 127.0.0.1（默认 19090）
  --sink-port N        本机 sink 端口（默认 18080）
  --bytes N            每个方向测试的已知字节数（默认 67108864）
  --rate BPS           测试限速，字节/秒（默认 4194304）
  --label NAME         collect 用的快照标签（默认 manual-<时间戳>）
  --expose             probe inbound 绑定 :: 以便外部客户端测试（默认只绑 127.0.0.1）
  --public-ip IP       外部客户端配置里使用的公网 IP（默认只读读取生产 config）
  --keep               run 结束后保留 probe/客户端/sink 运行（供外部测试用，之后必须 cleanup）

安全边界:
  * 只读写 PROBE_ROOT，不修改 /root/sbox 下的任何文件
  * 不 stop/restart/disable sing-box.service，不写生产 firewall 规则
  * 只对 /proc cmdline 命中 PROBE_ROOT 且不是生产 MainPID 的进程发送信号
  * 不创建 systemd unit，因此不会开机自启
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    prepare|run|collect|cleanup|status) CMD="$1"; shift ;;
    --prepare|--run|--collect|--cleanup|--status) CMD="${1#--}"; shift ;;
    --probe-root)    PROBE_ROOT="$2"; shift 2 ;;
    --reality-port)  REALITY_PORT="$2"; shift 2 ;;
    --hy2-port)      HY2_PORT="$2"; shift 2 ;;
    --clash-port)    CLASH_PORT="$2"; shift 2 ;;
    --sink-port)     SINK_PORT="$2"; shift 2 ;;
    --bytes)         PAYLOAD_BYTES="$2"; shift 2 ;;
    --rate)          TRANSFER_RATE="$2"; shift 2 ;;
    --label)         LABEL="$2"; shift 2 ;;
    --public-ip)     PUBLIC_IP="$2"; shift 2 ;;
    --expose)        EXPOSE=1; shift ;;
    --keep)          KEEP=1; shift ;;
    -h|--help|help)  CMD="help"; shift ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

export PROBE_ROOT REALITY_PORT HY2_PORT CLASH_PORT SINK_PORT
export SOCKS_AR SOCKS_AH SOCKS_BR SOCKS_BH
export EXPOSE PUBLIC_IP PAYLOAD_BYTES TRANSFER_RATE KEEP LABEL

# shellcheck source=lib/common.sh
. "$LIB_DIR/common.sh"
# shellcheck source=lib/probe-config.sh
. "$LIB_DIR/probe-config.sh"
# shellcheck source=lib/evidence.sh
. "$LIB_DIR/evidence.sh"

print_paths() {
  printf '\n'
  ok "evidence 目录: $EVID_DIR"
  ok "报告: $EVID_DIR/report.md / $EVID_DIR/SUMMARY.txt / $EVID_DIR/analysis.json"
  printf '如需清理: %s cleanup\n' "${BASH_SOURCE[0]}"
}

cmd_prepare() {
  prepare_all
  cat <<EOF

下一步（可选）:
  1) 本机自测并采集:  $0 run
  2) 只启动、留给外部客户端:  $0 run --keep --expose
  3) 外部测试后再次采集:  $0 collect --label reality-external
  4) 结束后清理:  $0 cleanup
EOF
}

cmd_run() {
  require_root
  require_probe_root_sane
  stop_extra_procs
  if [ ! -s "$PROBE_CONFIG" ]; then
    log "未检测到已生成的 probe 配置，先执行 prepare（只写入 $PROBE_ROOT）"
    prepare_all
  fi
  trap 'kill_transfers' EXIT
  start_probe
  run_local_matrix
  assert_production_unchanged
  if [ "${KEEP:-0}" = "1" ]; then
    warn "--keep 已启用: probe/客户端/sink 保持运行；采集完成后必须执行 $0 cleanup"
  else
    stop_all_probe_procs
  fi
  run_analysis
  print_paths
}

cmd_collect() {
  require_root
  require_probe_root_sane
  api_ready || die "probe 的 Clash API 未就绪；请先执行 $0 run --keep"
  local label="${LABEL:-manual-$(date +%Y%m%d-%H%M%S)}"
  case "$label" in
    *[!A-Za-z0-9._-]*) die "label 只允许字母、数字、点、下划线和减号: $label" ;;
  esac
  ev_meta
  api_snapshot "$label"
  ok "已保存 $EVID_DIR/$label.connections.json"
  run_analysis
  print_paths
}

cmd_status() {
  require_probe_root_sane
  printf 'probe root : %s\n' "$PROBE_ROOT"
  printf 'ports      : reality=%s hy2=%s clash=127.0.0.1:%s sink=%s\n' \
    "$REALITY_PORT" "$HY2_PORT" "$CLASH_PORT" "$SINK_PORT"
  printf 'expose     : %s\n' "$EXPOSE"
  local name pid state
  for name in probe sink client-a-reality client-a-hy2 client-b-reality client-b-hy2; do
    pid="$(read_pid "$name")"
    if [ -z "$pid" ]; then state="no pidfile"; elif pid_is_probe "$pid"; then state="running (pid $pid)"; else state="stale/foreign pid $pid"; fi
    printf '  %-16s %s\n' "$name" "$state"
  done
  if api_ready; then printf 'clash api  : ready\n'; else printf 'clash api  : not reachable\n'; fi
  if [ -s "$PROBE_CONFIG" ]; then printf 'config     : %s\n' "$PROBE_CONFIG"; else printf 'config     : (not prepared)\n'; fi
  if [ -d "$EVID_DIR" ]; then printf 'evidence   : %s (%s files)\n' "$EVID_DIR" "$(find "$EVID_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')"; fi
  printf 'production : %s (%s)\n' "$(prod_version)" "$(prod_service_state)"
}

cmd_cleanup() {
  require_probe_root_sane
  log "停止 probe 自有进程（仅当 cmdline 命中 $PROBE_ROOT）"
  stop_all_probe_procs
  stop_extra_procs
  if [ ! -d "$PROBE_ROOT" ]; then
    ok "$PROBE_ROOT 不存在，无需删除"
    return 0
  fi
  if [ -e "$PROBE_ROOT/sbconfig_server.json" ]; then
    die "拒绝删除: $PROBE_ROOT 内出现 sbconfig_server.json，可能指向生产目录"
  fi
  rm -rf -- "$PROBE_ROOT"
  ok "已删除 $PROBE_ROOT"
  if port_in_use "$REALITY_PORT" || port_in_use "$HY2_PORT" || port_in_use "$CLASH_PORT"; then
    warn "probe 端口仍被占用，请人工确认是否有残留进程"
  else
    ok "probe 端口已释放"
  fi
  printf '生产状态: %s (%s) 未受影响\n' "$(prod_version)" "$(prod_service_state)"
}

case "${CMD:-help}" in
  prepare) cmd_prepare ;;
  run)     cmd_run ;;
  collect) cmd_collect ;;
  status)  cmd_status ;;
  cleanup) cmd_cleanup ;;
  *)       usage ;;
esac
