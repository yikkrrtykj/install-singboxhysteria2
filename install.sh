#!/usr/bin/env bash
# Thin wrapper: preserve the original installer as install-core.sh, then ensure
# the independent read-only proxy monitor is installed after a successful run.
set -uo pipefail
RAW_BASE="https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main"
CORE_URL="$RAW_BASE/install-core.sh"
MONITOR_URL="$RAW_BASE/install-monitor.sh"
MONITOR_SERVICE="/etc/systemd/system/sbox-monitor.service"

cleanup_monitor(){
  systemctl disable --now sbox-monitor >/dev/null 2>&1 || true
  rm -f "$MONITOR_SERVICE" /usr/bin/sbox-monitor /etc/sysctl.d/98-sbox-monitor.conf
  systemctl daemon-reload >/dev/null 2>&1 || true
}

core=$(mktemp)
trap 'rm -f "$core"' EXIT
curl -fsSL "$CORE_URL" -o "$core" || { echo "下载核心安装脚本失败" >&2; exit 1; }
bash "$core" "$@"
rc=$?

if [ "$rc" -eq 0 ]; then
  if [ -f /root/sbox/sbconfig_server.json ] && [ -f /root/sbox/config ]; then
    if [ ! -f "$MONITOR_SERVICE" ] || [ ! -x /root/sbox/monitor/proxy-monitor.py ]; then
      bash <(curl -fsSL "$MONITOR_URL") || echo "警告: 代理本身已安装成功，但监控安装失败；可稍后重新运行脚本。" >&2
    fi
  else
    # The core installer was most likely used to uninstall sing-box.
    cleanup_monitor
  fi
fi
exit "$rc"
