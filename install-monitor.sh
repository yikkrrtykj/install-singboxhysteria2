#!/usr/bin/env bash
set -euo pipefail

RAW="${SBOX_REPO_RAW_BASE:-https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main}"
DIR=/root/sbox/monitor
SCRIPT=$DIR/proxy-monitor.py
TOKEN=/root/sbox/monitor-token
UNIT=/etc/systemd/system/sbox-monitor.service
HELPER=/usr/bin/sbox-monitor
PORT="${SBOX_MONITOR_PORT:-9191}"

say(){ printf '\033[32m%s\033[0m\n' "$*"; }
warn(){ printf '\033[33m%s\033[0m\n' "$*"; }
fail(){ printf '\033[31m%s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "请使用 root 运行"
[ -f /root/sbox/sbconfig_server.json ] || fail "未找到 sing-box 服务端配置"
[[ "$PORT" =~ ^[0-9]+$ ]] && ((PORT>0 && PORT<65536)) || fail "监控端口无效: $PORT"

pkg(){
  local cmd=$1 deb=$2 rpm=$3
  command -v "$cmd" >/dev/null 2>&1 && return 0
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$deb" >/dev/null 2>&1
  elif command -v dnf >/dev/null 2>&1; then dnf install -y "$rpm" >/dev/null 2>&1
  elif command -v yum >/dev/null 2>&1; then yum install -y "$rpm" >/dev/null 2>&1
  else return 1; fi
}

pkg python3 python3 python3 || fail "无法安装 python3"
pkg ss iproute2 iproute || warn "未安装 ss，Reality RTT 将不可用"
pkg ip iproute2 iproute || true
pkg ping iputils-ping iputils || warn "未安装 ping，外部探测将不可用"
pkg conntrack conntrack conntrack-tools || warn "未安装 conntrack，HY2 客户端流量将不可用"

if [ -e /proc/sys/net/netfilter/nf_conntrack_acct ]; then
  cat >/etc/sysctl.d/98-sbox-monitor.conf <<'EOF'
# Managed by install-singboxhysteria2 proxy monitor.
net.netfilter.nf_conntrack_acct = 1
EOF
  sysctl -p /etc/sysctl.d/98-sbox-monitor.conf >/dev/null 2>&1 || true
fi

install -d -m 0700 "$DIR"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
curl -fsSL "$RAW/proxy-monitor.py" -o "$tmp" || fail "下载 proxy-monitor.py 失败"
python3 -m py_compile "$tmp" || fail "proxy-monitor.py 语法检查失败"
install -m 0700 "$tmp" "$SCRIPT"

if [ ! -s "$TOKEN" ]; then
  umask 077
  python3 - <<'PY' >"$TOKEN"
import secrets
print(secrets.token_urlsafe(24))
PY
fi
chmod 0600 "$TOKEN"

cat >"$UNIT" <<EOF
[Unit]
Description=Read-only sing-box proxy monitor
After=network-online.target sing-box.service
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 $SCRIPT --listen 0.0.0.0 --port $PORT
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

cat >"$HELPER" <<EOF
#!/usr/bin/env bash
set -euo pipefail
PORT="\${SBOX_MONITOR_PORT:-9191}"
IP=\$(sed -n "s/^SERVER_IP=['\\\"]\\{0,1\\}\\([^'\\\"]*\\)['\\\"]\\{0,1\\}$/\\1/p" /root/sbox/config 2>/dev/null | tail -n1)
IP=\${IP:-SERVER_IP}
TOKEN=\$(cat /root/sbox/monitor-token 2>/dev/null || true)
case "\${1:-url}" in
  url) echo "http://\${IP}:\${PORT}/\${TOKEN}/" ;;
  status) systemctl status sbox-monitor --no-pager ;;
  logs) journalctl -u sbox-monitor -n 100 --no-pager ;;
  restart) systemctl restart sbox-monitor ;;
  update) SBOX_REPO_RAW_BASE="$RAW" bash <(curl -fsSL "$RAW/install-monitor.sh") ;;
  *) echo "Usage: sbox-monitor {url|status|logs|restart|update}" >&2; exit 2 ;;
esac
EOF
chmod 0755 "$HELPER"

systemctl daemon-reload
systemctl enable --now sbox-monitor >/dev/null
sleep 1
systemctl is-active --quiet sbox-monitor || { journalctl -u sbox-monitor -n 50 --no-pager >&2 || true; fail "监控启动失败"; }

IP=$(sed -n "s/^SERVER_IP=['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}$/\1/p" /root/sbox/config 2>/dev/null | tail -n1); IP=${IP:-SERVER_IP}
T=$(cat "$TOKEN")
say "独立代理监控已安装"
echo "监控地址: http://${IP}:${PORT}/${T}/"
echo "以后执行: sbox-monitor url"
warn "脚本不会自动开放云安全组/UFW；如需公网查看，请仅向你的管理 IP 放行 TCP ${PORT}。"
warn "当前页面使用 HTTP + 随机 URL token，只读但未加 TLS；不要公开监控 URL。"
