#!/usr/bin/env bash
# gen-mt-client.sh
# 在 VPS 上运行，读取 install.sh 已生成的 sing-box server 配置，
# 生成 MikroTik 容器侧要用的一整套文件并打包。
#
# 前置：本机已跑过 install.sh（mianyang），以下文件存在：
#   /root/sbox/sbconfig_server.json
#   /root/sbox/config
#
# 用法：
#   curl -fsSL <raw-url>/gen-mt-client.sh -o gen-mt-client.sh
#   bash gen-mt-client.sh
#
# 输出：
#   /root/mt-client-pkg.tar.gz        <- 下载到本机，传到 MikroTik USB 盘
#   /root/mt-client-pkg/              <- 解包目录，便于核查
#
set -euo pipefail

red="\033[31m\033[01m"; green="\033[32m\033[01m"; yellow="\033[33m\033[01m"; reset="\033[0m"
err()  { echo -e "${red}[ERR]${reset} $*" >&2; exit 1; }
info() { echo -e "${green}[OK]${reset}  $*"; }
warn() { echo -e "${yellow}[!]${reset}  $*"; }

SERVER_CFG=/root/sbox/sbconfig_server.json
ENV_CFG=/root/sbox/config
OUT_DIR=/root/mt-client-pkg
TAR_PATH=/root/mt-client-pkg.tar.gz

# ---------------- 前置检查 ----------------
command -v jq >/dev/null 2>&1 || err "jq 未安装，请先 apt/yum install jq"
[[ -f "$SERVER_CFG" ]] || err "$SERVER_CFG 不存在，请先跑 install.sh 装好 sing-box server"
[[ -f "$ENV_CFG" ]]    || err "$ENV_CFG 不存在"

# ---------------- 从 server 配置读参数 ----------------
SERVER_IP=$(grep -oP "^SERVER_IP='\K[^']+" "$ENV_CFG")
REALITY_PUBKEY=$(grep -oP "^PUBLIC_KEY='\K[^']+" "$ENV_CFG")
HY_SNI=$(grep -oP "^HY_SERVER_NAME='\K[^']+" "$ENV_CFG")

REALITY_PORT=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .listen_port' "$SERVER_CFG")
REALITY_UUID=$(jq -r '.inbounds[] | select(.tag=="vless-in") | .users[0].uuid' "$SERVER_CFG")
REALITY_SNI=$(jq  -r '.inbounds[] | select(.tag=="vless-in") | .tls.server_name' "$SERVER_CFG")
REALITY_SID=$(jq  -r '.inbounds[] | select(.tag=="vless-in") | .tls.reality.short_id[0]' "$SERVER_CFG")

HY_PORT=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .listen_port' "$SERVER_CFG")
HY_PWD=$(jq  -r '.inbounds[] | select(.tag=="hy2-in") | .users[0].password' "$SERVER_CFG")
HY_OBFS_TYPE=$(jq -r '.inbounds[] | select(.tag=="hy2-in") | .obfs.type // empty' "$SERVER_CFG")
HY_OBFS_PWD=$(jq  -r '.inbounds[] | select(.tag=="hy2-in") | .obfs.password // empty' "$SERVER_CFG")

for v in SERVER_IP REALITY_PUBKEY HY_SNI REALITY_PORT REALITY_UUID REALITY_SNI REALITY_SID HY_PORT HY_PWD; do
  [[ -n "${!v:-}" && "${!v}" != "null" ]] || err "无法从 server 配置读取 $v"
done
info "已读取 server 参数：IP=$SERVER_IP  Reality=$REALITY_PORT  Hy2=$HY_PORT"

# ---------------- 询问 MikroTik 侧参数 ----------------
ask() {
  local prompt="$1" default="$2" var
  read -rp "$prompt [默认 $default]: " var
  echo "${var:-$default}"
}

echo
warn "下面这些参数与 MikroTik 拓扑相关，不清楚就用默认值。"

UP_MBPS=$(ask   "实际上行带宽 Mbps (Hy2 BBR 参数)"         "300")
DOWN_MBPS=$(ask "实际下行带宽 Mbps (Hy2 BBR 参数)"         "500")
MT_LAN_IF=$(ask "MikroTik 上连 WatchGuard eth2 的物理口名"  "ether1")
MT_LAN_IP=$(ask "MikroTik 侧代理-WAN IP (CIDR)"             "192.168.99.2/30")
MT_LAN_GW=$(ask "WatchGuard eth2 对端 IP (代理-WAN 网关)"   "192.168.99.1")
VETH_NET=$(ask  "MikroTik 宿主↔容器 veth 网段"              "172.20.0.0/24")
VETH_HOST_IP=$(ask "MikroTik bridge-sbox IP (网段第 1 个)"  "172.20.0.1")
VETH_CT_IP=$(ask   "容器 eth0 IP (网段第 2 个)"             "172.20.0.2")
TUN_NET=$(ask      "容器 sing-box tun 网段"                 "172.19.0.0/24")
TUN_IP=$(ask       "容器 sing-box tun IP"                   "172.19.0.1/24")
USB_LABEL=$(ask    "USB 盘挂载名 (RouterOS disk label)"     "usb-sbox")
IMG_NAME=$(ask     "容器镜像名:tag"                          "singbox-mt:1.13")

# ---------------- 生成目录 ----------------
rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"/{sbox-conf,docker}

# 预构造可选字段行（避免嵌套 heredoc 的解析坑）
OBFS_LINE=""
if [[ -n "$HY_OBFS_TYPE" ]]; then
  OBFS_LINE="      \"obfs\": { \"type\": \"$HY_OBFS_TYPE\", \"password\": \"$HY_OBFS_PWD\" },"
fi

# ---------------- client.json ----------------
# 关键适配点（对比原 install.sh L480-715 的个人客户端版本）：
#   tun 地址 /24 而非 /30；mtu 1420；auto_route=true 让 sing-box 自己托管容器内路由；
#   default_interface=eth0；final=proxy，不做 GEO 分流（分流交给 WatchGuard PBR）
cat > "$OUT_DIR/sbox-conf/client.json" <<JSON
{
  "log": { "level": "info", "timestamp": true },
  "dns": {
    "servers": [
      { "tag": "proxy-dns",  "type": "udp", "server": "8.8.8.8",   "detour": "proxy"  },
      { "tag": "direct-dns", "type": "udp", "server": "223.5.5.5", "detour": "direct" }
    ],
    "final": "proxy-dns",
    "strategy": "ipv4_only"
  },
  "inbounds": [
    {
      "type": "tun",
      "tag": "tun-in",
      "address": ["$TUN_IP"],
      "mtu": 1420,
      "auto_route": true,
      "strict_route": false,
      "stack": "system",
      "sniff": true,
      "sniff_override_destination": false
    }
  ],
  "outbounds": [
    {
      "type": "selector",
      "tag": "proxy",
      "outbounds": ["auto", "hy2", "reality"],
      "default": "hy2"
    },
    {
      "type": "urltest",
      "tag": "auto",
      "outbounds": ["hy2", "reality"],
      "url": "http://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50
    },
    {
      "type": "hysteria2",
      "tag": "hy2",
      "server": "$SERVER_IP",
      "server_port": $HY_PORT,
      "password": "$HY_PWD",
      "up_mbps": $UP_MBPS,
      "down_mbps": $DOWN_MBPS,
$OBFS_LINE
      "tls": {
        "enabled": true,
        "server_name": "$HY_SNI",
        "insecure": true,
        "alpn": ["h3"]
      }
    },
    {
      "type": "vless",
      "tag": "reality",
      "server": "$SERVER_IP",
      "server_port": $REALITY_PORT,
      "uuid": "$REALITY_UUID",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "tls": {
        "enabled": true,
        "server_name": "$REALITY_SNI",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": {
          "enabled": true,
          "public_key": "$REALITY_PUBKEY",
          "short_id": "$REALITY_SID"
        }
      }
    },
    { "type": "direct", "tag": "direct" }
  ],
  "route": {
    "auto_detect_interface": false,
    "default_interface": "eth0",
    "final": "proxy",
    "rules": [
      { "action": "sniff" },
      { "ip_is_private": true, "outbound": "direct" },
      { "protocol": "dns", "action": "hijack-dns" }
    ]
  }
}
JSON
info "生成 client.json"

# ---------------- Dockerfile + entrypoint ----------------
cat > "$OUT_DIR/docker/Dockerfile" <<'DOCKERFILE'
# 自建 MikroTik 容器镜像：sing-box + iptables + entrypoint
# 在任意有 Docker 的机器上 build，然后 push 到 registry 或 docker save 成 tar
FROM sagernet/sing-box:v1.13.4

# Alpine 包管理
RUN apk add --no-cache iptables ip6tables procps

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["run", "-c", "/etc/sing-box/client.json"]
DOCKERFILE

cat > "$OUT_DIR/docker/entrypoint.sh" <<'ENTRYPOINT'
#!/bin/sh
# MikroTik 容器入口。核心逻辑：
#   1. 开 ip_forward（容器 net 空间内）
#   2. 后台等 tun0 出现后补 iptables（非严格必需，sing-box auto_route 已处理，
#      但 MASQUERADE 给 forwarding 流量兜底）
#   3. 前台 exec sing-box，使其成为 1 号进程，signal 正常转发
set -e

sysctl -w net.ipv4.ip_forward=1          2>/dev/null || true
sysctl -w net.ipv4.conf.all.rp_filter=2  2>/dev/null || true  # Hy2 多路径友好
sysctl -w net.core.rmem_max=16777216     2>/dev/null || true
sysctl -w net.core.wmem_max=16777216     2>/dev/null || true

(
  # 等 sing-box 起来创建 tun0，最多等 60 秒
  for i in $(seq 1 60); do
    if ip link show tun0 >/dev/null 2>&1; then
      iptables  -A FORWARD -i eth0 -o tun0 -j ACCEPT
      iptables  -A FORWARD -i tun0 -o eth0 -m state --state RELATED,ESTABLISHED -j ACCEPT
      iptables  -t nat -A POSTROUTING -o tun0 -j MASQUERADE
      echo "[entrypoint] iptables rules applied for tun0"
      exit 0
    fi
    sleep 1
  done
  echo "[entrypoint] tun0 never appeared after 60s" >&2
) &

exec /usr/local/bin/sing-box "$@"
ENTRYPOINT
chmod +x "$OUT_DIR/docker/entrypoint.sh"
info "生成 Dockerfile + entrypoint.sh"

# ---------------- RouterOS 导入脚本 ----------------
# 在 MikroTik 侧粘贴执行。假设已 enable container 模式、USB 盘已格式化为 ext4。
cat > "$OUT_DIR/mt-setup.rsc" <<RSC
# =========================================================================
# MikroTik CCR2004 - sing-box container setup
# 前置条件（必须人工确认）：
#   1) RouterOS 7.14+ 已安装 container package
#   2) /system/device-mode/update container=yes 已通过物理确认
#   3) USB 盘已格式化 ext4，disk-label=$USB_LABEL，挂载点 /$USB_LABEL/
#   4) 镜像已通过下面两种方式之一准备好：
#      A) docker push 到某 registry 后，MikroTik 能访问该 registry
#      B) docker save -o image.tar $IMG_NAME 后，上传到 /$USB_LABEL/image.tar
# =========================================================================

# --- 1. veth 虚拟网卡 + bridge（容器网络）---
/interface/veth
add name=veth-sbox address=$VETH_CT_IP/24 gateway=$VETH_HOST_IP

/interface/bridge
add name=bridge-sbox

/interface/bridge/port
add bridge=bridge-sbox interface=veth-sbox

/ip/address
add address=$VETH_HOST_IP/24 interface=bridge-sbox

# --- 2. 对外物理口（连 WatchGuard eth2）---
/ip/address
add address=$MT_LAN_IP interface=$MT_LAN_IF

# 给 MikroTik 本身加一条默认路由，经 WatchGuard eth2 出去（用于容器拉镜像 / DNS）
# 如果 MikroTik 还有别的 WAN，调整 distance
/ip/route
add dst-address=0.0.0.0/0 gateway=$MT_LAN_GW distance=10 comment="via watchguard proxy-wan"

# --- 3. NAT：容器网段出去时伪装为 MikroTik 对外 IP ---
/ip/firewall/nat
add chain=srcnat src-address=$VETH_NET action=masquerade comment="sbox-container egress"

# --- 4. Container 全局配置 ---
/container/config
set registry-url=https://registry-1.docker.io tmpdir=$USB_LABEL/pull

# --- 5. 挂载点（把 client.json 放到 /$USB_LABEL/sbox-conf/ 下后，容器看到 /etc/sing-box/client.json）---
/container/mounts
add name=sbox-conf src=/$USB_LABEL/sbox-conf dst=/etc/sing-box

# --- 6. 时区环境变量 ---
/container/envs
add name=sbox-env key=TZ value=Asia/Shanghai

# --- 7. 创建容器（RouterOS .rsc 里命令必须单行，不要折行）---
# 方式 A: remote-image 从 registry 拉（需先 docker push $IMG_NAME 到能访问的 registry）
# /container/add remote-image=$IMG_NAME interface=veth-sbox root-dir=$USB_LABEL/sbox-root mounts=sbox-conf envs=sbox-env start-on-boot=yes logging=yes

# 方式 B: file 从 USB 盘的 tar 导入（推荐，无需 registry）
/container/add file=$USB_LABEL/image.tar interface=veth-sbox root-dir=$USB_LABEL/sbox-root mounts=sbox-conf envs=sbox-env start-on-boot=yes logging=yes

# --- 8. 防火墙：允许容器与外部通信 ---
/ip/firewall/filter
add chain=forward src-address=$VETH_NET action=accept comment="sbox-container out"
add chain=forward dst-address=$VETH_NET action=accept connection-state=established,related comment="sbox-container in"

# --- 9. 启动 ---
# /container/start [find where root-dir=$USB_LABEL/sbox-root]
# /container/print
# /container/shell 0    # 进容器排障
RSC
info "生成 mt-setup.rsc"

# ---------------- WatchGuard 侧清单（文字手册）---------------
cat > "$OUT_DIR/watchguard-12.7.2-pbr.md" <<WG
# WatchGuard M670 Fireware 12.7.2 - SD-WAN PBR 配置手册

目标：目标 IP ∈ 别名 \`PROXY_DST\` 的流量，走新建 External 接口 eth2（物理连 MikroTik \`$MT_LAN_IF\`），
其他流量走默认 ISP 出口。

## 1. 添加代理-WAN 接口
Network → Interfaces → 选一个未用物理口（假设 eth2）→ Edit
- Interface Name: \`Proxy-WAN\`
- Interface Type: \`External\`
- Configuration: \`Manual (Static)\`
- IP Address: \`$MT_LAN_GW/30\`
- **不要勾** \"Default Gateway\"
- Save

## 2. 创建 Alias
Firewall → Aliases → Add
- Alias Name: \`PROXY_DST\`
- Alias Type: \`Host IPv4 Addresses\`
- Members: 先加几条测试用 IP（例如 \`208.65.152.0/22\`, \`74.125.0.0/16\`, \`173.194.0.0/16\`）
- Save

## 3. 创建 SD-WAN Action
Network → SD-WAN → Actions → Add
- Name: \`Via_Proxy\`
- Type: \`Failover\`
- External Interfaces: Add \`Proxy-WAN\`
- Probe: ICMP to \`$VETH_CT_IP\` (容器 IP) 或 \`1.1.1.1\`（容器能出网后可达）
- Save

## 4. 创建 PBR Firewall Policy
Firewall → Firewall Policies → Add
- Name: \`Proxy-to-Container\`
- Policy Type: \`Any\` (Packet Filter)
- From: \`Any-Trusted\`, \`Any-Optional\`
- To: \`PROXY_DST\`
- Advanced tab:
    - ✅ Use policy-based routing → \`Via_Proxy\`
    - ✅ Failover to default route （容器挂了不断网）
- Save, Deploy

## 后续维护
只改 \`PROXY_DST\` Alias 的 IP 列表 → Save → Deploy
WG
info "生成 watchguard-12.7.2-pbr.md"

# ---------------- README ----------------
cat > "$OUT_DIR/README.md" <<README
# MikroTik 容器客户端包

由 \`gen-mt-client.sh\` 在 VPS \`$SERVER_IP\` 上于 $(date '+%F %T') 生成。

## 文件说明
\`\`\`
sbox-conf/client.json              # sing-box 客户端配置（容器挂载点 /etc/sing-box/）
docker/Dockerfile                  # 自建镜像（sing-box + iptables + entrypoint）
docker/entrypoint.sh               # 容器入口脚本
mt-setup.rsc                       # RouterOS 批量导入脚本
watchguard-12.7.2-pbr.md           # WatchGuard Fireware 12.7.2 PBR 配置手册
\`\`\`

## 部署顺序
1. **Docker 机器上 build 镜像**（重要：CCR2004 是 **ARM64**，如果你用 x86 Mac/PC，必须交叉 build）：
   \`\`\`bash
   cd docker/
   # x86 机器上：
   docker buildx create --use --name mt-build 2>/dev/null || docker buildx use mt-build
   docker buildx build --platform linux/arm64 -t $IMG_NAME --load .
   # Apple Silicon 机器上：docker build -t $IMG_NAME . 即可（已经是 arm64）
   docker save -o image.tar $IMG_NAME
   \`\`\`
   验证架构：\`tar -xOf image.tar manifest.json | jq\` 看到 arm64 字样才对。
2. **把 image.tar 和 sbox-conf/client.json 拷到 MikroTik USB 盘**（通过 Winbox Files 上传到 /$USB_LABEL/）：
   \`\`\`
   /$USB_LABEL/image.tar
   /$USB_LABEL/sbox-conf/client.json
   \`\`\`
3. **MikroTik 上执行**：
   \`\`\`
   /import mt-setup.rsc
   /container/start [find]
   /container/print     # state 应该是 running
   \`\`\`
4. **排障**：
   \`\`\`
   /container/shell 0
   # 容器里：
   ip a                                  # 看 eth0 和 tun0
   sing-box check -c /etc/sing-box/client.json
   /log print where message~"container"  # MikroTik 看容器日志
   \`\`\`
5. **WatchGuard** 按 watchguard-12.7.2-pbr.md 配置 PBR。

## 换 VPS 时
- 在新 VPS 上跑 install.sh → 装好 server
- 在新 VPS 上跑 gen-mt-client.sh → 生成新的 mt-client-pkg.tar.gz
- 只需要替换 MikroTik 上 \`/$USB_LABEL/sbox-conf/client.json\`
- MikroTik: \`/container/stop 0 ; /container/start 0\`
- WatchGuard/Docker 镜像都不用动
README
info "生成 README.md"

# ---------------- 打包 ----------------
tar -czf "$TAR_PATH" -C /root "$(basename "$OUT_DIR")"
SIZE=$(du -h "$TAR_PATH" | cut -f1)
info "打包完成：$TAR_PATH (${SIZE})"

echo
echo -e "${green}====== 下一步 ======${reset}"
echo "在你本机（Mac/Windows）执行："
echo "  scp root@$SERVER_IP:$TAR_PATH ."
echo
echo "或者用 sftp/WinSCP 下载。解压后按 README.md 操作。"
