#!/bin/bash

red="\033[31m\033[01m"
green="\033[32m\033[01m"
yellow="\033[33m\033[01m"
reset="\033[0m"
bold="\e[1m"

warning() { echo -e "${red}$*${reset}"; }
error() { warning "$*" && exit 1; }
info() { echo -e "${green}$*${reset}"; }
hint() { echo -e "${yellow}$*${reset}"; }

show_status(){
    singbox_pid=$(pgrep sing-box)
    singbox_status=$(systemctl is-active sing-box)
    if [ "$singbox_status" == "active" ]; then
        cpu_usage=$(ps -p $singbox_pid -o %cpu | tail -n 1)
        memory_usage_mb=$(( $(ps -p "$singbox_pid" -o rss | tail -n 1) / 1024 ))
        iswarp=$(grep '^WARP_ENABLE=' /root/sbox/config | cut -d'=' -f2)
        
        warning "SING-BOX服务状态信息:"
        hint "========================="
        info "状态: 运行中"
        info "CPU 占用: $cpu_usage%"
        info "内存 占用: ${memory_usage_mb}MB"
        info "当前版本: $(/root/sbox/sing-box version 2>/dev/null | awk '/version/{print $NF}')"
        info "warp谷歌解锁: $(if [ "$iswarp" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        hint "========================="
    else
        warning "SING-BOX 未运行！"
    fi
}

install_pkgs() {
  local pkgs=("qrencode" "jq" "iptables")
  for pkg in "${pkgs[@]}"; do
    command -v "$pkg" &> /dev/null || (hint "安装 $pkg..." && (apt update && apt install -y "$pkg" || yum install -y "$pkg"))
  done
}

install_shortcut() {
  cat > /usr/bin/mianyang << EOF
#!/usr/bin/env bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh) \$1
EOF
  chmod +x /usr/bin/mianyang
}

reload_singbox() {
    if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
        systemctl restart sing-box && info "服务已重启."
    else
        error "配置文件检查失败"
    fi
}

install_singbox(){
    latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name' 2>/dev/null)
    latest_version=${latest_version_tag:-v1.13.4}
    arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
    hint "安装版本: $latest_version, 架构: $arch"
    curl -L#o "/tmp/sb.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/${latest_version}/sing-box-${latest_version#v}-linux-${arch}.tar.gz"
    tar -xzf "/tmp/sb.tar.gz" -C /tmp && mv /tmp/sing-box-*/sing-box /root/sbox/ && rm -rf /tmp/sing-box-* /tmp/sb.tar.gz
    chmod +x /root/sbox/sing-box
}

show_client_configuration() {
  local server_ip=$(grep -o "SERVER_IP='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  local public_key=$(grep -o "PUBLIC_KEY='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  local reality_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' /root/sbox/sbconfig_server.json)
  local reality_uuid=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .users[0].uuid' /root/sbox/sbconfig_server.json)
  local short_id=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.reality.short_id[0]' /root/sbox/sbconfig_server.json)
  local hy_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' /root/sbox/sbconfig_server.json)
  local hy_password=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .users[0].password' /root/sbox/sbconfig_server.json)
  local hy_sni=$(grep -o "HY_SERVER_NAME='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')

  local reality_link="vless://$reality_uuid@$server_ip:$reality_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#SING-BOX-REALITY"
  local hy2_link="hysteria2://$hy_password@$server_ip:$hy_port?insecure=1&sni=$hy_sni#SING-BOX-HYSTERIA2"

  hint "==== Reality 链接 ===="
  echo "$reality_link"
  qrencode -t UTF8 "$reality_link"
  hint "==== Hysteria2 链接 ===="
  echo "$hy2_link"
  qrencode -t UTF8 "$hy2_link"

  # Clash Meta 纠错版
  hint "==== Clash Verge 专用配置 (复制 proxies 部分) ===="
cat << EOF
proxies:
  - name: Reality
    type: vless
    server: $server_ip
    port: ${reality_port:-19887}
    uuid: $reality_uuid
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: itunes.apple.com
    reality-opts:
      public-key: $public_key
      short-id: $short_id

  - name: Hysteria2
    type: hysteria2
    server: $server_ip
    port: ${hy_port:-10809}
    password: $hy_password
    sni: $hy_sni
    skip-cert-verify: true

rules:
  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT
  - MATCH,DIRECT
EOF
}

process_warp(){
    iswarp=$(grep '^WARP_ENABLE=' /root/sbox/config | cut -d'=' -f2)
    if [ "$iswarp" = "FALSE" ]; then
        enable_warp
    else
        disable_warp
    fi
}

enable_warp(){
    info "重构 1.13.x 架构并洗白 Google IP..."
    local pk="wIC19yRRSJkhVJcE09Qo9bE3P3PIwS3yyqyUnjwNO34="
    local v6="2606:4700:110:87ad:b400:91:eadb:887f"
    local res="XiBe"

    jq --arg pk "$pk" --arg v6 "$v6" --arg res "$res" '
    .endpoints = [
        {
            "type": "wireguard",
            "tag": "wg-out",
            "address": ["172.16.0.2/32", ($v6 + "/128")],
            "private_key": $pk,
            "peers": [{"address": "162.159.192.1", "port": 2408, "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "allowed_ips": ["0.0.0.0/0", "::/0"], "reserved": $res}]
        }
    ] | .route.rules = [
        {"action": "sniff"},
        {"network": "udp", "port": 443, "action": "reject"},
        {"rule_set": ["geosite-google","geosite-youtube","geosite-openai","geosite-netflix"], "outbound": "warp-out"}
    ] | .route.rule_set = [
        {"tag": "geosite-google", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google.srs", "download_detour": "direct"},
        {"tag": "geosite-youtube", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs", "download_detour": "direct"},
        {"tag": "geosite-openai", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs", "download_detour": "direct"},
        {"tag": "geosite-netflix", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs", "download_detour": "direct"}
    ] | .outbounds |= map(if .tag == "direct" then .detour = "wg-out" | del(.domain_resolver) else . end) | .outbounds += [{"type": "direct", "tag": "warp-out", "detour": "wg-out", "domain_resolver": {"server": "dns-local", "strategy": "ipv4_only"}}]
    ' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json
    
    sed -i "s/WARP_ENABLE=FALSE/WARP_ENABLE=TRUE/" /root/sbox/config
    reload_singbox
}

disable_warp(){
    jq '.route.rules = [{"action": "sniff"}, {"network": "udp", "port": 443, "action": "reject"}] | del(.route.rule_set, .endpoints) | .outbounds |= map(if .tag == "direct" then del(.detour) else . end) | del(.outbounds[] | select(.tag == "warp-out"))' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json
    sed -i "s/WARP_ENABLE=TRUE/WARP_ENABLE=FALSE/" /root/sbox/config
    reload_singbox
}

mkdir -p /root/sbox/self-cert
install_pkgs

if [ -f "/root/sbox/sbconfig_server.json" ]; then
    show_status
    echo "1. 重新安装"
    echo "2. 查看配置/Clash"
    echo "6. 开启谷歌解锁(解决异常流量)"
    echo "0. 退出"
    read -p "选择: " choice
    case $choice in
        1) rm -rf /root/sbox/* ;;
        2) show_client_configuration; exit 0 ;;
        6) process_warp; exit 0 ;;
        0) exit 0 ;;
    esac
fi

install_singbox
uuid=$(/root/sbox/sing-box generate uuid)
key_pair=$(/root/sbox/sing-box generate reality-keypair)
pk=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
pubk=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
sid=$(/root/sbox/sing-box generate rand --hex 8)

cat > /root/sbox/sbconfig_server.json << EOF
{
  "log": {"level": "info", "timestamp": true},
  "dns": {"servers": [{"tag": "dns-local", "type": "local"}]},
  "route": {"rules": [{"action": "sniff"},{"network": "udp", "port": 443, "action": "reject"}]},
  "inbounds": [
    {"type": "vless","tag": "vless-in","listen": "::","listen_port": 19887,"users": [{"uuid": "$uuid","flow": "xtls-rprx-vision"}],"tls": {"enabled": true,"server_name": "itunes.apple.com","reality": {"enabled": true,"handshake": {"server": "itunes.apple.com","server_port": 443},"private_key": "$pk","short_id": ["$sid"]}}},
    {"type": "hysteria2","tag": "hy2-in","listen": "::","listen_port": 10809,"users": [{"password": "pass123456"}],"tls": {"enabled": true,"alpn": ["h3"],"certificate_path": "/root/sbox/self-cert/cert.pem","key_path": "/root/sbox/self-cert/private.key"}}
  ],
  "outbounds": [{"type": "direct","tag": "direct","domain_resolver": {"server": "dns-local","strategy": "ipv4_only"}}]
}
EOF

openssl ecparam -genkey -name prime256v1 -out /root/sbox/self-cert/private.key
openssl req -new -x509 -days 36500 -key /root/sbox/self-cert/private.key -out /root/sbox/self-cert/cert.pem -subj "/CN=bing.com"

cat > /root/sbox/config <<EOF
SERVER_IP='$(curl -s4 ip.sb)'
PUBLIC_KEY='$pubk'
HY_SERVER_NAME='bing.com'
WARP_ENABLE=FALSE
EOF

cat > /etc/systemd/system/sing-box.service <<EOF
[Service]
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
Restart=always
WorkingDirectory=/root/sbox
EOF

systemctl daemon-reload && systemctl enable --now sing-box
install_shortcut
show_client_configuration
