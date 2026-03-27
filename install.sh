#!/bin/bash

# 颜色定义
red="\033[31m\033[01m"
green="\033[32m\033[01m"
yellow="\033[33m\033[01m"
reset="\033[0m"

info() { echo -e "${green}$*${reset}"; }
warning() { echo -e "${yellow}$*${reset}"; }
error() { echo -e "${red}$*${reset}" && exit 1; }

# 环境安装
install_pkgs() {
    local pkgs=("qrencode" "jq" "curl" "openssl" "iptables")
    for pkg in "${pkgs[@]}"; do
        if ! command -v "$pkg" &> /dev/null; then
            if command -v apt &> /dev/null; then
                sudo apt update > /dev/null 2>&1 && sudo apt install -y "$pkg" > /dev/null 2>&1
            elif command -v yum &> /dev/null; then
                sudo yum install -y "$pkg" > /dev/null 2>&1
            fi
        fi
    done
}

# 快捷指令
install_shortcut() {
    cat > /usr/bin/mianyang << EOF
#!/usr/bin/env bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh) \$1
EOF
    chmod +x /usr/bin/mianyang
}

# 生成 1.13.x 洁净配置模板
generate_base_config() {
    local uuid=$(/root/sbox/sing-box generate uuid)
    local key_pair=$(/root/sbox/sing-box generate reality-keypair)
    local pk=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
    local pubk=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
    local sid=$(/root/sbox/sing-box generate rand --hex 8)
    local hy2_pass=$(/root/sbox/sing-box generate rand --hex 12)
    local vps_ip=$(curl -s4 ip.sb || curl -s6 ip.sb)

    cat > /root/sbox/sbconfig_server.json << EOF
{
  "log": {"level": "info", "timestamp": true},
  "dns": {"servers": [{"tag": "dns-local", "type": "local"}]},
  "route": {
    "rules": [
      {"action": "sniff"},
      {"network": "udp", "port": 443, "action": "reject"}
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": 19887,
      "users": [{"uuid": "$uuid", "flow": "xtls-rprx-vision"}],
      "tls": {"enabled": true, "server_name": "itunes.apple.com", "reality": {"enabled": true, "handshake": {"server": "itunes.apple.com", "server_port": 443}, "private_key": "$pk", "short_id": ["$sid"]}}
    },
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": 10809,
      "users": [{"password": "$hy2_pass"}],
      "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "/root/sbox/self-cert/cert.pem", "key_path": "/root/sbox/self-cert/private.key"}
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct", "domain_resolver": {"server": "dns-local", "strategy": "ipv4_only"}}]
}
EOF
    cat > /root/sbox/config <<EOF
SERVER_IP='$vps_ip'
PUBLIC_KEY='$pubk'
REALITY_UUID='$uuid'
SHORT_ID='$sid'
HY2_PASS='$hy2_pass'
WARP_ENABLE=FALSE
EOF
}

# 开启 WARP 谷歌分流解锁 (1.13.0+ 架构)
process_warp() {
    info "正在开启 1.13.0+ 标准架构的 WARP 解锁..."
    # 模拟分配
    local v6="2606:4700:110:87ad:b400:91:eadb:887f"
    local wpk="wIC19yRRSJkhVJcE09Qo9bE3P3PIwS3yyqyUnjwNO34="
    local res="XiBe"

    jq --arg pk "$wpk" --arg v6 "$v6" --arg res "$res" '
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
        {"rule_set": ["geosite-google","geosite-youtube","geosite-openai","geosite-netflix"], "outbound": "warp-direct"}
    ] | .route.rule_set = [
        {"tag": "geosite-google", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google.srs", "download_detour": "direct"},
        {"tag": "geosite-youtube", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs", "download_detour": "direct"},
        {"tag": "geosite-openai", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs", "download_detour": "direct"},
        {"tag": "geosite-netflix", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs", "download_detour": "direct"}
    ] | .outbounds += [{"type": "direct", "tag": "warp-direct", "detour": "wg-out", "domain_resolver": {"server": "dns-local", "strategy": "ipv4_only"}}]
    ' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json

    sed -i "s/WARP_ENABLE=FALSE/WARP_ENABLE=TRUE/" /root/sbox/config
    systemctl restart sing-box
    info "WARP 解锁配置完成！"
}

# 显示配置
show_conf() {
    local vps_ip=$(grep "SERVER_IP=" /root/sbox/config | cut -d"'" -f2)
    local pubk=$(grep "PUBLIC_KEY=" /root/sbox/config | cut -d"'" -f2)
    local uuid=$(grep "REALITY_UUID=" /root/sbox/config | cut -d"'" -f2)
    local sid=$(grep "SHORT_ID=" /root/sbox/config | cut -d"'" -f2)
    local hy2p=$(grep "HY2_PASS=" /root/sbox/config | cut -d"'" -f2)
    
    local reality_link="vless://$uuid@$vps_ip:19887?encryption=none&flow=xtls-rprx-vision&security=reality&sni=itunes.apple.com&fp=chrome&pbk=$pubk&sid=$sid&type=tcp&headerType=none#SING-BOX-REALITY"
    local hy2_link="hysteria2://$hy2p@$vps_ip:10809?insecure=1&sni=bing.com#SING-BOX-HYSTERIA2"
    
    show_notice "VLESS Reality 链接"
    info "$reality_link"
    qrencode -t UTF8 "$reality_link"
    show_notice "Hysteria2 链接"
    info "$hy2_link"
    qrencode -t UTF8 "$hy2_link"
}

# 入口逻辑
mkdir -p /root/sbox/self-cert
install_pkgs

if [ -f "/root/sbox/sbconfig_server.json" ] && [ "$1" != "_install" ]; then
    show_status
    echo "1. 彻底清空并重新安装"
    echo "6. 开启/管理 WARP 解锁"
    echo "0. 卸载"
    read -p "请选择: " choice
    case $choice in
        1) rm -rf /root/sbox/*; bash $0 _install ;;
        6) process_warp ;;
        0) systemctl stop sing-box; rm -rf /root/sbox; info "已卸载" ;;
    esac
    exit 0
fi

# 安装内核
arch=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
curl -L "https://github.com/SagerNet/sing-box/releases/download/v1.13.4/sing-box-1.13.4-linux-${arch}.tar.gz" -o /tmp/sbox.tar.gz
tar -xzf /tmp/sbox.tar.gz -C /tmp && mv /tmp/sing-box-*/sing-box /root/sbox/ && rm -rf /tmp/sing-box-* /tmp/sbox.tar.gz

# 证书
openssl ecparam -genkey -name prime256v1 -out /root/sbox/self-cert/private.key
openssl req -new -x509 -days 36500 -key /root/sbox/self-cert/private.key -out /root/sbox/self-cert/cert.pem -subj "/CN=bing.com"

generate_base_config

# 服务
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box
After=network.target
[Service]
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
Restart=always
WorkingDirectory=/root/sbox
EOF
systemctl daemon-reload && systemctl enable --now sing-box
install_shortcut
show_conf
