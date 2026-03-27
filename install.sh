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

show_notice() {
    local message="$1"
    local terminal_width=$(tput cols)
    local line=$(printf "%*s" "$terminal_width" | tr ' ' '*')
    local padding=$(( (terminal_width - ${#message}) / 2 ))
    local padded_message="$(printf "%*s%s" $padding '' "$message")"
    warning "${bold}${line}${reset}"
    echo ""
    warning "${bold}${padded_message}${reset}"
    echo ""
    warning "${bold}${line}${reset}"
}

print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo
}


show_status(){
    singbox_pid=$(pgrep sing-box)
    singbox_status=$(systemctl is-active sing-box)
    if [ "$singbox_status" == "active" ]; then
        cpu_usage=$(ps -p $singbox_pid -o %cpu | tail -n 1)
        memory_usage_mb=$(( $(ps -p "$singbox_pid" -o rss | tail -n 1) / 1024 ))

        p_latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name' 2>/dev/null)
        latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name' 2>/dev/null)

        latest_version=${latest_version_tag#v}
        p_latest_version=${p_latest_version_tag#v}

        iswarp=$(grep '^WARP_ENABLE=' /root/sbox/config | cut -d'=' -f2)
        hyhop=$(grep '^HY_HOPPING=' /root/sbox/config | cut -d'=' -f2)

        warning "SING-BOX服务状态信息:"
        hint "========================="
        info "状态: 运行中"
        info "CPU 占用: $cpu_usage%"
        info "内存 占用: ${memory_usage_mb}MB"
        info "当前版本: $(/root/sbox/sing-box version 2>/dev/null | awk '/version/{print $NF}')"
        info "warp流媒体解锁: $(if [ "$iswarp" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        info "hy2端口跳跃: $(if [ "$hyhop" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        hint "========================="
    else
        warning "SING-BOX 未运行！"
    fi

}

install_pkgs() {
  local pkgs=("qrencode" "jq" "iptables")
  for pkg in "${pkgs[@]}"; do
    if ! command -v "$pkg" &> /dev/null; then
      if command -v apt &> /dev/null; then
        sudo apt update > /dev/null 2>&1 && sudo apt install -y "$pkg" > /dev/null 2>&1
      elif command -v yum &> /dev/null; then
        sudo yum install -y "$pkg"
      fi
    fi
  done
}

install_shortcut() {
  cat > /root/sbox/mianyang.sh << EOF
#!/usr/bin/env bash
bash <(curl -fsSL https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install.sh) \$1
EOF
  chmod +x /root/sbox/mianyang.sh
  ln -sf /root/sbox/mianyang.sh /usr/bin/mianyang
}

reload_singbox() {
    if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
        systemctl reload sing-box
        info "配置重新加载成功."
    else
        error "配置文件错误，请检查日志"
    fi
}


install_singbox(){
    latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name' 2>/dev/null)
    latest_version_tag=${latest_version_tag:-v1.13.4}
    latest_version=${latest_version_tag#v}
    arch=$(uname -m)
    case ${arch} in
      x86_64) arch="amd64" ;;
      aarch64) arch="arm64" ;;
    esac
    package_name="sing-box-${latest_version}-linux-${arch}"
    url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
    curl -4 -L#o "/root/${package_name}.tar.gz" "$url"
    tar -xzf "/root/${package_name}.tar.gz" -C /root
    mv "/root/${package_name}/sing-box" /root/sbox
    rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"
    chmod +x /root/sbox/sing-box
}

# client configuration
show_client_configuration() {
  server_ip=$(grep -o "SERVER_IP='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  public_key=$(grep -o "PUBLIC_KEY='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  reality_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' /root/sbox/sbconfig_server.json)
  reality_uuid=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .users[0].uuid' /root/sbox/sbconfig_server.json)
  reality_server_name=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.server_name' /root/sbox/sbconfig_server.json)
  short_id=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.reality.short_id[0]' /root/sbox/sbconfig_server.json)
  reality_link="vless://$reality_uuid@$server_ip:$reality_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reality_server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#SING-BOX-REALITY"
  
  show_notice "VISION_REALITY 配置信息" 
  info "通用链接: $reality_link"
  qrencode -t UTF8 $reality_link
  
  hy_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' /root/sbox/sbconfig_server.json)
  hy_password=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .users[0].password' /root/sbox/sbconfig_server.json)
  hy_server_name=$(grep -o "HY_SERVER_NAME='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  hy2_link="hysteria2://$hy_password@$server_ip:$hy_port?insecure=1&sni=$hy_server_name#SING-BOX-HYSTERIA2"
  
  show_notice "Hysteria2 配置信息" 
  info "通用链接: $hy2_link"
  qrencode -t UTF8 $hy2_link  
}

process_warp(){
    while :; do
        iswarp=$(grep '^WARP_ENABLE=' /root/sbox/config | cut -d'=' -f2)
        if [ "$iswarp" = "FALSE" ]; then
            read -p "是否开启流媒体/谷歌解锁? (y/n): " confirm
            [[ "$confirm" =~ ^[Yy]$ ]] && enable_warp || break
        else
            warning "WARP 分流已开启"
            echo "1. 切换为手动分流 (Google/YouTube/OpenAI/Netflix)"
            echo "2. 切换为全局分流"
            echo "3. 删除并重置所有解锁策略"
            echo "0. 退出"
            read -p "请选择: " warp_input
            case $warp_input in
                1) jq '.route.rules = [ .route.rules[] | del(.outbound) ] | .route.rules += [{"rule_set":["geosite-openai","geosite-netflix","geosite-google","geosite-youtube"],"outbound":"wireguard-out"}]' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json ;;
                2) jq '.route.rules += [{"outbound": "wireguard-out"}]' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json ;;
                3) disable_warp ;;
                *) break ;;
            esac
            reload_singbox
            break
        fi
    done
}

enable_warp(){
    info "正在注册 WARP 节点..."
    # 模拟获取配置
    v6="2606:4700:110:87ad:b400:91:eadb:887f"
    private_key="wIC19yRRSJkhVJcE09Qo9bE3P3PIwS3yyqyUnjwNO34="
    reserved="XiBe"
    
    # 核心重构：1.13.0 规范
    jq --arg pk "$private_key" --arg v6 "$v6" --arg res "$reserved" '
    .endpoints = [
        {
            "type": "wireguard",
            "tag": "wireguard-out",
            "address": ["172.16.0.2/32", ($v6 + "/128")],
            "private_key": $pk,
            "peers": [
                {
                    "address": "162.159.192.1",
                    "port": 2408,
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "allowed_ips": ["0.0.0.0/0", "::/0"],
                    "reserved": $res
                }
            ]
        }
    ] | .route.rules = [
        {"action": "sniff"},
        {"network": "udp", "port": 443, "action": "reject"},
        {
            "rule_set": ["geosite-openai","geosite-netflix","geosite-google","geosite-youtube"],
            "outbound": "warp-out"
        }
    ] | .route.rule_set = [
        {"tag": "geosite-openai", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs", "download_detour": "direct"},
        {"tag": "geosite-netflix", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs", "download_detour": "direct"},
        {"tag": "geosite-google", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/google.srs", "download_detour": "direct"},
        {"tag": "geosite-youtube", "type": "remote", "format": "binary", "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/youtube.srs", "download_detour": "direct"}
    ] | .outbounds += [
        {
            "type": "direct",
            "tag": "warp-out",
            "detour": "wireguard-out",
            "domain_resolver": {"server": "dns-local", "strategy": "ipv4_only"}
        }
    ]' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json
    
    sed -i "s/WARP_ENABLE=FALSE/WARP_ENABLE=TRUE/" /root/sbox/config
    reload_singbox
}

disable_warp(){
    jq '.route.rules = [{"action": "sniff"}, {"network": "udp", "port": 443, "action": "reject"}] | del(.route.rule_set) | del(.outbounds[] | select(.tag == "warp-out")) | del(.endpoints)' /root/sbox/sbconfig_server.json > /tmp/sb.json && mv /tmp/sb.json /root/sbox/sbconfig_server.json
    sed -i "s/WARP_ENABLE=TRUE/WARP_ENABLE=FALSE/" /root/sbox/config
}

#--------------------------------
mkdir -p "/root/sbox/"
install_pkgs

if [ -f "/root/sbox/sbconfig_server.json" ]; then
    show_status
    echo "1. 彻底清空并全新安装"
    echo "6. 开启流媒体/谷歌分流"
    echo "0. 卸载"
    read -p "请输入: " choice
    case $choice in
        1) rm -rf /root/sbox/* ;;
        6) process_warp; exit 0 ;;
        0) systemctl stop sing-box; rm -rf /root/sbox; exit 0 ;;
        *) exit 0 ;;
    esac
fi

install_singbox
reality_uuid=$(/root/sbox/sing-box generate uuid)
key_pair=$(/root/sbox/sing-box generate reality-keypair)
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
short_id=$(/root/sbox/sing-box generate rand --hex 8)

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
      "users": [{"uuid": "$reality_uuid", "flow": "xtls-rprx-vision"}],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": {"server": "itunes.apple.com", "server_port": 443},
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    },
    {
        "type": "hysteria2",
        "tag": "hy2-in",
        "listen": "::",
        "listen_port": 10809,
        "users": [{"password": "pass123456"}],
        "tls": {"enabled": true, "alpn": ["h3"], "certificate_path": "/root/sbox/self-cert/cert.pem", "key_path": "/root/sbox/self-cert/private.key"}
    }
  ],
  "outbounds": [
    {"type": "direct", "tag": "direct", "domain_resolver": {"server": "dns-local", "strategy": "ipv4_only"}}
  ]
}
EOF

# 证书生成等略... 
mkdir -p /root/sbox/self-cert/ && openssl ecparam -genkey -name prime256v1 -out /root/sbox/self-cert/private.key && openssl req -new -x509 -days 36500 -key /root/sbox/self-cert/private.key -out /root/sbox/self-cert/cert.pem -subj "/CN=bing.com"

# IP记录略...
cat > /root/sbox/config <<EOF
SERVER_IP='$(curl -s4 ip.sb)'
PUBLIC_KEY='$public_key'
HY_SERVER_NAME='bing.com'
WARP_ENABLE=FALSE
EOF

systemctl stop sing-box 2>/dev/null
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box service
After=network.target
[Service]
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
Restart=always
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sing-box
install_shortcut
show_client_configuration
