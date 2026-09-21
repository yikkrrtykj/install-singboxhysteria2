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
    local terminal_width
    terminal_width=$(tput cols)
    local line
    line=$(printf '%*s' "$terminal_width" '' | tr ' ' '*')
    local padding=$(( (terminal_width - ${#message}) / 2 ))
    [ "$padding" -lt 0 ] && padding=0
    local padded_message
    padded_message="$(printf '%*s' "$padding" '')${message}"
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
    singbox_pid=$(pgrep -o -x sing-box 2>/dev/null || true)
    singbox_status=$(systemctl is-active sing-box 2>/dev/null || true)
    if [ -n "$singbox_pid" ]; then
        cpu_usage=$(ps -p "$singbox_pid" -o %cpu= | xargs)
        memory_usage_kb=$(ps -p "$singbox_pid" -o rss= | xargs)
        memory_usage_mb=$(( ${memory_usage_kb:-0} / 1024 ))

        latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name' 2>/dev/null)
        if [ -n "$latest_version_tag" ] && [ "$latest_version_tag" != "null" ]; then
            latest_version=${latest_version_tag#v}
        else
            latest_version="查询失败"
        fi

        hyhop=$(grep '^HY_HOPPING=' /root/sbox/config | cut -d'=' -f2)

        info "SING-BOX服务状态信息:"
        hint "========================="
        info "状态: 运行中"
        if [ "$singbox_status" == "active" ]; then
            info "启动方式: systemd (sing-box.service)"
        else
            warning "启动方式: 手工进程（旧安装，未由 systemd 管理）"
        fi
        info "CPU 占用: $cpu_usage%"
        info "内存 占用: ${memory_usage_mb}MB"
        info "singbox正式版最新版本: $latest_version"
		info "singbox当前版本: $(/root/sbox/sing-box version 2>/dev/null | awk '/version/{print $NF}')"
        info "hy2端口跳跃(输入6管理): $(if [ "$hyhop" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        hint "========================="
    else
        warning "SING-BOX 未运行！"
    fi

}

install_pkgs() {
  # Install qrencode, jq, and iptables if not already installed
  local pkgs=("qrencode" "jq" "iptables")
  for pkg in "${pkgs[@]}"; do
    if command -v "$pkg" &> /dev/null; then
      hint "$pkg 已经安装"
    else
      hint "开始安装 $pkg..."
      if command -v apt &> /dev/null; then
        sudo apt update > /dev/null 2>&1 && sudo apt install -y "$pkg" > /dev/null 2>&1
      elif command -v yum &> /dev/null; then
        sudo yum install -y "$pkg"
      elif command -v dnf &> /dev/null; then
        sudo dnf install -y "$pkg"
      else
        error "Unable to install $pkg. Please install it manually and rerun the script."
      fi
      hint "$pkg 安装成功"
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
        echo "检查配置文件成功，开始重新加载服务..."
        if systemctl is-active --quiet sing-box; then
            if systemctl reload sing-box; then
                echo "systemd 服务重新加载成功."
            else
                error "systemd 服务重新加载失败，请检查日志"
            fi
        elif pgrep -x sing-box >/dev/null 2>&1; then
            singbox_pid=$(pgrep -o -x sing-box)
            if kill -HUP "$singbox_pid"; then
                echo "手工启动的 sing-box 进程已重新加载配置."
            else
                error "无法重新加载手工启动的 sing-box 进程"
            fi
        else
            error "未找到正在运行的 sing-box 进程"
        fi

        if systemctl is-active --quiet sing-box-hy2-hopping.service; then
            if systemctl reload sing-box-hy2-hopping.service; then
                info "Hysteria2 端口跳跃规则已同步刷新."
            else
                error "Hysteria2 端口跳跃规则刷新失败"
            fi
        fi
    else
        error "配置文件检查错误，请检查配置文件"
    fi
}


install_singbox(){
	echo "Installing sing-box 1.14.x stable version..."
	# Phase D: fresh installs are pinned to the newest STABLE 1.14.x release.
	# 1.13.x / 1.15.x / prereleases are rejected by the selector itself.
	latest_version_tag="$(select_1_14_stable_tag)" || error "无法确定 sing-box 1.14.x stable 版本"
	latest_version=${latest_version_tag#v}
	echo "Selected 1.14.x stable version: $latest_version"
		# Detect server architecture
		arch=$(uname -m)
		echo "本机架构为: $arch"
    case ${arch} in
      x86_64) arch="amd64" ;;
      aarch64) arch="arm64" ;;
      armv7l) arch="armv7" ;;
    esac
    echo "最新版本为: $latest_version"
    package_name="sing-box-${latest_version}-linux-${arch}"
    url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
    archive_path="/root/${package_name}.tar.gz"
    candidate_path="/root/sbox/sing-box.new"
    curl -4 -fL --progress-bar -o "$archive_path" "$url" || error "下载 sing-box 失败"
    tar -tzf "$archive_path" >/dev/null 2>&1 || error "下载包校验失败"
    tar -xzf "$archive_path" -C /root || error "解压 sing-box 失败"
    install -m 0755 -o root -g root "/root/${package_name}/sing-box" "$candidate_path" || error "准备新版 sing-box 失败"
    rm -rf "$archive_path" "/root/${package_name}"

    if [ -f /root/sbox/sbconfig_server.json ]; then
        "$candidate_path" check -c /root/sbox/sbconfig_server.json || {
            rm -f "$candidate_path"
            error "新版 sing-box 无法通过现有配置检查，已保留当前版本"
        }
    fi

    if [ -x /root/sbox/sing-box ]; then
        backup_path="/root/sbox/sing-box.backup-$(date +%Y%m%d-%H%M%S)"
        cp -a /root/sbox/sing-box "$backup_path" || error "备份当前 sing-box 失败"
        info "旧版 sing-box 已备份到: $backup_path"
    fi
    mv -f "$candidate_path" /root/sbox/sing-box || error "替换 sing-box 失败"
}

restart_singbox() {
    if systemctl is-active --quiet sing-box; then
        systemctl restart sing-box
        return $?
    fi

    if pgrep -x sing-box >/dev/null 2>&1; then
        warning "检测到 sing-box 正由手工进程运行，拒绝启动第二个 systemd 实例。"
        warning "请先安排维护窗口，将现有进程平滑迁移到 sing-box.service。"
        return 2
    fi

    systemctl start sing-box
}

generate_port() {
   local protocol="$1"
    while :; do
        port=$((RANDOM % 10001 + 10000))
        read -p "请为 ${protocol} 输入监听端口(默认为随机生成): " user_input
        port=${user_input:-$port}
        ss -tuln | grep -q ":$port\b" || { echo "$port"; return 0; }
        echo "端口 $port 被占用，请输入其他端口"
    done
}

modify_port() {
    local current_port="$1"
    local protocol="$2"
    while :; do
        read -p "请输入需要修改的 ${protocol} 端口，回车不修改 (当前 ${protocol} 端口为: $current_port): " modified_port
        modified_port=${modified_port:-$current_port}
        if [ "$modified_port" -eq "$current_port" ] || ! ss -tuln | grep -q ":$modified_port\b"; then
            break
        else
            echo "端口 $modified_port 被占用，请输入其他端口"
        fi
    done
    echo "$modified_port"
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
  echo ""
  show_notice "VISION_REALITY 通用链接 二维码 通用参数" 
  echo ""
  info "通用链接如下"
  echo "" 
  echo "$reality_link"
  echo ""
  info "二维码如下"
  echo ""
  qrencode -t UTF8 "$reality_link"
  echo ""
  info "客户端通用参数如下"
  echo "------------------------------------"
  echo "服务器ip: $server_ip"
  echo "监听端口: $reality_port"
  echo "UUID: $reality_uuid"
  echo "域名SNI: $reality_server_name"
  echo "Public Key: $public_key"
  echo "Short ID: $short_id"
  echo "------------------------------------"

  # hy2
  hy_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' /root/sbox/sbconfig_server.json)
  hy_server_name=$(grep -o "HY_SERVER_NAME='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  hy_password=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .users[0].password' /root/sbox/sbconfig_server.json)
  ishopping=$(grep '^HY_HOPPING=' /root/sbox/config | cut -d'=' -f2)
  hy_hopping_start=$(grep '^HY_HOPPING_START=' /root/sbox/config | cut -d'=' -f2)
  hy_hopping_end=$(grep '^HY_HOPPING_END=' /root/sbox/config | cut -d'=' -f2)
  hy_server_port_json="            \"server_port\": $hy_port,"
  formatted_range=""
  if [ "$ishopping" = "TRUE" ] &&
     [[ "$hy_hopping_start" =~ ^[0-9]+$ ]] &&
     [[ "$hy_hopping_end" =~ ^[0-9]+$ ]]; then
      formatted_range="${hy_hopping_start}-${hy_hopping_end}"
      hy_server_port_json="            \"server_ports\": [\"${hy_hopping_start}:${hy_hopping_end}\"],"
      hy2_link="hysteria2://$hy_password@$server_ip:$hy_port?insecure=1&sni=$hy_server_name&mport=${hy_port},${formatted_range}#SING-BOX-HYSTERIA2"
  elif [ "$ishopping" = "TRUE" ]; then
      warning "端口跳跃已标记为开启，但配置中没有有效端口范围，将显示固定端口配置。"
      hy2_link="hysteria2://$hy_password@$server_ip:$hy_port?insecure=1&sni=$hy_server_name#SING-BOX-HYSTERIA2"
  else
      hy2_link="hysteria2://$hy_password@$server_ip:$hy_port?insecure=1&sni=$hy_server_name#SING-BOX-HYSTERIA2"
  fi
  echo ""
  echo "" 
  show_notice "Hysteria2通用链接 二维码 通用参数" 
  echo ""
  info "通用链接如下"
  echo "" 
  echo "$hy2_link"
  echo ""
  info "二维码如下"
  echo ""
  qrencode -t UTF8 "$hy2_link"
  echo ""
  info "客户端通用参数如下"
  echo "------------------------------------"
  echo "服务器ip: $server_ip"
  echo "端口号: $hy_port"
  if [ "$ishopping" = "TRUE" ] && [ -n "$formatted_range" ]; then
    echo "跳跃端口为${formatted_range}"
  else
    echo "端口跳跃未开启"
  fi
  echo "密码password: $hy_password"
  echo "域名SNI: $hy_server_name"
  echo "跳过证书验证（允许不安全）: True"
  echo "------------------------------------"

  show_notice "Mihomo/Clash Meta客户端配置参数"
  mihomo_config_path="/root/sbox/mihomo_client.yaml"
  # 共享账号（保留名 legacy，即两个入站的首个用户）的展示路径，渲染统一走 canonical renderer；
  # 多客户端请用"客户端管理 -> 生成客户端配置"
  write_mihomo_template "$mihomo_config_path" || error "保存 Mihomo 客户端配置失败"
  chmod 0600 "$mihomo_config_path" || error "设置 Mihomo 客户端配置权限失败"
  cat "$mihomo_config_path"
  echo ""
  info "Mihomo 客户端配置已保存到: $mihomo_config_path"
  echo ""
  echo ""
  show_notice "sing-box客户端配置1.13.0及以上"
  client_config_path="/root/sbox/sbconfig_client.json"
cat > "$client_config_path" << EOF || error "保存 sing-box 客户端配置失败"
{
  "log": {
    "level": "debug",
    "timestamp": true
  },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui_download_url": "",
      "external_ui_download_detour": "",
      "external_ui": "ui",
      "secret": "",
      "default_mode": "rule"
    },
    "cache_file": {
      "enabled": true,
      "store_fakeip": false
    }
  },
  "dns": {
    "servers": [
      {
        "tag": "proxyDns",
        "type": "udp",
        "server": "8.8.8.8",
        "detour": "proxy"
      },
      {
        "tag": "localDns",
        "type": "udp",
        "server": "223.5.5.5",
        "detour": "direct"
      },
      {
        "tag": "fakeip",
        "type": "fakeip",
        "inet4_range": "198.18.0.0/15",
        "inet6_range": "fc00::/18"
      }
    ],
    "rules": [
      {
        "domain": [
          "ghproxy.com",
          "cdn.jsdelivr.net",
          "testingcf.jsdelivr.net"
        ],
        "server": "localDns"
      },
      {
        "rule_set": "geosite-category-ads-all",
        "action": "reject"
      },
      {
        "rule_set": "geosite-cn",
        "action": "route",
        "server": "localDns"
      },
      {
        "clash_mode": "direct",
        "action": "route",
        "server": "localDns"
      },
      {
        "clash_mode": "global",
        "action": "route",
        "server": "proxyDns"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "action": "route",
        "server": "proxyDns"
      },
      {
        "query_type": [
          "A",
          "AAAA"
        ],
        "action": "route",
        "server": "fakeip"
      }
    ],
    "final": "proxyDns"
  },
  "inbounds": [
    {
      "type": "tun",
      "address": ["172.19.0.1/30"],
      "mtu": 9000,
      "auto_route": true,
      "strict_route": true,
      "endpoint_independent_nat": false,
      "stack": "system",
      "platform": {
        "http_proxy": {
          "enabled": true,
          "server": "127.0.0.1",
          "server_port": 2080
        }
      }
    },
    {
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 2080,
      "users": []
    }
  ],
    "outbounds": [
    {
      "tag": "proxy",
      "type": "selector",
      "outbounds": [
        "auto",
        "direct",
        "sing-box-reality",
        "sing-box-hysteria2"
      ]
    },
    {
      "type": "vless",
      "tag": "sing-box-reality",
      "uuid": "$reality_uuid",
      "flow": "xtls-rprx-vision",
      "packet_encoding": "xudp",
      "server": "$server_ip",
      "server_port": $reality_port,
      "tls": {
        "enabled": true,
        "server_name": "$reality_server_name",
        "utls": {
          "enabled": true,
          "fingerprint": "chrome"
        },
        "reality": {
          "enabled": true,
          "public_key": "$public_key",
          "short_id": "$short_id"
        }
      }
    },
    {
            "type": "hysteria2",
            "server": "$server_ip",
${hy_server_port_json}
            "tag": "sing-box-hysteria2",
            "up_mbps": 300,
            "down_mbps": 300,
            "password": "$hy_password",
            "tls": {
                "enabled": true,
                "server_name": "$hy_server_name",
                "insecure": true,
                "alpn": [
                    "h3"
                ]
            }
        },
    {
      "tag": "direct",
      "type": "direct",
      "domain_resolver": {
        "server": "localDns"
      }
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": [
        "sing-box-reality",
        "sing-box-hysteria2"
      ],
      "url": "http://www.gstatic.com/generate_204",
      "interval": "1m",
      "tolerance": 50
    },
    {
      "tag": "WeChat",
      "type": "selector",
      "outbounds": [
        "direct",
        "sing-box-reality",
        "sing-box-hysteria2"
      ]
    },
    {
      "tag": "Apple",
      "type": "selector",
      "outbounds": [
        "direct",
        "sing-box-reality",
        "sing-box-hysteria2"
      ]
    },
    {
      "tag": "Microsoft",
      "type": "selector",
      "outbounds": [
        "direct",
        "sing-box-reality",
        "sing-box-hysteria2"
      ]
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "default_domain_resolver": "localDns",
    "final": "proxy",
    "rules": [
      {
        "action": "sniff"
      },
      {
        "protocol": "dns",
        "action": "hijack-dns"
      },
      {
        "network": "udp",
        "port": 443,
        "action": "reject"
      },
      {
        "rule_set": "geosite-category-ads-all",
        "action": "reject"
      },
      {
        "clash_mode": "direct",
        "outbound": "direct"
      },
      {
        "clash_mode": "global",
        "outbound": "proxy"
      },
      {
        "domain": [
          "clash.razord.top",
          "yacd.metacubex.one",
          "yacd.haishan.me",
          "d.metacubex.one"
        ],
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-wechat",
        "outbound": "WeChat"
      },
      {
        "rule_set": "geosite-geolocation-!cn",
        "outbound": "proxy"
      },
      {
        "ip_is_private": true,
        "outbound": "direct"
      },
      {
        "rule_set": "geoip-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-cn",
        "outbound": "direct"
      },
      {
        "rule_set": "geosite-apple",
        "outbound": "Apple"
      },
      {
        "rule_set": "geosite-microsoft",
        "outbound": "Microsoft"
      }
    ],
    "rule_set": [
      {
        "tag": "geoip-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-cn",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-geolocation-!cn",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-category-ads-all",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/category-ads-all.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-wechat",
        "type": "remote",
        "format": "source",
        "url": "https://testingcf.jsdelivr.net/gh/Toperlock/sing-box-geosite@main/wechat.json",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-apple",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/apple.srs",
        "download_detour": "direct"
      },
      {
        "tag": "geosite-microsoft",
        "type": "remote",
        "format": "binary",
        "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/microsoft.srs",
        "download_detour": "direct"
      }
    ]
  }
}
EOF

  chmod 0600 "$client_config_path" || error "设置 sing-box 客户端配置权限失败"
  cat "$client_config_path"
  echo ""
  info "sing-box 客户端配置已保存到: $client_config_path"

  if command -v base64 >/dev/null 2>&1; then
    mihomo_config_base64=$(base64 "$mihomo_config_path" | tr -d '\r\n')
    echo ""
    echo ""
    show_notice "Linux Mihomo 网关：复制以下命令到客户端"
    info "命令 1：把本次节点配置写入 Linux 客户端"
    printf "umask 077 && printf '%%s' '%s' | base64 -d > /tmp/mihomo_client.yaml && chmod 600 /tmp/mihomo_client.yaml\n" "$mihomo_config_base64"
    echo ""
    info "命令 2：下载 Linux 网关安装器"
    echo "curl -fsSL -o /tmp/install-linux-gateway.sh https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/main/install-linux-gateway.sh && chmod 700 /tmp/install-linux-gateway.sh"
    echo ""
    info "命令 3：安装 Mihomo、启用 TUN 网关并开放局域网 9090 UI"
    # Keep command substitution literal so it runs on the Linux client.
    # shellcheck disable=SC2016
    echo 'if [ "$(id -u)" -eq 0 ]; then bash /tmp/install-linux-gateway.sh --config /tmp/mihomo_client.yaml --ui-lan --yes; else sudo bash /tmp/install-linux-gateway.sh --config /tmp/mihomo_client.yaml --ui-lan --yes; fi'
    echo ""
    hint "安装完成后查看 UI 密钥: cat /etc/mihomo/ui-secret"
  else
    warning "未找到 base64，无法生成 Linux 客户端的一键复制命令。"
  fi

}

# >>> phase-c client-management >>> ============================================
# Phase C: multi-client identity management.
#
# Single source of truth remains /root/sbox/sbconfig_server.json (no clients.json).
# Every logical client is ONE name present in BOTH inbounds:
#   vless-in.users[] -> {"name": ..., "uuid": ..., "flow": "xtls-rprx-vision"}
#   hy2-in.users[]   -> {"name": ..., "password": ...}
# Hard rule: Reality name == HY2 name == device_id.
# The name "legacy" is RESERVED: it labels the pre-Phase-C shared account,
# is never created through "add client" and never deleted by this version.
# Everything under /root/sbox/clients/ is DERIVED output; it can always be
# regenerated from the server config.
SB_SERVER_CONFIG="${SB_SERVER_CONFIG:-/root/sbox/sbconfig_server.json}"
SB_STATE_FILE="${SB_STATE_FILE:-/root/sbox/config}"
SB_CLIENTS_DIR="${SB_CLIENTS_DIR:-/root/sbox/clients}"
SB_SING_BOX_BIN="${SB_SING_BOX_BIN:-/root/sbox/sing-box}"
SB_LOCK_FILE="${SB_LOCK_FILE:-/root/sbox/config.lock}"
SB_ROOT_DIR="${SB_ROOT_DIR:-$(dirname "$SB_SERVER_CONFIG")}"
SB_SHORTCUT="${SB_SHORTCUT:-/usr/bin/mianyang}"
SB_SYSTEMD_UNIT="${SB_SYSTEMD_UNIT:-/etc/systemd/system/sing-box.service}"
RESERVED_CLIENT_NAME="legacy"
# CLIENT_NAME_PATTERN lives in lib/client-management.sh together with its only
# consumer (validate_client_name); keeping a second copy here would be an unused
# variable (shellcheck SC2034).
REALITY_INBOUND_TAG="vless-in"
HY2_INBOUND_TAG="hy2-in"

# M1-A0: validate_client_name is defined in lib/client-management.sh -- the one
# canonical copy shared by install.sh and the privileged sbox-cm worker.

# M0/G1: the lock/commit/rollback primitives have a single canonical source in
# lib/client-management.sh. Local repository execution sources the sibling file;
# the historical curl/process-substitution entry point fetches the same path from
# the selected repository ref. Tests/helpers may inject SB_CLIENT_MANAGEMENT_LIB.
SB_CLIENT_MANAGEMENT_SHA256="6a2e2b97f259a0f97d7c3c16dde444603bbbacc4e619606036aca851f8984965"

verify_client_management_library() { # <path>
    local lib="$1" got=""
    if ! command -v sha256sum >/dev/null 2>&1; then
        warning "sha256sum 不可用，无法验证共享事务库，已拒绝加载（fail-closed）"
        return 1
    fi
    if [ ! -f "$lib" ]; then
        warning "共享事务库不存在: $lib"
        return 1
    fi
    got="$(sha256sum "$lib" 2>/dev/null | awk '{print $1}')" || return 1
    if [ "$got" != "$SB_CLIENT_MANAGEMENT_SHA256" ]; then
        warning "共享事务库完整性校验失败，已拒绝加载（fail-closed）"
        return 1
    fi
    return 0
}

load_client_management_library() {
    local lib="${SB_CLIENT_MANAGEMENT_LIB:-}" source_dir="" tmp="" fn

    if [ -z "$lib" ] && [ -n "${BASH_SOURCE[0]:-}" ]; then
        source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
        if [ -n "$source_dir" ] && [ -f "$source_dir/lib/client-management.sh" ]; then
            lib="$source_dir/lib/client-management.sh"
        fi
    fi

    if [ -z "$lib" ]; then
        local ref="${SB_CLIENT_MANAGEMENT_REF:-main}"
        tmp="$(mktemp 2>/dev/null)" || {
            warning "无法创建共享事务库临时文件"
            return 1
        }
        if ! curl -fsSL \
            "https://raw.githubusercontent.com/yikkrrtykj/install-singboxhysteria2/${ref}/lib/client-management.sh" \
            -o "$tmp"; then
            warning "无法获取共享事务库 lib/client-management.sh (ref=$ref)"
            rm -f "$tmp"
            return 1
        fi
        lib="$tmp"
    fi

    # IMPORTANT: verify BEFORE sourcing. This binds install.sh to the exact
    # reviewed shared transaction implementation. A future main/lib change
    # makes an older installer fail closed instead of silently importing newer
    # privileged transaction code. SB_CLIENT_MANAGEMENT_REF changes location,
    # never the expected content digest.
    if ! verify_client_management_library "$lib"; then
        [ -n "$tmp" ] && rm -f "$tmp"
        return 1
    fi

    # shellcheck source=/dev/null
    . "$lib" || { [ -n "$tmp" ] && rm -f "$tmp"; return 1; }
    [ -n "$tmp" ] && rm -f "$tmp"

    for fn in with_client_lock reload_running_singbox reload_health_ok \
              restore_file_atomically new_candidate_path new_backup_path \
              commit_server_config cm_transaction_result_json \
              cm_render_client_mihomo_yaml; do
        if ! declare -F "$fn" >/dev/null 2>&1; then
            warning "共享事务库缺少函数: $fn"
            return 1
        fi
    done
    return 0
}

load_client_management_library || error "共享事务库加载失败，拒绝进入管理路径"

# M1-A0: the client-management semantics that used to live here have moved to
# lib/client-management.sh so that BOTH writers share exactly one copy:
#   validate_client_name      get_reality_client_names   get_hy2_client_names
#   client_structure_problems candidate_problems         audit_client_consistency
#   client_name_exists        get_client_credentials
# They are loaded by load_client_management_library above (fail-closed digest
# pin) and are available to the rest of this script unchanged.

# One-shot, key-preserving migration of the pre-Phase-C shared account:
#   {"uuid": "AAAA", ...}  ->  {"name": "legacy", "uuid": "AAAA", ...}
# Only fills in the missing name; never touches uuid/password/flow.
# Idempotent: running it again on an already-migrated config is a no-op.
# The ENTIRE decision + candidate generation runs under the config lock, so a
# migration can never interleave with a concurrent add/delete.
migrate_legacy_clients() {
    with_client_lock _migrate_legacy_clients_locked
}

_migrate_legacy_clients_locked() {
    local cfg="$SB_SERVER_CONFIG" candidate r_unnamed h_unnamed structural
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    # Structure precheck (identity audit would wrongly reject nameless users,
    # which is exactly what migration must accept). For {} this must FAIL,
    # never fall through to "all users already named".
    if ! structural="$(client_structure_problems "$cfg")"; then
        warning "客户端结构审计执行失败: $cfg"
        return 1
    fi
    if [ -n "$structural" ]; then
        warning "配置结构不满足迁移前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$structural"
        return 1
    fi
    r_unnamed="$(get_reality_client_names "$cfg" | grep -c '^$' || true)"
    h_unnamed="$(get_hy2_client_names "$cfg" | grep -c '^$' || true)"
    if [ "$r_unnamed" -eq 0 ] && [ "$h_unnamed" -eq 0 ]; then
        info "所有用户都已具备 name，无需迁移"
        return 0
    fi
    if [ "$r_unnamed" != "$h_unnamed" ]; then
        warning "Reality 有 $r_unnamed 个无名用户，HY2 有 $h_unnamed 个，无法安全迁移；请先运行一致性检查"
        return 1
    fi
    if [ "$r_unnamed" -gt 1 ]; then
        warning "存在多个无名用户，无法确定哪一个是 legacy，已拒绝迁移"
        return 1
    fi
    if grep -qxF "$RESERVED_CLIENT_NAME" <(get_reality_client_names "$cfg") ||
       grep -qxF "$RESERVED_CLIENT_NAME" <(get_hy2_client_names "$cfg"); then
        warning "配置中已存在名为 $RESERVED_CLIENT_NAME 的用户，拒绝迁移以避免覆盖"
        return 1
    fi

    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    jq --arg legacy "$RESERVED_CLIENT_NAME" '
      (.inbounds[] | select(.tag == "vless-in") | .users) |=
        map(if has("name") then . else . + {"name": $legacy} end) |
      (.inbounds[] | select(.tag == "hy2-in") | .users) |=
        map(if has("name") then . else . + {"name": $legacy} end)
    ' "$cfg" > "$candidate" || { warning "生成迁移 candidate 失败"; rm -f "$candidate"; return 1; }

    commit_server_config "$candidate" "migrate unnamed user to legacy"
}

add_client() { # add_client <name> -> adds to BOTH inbounds atomically
    with_client_lock _add_client_locked "$1"
}

# Runs under the config lock: every judgement below re-reads the LIVE config,
# so a transaction that lost the lock race starts from the winner's state
# instead of overwriting it with a stale snapshot (no lost update).
_add_client_locked() {
    local name="$1" candidate
    if ! validate_client_name "$name"; then
        warning "客户端名称非法: '$name'（允许: 字母/数字开头，仅字母数字._-，长度 1-32）"
        return 1
    fi
    if [ "$name" = "$RESERVED_CLIENT_NAME" ]; then
        warning "'$RESERVED_CLIENT_NAME' 是保留名称，不能通过添加客户端创建"
        return 1
    fi
    [ -f "$SB_SERVER_CONFIG" ] || { warning "服务端配置不存在: $SB_SERVER_CONFIG"; return 1; }
    if ! jq empty "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $SB_SERVER_CONFIG"
        return 1
    fi
    if ! audit_client_consistency "$SB_SERVER_CONFIG" >/dev/null; then
        warning "当前 Reality/HY2 用户集合不一致，先修复后再添加客户端（运行一致性检查）"
        audit_client_consistency "$SB_SERVER_CONFIG"
        return 1
    fi
    if client_name_exists "$name" "$SB_SERVER_CONFIG"; then
        warning "客户端 '$name' 已存在（Reality 或 HY2），拒绝重复添加"
        return 1
    fi

    # M1-A: the planned credentials never reach argv, env, stdout, stderr or a
    # temp file. cm_add_client_candidate_planned generates them into shell
    # memory, digests them, and streams them to jq over an anonymous pipe.
    if ! cm_add_client_candidate_planned "$name"; then
        warning "生成 add candidate 失败"
        return 1
    fi
    candidate="$CM_ADD_CANDIDATE"

    # Single transaction: Reality + HY2 appear together or not at all.
    if commit_server_config "$candidate" "add client $name"; then
        info "客户端 '$name' 已同时添加到 Reality 与 HY2（UUID/password 已生成）"
        return 0
    fi
    return 1
}

delete_client() { # delete_client <name> -> removes from BOTH inbounds atomically
    # Confirmation happens outside the lock (it is interactive UI), but every
    # safety judgement is re-made against the LIVE config inside the lock, so a
    # config changed between "y" and the transaction cannot be deleted blindly.
    local name="$1" r_found h_found confirm
    if [ "$name" = "$RESERVED_CLIENT_NAME" ]; then
        warning "'$RESERVED_CLIENT_NAME' 是保留名称，本版本禁止删除（legacy retirement 属于后续功能）"
        return 1
    fi
    [ -n "$name" ] || { warning "客户端名称不能为空"; return 1; }
    [ -f "$SB_SERVER_CONFIG" ] || { warning "服务端配置不存在: $SB_SERVER_CONFIG"; return 1; }

    r_found="MISSING"; h_found="MISSING"
    grep -qxF "$name" <(get_reality_client_names "$SB_SERVER_CONFIG") && r_found="FOUND"
    grep -qxF "$name" <(get_hy2_client_names "$SB_SERVER_CONFIG") && h_found="FOUND"
    info "准备删除客户端: $name"
    info "Reality: $r_found"
    info "HY2:     $h_found"
    read -r -p "确认删除 '$name'？此操作会同时移除 Reality 与 HY2 凭据 (y/n): " confirm
    if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
        info "已取消删除 '$name'"
        return 1
    fi

    with_client_lock _delete_client_locked "$name"
}

_delete_client_locked() {
    local name="$1" candidate
    # The destructive helper revalidates EVERYTHING itself and never trusts the
    # outer delete_client(): order is name syntax -> reserved -> consistency
    # audit -> existence -> mutation. Any rejection leaves the live config and
    # the filesystem untouched.
    if ! validate_client_name "$name"; then
        warning "客户端名称非法: '$name'（locked helper 二次防护，允许: 字母/数字开头，仅字母数字._-，长度 1-32）"
        return 1
    fi
    # Invariant enforced again INSIDE the destructive helper: even a future
    # caller that bypasses delete_client must never be able to remove legacy.
    if [ "$name" = "$RESERVED_CLIENT_NAME" ]; then
        warning "'$RESERVED_CLIENT_NAME' 是保留名称，本版本禁止删除（locked helper 二次防护）"
        return 1
    fi
    if ! audit_client_consistency "$SB_SERVER_CONFIG" >/dev/null; then
        warning "当前 Reality/HY2 用户集合不一致，禁止破坏性操作（先运行一致性检查并修复）"
        audit_client_consistency "$SB_SERVER_CONFIG"
        return 1
    fi
    if ! grep -qxF "$name" <(get_reality_client_names "$SB_SERVER_CONFIG") ||
       ! grep -qxF "$name" <(get_hy2_client_names "$SB_SERVER_CONFIG"); then
        warning "客户端 '$name' 未在两个协议中同时存在（锁内复核），拒绝删除（请先修复一致性）"
        return 1
    fi

    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    # M1-A0: the delete candidate is produced by the canonical library so the
    # CLI and the privileged worker cannot drift.
    if ! cm_delete_candidate "$SB_SERVER_CONFIG" "$name" "$candidate"; then
        warning "生成 delete candidate 失败"; rm -f "$candidate"; return 1
    fi

    if ! commit_server_config "$candidate" "delete client $name"; then
        warning "服务端修改失败，客户端配置目录 $SB_CLIENTS_DIR/$name 保持不变"
        return 1
    fi
    # Only after the server-side commit succeeded may the derived files go.
    # The name was revalidated above; "--" only stops option parsing, it is
    # never a substitute for validation.
    if [ -d "$SB_CLIENTS_DIR/$name" ]; then
        rm -rf -- "${SB_CLIENTS_DIR:?}/$name"
        info "已删除派生客户端配置目录: $SB_CLIENTS_DIR/$name"
    fi
    info "客户端 '$name' 已从 Reality 与 HY2 同时删除"
}
# get_client_credentials is provided by lib/client-management.sh (M1-A0).

# M4-A / review R2: there is exactly ONE Mihomo/Clash Meta YAML template in
# this repository -- lib/client-management.sh :: cm_render_client_mihomo_yaml.
# This is a thin wrapper over it for the installer's shared-account display
# path (the reserved "legacy" account, which is users[0] in both inbounds),
# so CLI files and privileged client.export downloads are byte-identical BY
# CONSTRUCTION. A static regression FAILS if install.sh ever carries a
# second template body again.
write_mihomo_template() { # write_mihomo_template <outfile>
    local outfile="$1"
    cm_render_client_mihomo_yaml "$RESERVED_CLIENT_NAME" "$SB_SERVER_CONFIG" \
        > "$outfile" || return 1
    return 0
}

# Per-client derived configuration: /root/sbox/clients/<name>/mihomo.yaml
# (directory 0700, file 0600). The YAML is DERIVED output only -- the server
# config remains the single source of truth and the YAML can be regenerated.
generate_client_configuration() { # generate_client_configuration <name>
    local name="$1" cfg="$SB_SERVER_CONFIG" uuid password creds
    local out_dir out_file
    if ! validate_client_name "$name"; then
        warning "客户端名称非法: '$name'"
        return 1
    fi
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! audit_client_consistency "$cfg" >/dev/null; then
        warning "客户端集合不一致，拒绝生成配置（先运行一致性检查）"
        return 1
    fi
    if ! creds="$(get_client_credentials "$name" "$cfg")"; then
        warning "客户端 '$name' 在 Reality/HY2 中不完整，无法生成配置"
        return 1
    fi
    uuid="$(printf '%s\n' "$creds" | sed -n '1p')"
    password="$(printf '%s\n' "$creds" | sed -n '2p')"

    server_ip=$(grep -o "SERVER_IP='[^']*'" "$SB_STATE_FILE" 2>/dev/null | awk -F"'" '{print $2}')
    public_key=$(grep -o "PUBLIC_KEY='[^']*'" "$SB_STATE_FILE" 2>/dev/null | awk -F"'" '{print $2}')
    reality_port=$(jq -r --arg tag "$REALITY_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .listen_port' "$cfg")
    reality_server_name=$(jq -r --arg tag "$REALITY_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .tls.server_name' "$cfg")
    short_id=$(jq -r --arg tag "$REALITY_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .tls.reality.short_id[0]' "$cfg")
    hy_port=$(jq -r --arg tag "$HY2_INBOUND_TAG" '.inbounds[] | select(.tag == $tag) | .listen_port' "$cfg")
    hy_server_name=$(grep -o "HY_SERVER_NAME='[^']*'" "$SB_STATE_FILE" 2>/dev/null | awk -F"'" '{print $2}')
    ishopping=$(grep '^HY_HOPPING=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)
    hy_hopping_start=$(grep '^HY_HOPPING_START=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)
    hy_hopping_end=$(grep '^HY_HOPPING_END=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)
    formatted_range=""
    if [ "$ishopping" = "TRUE" ] &&
       [[ "$hy_hopping_start" =~ ^[0-9]+$ ]] &&
       [[ "$hy_hopping_end" =~ ^[0-9]+$ ]]; then
        formatted_range="${hy_hopping_start}-${hy_hopping_end}"
    fi

    out_dir="$SB_CLIENTS_DIR/$name"
    if ! mkdir -p "$out_dir"; then
        warning "创建客户端目录失败: $out_dir"
        return 1
    fi
    chmod 0700 "$out_dir"
    out_file="$out_dir/mihomo.yaml"
    # M4-A: the file content comes from the ONE canonical renderer in
    # lib/client-management.sh (the same copy the privileged export op uses);
    # the output is byte-identical to the historical template.
    if ! cm_render_client_mihomo_yaml "$name" "$cfg" > "$out_file"; then
        warning "写入客户端配置失败: $out_file"
        return 1
    fi
    chmod 0600 "$out_file"

    info "客户端 '$name' 的 Mihomo 配置已生成: $out_file（使用 '$name' 自己的 UUID/password）"
    info "Reality 链接: vless://$uuid@$server_ip:$reality_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reality_server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#REALITY-$name"
    if [ -n "$formatted_range" ]; then
        info "HY2 链接: hysteria2://$password@$server_ip:$hy_port?insecure=1&sni=$hy_server_name&mport=${hy_port},${formatted_range}#HY2-$name"
    else
        info "HY2 链接: hysteria2://$password@$server_ip:$hy_port?insecure=1&sni=$hy_server_name#HY2-$name"
    fi
}
list_clients() { # 查看客户端（只读，不作为破坏性操作的门槛）
    audit_client_consistency "$SB_SERVER_CONFIG"
}

add_client_interactive() {
    local name
    read -r -p "请输入客户端名称 (例如 vmix-01，字母/数字开头，仅字母数字._-，最长32): " name
    add_client "$name"
}

generate_client_configuration_interactive() {
    local name
    audit_client_consistency "$SB_SERVER_CONFIG" || return 1
    read -r -p "请输入要生成配置的客户端名称: " name
    generate_client_configuration "$name"
}

delete_client_interactive() {
    local name
    read -r -p "请输入要删除的客户端名称: " name
    delete_client "$name"
}

client_management_menu() {
    while :; do
        echo ""
        show_notice "客户端管理"
        info "1. 查看客户端"
        info "2. 添加客户端"
        info "3. 生成客户端配置"
        info "4. 删除客户端"
        info "5. 迁移旧客户端为 legacy"
        info "6. 检查客户端一致性"
        info "0. 返回"
        echo ""
        read -r -p "请输入对应数字（0-6）: " cm_choice
        echo ""
        case "$cm_choice" in
            1) list_clients ;;
            2) add_client_interactive ;;
            3) generate_client_configuration_interactive ;;
            4) delete_client_interactive ;;
            5)
                warning "迁移只会为没有 name 的旧用户补上 name=legacy，绝不更换 UUID/password。"
                migrate_legacy_clients
                ;;
            6) audit_client_consistency "$SB_SERVER_CONFIG" ;;
            0) break ;;
            *) warning "无效的选项，请重新选择" ;;
        esac
    done
}
# <<< phase-c client-management <<< ============================================

# >>> s0 credential-boundary hardening >>> =====================================
# S0 baseline hardening for the files this installer owns.
#
# Secret truth model: sbconfig_server.json is the single runtime source of
# truth for the monitor-api service secret. /root/sbox/monitor-api.secret is a
# DERIVED, convenience copy for the local collector (root:root, 0600). When
# the two disagree, the CONFIG wins and the derived file is regenerated --
# never the reverse, and a configured secret is never rotated on rerun. The
# secret is transport authentication for service.api only; the identity model
# (Device = service.api USER, Protocol = INBOUND, Lifecycle = connection id)
# is unchanged.
SB_API_SECRET_FILE="${SB_API_SECRET_FILE:-/root/sbox/monitor-api.secret}"
SB_SELF_CERT_KEY="${SB_SELF_CERT_KEY:-/root/sbox/self-cert/private.key}"
SB_SELF_CERT_CERT="${SB_SELF_CERT_CERT:-/root/sbox/self-cert/cert.pem}"

# 256-bit secret from a CSPRNG. Never derived from timestamps, client
# credentials, recovery keys or admin passwords; callers fail closed when no
# CSPRNG is available. Prints ONLY the secret (callers must not echo it).
generate_api_secret() {
    local secret=""
    if command -v openssl >/dev/null 2>&1; then
        secret="$(openssl rand -hex 32 2>/dev/null | tr -d '\r\n')"
    fi
    if [ -z "$secret" ] && [ -r /dev/urandom ]; then
        secret="$(od -An -N32 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
    fi
    [ ${#secret} -eq 64 ] || return 1
    [[ "$secret" =~ ^[0-9a-f]{64}$ ]] || return 1
    printf '%s\n' "$secret"
}

# The config's monitor-api secret; "" when the entry is absent or its secret
# is not a non-empty string. Never prints anything but the value itself.
read_api_secret_from_config() { # [config]
    jq -r --arg tag "$PHASE_D_API_TAG" '
      ([(.services // [])[] | select(.tag == $tag)][0].secret // "") as $s |
      if (($s | type) == "string") and (($s | length) > 0) then $s else "" end
    ' "${1:-$SB_SERVER_CONFIG}" 2>/dev/null | tr -d '\r'
}

# Atomically writes the derived collector secret file (root:root, 0600).
write_api_secret_file() { # <secret>
    local secret="$1" tmp
    [ -n "$secret" ] || return 1
    tmp="$(mktemp "${SB_API_SECRET_FILE}.tmp.XXXXXX")" || return 1
    if ! (umask 077 && printf '%s\n' "$secret" > "$tmp"); then
        rm -f "$tmp"
        return 1
    fi
    if ! chmod 0600 "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    # The installer always runs as root on the server; only skip the chown in
    # non-root sandboxes (tests), never silently on the real host.
    if [ "$(id -u)" = "0" ] && ! chown root:root "$tmp" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    if ! mv -f "$tmp" "$SB_API_SECRET_FILE" 2>/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    return 0
}

# Config is authoritative: (re)generate the derived file when it is missing or
# disagrees with the live config. Warnings never contain the secret itself.
sync_api_secret_file() { # -> rc 0 when the derived file matches the live config
    local secret current
    secret="$(read_api_secret_from_config "$SB_SERVER_CONFIG")"
    [ -n "$secret" ] || return 0   # no usable API secret in config: nothing to sync
    if [ -f "$SB_API_SECRET_FILE" ]; then
        current="$(tr -d '\r\n' < "$SB_API_SECRET_FILE" 2>/dev/null)"
        [ "$current" = "$secret" ] && return 0
        warning "monitor-api.secret 派生文件与服务端配置不一致，已按配置重新生成（以配置为准）"
    else
        warning "monitor-api.secret 派生文件缺失，已按服务端配置重新生成"
    fi
    write_api_secret_file "$secret"
}

# Existing-install bootstrap (S0), called BEFORE the interactive menu. A
# failing permission hardening -- or a derived secret file that cannot be
# brought back in sync with the config, which is the secret's authoritative
# source -- must ABORT the installer here (error exits): the menu is never
# entered and no management mutation can run against an unsafe or
# desynced-credential state. Installations whose config carries no valid
# monitor-api secret yet (Phase D migration not done) stay unaffected: sync
# treats that as nothing-to-do.
repair_existing_install_security_baseline() {
    harden_sensitive_permissions ||
        { error "敏感文件权限加固失败，请先人工检查磁盘/权限后再运行"; return 1; }
    sync_api_secret_file ||
        { error "monitor-api.secret 派生文件修复失败，请先人工检查磁盘/目录/权限后再运行"; return 1; }
    return 0
}

# Idempotent permission repair for sensitive files. Existing files are forced
# to 0600 (clients dir 0700, public cert 0644); missing files are skipped
# without error; ANY chmod failure is fail-closed and callers must abort the
# install. Never prints file contents.
harden_sensitive_permissions() {
    local target sub
    for target in \
        "$SB_SERVER_CONFIG" \
        "$SB_STATE_FILE" \
        "$SB_API_SECRET_FILE" \
        "$SB_SELF_CERT_KEY" \
        /root/sbox/mihomo_client.yaml \
        /root/sbox/sbconfig_client.json; do
        [ -f "$target" ] || continue
        if ! chmod 0600 "$target" 2>/dev/null; then
            warning "无法将敏感文件权限收紧为 0600: $target（拒绝继续，请人工检查）"
            return 1
        fi
    done
    if [ -f "$SB_SELF_CERT_CERT" ] && ! chmod 0644 "$SB_SELF_CERT_CERT" 2>/dev/null; then
        warning "无法设置公钥证书权限为 0644: $SB_SELF_CERT_CERT"
        return 1
    fi
    if [ -d "$SB_CLIENTS_DIR" ]; then
        if ! chmod 0700 "$SB_CLIENTS_DIR" 2>/dev/null; then
            warning "无法将客户端目录权限收紧为 0700: $SB_CLIENTS_DIR（拒绝继续）"
            return 1
        fi
        for sub in "$SB_CLIENTS_DIR"/*; do
            [ -d "$sub" ] || continue
            if ! chmod 0700 "$sub" 2>/dev/null; then
                warning "无法将客户端目录权限收紧为 0700: $sub（拒绝继续）"
                return 1
            fi
            if [ -f "$sub/mihomo.yaml" ] && ! chmod 0600 "$sub/mihomo.yaml" 2>/dev/null; then
                warning "无法将客户端配置权限收紧为 0600: $sub/mihomo.yaml（拒绝继续）"
                return 1
            fi
        done
    fi
    return 0
}
# <<< s0 credential-boundary hardening <<< =====================================

# >>> existing-api-auth narrow migration >>> ===================================
# Narrow S0 migration for OLD servers that already run sing-box 1.14.x with a
# structurally compliant localhost-only service.api (tag monitor-api,
# 127.0.0.1:9091) but WITHOUT authentication (the secret KEY is absent).
#
# Why this exists: the Phase D upgrade path injects the secret, but it is a
# BINARY upgrade transaction (download/replace sing-box, restart). An old
# server that already runs a compliant 1.14.x service.api must be able to add
# authentication WITHOUT touching the binary, the version, or any credential.
#
# Scope of the only allowed semantic change:
#   .services[] entry where tag == "monitor-api" gains "secret": "<256-bit hex>"
# Everything else (Reality UUIDs, HY2 passwords, Reality private key, short_id,
# SNI, ports, certificates, /root/sbox/config state, binary, firewall, MTU,
# port hopping, other services/inbounds/outbounds/routes) is preserved and
# mechanically proven identical before commit. No credential rotation, ever.
#
# Discipline (same as Phase C/D):
#   - interactive confirmation is gathered OUTSIDE /root/sbox/config.lock;
#   - the locked helper re-reads LIVE state, revalidates, and is idempotent:
#     if another process already added a valid secret it treats that as
#     success, converges the derived anchor, and NEVER rotates the secret;
#   - every mutation runs under the SAME with_client_lock as every other
#     durable state change, fail-closed (no lock -> zero mutation);
#   - pre-commit failure -> zero live mutation; post-commit failure ->
#     atomic config restore (restore_file_atomically) + anchor restore +
#     restart + re-verify; an unconfirmable restore is reported as
#     MANUAL INTERVENTION REQUIRED and never as success.
# The config remains the secret's single source of truth; the derived
# /root/sbox/monitor-api.secret stays a root:root 0600 convenience copy.
# This migration is NOT a sing-box binary upgrade and never replaces it.
# ==============================================================================

# Read-only classification of the live service.api authentication state:
#   exact            exactly one compliant monitor-api WITH a non-empty string
#                    secret
#   needed           exactly one compliant monitor-api whose secret KEY IS
#                    ABSENT -- nothing to overwrite; the ONLY auto-migratable
#                    shape
#   malformed-secret exactly one compliant monitor-api but the secret KEY
#                    EXISTS with an unusable value ("", null, number/bool/
#                    object/array): narrow migration MUST refuse (overwriting
#                    an unknown secret value/type is never a narrow change)
#                    -- the normal Phase D repair/upgrade path is required
#   absent           no monitor-api entry at all (narrow migration must NOT
#                    reinvent it -- that is the Phase D path)
#   structural       monitor-api count/type/listen/port violate the contract
#   unreadable       config missing or invalid JSON
#   audit-error      jq/audit failure (fail-closed: never "no problems")
existing_api_auth_classify() { # existing_api_auth_classify <config>
    local cfg="$1" problems count secret_type
    [ -f "$cfg" ] || { printf 'unreadable\n'; return 0; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        printf 'unreadable\n'; return 0
    fi
    if ! problems="$(phase_d_config_structure_problems "$cfg")"; then
        printf 'audit-error\n'; return 0
    fi
    if [ -n "$problems" ]; then
        printf 'structural\n'; return 0
    fi
    count="$(jq -er --arg tag "$PHASE_D_API_TAG" \
        '[(.services // [])[] | select(.tag == $tag)] | length' \
        "$cfg" 2>/dev/null | tr -d '\r')" || { printf 'audit-error\n'; return 0; }
    if [ "$count" -eq 0 ]; then
        printf 'absent\n'; return 0
    fi
    if phase_d_api_service_exact "$cfg"; then
        printf 'exact\n'
        return 0
    fi
    # Not exact: classify the secret VALUE SHAPE. "Missing" means the secret
    # KEY IS ABSENT -- nothing to overwrite. A PRESENT key with an unusable
    # value ("", null, number, boolean, object, array) is malformed-secret:
    # it is NEVER treated as missing and never overwritten by the narrow
    # migration (the normal Phase D path owns it).
    secret_state="$(jq -r --arg tag "$PHASE_D_API_TAG" '
        ([(.services // [])[] | select(.tag == $tag)][0]) as $svc |
        if ($svc | type) != "object" then "absent-service"
        elif ($svc | has("secret") | not) then "absent"
        elif ($svc.secret | type) == "string" then
            (if ($svc.secret | length) == 0 then "empty-string" else "nonempty-string" end)
        else ($svc.secret | type)
        end' "$cfg" 2>/dev/null | tr -d '\r')" || { printf 'audit-error\n'; return 0; }
    case "$secret_state" in
        absent) printf 'needed\n' ;;                  # key absent = genuinely missing
        empty-string)  printf 'malformed-secret\n' ;; # present "" -> refuse
        null)          printf 'malformed-secret\n' ;; # present null -> refuse
        nonempty-string) printf 'malformed-secret\n' ;; # unreachable edge (exact covers it) -> fail-closed
        *)             printf 'malformed-secret\n' ;; # number/boolean/object/array -> refuse
    esac
    return 0
}

# Narrow migration entry point, called on EXISTING installs before the menu.
# Fresh installs never reach this function and are unaffected.
#   exact      -> no prompt, no restart, never rotate; converge the derived
#                 anchor from the authoritative config if it is missing/stale
#   needed     -> the secret KEY is ABSENT: explicit [y/N] confirmation
#                 OUTSIDE the lock (default NO); declined -> ZERO changes,
#                 no restart, warn that Monitor v2 requires this migration
#                 before deployment
#   malformed-
#   secret     -> refuse: the secret KEY EXISTS but its value is unusable
#                 ("", null, number, boolean, object, array). Malformed
#                 values are NEVER treated as missing and never overwritten
#                 -- that is not a narrow change. Zero changes, no prompt,
#                 the Phase D repair/upgrade path is required
#   absent /
#   structural -> refuse: report that the normal Phase D repair/upgrade path
#                 is required; zero changes, no prompt
#   unreadable /
#   audit-error -> warn and skip; zero changes
maybe_migrate_existing_api_auth() {
    local state answer
    state="$(existing_api_auth_classify "$SB_SERVER_CONFIG")"
    case "$state" in
        exact)
            # Already authenticated: converge the derived anchor, never rotate.
            sync_api_secret_file || \
                { error "monitor-api.secret 派生文件修复失败，请先人工检查磁盘/目录/权限后再运行"; return 1; }
            return 0
            ;;
        needed)
            : ;;
        malformed-secret)
            warning "monitor-api 已配置 secret 但其类型/值形态不符合约定（非字符串或畸形值），窄迁移拒绝覆盖未知凭据"
            warning "该环境需要正常的 Phase D 修复/升级路径，本次未做任何修改"
            return 0
            ;;
        absent|structural)
            warning "现有 service.api 结构不符合窄迁移条件（monitor-api 缺失或 type/listen/port/数量不合规），已跳过"
            warning "该环境需要正常的 Phase D 修复/升级路径，本次未做任何修改"
            return 0
            ;;
        *)
            warning "无法读取或审计服务端配置，已跳过 service.api 认证窄迁移（未做任何修改）"
            return 0
            ;;
    esac

    echo ""
    warning "检测到旧版 service.api 已启用但尚未配置认证。"
    info "是否执行安全迁移，为 localhost service.api 增加认证？"
    info "该操作不会修改 Reality/HY2 凭据、端口或 sing-box 版本，"
    info "但会受控重启 sing-box 一次。"
    # Interactive input is gathered OUTSIDE /root/sbox/config.lock (never hold
    # the lock while waiting for the operator).
    read -r -p "[y/N]: " answer
    case "$answer" in
        y|Y|yes|YES|Yes) ;;
        *)
            warning "已取消：未做任何修改，未重启 sing-box。"
            warning "注意: Monitor v2 部署前必须先完成该认证迁移。"
            return 0
            ;;
    esac
    with_client_lock _migrate_existing_api_auth_locked
}

# Rollback for the narrow migration: atomically restore the pre-migration
# config from the hardened backup, restore/remove the derived anchor, restart
# sing-box to reload the old config and re-verify. ANY failure is reported as
# needing manual intervention -- never as a successful recovery. Backups are
# always preserved. Caller holds with_client_lock.
_rollback_existing_api_auth() { # <backup_cfg> <anchor_had> <anchor_bak> <old_version>
    local backup_cfg="$1" anchor_had="$2" anchor_bak="$3" old_version="$4"
    warning "迁移提交后失败，执行回滚（config + anchor）..."
    if ! restore_file_atomically "$backup_cfg" "$SB_SERVER_CONFIG"; then
        warning "回滚 config 恢复失败，请立即人工介入！备份: $backup_cfg"
        return 1
    fi
    if [ "$anchor_had" = "1" ]; then
        if ! restore_file_atomically "$anchor_bak" "$SB_API_SECRET_FILE"; then
            warning "回滚 monitor-api.secret 恢复失败，请立即人工介入！备份: $anchor_bak"
            return 1
        fi
    else
        # The pre-state had NO anchor: the derived file created by this
        # migration must be removed. The rm return status is checked AND the
        # actual absence is verified afterwards -- a failed removal is
        # MANUAL INTERVENTION (nonzero), never a claimed successful rollback.
        if ! rm -f -- "$SB_API_SECRET_FILE" 2>/dev/null; then
            warning "回滚时无法删除迁移新建的 monitor-api.secret 派生文件（rm 返回非零: $SB_API_SECRET_FILE），请立即人工介入！备份: $backup_cfg"
            return 1
        fi
        if [ -e "$SB_API_SECRET_FILE" ] || [ -L "$SB_API_SECRET_FILE" ]; then
            warning "回滚时无法删除迁移新建的 monitor-api.secret 派生文件（$SB_API_SECRET_FILE），请立即人工介入！备份: $backup_cfg"
            return 1
        fi
    fi
    if ! systemctl restart sing-box 2>/dev/null; then
        warning "回滚后 restart sing-box 失败，请立即人工介入！备份: $backup_cfg"
        return 1
    fi
    # The restored config has no usable monitor-api secret; the runtime must
    # come back with the old (pre-auth) API behaviour and all proxy listeners.
    if ! phase_d_health_ok "$old_version" "yes"; then
        warning "回滚后健康检查失败，请立即人工介入！备份: $backup_cfg"
        return 1
    fi
    if ! ensure_hy2_hopping_after_restart; then
        warning "回滚后端口跳跃规则未能确认恢复，请人工检查"
        return 1
    fi
    warning "已回滚到迁移前状态（config + anchor），服务健康"
    return 0
}

# The whole transaction runs under the SAME /root/sbox/config.lock: re-read ->
# revalidate -> candidate -> mechanical proof -> check -> backup -> commit ->
# anchor -> one controlled restart -> health. Re-reads LIVE state under the
# lock so a concurrent first migration wins and a second invocation becomes an
# idempotent no-op (same secret, no rotation, no restart).
_migrate_existing_api_auth_locked() {
    local problems count secret cand_secret old_version secret_type
    local candidate_cfg backup_cfg anchor_bak=""
    local anchor_had=0
    [ -f "$SB_SERVER_CONFIG" ] || { warning "服务端配置不存在: $SB_SERVER_CONFIG"; return 1; }
    if ! jq empty "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $SB_SERVER_CONFIG"
        return 1
    fi

    # Same identity gate as Phase D: the multi-client model must be intact.
    if ! problems="$(candidate_problems "$SB_SERVER_CONFIG")"; then
        warning "客户端结构审计执行失败: $SB_SERVER_CONFIG"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "客户端身份审计未通过，窄迁移拒绝执行:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi

    # Revalidate under the lock: the live state may have changed since the
    # operator was asked (or since a concurrent invocation migrated already).
    if ! problems="$(phase_d_config_structure_problems "$SB_SERVER_CONFIG")"; then
        warning "API 配置审计执行失败: $SB_SERVER_CONFIG"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "现有 API 配置不合规（拒绝窄迁移），该环境需要 Phase D 修复/升级路径:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    count="$(jq -er --arg tag "$PHASE_D_API_TAG" \
        '[(.services // [])[] | select(.tag == $tag)] | length' \
        "$SB_SERVER_CONFIG" 2>/dev/null | tr -d '\r')" || {
        warning "无法读取 monitor-api service 数量"
        return 1
    }
    [ "$count" -eq 1 ] || { warning "monitor-api service 数量不是 1，窄迁移拒绝执行"; return 1; }

    if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then
        # Idempotent: a concurrent invocation already added a valid secret.
        # Converge the anchor from the config, NEVER rotate, NO restart.
        if ! sync_api_secret_file; then
            warning "monitor-api.secret 派生文件修复失败，请人工检查磁盘/目录/权限"
            return 1
        fi
        info "service.api 已配置认证（无需迁移），未修改任何内容"
        return 0
    fi

    # Secret-shape re-check UNDER THE LOCK: only the explicitly approved
    # "missing secret" shape -- the secret KEY ABSENT -- may be auto-migrated.
    # A secret key that EXISTS with an unusable value ("", null, number,
    # boolean, object, array) is malformed: it is never treated as missing
    # and never overwritten. A concurrent change that made the secret
    # malformed between the prompt and this lock is refused here --
    # overwriting unknown credential material is never a narrow change.
    secret_type="$(jq -r --arg tag "$PHASE_D_API_TAG" '
        ([(.services // [])[] | select(.tag == $tag)][0]) as $svc |
        if ($svc | type) != "object" then "absent-service"
        elif ($svc | has("secret") | not) then "absent"
        else ($svc.secret | type)
        end' "$SB_SERVER_CONFIG" 2>/dev/null | tr -d '\r')" || {
        warning "无法读取 monitor-api secret 类型（锁内复核失败）"
        return 1
    }
    case "$secret_type" in
        absent) : ;;
        *)
            warning "monitor-api secret 键存在但值形态不符合约定（$secret_type），窄迁移拒绝覆盖未知凭据；该环境需要 Phase D 修复/升级路径"
            return 1
            ;;
    esac

    # Capture the pre-migration anchor state for rollback (the anchor is a
    # DERIVED file; if it did not exist, rollback removes any new one).
    if [ -f "$SB_API_SECRET_FILE" ]; then
        anchor_had=1
        anchor_bak="$(mktemp "${SB_API_SECRET_FILE}.bak.XXXXXX")" || {
            warning "创建 anchor 备份失败，正式环境未修改"
            return 1
        }
        if ! cp -a "$SB_API_SECRET_FILE" "$anchor_bak" || ! chmod 0600 "$anchor_bak" 2>/dev/null; then
            warning "备份当前 anchor 失败，正式环境未修改"
            rm -f "$anchor_bak"
            return 1
        fi
    fi

    if ! secret="$(generate_api_secret)"; then
        warning "生成 monitor-api secret 失败，正式环境未修改"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi

    candidate_cfg="$(mktemp "${SB_SERVER_CONFIG}.candidate.XXXXXX")" || {
        warning "创建 candidate config 失败，正式环境未修改"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    }
    # count==1 and not exact: the structural audit already proved the ONLY gap
    # is the missing secret, so this fills in .secret and touches nothing else.
    if ! phase_d_inject_api_service "$SB_SERVER_CONFIG" "$candidate_cfg" "$secret"; then
        warning "生成 candidate config 失败，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi

    # ---- mechanical proof (all six must hold before commit) ----
    # 1. canonicalized config excluding .services is identical
    # 2. all services other than monitor-api are identical
    # 3. monitor-api excluding .secret is identical
    if [ "$(jq -Sc 'del(.services)' "$SB_SERVER_CONFIG" 2>/dev/null)" != \
         "$(jq -Sc 'del(.services)' "$candidate_cfg" 2>/dev/null)" ] ||
       [ "$(jq -Sc --arg tag "$PHASE_D_API_TAG" \
            '[.services[]? | select(.tag != $tag)]' "$SB_SERVER_CONFIG" 2>/dev/null)" != \
         "$(jq -Sc --arg tag "$PHASE_D_API_TAG" \
            '[.services[]? | select(.tag != $tag)]' "$candidate_cfg" 2>/dev/null)" ] ||
       [ "$(jq -Sc --arg tag "$PHASE_D_API_TAG" \
            '[.services[]? | select(.tag == $tag) | del(.secret)]' "$SB_SERVER_CONFIG" 2>/dev/null)" != \
         "$(jq -Sc --arg tag "$PHASE_D_API_TAG" \
            '[.services[]? | select(.tag == $tag) | del(.secret)]' "$candidate_cfg" 2>/dev/null)" ]; then
        warning "candidate 校验失败: 窄迁移只允许新增 monitor-api secret，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi
    # 4. exactly one monitor-api exists
    count="$(jq -er --arg tag "$PHASE_D_API_TAG" \
        '[(.services // [])[] | select(.tag == $tag)] | length' \
        "$candidate_cfg" 2>/dev/null | tr -d '\r')" || count=0
    if [ "$count" -ne 1 ]; then
        warning "candidate 校验失败: monitor-api 数量不是 1，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi
    # 5. the committed secret is exactly the generated non-empty value
    cand_secret="$(jq -r --arg tag "$PHASE_D_API_TAG" \
        '[(.services // [])[] | select(.tag == $tag)][0].secret // ""' \
        "$candidate_cfg" 2>/dev/null | tr -d '\r')"
    if [ "$cand_secret" != "$secret" ] || [[ ! "$cand_secret" =~ ^[0-9a-f]{64}$ ]]; then
        warning "candidate 校验失败: secret 不是本次生成的有效值，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi
    # 6. candidate passes the identity audit and the real sing-box check
    if ! problems="$(candidate_problems "$candidate_cfg")" || [ -n "$problems" ]; then
        warning "candidate 身份审计未通过，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi
    if ! phase_d_api_service_exact "$candidate_cfg"; then
        warning "candidate API 配置验证失败，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi
    if ! "$SB_SING_BOX_BIN" check -c "$candidate_cfg" >/dev/null 2>&1; then
        warning "candidate sing-box check 未通过，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi

    # Unique same-directory backup, retained, mode 0600.
    backup_cfg="$(mktemp "${SB_SERVER_CONFIG}.bak.$(date +%Y%m%d-%H%M%S).XXXXXX")" || {
        warning "创建配置备份失败，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    }
    if ! cp -a "$SB_SERVER_CONFIG" "$backup_cfg"; then
        warning "备份当前配置失败，正式环境未修改"
        rm -f "$candidate_cfg" "$backup_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi
    # cp -a preserves the source mode; an old 0644 live config must never
    # produce a world-readable backup.
    if ! chmod 0600 "$backup_cfg" 2>/dev/null; then
        warning "备份文件权限收紧为 0600 失败，正式环境未修改"
        rm -f "$candidate_cfg" "$backup_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi

    old_version="$("$SB_SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
    [ -n "$old_version" ] || old_version="unknown"

    # Atomic live config replace (binary is NEVER touched). The backup is
    # KEPT even when the replace itself fails (never destroys a recovery copy).
    chmod 0600 "$candidate_cfg" 2>/dev/null || true
    if ! mv -f "$candidate_cfg" "$SB_SERVER_CONFIG"; then
        warning "原子替换 config 失败，正式环境未修改"
        rm -f "$candidate_cfg"
        [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
        return 1
    fi

    # Derived anchor next (runtime is untouched so far; a failure here needs a
    # config restore but NO restart -- sing-box still runs the old config).
    if ! write_api_secret_file "$secret"; then
        if ! restore_file_atomically "$backup_cfg" "$SB_SERVER_CONFIG"; then
            warning "anchor 写入失败且 config 回滚失败，请立即人工介入！备份: $backup_cfg"
            return 1
        fi
        warning "monitor-api.secret 派生文件写入失败，已回滚 config（未重启，sing-box 仍运行旧配置）"
        return 1
    fi

    # Exactly ONE controlled restart to activate the new secret.
    if ! systemctl restart sing-box 2>/dev/null; then
        _rollback_existing_api_auth "$backup_cfg" "$anchor_had" "$anchor_bak" "$old_version"
        return 1
    fi
    if ! phase_d_health_ok "$old_version" "yes"; then
        _rollback_existing_api_auth "$backup_cfg" "$anchor_had" "$anchor_bak" "$old_version"
        return 1
    fi
    if ! ensure_hy2_hopping_after_restart; then
        _rollback_existing_api_auth "$backup_cfg" "$anchor_had" "$anchor_bak" "$old_version"
        return 1
    fi

    [ -n "$anchor_bak" ] && rm -f "$anchor_bak"
    info "service.api 认证迁移完成: localhost monitor-api 已启用认证（受控重启一次，binary 未变更）"
    info "monitor-api.secret 派生文件: $SB_API_SECRET_FILE（root:root 0600，以服务端配置为唯一权威来源）"
    info "迁移前备份已保留: $backup_cfg"
    return 0
}
# <<< existing-api-auth narrow migration <<< ===================================

# >>> phase-d singbox-1.14-api >>> =============================================
# Phase D: safe production upgrade to 1.14.x stable with a localhost-only
# service.api (top-level "services" entry); the installer is a single
# self-contained file, so all Phase D primitives live here.
PHASE_D_TARGET_MAJOR="${PHASE_D_TARGET_MAJOR:-1}"
PHASE_D_TARGET_MINOR="${PHASE_D_TARGET_MINOR:-14}"
PHASE_D_MIN_VERSION="${PHASE_D_MIN_VERSION:-1.14.0}"
PHASE_D_API_TAG="${PHASE_D_API_TAG:-monitor-api}"
PHASE_D_API_LISTEN="${PHASE_D_API_LISTEN:-127.0.0.1}"
PHASE_D_API_PORT="${PHASE_D_API_PORT:-9091}"
SB_RELEASES_URL="https://api.github.com/repos/SagerNet/sing-box/releases?per_page=100"

# Selects the newest STABLE 1.14.x release tag from GitHub. Fail-closed:
# drafts/prereleases, 1.13.x and 1.15.x are never accepted, and "latest" can
# never drift the target across major/minor lines. Prints e.g. "v1.14.7".
select_1_14_stable_tag() {
    local releases
    releases="$(curl -fsSL "$SB_RELEASES_URL" 2>/dev/null)" || {
        warning "无法获取 sing-box releases 列表"
        return 1
    }
    local tag
    tag="$(printf '%s' "$releases" | phase_d_select_release_from_json 2>/dev/null | tr -d '\r')" || {
        warning "GitHub releases 中没有可用的 stable v1.14.x（拒绝 1.13.x / 1.15.x / prerelease）"
        return 1
    }
    [ -n "$tag" ] || {
        warning "GitHub releases 中没有可用的 stable v1.14.x（拒绝 1.13.x / 1.15.x / prerelease）"
        return 1
    }
    printf '%s\n' "$tag"
}

phase_d_version_in_target_series() { # <version-or-tag>
    local version="${1#v}"
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
    [ "${BASH_REMATCH[1]}" = "$PHASE_D_TARGET_MAJOR" ] || return 1
    [ "${BASH_REMATCH[2]}" = "$PHASE_D_TARGET_MINOR" ] || return 1
    return 0
}

phase_d_version_at_least_min() { # <version-or-tag>
    local version="${1#v}" minimum="${PHASE_D_MIN_VERSION#v}"
    local v_major v_minor v_patch m_major m_minor m_patch
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    [[ "$minimum" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS='.' read -r v_major v_minor v_patch <<< "$version"
    IFS='.' read -r m_major m_minor m_patch <<< "$minimum"
    (( 10#$v_major > 10#$m_major )) && return 0
    (( 10#$v_major < 10#$m_major )) && return 1
    (( 10#$v_minor > 10#$m_minor )) && return 0
    (( 10#$v_minor < 10#$m_minor )) && return 1
    (( 10#$v_patch >= 10#$m_patch ))
}

phase_d_release_tag_is_allowed() { # <tag>
    local tag="$1"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    phase_d_version_in_target_series "$tag" || return 1
    phase_d_version_at_least_min "$tag"
}

# Pure release selector: reads the GitHub releases JSON array on stdin and
# prints the newest stable v1.14.x tag.
phase_d_select_release_from_json() {
    local selected
    selected="$(jq -er \
        --argjson major "$PHASE_D_TARGET_MAJOR" \
        --argjson minor "$PHASE_D_TARGET_MINOR" '
          [ .[]
            | select((.draft // false) == false)
            | select((.prerelease // false) == false)
            | .tag_name as $tag
            | select($tag | type == "string")
            | ($tag | capture("^v(?<major>[0-9]+)\\.(?<minor>[0-9]+)\\.(?<patch>[0-9]+)$")?) as $v
            | select($v != null)
            | select(($v.major | tonumber) == $major and ($v.minor | tonumber) == $minor)
            | {
                tag: $tag,
                major: ($v.major | tonumber),
                minor: ($v.minor | tonumber),
                patch: ($v.patch | tonumber)
              }
          ]
          | sort_by([.major, .minor, .patch])
          | last
          | .tag
        ' 2>/dev/null)" || return 1
    phase_d_release_tag_is_allowed "$selected" || return 1
    printf '%s\n' "$selected"
}

# Structural audit of the top-level services state: services (if present) must
# be an array; the monitor-api service must appear at most once with exactly
# the compliant type/listen/port. Empty output = injectable or already exact.
# Exit code also fail-closed.
phase_d_config_structure_problems() { # <config>
    local cfg="$1"
    jq -r \
      --arg tag "$PHASE_D_API_TAG" \
      --arg listen "$PHASE_D_API_LISTEN" \
      --argjson port "$PHASE_D_API_PORT" '
      if type != "object" then
        ["配置根节点不是 object"]
      elif (has("services") and ((.services | type) != "array")) then
        ["services 存在但不是数组"]
      else
        ((.services // []) | map(select(.tag == $tag))) as $m |
        ([ ]
          + (if ($m | length) > 1 then ["monitor-api service 数量大于 1"] else [] end)
          + (if ($m | length) == 1 and ($m[0].type // "") != "api"
             then ["monitor-api type 不是 api"] else [] end)
          + (if ($m | length) == 1 and ($m[0].listen // "") != $listen
             then ["monitor-api listen 不是 127.0.0.1"] else [] end)
          + (if ($m | length) == 1 and ($m[0].listen_port // -1) != $port
             then ["monitor-api listen_port 不是 9091"] else [] end)
        )
      end
      | .[]
    ' "$cfg" 2>/dev/null
}

# True when the config already carries exactly one compliant monitor-api
# service entry (loopback-only, fixed port) WITH a non-empty string secret.
phase_d_api_service_exact() { # <config>
    local cfg="$1"
    jq -e \
      --arg tag "$PHASE_D_API_TAG" \
      --arg listen "$PHASE_D_API_LISTEN" \
      --argjson port "$PHASE_D_API_PORT" '
        [(.services // [])[] | select(.tag == $tag)] as $m |
        ($m | length) == 1 and
        $m[0].type == "api" and
        $m[0].listen == $listen and
        $m[0].listen_port == $port and
        ($m[0].secret | type) == "string" and
        ($m[0].secret | length) > 0
      ' "$cfg" >/dev/null 2>&1
}

# Idempotent injection of the localhost-only service.api entry WITH its
# authentication secret:
#   - no monitor-api entry           -> append a full entry (incl. secret)
#   - entry without a usable secret  -> fill in the secret, touch nothing else
#   - already exact (incl. secret)   -> preserve the config byte-for-byte
#                                      (a rerun NEVER rotates the secret)
# When the structural audit passes and the entry exists but is not exact, the
# only possible gap IS the missing secret (type/listen/port/count are already
# enforced by the structural audit). An explicit secret argument is honoured;
# otherwise one is generated. Fails closed on any audit error; re-audits the
# output including the secret.
phase_d_inject_api_service() { # <input> <output> [secret]
    local input="$1" output="$2" problems rc count tmp
    local secret="${3:-}"
    problems="$(phase_d_config_structure_problems "$input")"; rc=$?
    if [ "$rc" -ne 0 ]; then
        warning "Phase D API 结构审计执行失败"
        return 1
    fi
    if [ -n "$problems" ]; then
        printf '%s\n' "$problems" >&2
        return 1
    fi

    count="$(jq -er --arg tag "$PHASE_D_API_TAG" '[(.services // [])[] | select(.tag == $tag)] | length' "$input" 2>/dev/null | tr -d '\r')" || return 1
    if [ "$count" -eq 1 ]; then
        if phase_d_api_service_exact "$input"; then
            # Existing exact service passed both audits; preserve config.
            cp -a -- "$input" "$output" || return 1
            return 0
        fi
        if [ -z "$secret" ] && ! secret="$(generate_api_secret)"; then
            warning "生成 monitor-api secret 失败"
            return 1
        fi
        tmp="${output}.tmp.$$"
        rm -f -- "$tmp"
        if ! jq --arg tag "$PHASE_D_API_TAG" --arg secret "$secret" \
          '(.services[] | select(.tag == $tag) | .secret) = $secret' \
          "$input" > "$tmp"; then
            rm -f -- "$tmp"
            return 1
        fi
        mv -f -- "$tmp" "$output" || { rm -f -- "$tmp"; return 1; }
    else
        if [ -z "$secret" ] && ! secret="$(generate_api_secret)"; then
            warning "生成 monitor-api secret 失败"
            return 1
        fi
        tmp="${output}.tmp.$$"
        rm -f -- "$tmp"
        if ! jq \
          --arg tag "$PHASE_D_API_TAG" \
          --arg listen "$PHASE_D_API_LISTEN" \
          --argjson port "$PHASE_D_API_PORT" \
          --arg secret "$secret" '
            .services = ((.services // []) + [{
              "type": "api",
              "tag": $tag,
              "listen": $listen,
              "listen_port": $port,
              "secret": $secret
            }])
          ' "$input" > "$tmp"; then
            rm -f -- "$tmp"
            return 1
        fi
        mv -f -- "$tmp" "$output" || { rm -f -- "$tmp"; return 1; }
    fi

    problems="$(phase_d_config_structure_problems "$output")"; rc=$?
    if [ "$rc" -ne 0 ] || [ -n "$problems" ]; then
        rm -f -- "$output"
        [ -n "$problems" ] && printf '%s\n' "$problems" >&2
        return 1
    fi
    if ! phase_d_api_service_exact "$output"; then
        rm -f -- "$output"
        warning "注入后 monitor-api 仍不合规（secret 校验失败）"
        return 1
    fi
    return 0
}

api_port_occupied() { # any current listener on the API port (v4 or v6)
    ss -H -lntu 2>/dev/null | grep -qE "[:.]${PHASE_D_API_PORT}[[:space:]]"
}

# Downloads and verifies a candidate binary for <tag>, placing it at
# <candidate_path> (which MUST live on the same filesystem as the live binary
# so the later replacement is an atomic rename).
acquire_candidate_binary() { # acquire_candidate_binary <tag> <version> <candidate_path>
    local tag="$1" ver="$2" candidate="$3"
    local arch package archive extract_dir
    arch="$(uname -m)"
    case "$arch" in
        x86_64) arch="amd64" ;;
        aarch64) arch="arm64" ;;
        armv7l) arch="armv7" ;;
    esac
    package="sing-box-${ver}-linux-${arch}"
    archive="$(mktemp "${SB_SING_BOX_BIN}.archive.XXXXXX")" || return 1
    extract_dir="$(mktemp -d "${SB_SING_BOX_BIN}.extract.XXXXXX")" || {
        rm -f "$archive"
        return 1
    }
    if ! curl -4 -fL --progress-bar -o "$archive" \
            "https://github.com/SagerNet/sing-box/releases/download/${tag}/${package}.tar.gz"; then
        warning "下载 sing-box ${tag} 失败"
        rm -rf "$archive" "$extract_dir"
        return 1
    fi
    if ! tar -tzf "$archive" >/dev/null 2>&1; then
        warning "下载包校验失败（非有效 tar.gz）"
        rm -rf "$archive" "$extract_dir"
        return 1
    fi
    if ! tar -xzf "$archive" -C "$extract_dir"; then
        warning "解压 sing-box 失败"
        rm -rf "$archive" "$extract_dir"
        return 1
    fi
    if [ ! -f "$extract_dir/$package/sing-box" ]; then
        warning "下载包内缺少 sing-box 二进制"
        rm -rf "$archive" "$extract_dir"
        return 1
    fi
    if ! install -m 0755 "$extract_dir/$package/sing-box" "$candidate"; then
        warning "准备 candidate 二进制失败"
        rm -rf "$archive" "$extract_dir"
        return 1
    fi
    rm -rf "$archive" "$extract_dir"
    return 0
}

verify_candidate_binary() { # verify_candidate_binary <candidate> <version>
    local out
    if ! out="$("$1" version 2>/dev/null)"; then
        warning "candidate 二进制无法执行 version"
        return 1
    fi
    if ! printf '%s' "$out" | grep -q "version $2"; then
        warning "candidate 二进制版本不是 $2（$(printf '%s' "$out" | head -n 1)）"
        return 1
    fi
    return 0
}

# Post-restart runtime verification. Expected version, service state, MainPID,
# Reality TCP / HY2 UDP listeners, the loopback-only API listener (never
# 0.0.0.0/[::]) and a live `sing-box api connection list` call.
phase_d_health_ok() { # phase_d_health_ok <expected_version> [require_api=yes|no]
    local expected="$1" require_api="${2:-yes}"
    local main_pid reality_port hy_port out api_secret
    if ! systemctl is-active --quiet sing-box 2>/dev/null; then
        warning "健康检查失败: sing-box 服务未 active"
        return 1
    fi
    main_pid="$(systemctl show sing-box -p MainPID --value 2>/dev/null)"
    case "$main_pid" in
        ''|*[!0-9]*) warning "健康检查失败: MainPID 无效（${main_pid:-空}）"; return 1 ;;
    esac
    [ "$main_pid" -gt 0 ] || { warning "健康检查失败: MainPID 无效（$main_pid）"; return 1; }
    if ! out="$("$SB_SING_BOX_BIN" version 2>/dev/null)"; then
        warning "健康检查失败: 当前二进制无法执行 version"
        return 1
    fi
    if ! printf '%s' "$out" | grep -q "version $expected"; then
        warning "健康检查失败: 当前二进制不是 $expected（$(printf '%s' "$out" | head -n 1)）"
        return 1
    fi
    reality_port="$(jq -r --arg tag "$REALITY_INBOUND_TAG" \
        '.inbounds[] | select(.tag == $tag) | .listen_port' "$SB_SERVER_CONFIG" 2>/dev/null)"
    hy_port="$(jq -r --arg tag "$HY2_INBOUND_TAG" \
        '.inbounds[] | select(.tag == $tag) | .listen_port' "$SB_SERVER_CONFIG" 2>/dev/null)"
    if ! ss -H -lnt 2>/dev/null | grep -qE "[:.]${reality_port}[[:space:]]"; then
        warning "健康检查失败: Reality TCP 监听缺失（$reality_port）"
        return 1
    fi
    if ! ss -H -lnu 2>/dev/null | grep -qE "[:.]${hy_port}[[:space:]]"; then
        warning "健康检查失败: HY2 UDP 监听缺失（$hy_port）"
        return 1
    fi
    if [ "$require_api" = "yes" ]; then
        if ! ss -H -lnt 2>/dev/null | grep -qE "127\.0\.0\.1:${PHASE_D_API_PORT}[[:space:]]"; then
            warning "健康检查失败: API 127.0.0.1:${PHASE_D_API_PORT} 未监听"
            return 1
        fi
        if ss -H -lnt 2>/dev/null | grep -qE "(0\.0\.0\.0|\[::\]):${PHASE_D_API_PORT}[[:space:]]"; then
            warning "健康检查失败: API 监听越界（检测到 0.0.0.0/[::]:${PHASE_D_API_PORT}）"
            return 1
        fi
        # The secret's source of truth is the (already committed) live config.
        api_secret="$(read_api_secret_from_config "$SB_SERVER_CONFIG")"
        if [ -n "$api_secret" ]; then
            if ! "$SB_SING_BOX_BIN" api --url "http://127.0.0.1:${PHASE_D_API_PORT}" --secret "$api_secret" connection list >/dev/null 2>&1; then
                warning "健康检查失败: sing-box api connection list 不可用"
                return 1
            fi
            # Negative canary: with a secret configured, an UNauthenticated call
            # MUST be rejected; success would mean auth is not enforced.
            if "$SB_SING_BOX_BIN" api --url "http://127.0.0.1:${PHASE_D_API_PORT}" connection list >/dev/null 2>&1; then
                warning "健康检查失败: service.api 未强制认证（无凭据调用竟然成功）"
                return 1
            fi
        else
            if ! "$SB_SING_BOX_BIN" api --url "http://127.0.0.1:${PHASE_D_API_PORT}" connection list >/dev/null 2>&1; then
                warning "健康检查失败: sing-box api connection list 不可用"
                return 1
            fi
        fi
    fi
    return 0
}

hy2_hopping_enabled() {
    [ "$(grep '^HY_HOPPING=' "$SB_STATE_FILE" 2>/dev/null | cut -d'=' -f2)" = "TRUE" ]
}

# Hopping rules must be restored after BOTH a successful upgrade and a rollback.
ensure_hy2_hopping_after_restart() {
    hy2_hopping_enabled || return 0
    local service="${SB_HOPPING_SERVICE:-${HY_HOPPING_SERVICE:-/etc/systemd/system/sing-box-hy2-hopping.service}}"
    if [ ! -f "$service" ]; then
        warning "HY_HOPPING=TRUE 但缺少 $service；端口跳跃规则未刷新，请人工确认"
        return 1
    fi
    if ! systemctl reload sing-box-hy2-hopping.service 2>/dev/null; then
        warning "Hysteria2 端口跳跃规则刷新失败（sing-box-hy2-hopping.service）"
        return 1
    fi
    return 0
}

# Double rollback: restores the old binary AND the old config, restarts, and
# re-verifies. A failing rollback restart is reported as needing manual
# intervention -- never as a successful recovery.
_rollback_upgrade() { # _rollback_upgrade <backup_bin> <backup_cfg> <old_version>
    local backup_bin="$1" backup_cfg="$2" old_version="$3"
    local require_api="no"
    warning "升级失败，执行双回滚（binary + config）..."
    if ! restore_file_atomically "$backup_cfg" "$SB_SERVER_CONFIG" 0600 ||
       ! restore_file_atomically "$backup_bin" "$SB_SING_BOX_BIN" 0755; then
        warning "回滚文件原子恢复失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
        return 1
    fi
    if ! systemctl restart sing-box 2>/dev/null; then
        warning "回滚后 restart sing-box 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
        return 1
    fi
    if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then
        require_api="yes"
    fi
    if ! phase_d_health_ok "$old_version" "$require_api"; then
        warning "回滚后健康检查失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
        return 1
    fi
    if ! ensure_hy2_hopping_after_restart; then
        warning "回滚后端口跳跃规则未能确认恢复，请人工检查"
        return 1
    fi
    warning "已回滚到升级前状态（binary $old_version + config），服务健康"
    return 0
}

upgrade_singbox_1_14() {
    # A manual (non-systemd) sing-box process must block the upgrade BEFORE any
    # binary/config change: Phase D only operates on a systemd-managed instance.
    if pgrep -x sing-box >/dev/null 2>&1 && ! systemctl is-active --quiet sing-box 2>/dev/null; then
        warning "检测到 sing-box 正由手工进程运行（非 systemd 管理），Phase D 拒绝修改 binary/config"
        warning "请先安排维护窗口，将现有进程迁移到 sing-box.service 后再执行升级"
        return 1
    fi
    with_client_lock _upgrade_singbox_1_14_locked
}

# The whole transaction runs under the SAME /root/sbox/config.lock as Phase C:
# read -> audit -> candidate -> check -> backup -> replace -> restart -> health.
_upgrade_singbox_1_14_locked() {
    local problems api_problems tag ver old_version
    local candidate_bin backup_bin backup_cfg candidate_cfg
    [ -f "$SB_SERVER_CONFIG" ] || { warning "服务端配置不存在: $SB_SERVER_CONFIG"; return 1; }
    if ! jq empty "$SB_SERVER_CONFIG" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $SB_SERVER_CONFIG"
        return 1
    fi

    # Phase C precondition: the multi-client identity model must already be in
    # place. Phase D NEVER auto-migrates an unnamed shared account.
    if ! problems="$(candidate_problems "$SB_SERVER_CONFIG")"; then
        warning "客户端结构审计执行失败: $SB_SERVER_CONFIG"
        return 1
    fi
    if [ -n "$problems" ]; then
        if grep -q '没有 name' <<<"$problems"; then
            warning "检测到旧的无名共享账号（Phase C legacy migration 尚未执行），Phase D 不自动迁移"
            warning "请先运行: mianyang → 10 客户端管理 → 5 迁移旧客户端为 legacy，然后再升级"
        else
            warning "客户端身份审计未通过（先在客户端管理中修复一致性）:"
            while IFS= read -r p; do
                [ -n "$p" ] && warning "  - $p"
            done <<< "$problems"
        fi
        return 1
    fi

    # Existing API state must be either absent or fully compliant; anything
    # else is fail-closed and never auto-overwritten.
    if ! api_problems="$(phase_d_config_structure_problems "$SB_SERVER_CONFIG")"; then
        warning "API 配置审计执行失败: $SB_SERVER_CONFIG"
        return 1
    fi
    if [ -n "$api_problems" ]; then
        warning "现有 API 配置不合规（拒绝自动覆盖）:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$api_problems"
        return 1
    fi

    if ! phase_d_api_service_exact "$SB_SERVER_CONFIG" && api_port_occupied; then
        warning "127.0.0.1:${PHASE_D_API_PORT} 已被占用，拒绝升级（即将新增 API 监听）"
        return 1
    fi

    tag="$(select_1_14_stable_tag)" || return 1
    ver="${tag#v}"
    old_version="$("$SB_SING_BOX_BIN" version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)"
    [ -n "$old_version" ] || { warning "无法读取当前 sing-box 版本"; return 1; }

    candidate_bin="$(mktemp "${SB_SING_BOX_BIN}.new.XXXXXX")" || {
        warning "创建 candidate 二进制失败"
        return 1
    }
    if ! acquire_candidate_binary "$tag" "$ver" "$candidate_bin"; then
        rm -f "$candidate_bin"
        return 1
    fi
    if ! verify_candidate_binary "$candidate_bin" "$ver"; then
        rm -f "$candidate_bin"
        return 1
    fi

    candidate_cfg="$(mktemp "${SB_SERVER_CONFIG}.candidate.XXXXXX")" || {
        rm -f "$candidate_bin"
        return 1
    }
    if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then
        cp -a "$SB_SERVER_CONFIG" "$candidate_cfg"
    elif ! phase_d_inject_api_service "$SB_SERVER_CONFIG" "$candidate_cfg"; then
        warning "生成 candidate config 失败"
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    fi

    if ! problems="$(candidate_problems "$candidate_cfg")"; then
        warning "candidate 结构审计执行失败"
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "candidate 身份审计未通过:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    fi
    if ! api_problems="$(phase_d_config_structure_problems "$candidate_cfg")"; then
        warning "candidate API 审计执行失败"
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    fi
    if [ -n "$api_problems" ] || ! phase_d_api_service_exact "$candidate_cfg"; then
        warning "candidate API 配置验证失败:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$api_problems"
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    fi

    if ! "$candidate_bin" check -c "$candidate_cfg" >/dev/null 2>&1; then
        warning "candidate binary check 未通过，正式环境未修改"
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    fi

    backup_bin="$(mktemp "${SB_SING_BOX_BIN}.bak.$(date +%Y%m%d-%H%M%S).XXXXXX")" || {
        rm -f "$candidate_bin" "$candidate_cfg"
        return 1
    }
    backup_cfg="$(mktemp "${SB_SERVER_CONFIG}.bak.$(date +%Y%m%d-%H%M%S).XXXXXX")" || {
        rm -f "$candidate_bin" "$candidate_cfg" "$backup_bin"
        return 1
    }
    if ! cp -a "$SB_SING_BOX_BIN" "$backup_bin"; then
        warning "备份当前 binary 失败，正式环境未修改"
        rm -f "$candidate_bin" "$candidate_cfg" "$backup_bin" "$backup_cfg"
        return 1
    fi
    if ! cp -a "$SB_SERVER_CONFIG" "$backup_cfg"; then
        warning "备份当前配置失败，正式环境未修改"
        rm -f "$candidate_bin" "$candidate_cfg" "$backup_bin" "$backup_cfg"
        return 1
    fi
    # cp -a preserves the source mode; an old 0644 live config must never
    # produce a world-readable backup.
    if ! chmod 0600 "$backup_cfg" 2>/dev/null; then
        warning "备份文件权限收紧为 0600 失败，正式环境未修改"
        rm -f "$candidate_bin" "$candidate_cfg" "$backup_bin" "$backup_cfg"
        return 1
    fi

    if ! mv -f "$candidate_bin" "$SB_SING_BOX_BIN"; then
        warning "原子替换 binary 失败，正式环境未修改"
        rm -f "$candidate_bin" "$candidate_cfg" "$backup_bin" "$backup_cfg"
        return 1
    fi
    if ! mv -f "$candidate_cfg" "$SB_SERVER_CONFIG"; then
        # The binary at the live path is ALREADY the new one: this is a mixed
        # state (new binary + old config). Restore BOTH -- config first, then
        # binary -- then restart immediately and verify, so that no future
        # restart ever runs the mixed pair. Backups are KEPT until the
        # recovered state is proven healthy.
        warning "原子替换 config 失败，执行双恢复（config → binary）..."
        if ! restore_file_atomically "$backup_cfg" "$SB_SERVER_CONFIG" 0600; then
            warning "恢复 config 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
            return 1
        fi
        if ! restore_file_atomically "$backup_bin" "$SB_SING_BOX_BIN" 0755; then
            warning "恢复 binary 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
            return 1
        fi
        rm -f "$candidate_bin" "$candidate_cfg"
        if ! systemctl restart sing-box 2>/dev/null; then
            warning "双恢复后 restart sing-box 失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
            return 1
        fi
        local require_api="no"
        if phase_d_api_service_exact "$SB_SERVER_CONFIG"; then require_api="yes"; fi
        if ! phase_d_health_ok "$old_version" "$require_api"; then
            warning "双恢复后健康检查失败，请立即人工介入！备份: $backup_bin / $backup_cfg"
            return 1
        fi
        if ! ensure_hy2_hopping_after_restart; then
            warning "双恢复后端口跳跃规则未能确认恢复，请人工检查"
            return 1
        fi
        warning "已恢复到升级前状态（binary $old_version + config），服务健康"
        info "升级前备份已保留: binary=$backup_bin config=$backup_cfg"
        return 1
    fi

    if ! systemctl restart sing-box 2>/dev/null; then
        _rollback_upgrade "$backup_bin" "$backup_cfg" "$old_version"
        return 1
    fi
    if ! phase_d_health_ok "$ver" "yes"; then
        _rollback_upgrade "$backup_bin" "$backup_cfg" "$old_version"
        return 1
    fi
    if ! ensure_hy2_hopping_after_restart; then
        _rollback_upgrade "$backup_bin" "$backup_cfg" "$old_version"
        return 1
    fi

    info "升级完成: sing-box $ver（binary + config 已替换并验证健康）"
    info "本机 service.api 已启用: http://${PHASE_D_API_LISTEN}:${PHASE_D_API_PORT}（仅回环监听）"
    info "升级前备份: binary=$backup_bin config=$backup_cfg"
    # S0: the committed config is the API secret's source of truth. Refresh the
    # derived collector file so the local collector never authenticates with a
    # missing/stale copy (a configured secret is never rotated here).
    if ! sync_api_secret_file; then
        warning "monitor-api.secret 派生文件刷新失败（binary/config 已提交且健康）；本机 collector 将无法认证，请手动检查权限"
        return 1
    fi
    return 0
}
# <<< phase-d singbox-1.14-api <<< ============================================

NETWORK_SYSCTL_FILE="/etc/sysctl.d/99-sing-box-network.conf"
UDP_BUFFER_MIN_BYTES=16777216

read_sysctl_number() {
    sysctl -n "$1" 2>/dev/null | tr -cd '0-9'
}

larger_number() {
    local first="${1:-0}"
    local second="${2:-0}"
    if (( first > second )); then
        echo "$first"
    else
        echo "$second"
    fi
}

write_network_sysctl() {
    local request_bbr="${1:-FALSE}"
    local current_rmem current_wmem target_rmem target_wmem current_cc temp_file

    current_rmem=$(read_sysctl_number net.core.rmem_max)
    current_wmem=$(read_sysctl_number net.core.wmem_max)
    target_rmem=$(larger_number "${current_rmem:-0}" "$UDP_BUFFER_MIN_BYTES")
    target_wmem=$(larger_number "${current_wmem:-0}" "$UDP_BUFFER_MIN_BYTES")
    current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || true)
    if [ "$current_cc" = "bbr" ]; then
        request_bbr="TRUE"
    fi

    mkdir -p /etc/sysctl.d
    temp_file=$(mktemp) || error "无法创建网络优化临时文件"
    {
        echo "# Managed by install-singboxhysteria2"
        echo "# Keep UDP socket buffer limits at least 16 MiB for Hysteria2/QUIC."
        echo "net.core.rmem_max = $target_rmem"
        echo "net.core.wmem_max = $target_wmem"
        if [ "$request_bbr" = "TRUE" ]; then
            echo "# TCP tuning for Reality and proxied TCP traffic."
            echo "net.core.default_qdisc = fq"
            echo "net.ipv4.tcp_congestion_control = bbr"
        fi
    } > "$temp_file"

    install -m 0644 "$temp_file" "$NETWORK_SYSCTL_FILE" || {
        rm -f "$temp_file"
        error "写入网络优化配置失败"
    }
    rm -f "$temp_file"
    sysctl -p "$NETWORK_SYSCTL_FILE" || error "应用网络优化配置失败"

    info "Hysteria2 UDP 接收缓冲上限: $(sysctl -n net.core.rmem_max)"
    info "Hysteria2 UDP 发送缓冲上限: $(sysctl -n net.core.wmem_max)"
}

configure_udp_buffers() {
    write_network_sysctl "FALSE"
}

enable_bbr() {
    local available_cc

    if command -v modprobe >/dev/null 2>&1; then
        modprobe tcp_bbr >/dev/null 2>&1 || true
    fi
    available_cc=$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)

    if grep -qw bbr <<< "$available_cc"; then
        write_network_sysctl "TRUE"
        info "TCP BBR 已启用: $(sysctl -n net.ipv4.tcp_congestion_control)"
        info "默认队列算法: $(sysctl -n net.core.default_qdisc)"
    else
        warning "当前内核不支持 TCP BBR；不会下载第三方脚本或自动更换内核。"
        configure_udp_buffers
        return 1
    fi
}

# >>> legacy-config-transaction-hardening >>> ==================================
# L1..L5: serialize EVERY durable sing-box management mutation under the SAME
# /root/sbox/config.lock used by Phase C / Phase D (see the with_client_lock
# note above). The legacy CLI flows below used to write sbconfig_server.json and
# /root/sbox/config directly, bypassing the lock and using shared fixed temp
# files. They now follow the same discipline:
#
#   public_function()  -> gather interactive input WITHOUT the lock
#                      -> with_client_lock _public_function_locked <values>
#
#   _..._locked()      -> re-read LIVE state, revalidate, mutate, commit
#                      -> never re-acquire the lock, never block on user input
#
# All JSON writers go through commit_server_config, so they inherit candidate
# audit + sing-box check + 0600 backup + atomic replace + reload + health +
# rollback. modify_singbox additionally owns /root/sbox/config, so it performs a
# dedicated TWO-FILE transaction (see _modify_singbox_locked).
# ==============================================================================

# Unique candidate/backup paths next to the DURABLE STATE file (/root/sbox/config).
# Same mktemp discipline as new_candidate_path/new_backup_path: never a shared
# fixed temp name, so two transactions can never collide on one path.
new_state_candidate_path() { # new_state_candidate_path -> unique candidate next to the live state
    mktemp "${SB_STATE_FILE}.candidate.XXXXXX" 2>/dev/null
}

new_state_backup_path() { # new_state_backup_path -> unique backup next to the live state
    mktemp "${SB_STATE_FILE}.bak.$(date +%Y%m%d-%H%M%S).XXXXXX" 2>/dev/null
}

# rc 0 when $1 is a usable TCP/UDP port number (1-65535, digits only).
valid_port() {
    case "$1" in
        ''|*[!0-9]*) return 1 ;;
    esac
    [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

# rc 0 when an inbound with this exact tag exists in <config>.
inbound_tag_exists() { # <tag> [config]
    jq -e --arg tag "$1" '[.inbounds[] | select(.tag == $tag)] | length > 0' \
        "${2:-$SB_SERVER_CONFIG}" >/dev/null 2>&1
}

# Structural precheck for the legacy JSON writers (direct-in / ss-in). The Phase C
# identity audit only knows vless-in/hy2-in, so these flows need their own
# fail-closed structural gate BEFORE building a candidate:
#   root object, .inbounds array, and (for the direct-in flows) .route.rules array.
# FAIL-CLOSED: a jq runtime error propagates as a non-zero exit code and must be
# treated as a failure by callers, never as "no problems".
legacy_json_structure_problems() { # <config> [require_route_rules yes|no]
    local cfg="$1" need_rules="${2:-no}"
    jq -r --arg need "$need_rules" '
      if (type != "object") then ["配置根节点不是 object"]
      elif ((.inbounds // null) | type) != "array" then
        (if (.inbounds // null) == null then ["缺少 inbounds 字段"] else ["inbounds 不是数组"] end)
      elif ($need == "yes") and has("route") and ((.route | type) != "object") then
        ["route 不是 object"]
      elif ($need == "yes") and (((.route // {}) | .rules // null) == null) then
        ["缺少 route.rules 字段"]
      elif ($need == "yes") and ((((.route // {}) | .rules) | type) != "array") then
        ["route.rules 不是数组"]
      else [] end | .[]
    ' "$cfg" 2>/dev/null
}

# live state -> candidate -> atomic replace, used by the HY2 state writers.
# The caller MUST already hold with_client_lock. Rewrites the single line whose
# key matches (appending when absent), leaving every other byte untouched.
set_state_key() { # set_state_key <live> <candidate> <key> <replacement-line>
    local live="$1" candidate="$2" key="$3" line="$4"
    awk -v key="$key" -v line="$line" '
        BEGIN { done = 0 }
        index($0, key "=") == 1 { print line; done = 1; next }
        { print }
        END { if (!done) print line }
    ' "$live" > "$candidate" 2>/dev/null
}

# ---------------------------------------------------------------- L5 guard --
# Narrowly scoped guard for the future E3 (Web Client Manager) enablement.
#
# E3 IS NOT IMPLEMENTED on this branch, so NO production code creates this
# signal and current installations keep the exact legacy behaviour (the marker
# path simply does not exist). This is the ACTIVATION HOOK that future E3 must
# own: while web/E3 management is active it must publish the marker (and remove
# it when management is disabled / maintenance mode is entered), so the
# destructive CLI uninstall/reinstall refuses BEFORE touching disk instead of
# racing a live manager. The concrete signal is deliberately a single
# root-owned file (the simplest durable signal); it is subordinate to the final
# E3/Integration decision and MUST be ratified there. SB_MANAGEMENT_ACTIVE_MARKER
# is overridable so tests can simulate the active state without inventing an
# irreversible production contract.
SB_MANAGEMENT_ACTIVE_MARKER="${SB_MANAGEMENT_ACTIVE_MARKER:-/var/lib/sbox-cm/management.active}"

management_is_active() { # rc 0 when web/E3 management is marked active
    [ -e "$SB_MANAGEMENT_ACTIVE_MARKER" ]
}

require_management_inactive() { # <operation-label> -> rc 0 when safe to proceed
    local op="${1:-该操作}"
    if ! management_is_active; then
        return 0
    fi
    warning "检测到 Web 管理已启用（$SB_MANAGEMENT_ACTIVE_MARKER）。"
    warning "为避免与 Web/E3 管理并发破坏 /root/sbox 配置，已拒绝 '$op'。"
    warning "请先关闭 Web 管理或进入维护模式，再执行 '$op'。"
    return 1
}

# -------------------------------------------------- L3 modify_singbox (2 files) --
# Interactive input is gathered BEFORE the lock (prompts, port picking and the
# TLS/HTTP2 probe are all user/network blocking). The dual-file transaction runs
# under with_client_lock.
modify_singbox() {
    local reality_current_port reality_port reality_current_server_name reality_server_name input_server_name
    local hy_current_port hy_port hy_current_cert hy_current_key hy_current_domain hy_domain hy_cert hy_key
    echo ""
    warning "开始修改VISION_REALITY 端口号和域名"
    echo ""
    reality_current_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' "$SB_SERVER_CONFIG")
    reality_port=$(modify_port "$reality_current_port" "VISION_REALITY")
    info "生成的端口号为: $reality_port"
    reality_current_server_name=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.server_name' "$SB_SERVER_CONFIG")
    reality_server_name="$reality_current_server_name"
    while :; do
        read -p "请输入需要偷取证书的网站，必须支持 TLS 1.3 and HTTP/2 (默认: $reality_server_name): " input_server_name
        reality_server_name=${input_server_name:-$reality_server_name}
        if curl --tlsv1.3 --http2 -sI "https://$reality_server_name" | grep -q "HTTP/2"; then
            break
        else
            warning "域名 $reality_server_name 不支持 TLS 1.3 或 HTTP/2，请重新输入."
        fi
    done
    info "域名 $reality_server_name 符合标准"
    echo ""
    warning "开始修改hysteria2端口号"
    echo ""
    hy_current_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' "$SB_SERVER_CONFIG")
    hy_port=$(modify_port "$hy_current_port" "HYSTERIA2")
    info "生成的端口号为: $hy_port"
    info "修改hysteria2应用证书路径"
    hy_current_cert=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .tls.certificate_path' "$SB_SERVER_CONFIG")
    hy_current_key=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .tls.key_path' "$SB_SERVER_CONFIG")
    hy_current_domain=$(grep -o "HY_SERVER_NAME='[^']*'" "$SB_STATE_FILE" | awk -F"'" '{print $2}')
    read -p "请输入证书域名 (默认: $hy_current_domain): " hy_domain
    hy_domain=${hy_domain:-$hy_current_domain}
    read -p "请输入证书cert路径 (默认: $hy_current_cert): " hy_cert
    hy_cert=${hy_cert:-$hy_current_cert}
    read -p "请输入证书key路径 (默认: $hy_current_key): " hy_key
    hy_key=${hy_key:-$hy_current_key}

    # No lock is held here; the transaction re-reads and revalidates LIVE state.
    with_client_lock _modify_singbox_locked \
        "$reality_port" "$hy_port" "$reality_server_name" "$hy_cert" "$hy_key" "$hy_domain"
}

# Two-file transaction: /root/sbox/sbconfig_server.json AND /root/sbox/config
# must change together. `commit_server_config` + `sed -i` is deliberately NOT
# used: that would still allow a split durable state (new JSON + old state).
# Order: re-read LIVE -> revalidate -> build BOTH unique candidates -> validate
# JSON -> sing-box check -> hardened 0600 backups of BOTH -> atomically replace
# BOTH -> reload -> health. Any failure after either live replacement restores
# BOTH artifacts, reloads the old configuration and verifies recovery; a success
# never leaves new JSON + old state (or old JSON + new state).
# Only the explicitly requested values are mutated: Reality UUIDs, HY2 passwords,
# the Reality private key and service.api.secret are never rotated here.
_modify_singbox_locked() { # <reality_port> <hy_port> <server_name> <hy_cert> <hy_key> <hy_domain>
    local reality_port="$1" hy_port="$2" server_name="$3" hy_cert="$4" hy_key="$5" hy_domain="$6"
    local cfg="$SB_SERVER_CONFIG" state="$SB_STATE_FILE"
    local json_cand="" state_cand="" json_bak="" state_bak=""
    local problems="" was_running="" p="" rj=0 rs=0

    # 1. re-read the LIVE artifacts (never a pre-lock snapshot).
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    [ -f "$state" ] || { warning "状态文件不存在: $state"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi

    # 2. revalidate every assumption against the LIVE config.
    if ! problems="$(candidate_problems "$cfg")"; then
        warning "服务端配置结构审计执行失败，修改已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足修改前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    if ! valid_port "$reality_port"; then
        warning "Reality 端口非法: '$reality_port'"
        return 1
    fi
    if ! valid_port "$hy_port"; then
        warning "HY2 端口非法: '$hy_port'"
        return 1
    fi
    [ -n "$server_name" ] || { warning "Reality server_name 不能为空"; return 1; }
    [ -n "$hy_cert" ] || { warning "HY2 证书 cert 路径不能为空"; return 1; }
    [ -n "$hy_key" ] || { warning "HY2 证书 key 路径不能为空"; return 1; }
    # The domain is written into a single-quoted state line; reject anything that
    # would break that line rather than emitting a corrupt durable state.
    case "$hy_domain" in
        ''|*"'"*|*'\'*)
            warning "证书域名非法（不得为空/引号/反斜杠）: '$hy_domain'"
            return 1
            ;;
    esac
    case "$hy_domain" in
        *[[:space:]]*)
            warning "证书域名不得包含空白: '$hy_domain'"
            return 1
            ;;
    esac

    # 3./4. build BOTH unique candidates from the LIVE files (no shared temp file).
    json_cand="$(new_candidate_path)" || { warning "创建 JSON candidate 失败"; return 1; }
    if ! jq --arg reality_port "$reality_port" \
        --arg hy_port "$hy_port" \
        --arg reality_server_name "$server_name" \
        --arg hy_cert "$hy_cert" \
        --arg hy_key "$hy_key" \
        '
        (.inbounds[] | select(.tag == "vless-in") | .listen_port) |= ($reality_port | tonumber) |
        (.inbounds[] | select(.tag == "hy2-in") | .listen_port) |= ($hy_port | tonumber) |
        (.inbounds[] | select(.tag == "vless-in") | .tls.server_name) |= $reality_server_name |
        (.inbounds[] | select(.tag == "vless-in") | .tls.reality.handshake.server) |= $reality_server_name |
        (.inbounds[] | select(.tag == "hy2-in") | .tls.certificate_path) |= $hy_cert |
        (.inbounds[] | select(.tag == "hy2-in") | .tls.key_path) |= $hy_key
        ' "$cfg" > "$json_cand"; then
        warning "生成 JSON candidate 失败"
        rm -f "$json_cand"
        return 1
    fi
    state_cand="$(new_state_candidate_path)" || { warning "创建状态 candidate 失败"; rm -f "$json_cand"; return 1; }
    if ! set_state_key "$state" "$state_cand" "HY_SERVER_NAME" "HY_SERVER_NAME='${hy_domain}'"; then
        warning "生成状态 candidate 失败"
        rm -f "$json_cand" "$state_cand"
        return 1
    fi

    # 5. validate the candidate JSON (syntax + identity audit) BEFORE any replace.
    if ! jq empty "$json_cand" >/dev/null 2>&1; then
        warning "candidate JSON 不是合法 JSON，修改已中止"
        rm -f "$json_cand" "$state_cand"
        return 1
    fi
    if ! problems="$(candidate_problems "$json_cand")"; then
        warning "candidate 结构审计执行失败，修改已中止"
        rm -f "$json_cand" "$state_cand"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "candidate 结构一致性检查失败，正式配置与状态均未修改:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        rm -f "$json_cand" "$state_cand"
        return 1
    fi

    # 6. sing-box check on the candidate (never on the live file).
    if ! "$SB_SING_BOX_BIN" check -c "$json_cand" >/dev/null 2>&1; then
        warning "sing-box check 未通过，正式配置与状态均未修改"
        rm -f "$json_cand" "$state_cand"
        return 1
    fi

    if systemctl is-active --quiet sing-box 2>/dev/null; then
        was_running=systemd
    elif pgrep -x sing-box >/dev/null 2>&1; then
        was_running=manual
    else
        was_running=no
    fi

    # 7. hardened backups of BOTH live files (0600, never inherit world-readable).
    json_bak="$(new_backup_path)" || { warning "创建 JSON 备份路径失败"; rm -f "$json_cand" "$state_cand"; return 1; }
    state_bak="$(new_state_backup_path)" || { warning "创建状态备份路径失败"; rm -f "$json_cand" "$state_cand"; return 1; }
    if ! cp -a "$cfg" "$json_bak" || ! chmod 0600 "$json_bak" 2>/dev/null; then
        warning "备份服务端配置失败"
        rm -f "$json_cand" "$state_cand" "$json_bak"
        return 1
    fi
    if ! cp -a "$state" "$state_bak" || ! chmod 0600 "$state_bak" 2>/dev/null; then
        warning "备份状态文件失败"
        rm -f "$json_cand" "$state_cand" "$json_bak" "$state_bak"
        return 1
    fi

    # 8. atomically replace BOTH durable artifacts. A failure after the first
    # replace restores both from the hardened backups: the pair is never split.
    if ! mv -f "$json_cand" "$cfg"; then
        warning "JSON 原子替换失败，持久化状态未修改"
        rm -f "$json_cand" "$state_cand"
        return 1
    fi
    if ! mv -f "$state_cand" "$state"; then
        # The state rename failed, so the old state is normally still in place;
        # nevertheless restore+verify BOTH artifacts atomically so the durable
        # pair is provably restored and never left split (new JSON + old state).
        rm -f "$state_cand"
        warning "状态文件原子替换失败，回滚服务端配置与状态并校验..."
        rj=0; rs=0
        restore_file_atomically "$json_bak" "$cfg" || rj=1
        restore_file_atomically "$state_bak" "$state" || rs=1
        if [ "$rj" -ne 0 ] || [ "$rs" -ne 0 ]; then
            warning "回滚恢复失败，需人工介入！两份持久化文件可能不一致，请勿继续操作。"
            warning "备份保留（请勿删除）: $json_bak / $state_bak"
            return 1
        fi
        if [ "$was_running" = "no" ]; then
            warning "已恢复并校验上一份配置与状态（当前无运行中的 sing-box，无需 reload）: $json_bak / $state_bak"
            return 1
        fi
        if reload_running_singbox && reload_health_ok; then
            warning "已回滚并重新加载上一份配置与状态: $json_bak / $state_bak"
        else
            warning "已恢复并校验上一份配置与状态，但服务未能确认恢复，请立即人工检查！备份: $json_bak / $state_bak"
        fi
        return 1
    fi

    # 9./10. reload + health.
    if [ "$was_running" = "no" ]; then
        info "配置与状态已同时提交（当前无运行中的 sing-box，跳过 reload）"
        info "上一份备份: $json_bak / $state_bak"
        return 0
    fi
    if reload_running_singbox && reload_health_ok; then
        info "配置与状态已同时提交并重载成功"
        info "上一份备份: $json_bak / $state_bak"
        return 0
    fi

    # 11./12. reload/health failed -> atomically restore+verify BOTH artifacts,
    # then reload the previous configuration.
    warning "reload 后健康检查失败，回滚配置与状态..."
    rj=0; rs=0
    restore_file_atomically "$json_bak" "$cfg" || rj=1
    restore_file_atomically "$state_bak" "$state" || rs=1
    if [ "$rj" -ne 0 ] || [ "$rs" -ne 0 ]; then
        warning "回滚恢复失败，需人工介入！两份持久化文件可能不一致，请勿继续操作。"
        warning "备份保留（请勿删除）: $json_bak / $state_bak"
        return 1
    fi
    if reload_running_singbox && reload_health_ok; then
        warning "已回滚并重新加载上一份配置与状态: $json_bak / $state_bak"
    else
        warning "已恢复磁盘上的配置与状态，但服务未能确认恢复，请立即人工检查！备份: $json_bak / $state_bak"
    fi
    return 1
}


backup_current_installation() {
    local backup_dir backup_name unit_path

    backup_name="sbox-backup-$(date +%Y%m%d-%H%M%S)"
    backup_dir="/root/${backup_name}"
    install -d -m 0700 "$backup_dir" || return 1
    cp -a /root/sbox "$backup_dir/" || return 1
    unit_path="$(systemctl show sing-box -p FragmentPath --value 2>/dev/null || true)"
    if [ -n "$unit_path" ] && [ -e "$unit_path" ]; then
        cp -a "$unit_path" "$backup_dir/sing-box.service.source"
        printf '%s\n' "$unit_path" > "$backup_dir/sing-box.service.source-path.txt"
    elif [ -e /etc/systemd/system/sing-box.service ]; then
        cp -a /etc/systemd/system/sing-box.service "$backup_dir/sing-box.service.source"
    fi
    if [ -e /usr/bin/mianyang ] || [ -L /usr/bin/mianyang ]; then
        cp -a --no-dereference /usr/bin/mianyang "$backup_dir/usr-bin-mianyang"
    fi
    systemctl cat sing-box > "$backup_dir/sing-box.unit.txt" 2>&1 || true
    systemctl show sing-box -p LoadState -p ActiveState -p FragmentPath -p MainPID > "$backup_dir/sing-box.state.txt" 2>&1 || true
    ps -ef | grep '[s]ing-box' > "$backup_dir/sing-box.process.txt" 2>&1 || true
    sysctl net.core.rmem_max net.core.wmem_max net.core.default_qdisc net.ipv4.tcp_congestion_control > "$backup_dir/network-sysctl.txt" 2>&1 || true
    iptables-save > "$backup_dir/iptables.rules" 2>/dev/null || true
    ip6tables-save > "$backup_dir/ip6tables.rules" 2>/dev/null || true
    tar -C /root -czf "/root/${backup_name}.tar.gz" "$backup_name" || return 1
    chmod 0600 "/root/${backup_name}.tar.gz"
    sha256sum "/root/${backup_name}.tar.gz" > "/root/${backup_name}.tar.gz.sha256"
    info "完整备份已创建: /root/${backup_name}.tar.gz"
}

# M0/G2 L-ANCHOR: uninstall is a destructive management transaction. The public
# entry point acquires the SAME global config.lock and delegates to a no-nesting
# helper. The lock pathname itself is a permanent control-plane anchor and is
# never unlinked, even by uninstall.
uninstall_singbox() {
    with_client_lock _uninstall_singbox_locked
}

_uninstall_singbox_locked() {
    # The activation gate MUST be evaluated while holding config.lock. This
    # closes the activate-vs-uninstall TOCTOU: either activation wins and this
    # refuses, or uninstall wins and activation later sees the missing config.
    if ! require_management_inactive "卸载"; then
        return 1
    fi

    warning "开始卸载..."
    if pgrep -x sing-box >/dev/null 2>&1 && ! systemctl is-active --quiet sing-box; then
        error "sing-box 当前由手工进程运行。为防止删除运行中的配置，已拒绝卸载。"
    fi

    # Already inside with_client_lock: call the locked hopping helper directly
    # so uninstall never nests a second flock acquisition.
    if [ -f "$SB_STATE_FILE" ]; then
        _disable_hy2hopping_locked || {
            warning "关闭 Hysteria2 端口跳跃失败，卸载已中止（控制面锚点保留）"
            return 1
        }
    else
        systemctl disable --now sing-box-hy2-hopping.service >/dev/null 2>&1 || true
        remove_hy2_hopping_rules
        rm -f "$HY_HOPPING_SERVICE" "$HY_HOPPING_HELPER"
    fi

    systemctl disable --now sing-box >/dev/null 2>&1 || true
    rm -f -- "$SB_SYSTEMD_UNIT"

    # Remove installation-owned runtime/config/credential artifacts, but DO NOT
    # rm -rf SB_ROOT_DIR. In particular, SB_LOCK_FILE must retain the same path
    # and inode for the lifetime of this critical section and afterwards.
    rm -f --         "$SB_SERVER_CONFIG"         "$SB_SING_BOX_BIN"         "$SB_ROOT_DIR/mianyang.sh"         "$SB_SHORTCUT"         "$SB_SELF_CERT_KEY"         "$SB_SELF_CERT_CERT"         "$SB_STATE_FILE"         "$SB_API_SECRET_FILE"

    rm -rf -- "$SB_CLIENTS_DIR" "$(dirname "$SB_SELF_CERT_KEY")"

    # Generated transaction residue/backups are installation-owned too. These
    # globs deliberately target only known durable artifacts; config.lock is not
    # matched and is never unlinked.
    rm -f --         "$SB_SERVER_CONFIG".candidate.*         "$SB_SERVER_CONFIG".restore.*         "$SB_SERVER_CONFIG".bak.*         "$SB_STATE_FILE".candidate.*         "$SB_STATE_FILE".restore.*         "$SB_STATE_FILE".bak.* 2>/dev/null || true

    systemctl daemon-reload >/dev/null 2>&1 || true

    if [ ! -e "$SB_LOCK_FILE" ]; then
        warning "控制面锚点异常消失: $SB_LOCK_FILE；需人工介入"
        return 1
    fi

    warning "卸载完成（控制面锚点已保留: $SB_LOCK_FILE）"
    return 0
}

update_singbox(){
    # Phase D: production upgrades go through the full transaction
    # (identity audit -> candidate binary+config -> check -> backup ->
    # atomic replace -> restart -> health / double rollback). The old
    # half-transaction (replace binary, then hope the restart works) is gone.
    info "升级 sing-box（Phase D 事务: 1.14.x stable + 本机 service.api）..."
    if ! upgrade_singbox_1_14; then
        warning "升级未完成；正式环境保持可用状态（详见上方原因/回滚信息）"
        return 1
    fi
    return 0
}

generate_random_number() {
    # Generates an 8-digit random number
    echo $((10000000 + RANDOM % 90000000))
}
process_doko() {
    local choice fport ipaddress tport delete_tag
    while :; do
        echo "已配置的任意门转发规则如下:"
        jq '.inbounds[] | select((.tag // "") | startswith("direct-in")) | "\(.tag): 转发至ip \(.override_address // "未设置"), 转发至端口 \(.override_port // "未设置")"' "$SB_SERVER_CONFIG"
        echo ""
        echo "选择操作:"
        echo "1. 添加规则"
        echo "2. 删除规则"
        echo "0. 退出"
        read -p "请输入选择的操作数字（0-2）: " choice
        case $choice in
            1)
                # Interactive input is gathered WITHOUT holding the config lock.
                fport=$(generate_port "本机任意门入站")
                echo "本机端口为: $fport"
                read -p "请输入转发至的vps ip: " ipaddress
                read -p "请输入转发至的vps端口: " tport
                with_client_lock _process_doko_add_locked "$fport" "$ipaddress" "$tport" ||
                    warning "添加任意门规则失败，配置未修改"
                ;;
            2)
                echo "请输入要删除的任意门规则标签 (例如：direct-in1): "
                read -r delete_tag
                with_client_lock _process_doko_delete_locked "$delete_tag" ||
                    warning "删除任意门规则失败，配置未修改"
                ;;
            0)
                echo "退出"
                break
                ;;
            *)
                echo "无效的选择"
                ;;
        esac
    done
}

# Locked helper: re-reads LIVE config, revalidates, generates a UNIQUE tag, builds
# a unique candidate and commits. Never re-acquires the lock and never reads input.
_process_doko_add_locked() { # <fport> <ipaddress> <tport>
    local fport="$1" ipaddress="$2" tport="$3"
    local cfg="$SB_SERVER_CONFIG" candidate="" tag="" suffix="" problems="" attempt=0 p=""
    if ! valid_port "$fport"; then
        warning "本机端口非法: '$fport'"
        return 1
    fi
    if ! valid_port "$tport"; then
        warning "转发端口非法: '$tport'"
        return 1
    fi
    [ -n "$ipaddress" ] || { warning "转发目标 IP 不能为空"; return 1; }
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    if ! problems="$(legacy_json_structure_problems "$cfg" yes)"; then
        warning "服务端配置结构审计执行失败，已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足添加前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi

    # Generate/REVALIDATE a unique direct-in tag while the lock is held.
    while :; do
        attempt=$((attempt + 1))
        if [ "$attempt" -gt 100 ]; then
            warning "无法生成唯一的任意门标签，已中止"
            return 1
        fi
        suffix="$(generate_random_number)"
        tag="direct-in${suffix}"
        if ! inbound_tag_exists "$tag" "$cfg"; then
            break
        fi
    done

    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    if ! jq --arg ipaddress "$ipaddress" --arg fport "$fport" --arg tport "$tport" --arg tag "$tag" '
        .inbounds += [
            {
                "type": "direct",
                "tag": $tag,
                "listen": "::",
                "override_address": $ipaddress,
                "override_port": ($tport | tonumber),
                "listen_port": ($fport | tonumber)
            }
        ] | .route.rules += [
            {
                "inbound": $tag,
                "outbound": "direct"
            }
        ]' "$cfg" > "$candidate"; then
        warning "生成 direct-in candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! commit_server_config "$candidate" "add direct-in $tag"; then
        warning "任意门规则写入失败（commit 未成功），配置未修改"
        return 1
    fi
    info "已添加任意门规则配置 ($tag)"
    return 0
}

# Locked helper: delete path. Re-checks the target exists WHILE LOCKED (a tag can
# disappear between the menu display and the transaction).
_process_doko_delete_locked() { # <tag>
    local tag="$1"
    local cfg="$SB_SERVER_CONFIG" candidate="" problems="" p=""
    [ -n "$tag" ] || { warning "标签不能为空"; return 1; }
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    if ! problems="$(legacy_json_structure_problems "$cfg" yes)"; then
        warning "服务端配置结构审计执行失败，已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足删除前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    if ! inbound_tag_exists "$tag" "$cfg"; then
        warning "任意门规则标签 '$tag' 不存在（锁内复核），拒绝删除"
        return 1
    fi
    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    if ! jq --arg tag "$tag" '
        del(.inbounds[] | select(.tag == $tag)) |
        del(.outbounds[] | select(.tag == ($tag + "-out"))) |
        .route.rules = (.route.rules | map(select(.inbound != $tag)))
    ' "$cfg" > "$candidate"; then
        warning "生成 direct-in delete candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! commit_server_config "$candidate" "delete direct-in $tag"; then
        warning "任意门规则删除失败（commit 未成功），配置未修改"
        return 1
    fi
    info "已删除任意门规则 ($tag)"
    return 0
}
process_dokoko() {
    warning "任意门落地机设置，目前只支持解锁使用443端口的网站"
    local cfg="$SB_SERVER_CONFIG" tag="direct-in"
    local existing_port existing_ip delete_option fport fip ip_regex
    existing_port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .listen_port' "$cfg")
    existing_ip=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .listen' "$cfg")

    if [ -n "$existing_port" ] && [ "$existing_port" != "null" ]; then
        echo "已存在的监听为: $existing_ip : $existing_port "
        read -p "是否删除已存在的配置？ (y/n): " delete_option
        if [ "$delete_option" = "y" ]; then
            # The delete decision is revalidated inside the lock.
            if with_client_lock _process_dokoko_delete_locked "$tag"; then
                echo "已删除配置"
            else
                warning "删除配置失败，配置未修改"
            fi
        else
            echo "未删除配置"
        fi
    else
        while true; do
            read -p "请输入解锁服务监听端口: " fport
            if [[ -n "$fport" && "$fport" =~ ^[0-9]+$ ]]; then
                break
            else
                warning "端口必须为非空数字，请重新输入."
            fi
        done
        while true; do
            read -p "请输入被解锁机vps ip: " fip
            ip_regex="^([0-9]{1,3}\.){3}[0-9]{1,3}$"
            if [[ $fip =~ $ip_regex ]]; then
                break
            else
                warning "输入的IP地址格式不合法"
            fi
        done
        # The "no existing direct-in" decision is revalidated inside the lock so
        # concurrent adds can never produce duplicate direct-in tags.
        if with_client_lock _process_dokoko_add_locked "$fport" "$fip"; then
            echo "已添加任意门解锁机配置"
        else
            warning "添加解锁机配置失败，配置未修改"
        fi
    fi
}

_process_dokoko_add_locked() { # <fport> <fip>
    local fport="$1" fip="$2"
    local cfg="$SB_SERVER_CONFIG" candidate="" problems="" p=""
    if ! valid_port "$fport"; then
        warning "监听端口非法: '$fport'"
        return 1
    fi
    if [[ ! "$fip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        warning "被解锁机 IP 非法: '$fip'"
        return 1
    fi
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    if ! problems="$(legacy_json_structure_problems "$cfg" yes)"; then
        warning "服务端配置结构审计执行失败，已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足添加前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    # Revalidate the "no existing direct-in" decision under the lock: a concurrent
    # add that won the race must make this one fail instead of duplicating the tag.
    if inbound_tag_exists "direct-in" "$cfg"; then
        warning "direct-in 已存在（锁内复核，可能已被并发操作创建），拒绝重复添加"
        return 1
    fi
    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    if ! jq --arg fport "$fport" --arg fip "$fip" '
        .inbounds += [
            {
                "type": "direct",
                "tag": "direct-in",
                "listen": $fip,
                "listen_port": ($fport | tonumber),
                "override_port": 443
            }
        ] | .route.rules += [
            {
                "inbound": "direct-in",
                "outbound": "direct"
            }
        ]' "$cfg" > "$candidate"; then
        warning "生成 direct-in candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! commit_server_config "$candidate" "add direct-in"; then
        warning "解锁机配置写入失败（commit 未成功），配置未修改"
        return 1
    fi
    return 0
}

_process_dokoko_delete_locked() { # <tag>
    local tag="$1"
    local cfg="$SB_SERVER_CONFIG" candidate="" problems="" p=""
    [ -n "$tag" ] || { warning "标签不能为空"; return 1; }
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    if ! problems="$(legacy_json_structure_problems "$cfg" yes)"; then
        warning "服务端配置结构审计执行失败，已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足删除前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    if ! inbound_tag_exists "$tag" "$cfg"; then
        warning "direct-in 不存在（锁内复核），拒绝删除"
        return 1
    fi
    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    if ! jq --arg tag "$tag" '
        del(.inbounds[] | select(.tag == $tag)) |
        del(.outbounds[] | select(.tag == ($tag + "-out"))) |
        .route.rules = (.route.rules | map(select(.inbound != $tag)))
    ' "$cfg" > "$candidate"; then
        warning "生成 delete candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! commit_server_config "$candidate" "delete direct-in"; then
        warning "解锁机配置删除失败（commit 未成功），配置未修改"
        return 1
    fi
    return 0
}

process_ssko() {
    warning "开始SS落地机设置"
    local cfg="$SB_SERVER_CONFIG" tag="ss-in"
    local existing_port existing_pwd server_ip delete_option fport
    existing_port=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .listen_port' "$cfg")
    existing_pwd=$(jq -r --arg tag "$tag" '.inbounds[] | select(.tag == $tag) | .password' "$cfg")
    server_ip=$(grep -o "SERVER_IP='[^']*'" "$SB_STATE_FILE" | awk -F"'" '{print $2}')

    if [ -n "$existing_port" ] && [ "$existing_port" != "null" ]; then
        info "已存在ss入站配置,监听端口号为: $existing_port"
        info "已存在ss入站配置,密码为: $existing_pwd"
        info "本机ip为: $server_ip"
        echo ""
        read -p "是否删除已存在的配置？ (y/n): " delete_option
        if [ "$delete_option" = "y" ]; then
            if with_client_lock _process_ssko_delete_locked "$tag"; then
                echo "已删除配置"
            else
                warning "删除配置失败，配置未修改"
            fi
        else
            echo "未删除配置"
        fi
    else
        while true; do
            read -p "请输入解锁服务监听端口: " fport
            if [[ -n "$fport" && "$fport" =~ ^[0-9]+$ ]]; then
                break
            else
                warning "端口必须为非空数字，请重新输入."
            fi
        done
        # Password generation is part of candidate planning: it happens INSIDE the
        # lock and never blocks on user input.
        if with_client_lock _process_ssko_add_locked "$fport"; then
            echo "已添加ss解锁机配置"
        else
            warning "添加ss解锁机配置失败，配置未修改"
        fi
    fi
}

_process_ssko_add_locked() { # <fport>
    local fport="$1"
    local cfg="$SB_SERVER_CONFIG" candidate="" problems="" sspwd="" server_ip="" p=""
    if ! valid_port "$fport"; then
        warning "监听端口非法: '$fport'"
        return 1
    fi
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    if ! problems="$(legacy_json_structure_problems "$cfg" no)"; then
        warning "服务端配置结构审计执行失败，已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足添加前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    # Revalidate ss-in non-existence while locked (no duplicate ss-in).
    if inbound_tag_exists "ss-in" "$cfg"; then
        warning "ss-in 已存在（锁内复核，可能已被并发操作创建），拒绝重复添加"
        return 1
    fi
    if ! sspwd="$("$SB_SING_BOX_BIN" generate rand 16 --base64)" || [ -z "$sspwd" ]; then
        warning "生成 SS 密码失败"
        return 1
    fi
    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    if ! jq --arg sspwd "$sspwd" --arg fport "$fport" '
        .inbounds += [
            {
                "type": "shadowsocks",
                "tag": "ss-in",
                "listen": "::",
                "listen_port": ($fport | tonumber),
                "method": "2022-blake3-aes-128-gcm",
                "password": $sspwd
            }
        ]' "$cfg" > "$candidate"; then
        warning "生成 ss-in candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! commit_server_config "$candidate" "add ss-in"; then
        warning "SS 落地机配置写入失败（commit 未成功），配置未修改"
        return 1
    fi
    server_ip="$(grep -o "SERVER_IP='[^']*'" "$SB_STATE_FILE" | awk -F"'" '{print $2}')"
    info "监听端口号为: $fport"
    info "ss密码为：$sspwd"
    info "本机ip为: $server_ip"
    return 0
}

_process_ssko_delete_locked() { # <tag>
    local tag="$1"
    local cfg="$SB_SERVER_CONFIG" candidate="" problems="" p=""
    [ -n "$tag" ] || { warning "标签不能为空"; return 1; }
    [ -f "$cfg" ] || { warning "服务端配置不存在: $cfg"; return 1; }
    if ! jq empty "$cfg" >/dev/null 2>&1; then
        warning "服务端配置不是合法 JSON: $cfg"
        return 1
    fi
    if ! problems="$(legacy_json_structure_problems "$cfg" no)"; then
        warning "服务端配置结构审计执行失败，已中止"
        return 1
    fi
    if [ -n "$problems" ]; then
        warning "服务端配置结构不满足删除前提:"
        while IFS= read -r p; do
            [ -n "$p" ] && warning "  - $p"
        done <<< "$problems"
        return 1
    fi
    if ! inbound_tag_exists "$tag" "$cfg"; then
        warning "ss-in 不存在（锁内复核），拒绝删除"
        return 1
    fi
    candidate="$(new_candidate_path)" || { warning "创建 candidate 失败"; return 1; }
    if ! jq --arg tag "$tag" '
        .inbounds = (.inbounds | map(select(.tag != $tag)))
    ' "$cfg" > "$candidate"; then
        warning "生成 delete candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! commit_server_config "$candidate" "delete ss-in"; then
        warning "SS 落地机配置删除失败（commit 未成功），配置未修改"
        return 1
    fi
    return 0
}

process_singbox() {
  while :; do
    echo ""
    echo ""
    info "请选择选项："
    echo ""
    info "1. 检查配置并重启 sing-box"
    info "2. 升级 sing-box 内核（Phase D: 1.14.x + 本机 service.api）"
    info "3. 查看 systemd 服务状态"
    info "4. 查看实时日志（Ctrl+C 退出）"
    info "5. 查看服务端配置（包含密钥）"
    info "0. 退出"
    echo ""
    read -r -p "请输入对应数字（0-5）: " user_input
    echo ""
    case "$user_input" in
        1)
            warning "重启sing-box..."
            # 检查配置
            if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
              info "检查配置文件，启动服务..."
              restart_singbox || warning "sing-box 未重启，请查看上方提示"
            fi
            break
            ;;
        2)
            update_singbox
            break
            ;;
        3)
            info "sing-box systemd 状态如下："
            systemctl status sing-box --no-pager
            break
            ;;
        4)
            warning "singbox日志如下(ctrl+c退出)："
            journalctl -u sing-box -o cat -f
            break
            ;;
        5)
            warning "以下服务端配置包含 UUID、密码和私钥，请勿公开："
            cat /root/sbox/sbconfig_server.json
            break
            ;;
        0)
          echo "退出"
          break
          ;;
        *)
            echo "请输入正确选项: 0-5"
            ;;
    esac
  done
}

process_hy2hopping(){
        while :; do
          ishopping=$(grep '^HY_HOPPING=' /root/sbox/config | cut -d'=' -f2)
          if [ "$ishopping" = "FALSE" ]; then
              warning "开始设置端口跳跃范围..."
              enable_hy2hopping       
          else
              warning "端口跳跃已开启"
              echo ""
              info "请选择选项："
              echo ""
              info "1. 关闭端口跳跃"
              info "2. 重新设置"
              info "3. 查看规则"
              info "0. 退出"
              echo ""
              read -p "请输入对应数字（0-3）: " hopping_input
              echo ""
              case $hopping_input in
                1)
                  disable_hy2hopping
                  echo "端口跳跃规则已删除"
                  break
                  ;;
                2)
                  disable_hy2hopping
                  echo "端口跳跃规则已删除"
                  echo "开始重新设置端口跳跃"
                  enable_hy2hopping
                  break
                  ;;
                3)
                  # 查看NAT规则
                  iptables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep "$HY_HOPPING_COMMENT"
                  ip6tables -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null | grep "$HY_HOPPING_COMMENT"
                  break
                  ;;
                0)
                  echo "退出"
                  break
                  ;;
                *)
                  echo "无效的选项,请重新选择"
                  ;;
              esac
          fi
        done
}
# 开启hysteria2端口跳跃
HY_HOPPING_COMMENT="sing-box-hy2-hopping"
HY_HOPPING_HELPER="${SB_HOPPING_HELPER:-/root/sbox/hy2-hopping.sh}"
HY_HOPPING_SERVICE="${SB_HOPPING_SERVICE:-/etc/systemd/system/sing-box-hy2-hopping.service}"

# NOTE: the caller MUST already hold the global config/state lock
# (with_client_lock). This rewrites the durable /root/sbox/config atomically
# (live -> unique candidate -> mv) instead of `sed -i` on the live file, so a
# concurrent modify_singbox can never observe or produce a torn state file.
set_config_value() { # set_config_value <key> <value>
    local key="$1"
    local value="$2"
    local config_file="$SB_STATE_FILE"
    local candidate=""
    case "$key" in
        ''|*[!A-Za-z0-9_]*) warning "非法状态键: '$key'"; return 1 ;;
    esac
    case "$value" in
        *$'\n'*|*$'\r'*) warning "状态值不得包含换行: '$key'"; return 1 ;;
    esac
    [ -f "$config_file" ] || { warning "状态文件不存在: $config_file"; return 1; }
    candidate="$(new_state_candidate_path)" || { warning "创建状态 candidate 失败"; return 1; }
    if ! set_state_key "$config_file" "$candidate" "$key" "${key}=${value}"; then
        warning "生成状态 candidate 失败"
        rm -f "$candidate"
        return 1
    fi
    if ! mv -f "$candidate" "$config_file"; then
        warning "状态文件原子替换失败"
        rm -f "$candidate"
        return 1
    fi
    return 0
}

remove_hy2_hopping_rules() {
    local firewall rule_number

    for firewall in iptables ip6tables; do
        command -v "$firewall" >/dev/null 2>&1 || continue
        while :; do
            rule_number=$("$firewall" -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null |
                awk -v marker="$HY_HOPPING_COMMENT" 'index($0, marker) {print $1; exit}')
            [ -n "$rule_number" ] || break
            "$firewall" -t nat -D PREROUTING "$rule_number" >/dev/null 2>&1 || break
        done
    done
}

install_hy2_hopping_helper() {
    cat > "$HY_HOPPING_HELPER" <<'EOF'
#!/usr/bin/env bash
set -u

CONFIG_FILE="/root/sbox/config"
SERVER_CONFIG="/root/sbox/sbconfig_server.json"
RULE_COMMENT="sing-box-hy2-hopping"

remove_rules() {
    local firewall rule_number
    for firewall in iptables ip6tables; do
        command -v "$firewall" >/dev/null 2>&1 || continue
        while :; do
            rule_number=$("$firewall" -t nat -L PREROUTING -n -v --line-numbers 2>/dev/null |
                awk -v marker="$RULE_COMMENT" 'index($0, marker) {print $1; exit}')
            [ -n "$rule_number" ] || break
            "$firewall" -t nat -D PREROUTING "$rule_number" >/dev/null 2>&1 || break
        done
    done
}

apply_rules() {
    local hy_port applied firewall hy_hopping hy_hopping_start hy_hopping_end
    [ -f "$CONFIG_FILE" ] || { echo "Missing $CONFIG_FILE" >&2; return 1; }
    hy_hopping=$(sed -n 's/^HY_HOPPING=//p' "$CONFIG_FILE" | tail -n 1 | tr -d "'\"")
    hy_hopping_start=$(sed -n 's/^HY_HOPPING_START=//p' "$CONFIG_FILE" | tail -n 1 | tr -d "'\"")
    hy_hopping_end=$(sed -n 's/^HY_HOPPING_END=//p' "$CONFIG_FILE" | tail -n 1 | tr -d "'\"")
    [ "$hy_hopping" = "TRUE" ] || { remove_rules; return 0; }
    [[ "$hy_hopping_start" =~ ^[0-9]+$ ]] || { echo "Invalid HY_HOPPING_START" >&2; return 1; }
    [[ "$hy_hopping_end" =~ ^[0-9]+$ ]] || { echo "Invalid HY_HOPPING_END" >&2; return 1; }
    (( hy_hopping_start >= 1 && hy_hopping_end <= 65535 && hy_hopping_start <= hy_hopping_end )) || {
        echo "Invalid Hysteria2 hopping range" >&2
        return 1
    }

    hy_port=$(jq -r '.inbounds[] | select(.tag == "hy2-in") | .listen_port' "$SERVER_CONFIG")
    [[ "$hy_port" =~ ^[0-9]+$ ]] || { echo "Invalid Hysteria2 listen port" >&2; return 1; }

    remove_rules
    applied=0
    for firewall in iptables ip6tables; do
        command -v "$firewall" >/dev/null 2>&1 || continue
        if "$firewall" -t nat -A PREROUTING -p udp \
            --dport "${hy_hopping_start}:${hy_hopping_end}" \
            -m comment --comment "$RULE_COMMENT" \
            -j REDIRECT --to-ports "$hy_port"; then
            applied=1
        fi
    done
    (( applied == 1 )) || { echo "Failed to apply Hysteria2 hopping rules" >&2; return 1; }
}

case "${1:-apply}" in
    apply) apply_rules ;;
    remove) remove_rules ;;
    *) echo "Usage: $0 {apply|remove}" >&2; exit 2 ;;
esac
EOF
    chmod 0755 "$HY_HOPPING_HELPER"

    cat > "$HY_HOPPING_SERVICE" <<'EOF'
[Unit]
Description=Persistent Hysteria2 port hopping rules for sing-box
After=network-online.target sing-box.service
Wants=network-online.target
PartOf=sing-box.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/root/sbox/hy2-hopping.sh apply
ExecReload=/root/sbox/hy2-hopping.sh apply
ExecStop=/root/sbox/hy2-hopping.sh remove

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
}

# Interactive port-range input happens here (OUTSIDE the lock); the durable state
# mutation runs in _enable_hy2hopping_locked under the global lock.
enable_hy2hopping(){
    local start_port end_port
    hint "开启端口跳跃..."
    warning "注意: 端口跳跃范围不要覆盖已经占用的端口，否则会错误！"
    while :; do
        read -p "输入UDP端口范围的起始值(默认50000): " -r start_port
        start_port=${start_port:-50000}
        read -p "输入UDP端口范围的结束值(默认51000): " -r end_port
        end_port=${end_port:-51000}
        if [[ "$start_port" =~ ^[0-9]+$ ]] && [[ "$end_port" =~ ^[0-9]+$ ]] &&
           (( start_port >= 1 && end_port <= 65535 && start_port <= end_port )); then
            break
        fi
        warning "端口范围无效，必须满足 1 <= 起始端口 <= 结束端口 <= 65535。"
    done
    with_client_lock _enable_hy2hopping_locked "$start_port" "$end_port"
}

# L4: the durable /root/sbox/config mutation is serialized under the SAME global
# lock as modify_singbox, so the two can never lose each other's update.
# NONBLOCKING weakness (documented, NOT fixed here): the state write, the systemd
# helper unit and the firewall rules are three separate effects -- the config lock
# serializes only the state mutation and does not make the trio atomic. A crash
# between the state write and `systemctl enable` is handled by the existing
# rollback below (state reset to FALSE). This can never corrupt E3-managed JSON.
_enable_hy2hopping_locked() { # <start_port> <end_port>
    local start_port="$1" end_port="$2"
    set_config_value HY_HOPPING_START "$start_port" || { warning "写入 HY_HOPPING_START 失败"; return 1; }
    set_config_value HY_HOPPING_END "$end_port" || { warning "写入 HY_HOPPING_END 失败"; return 1; }
    set_config_value HY_HOPPING TRUE || { warning "写入 HY_HOPPING 失败"; return 1; }
    install_hy2_hopping_helper

    if systemctl enable --now sing-box-hy2-hopping.service; then
        info "端口跳跃已开启并设置为重启后自动恢复: ${start_port}-${end_port}"
        warning "请同时确认云防火墙和本机防火墙已放行该 UDP 端口范围。"
        return 0
    fi
    systemctl disable --now sing-box-hy2-hopping.service >/dev/null 2>&1 || true
    set_config_value HY_HOPPING FALSE
    remove_hy2_hopping_rules
    rm -f "$HY_HOPPING_SERVICE" "$HY_HOPPING_HELPER"
    systemctl daemon-reload
    error "端口跳跃规则应用失败，已回退为关闭状态"
    return 1
}

# L4: serialize the durable state mutation; the menu/interactive work stays
# outside the lock. The systemd/firewall teardown is intentionally NOT claimed to
# be atomic with the state write (see the L4 note on _enable_hy2hopping_locked).
disable_hy2hopping(){
    with_client_lock _disable_hy2hopping_locked
}

_disable_hy2hopping_locked() {
    echo "正在关闭端口跳跃..."
    if [ -f "$HY_HOPPING_SERVICE" ]; then
        systemctl disable --now sing-box-hy2-hopping.service >/dev/null 2>&1 || true
    fi
    remove_hy2_hopping_rules
    set_config_value HY_HOPPING FALSE || { warning "写入 HY_HOPPING 失败"; return 1; }
    set_config_value HY_HOPPING_START "" || { warning "写入 HY_HOPPING_START 失败"; return 1; }
    set_config_value HY_HOPPING_END "" || { warning "写入 HY_HOPPING_END 失败"; return 1; }
    rm -f "$HY_HOPPING_SERVICE" "$HY_HOPPING_HELPER"
    systemctl daemon-reload
    echo "关闭完成"
    return 0
}

# <<< legacy-config-transaction-hardening <<< ==================================

#--------------------------------
INSTALLATION_MARKERS=(
    /root/sbox/sbconfig_server.json
    /root/sbox/config
    /root/sbox/mianyang.sh
    /usr/bin/mianyang
    /root/sbox/sing-box
    /etc/systemd/system/sing-box.service
    /lib/systemd/system/sing-box.service
    /usr/lib/systemd/system/sing-box.service
)

has_any_installation_marker() {
    local marker
    for marker in "${INSTALLATION_MARKERS[@]}"; do
        if [ -e "$marker" ] || [ -L "$marker" ]; then
            return 0
        fi
    done
    return 1
}

show_installation_markers() {
    local marker service_unit=""
    for marker in \
        /root/sbox/sbconfig_server.json \
        /root/sbox/config \
        /root/sbox/sing-box; do
        if [ -e "$marker" ] || [ -L "$marker" ]; then
            info "存在: $marker"
        else
            warning "缺失: $marker"
        fi
    done

    if [ -x /root/sbox/mianyang.sh ] && { [ -e /usr/bin/mianyang ] || [ -L /usr/bin/mianyang ]; }; then
        info "管理命令: /usr/bin/mianyang"
    else
        warning "管理命令不完整: /usr/bin/mianyang"
    fi

    service_unit=$(systemctl show sing-box -p FragmentPath --value 2>/dev/null || true)
    if [ -z "$service_unit" ] || [ ! -e "$service_unit" ]; then
        for marker in \
            /etc/systemd/system/sing-box.service \
            /lib/systemd/system/sing-box.service \
            /usr/lib/systemd/system/sing-box.service; do
            if [ -e "$marker" ]; then
                service_unit="$marker"
                break
            fi
        done
    fi
    if [ -n "$service_unit" ] && [ -e "$service_unit" ]; then
        info "systemd 服务文件: $service_unit"
    else
        warning "未找到 sing-box.service"
    fi
}

print_with_delay "Reality Hysteria2 二合一脚本" 0.03
echo ""
echo ""

# Any existing marker blocks the automatic fresh-install path. This prevents a
# missing shortcut or service file from causing silent key/config regeneration.
if has_any_installation_marker; then
    if [ ! -f /root/sbox/sbconfig_server.json ] ||
       [ ! -f /root/sbox/config ] ||
       [ ! -x /root/sbox/sing-box ]; then
        warning "检测到不完整或非标准的现有安装。为防止覆盖 Reality/Hysteria2 配置，脚本已停止。"
        show_installation_markers
        error "请先备份并修复缺失文件，不会自动执行全新安装"
    fi

    install_pkgs
    # S0: fail-closed bootstrap repair on every existing install, BEFORE the
    # interactive menu runs. A failing chmod or an unrepairable derived secret
    # file aborts here (see repair_existing_install_security_baseline) -- the
    # menu is never entered, so no management mutation can continue on an
    # unsafe or desynced-credential state.
    repair_existing_install_security_baseline
    # Narrow service.api auth migration for old servers: exact-with-secret and
    # structurally-compliant-but-secret-less states are handled here, BEFORE
    # the menu. Declined and not-applicable paths return 0 and NEVER abort the
    # installer; any approved-migration / rollback / anchor / health failure
    # returns nonzero and aborts the existing-install flow right here -- the
    # menu is never entered on a failed migration (fail-closed).
    maybe_migrate_existing_api_auth
    echo ""
    info "sing-box-reality-hysteria2 已安装"
    show_status
    echo ""
    hint "=======常规配置========="
    hint "请选择选项:"
    echo ""
    info "1. 重新安装"
    info "2. 修改配置"
    info "3. 显示客户端配置和 Linux 安装命令"
    info "4. sing-box基础操作"
    info "5. 启用本地 BBR + 优化 Hysteria2 UDP 缓冲"
    info "6. Hysteria2 端口跳跃"
    info "7. 本机添加任意门中转规则（本机做中转机）"
    info "0. 卸载"
    echo ""
    hint "=======落地机解锁配置======"
    echo ""
    info "8. 落地机任意门解锁（本机做解锁机）"
    info "9. 落地机 SS 解锁（本机做解锁机）"
    info "10. 客户端管理（多设备身份 / legacy 迁移 / 一致性检查）"
    echo ""
    hint "========================="
    echo ""
    read -r -p "请输入对应数字 (0-10): " choice

    case $choice in
      1)
          # L5: refuse BEFORE any destructive mutation when web/E3 management is
          # active (the guard runs before the backup and before uninstall).
          if ! require_management_inactive "重新安装"; then
              exit 1
          fi
          warning "重新安装会生成新的 Reality 密钥、UUID、端口和 Hysteria2 密码。"
          read -r -p "如已确认，请输入 REINSTALL 继续: " reinstall_confirm
          if [ "$reinstall_confirm" != "REINSTALL" ]; then
              warning "输入不匹配，已取消重新安装"
              exit 0
          fi
          backup_current_installation || error "重新安装前备份失败，已停止"
          if ! uninstall_singbox; then
              exit 1
          fi
        ;;
      2)
          modify_singbox
          show_client_configuration
          exit 0
        ;;
      3)  
          show_client_configuration
          exit 0
      ;;	
      4)  
          process_singbox
          exit 0
          ;;
      5)
          enable_bbr
          exit 0
          ;;
      6)
          process_hy2hopping
          exit 0
          ;;
      7)
          process_doko
          exit 0
          ;;
      8)
          process_dokoko
          exit 0
          ;;
      9)
          process_ssko
          exit 0
          ;;
      10)
          client_management_menu
          exit 0
          ;;
      0)
          if ! uninstall_singbox; then
              exit 1
          fi
	        exit 0
          ;;
      *)
          echo "选择错误，退出"
          exit 1
          ;;
	esac
	fi

install_pkgs
mkdir -p "/root/sbox/"

install_singbox
echo ""
echo ""

warning "开始配置VISION_REALITY..."
echo ""
key_pair=$(/root/sbox/sing-box generate reality-keypair)
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
info "生成的公钥为:  $public_key"
info "生成的私钥为:  $private_key"
reality_uuid=$(/root/sbox/sing-box generate uuid)
short_id=$(/root/sbox/sing-box generate rand --hex 8)
info "生成的uuid为:  $reality_uuid"
info "生成的短id为:  $short_id"
echo ""
reality_port=$(generate_port "VISION_REALITY")
info "生成的端口号为: $reality_port"
reality_server_name="itunes.apple.com"
while :; do
    read -p "请输入需要偷取证书的网站，必须支持 TLS 1.3 and HTTP/2 (默认: $reality_server_name): " input_server_name
    reality_server_name=${input_server_name:-$reality_server_name}

    if curl --tlsv1.3 --http2 -sI "https://$reality_server_name" | grep -q "HTTP/2"; then
        break
    else
        echo "域名 $reality_server_name 不支持 TLS 1.3 或 HTTP/2，请重新输入."
    fi
done
info "域名 $reality_server_name 符合."
echo ""
echo ""
# hysteria2
warning "开始配置hysteria2..."
echo ""
hy_password=$(/root/sbox/sing-box generate rand --hex 8)
info "password: $hy_password"
echo ""
hy_port=$(generate_port "HYSTERIA2")
info "生成的端口号为: $hy_port"
read -p "输入自签证书域名 (默认为: bing.com): " hy_server_name
hy_server_name=${hy_server_name:-bing.com}
mkdir -p /root/sbox/self-cert/ && openssl ecparam -genkey -name prime256v1 -out /root/sbox/self-cert/private.key && openssl req -new -x509 -days 36500 -key /root/sbox/self-cert/private.key -out /root/sbox/self-cert/cert.pem -subj "/CN=${hy_server_name}"
info "自签证书生成完成,保存于/root/sbox/self-cert/"
echo ""
echo ""

# S0: service.api transport authentication secret. Generated once at install
# time from a CSPRNG (256 bit); sbconfig_server.json stays its single source
# of truth and /root/sbox/monitor-api.secret is the derived copy for the local
# collector. Never reused from client credentials or admin passwords.
monitor_api_secret="$(generate_api_secret)" || error "无法生成 monitor-api secret（需要可用的 CSPRNG）"
#get ip
server_ip=$(curl -s4m8 ip.sb -k) || server_ip=$(curl -s6m8 ip.sb -k)

#generate config
cat > /root/sbox/config <<EOF
# VPS ip
SERVER_IP='$server_ip'
# Reality
PUBLIC_KEY='$public_key'
# Hysteria2
HY_SERVER_NAME='$hy_server_name'
HY_HOPPING=FALSE
HY_HOPPING_START=
HY_HOPPING_END=
EOF

#generate singbox server config
cat > /root/sbox/sbconfig_server.json << EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "dns": {
    "servers": [
      {
        "tag": "dns-local",
        "type": "local"
      }
    ]
  },
  "route": {
    "rules": [
      {
        "action": "sniff"
      },
      {
        "network": "udp",
        "port": 443,
        "action": "reject"
      }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $reality_port,
      "users": [
        {
          "name": "legacy",
          "uuid": "$reality_uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$reality_server_name",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$reality_server_name",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    },
    {
        "type": "hysteria2",
        "tag": "hy2-in",
        "listen": "::",
        "listen_port": $hy_port,
        "up_mbps": 1000,
        "down_mbps": 1000,
        "users": [
            {
                "name": "legacy",
                "password": "$hy_password"
            }
        ],
        "tls": {
            "enabled": true,
            "alpn": [
                "h3"
            ],
            "certificate_path": "/root/sbox/self-cert/cert.pem",
            "key_path": "/root/sbox/self-cert/private.key"
        }
    }
  ],
  "services": [
    {
      "type": "api",
      "tag": "monitor-api",
      "listen": "127.0.0.1",
      "listen_port": 9091,
      "secret": "$monitor_api_secret"
    }
  ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct",
            "domain_resolver": {
                "server": "dns-local",
                "strategy": "ipv4_only"
            }
        }
    ]
}
EOF

# S0: derived collector secret file, then explicit permission hardening for
# every credential-bearing file this installer just created. Missing optional
# files are skipped; any chmod failure aborts the install (fail-closed).
write_api_secret_file "$monitor_api_secret" || error "无法写入 monitor-api.secret（root:root 0600）"
harden_sensitive_permissions || error "敏感文件权限加固失败，安装已停止"

configure_udp_buffers

cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target
[Service]
User=root
WorkingDirectory=/root/sbox
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity
[Install]
WantedBy=multi-user.target
EOF

if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
    hint "check config profile..."
    systemctl daemon-reload
    systemctl enable sing-box > /dev/null 2>&1
    systemctl start sing-box
    install_shortcut
    show_client_configuration
    warning "输入mianyang,即可打开菜单"
else
    error "配置文件检查失败，启动失败!"
fi
