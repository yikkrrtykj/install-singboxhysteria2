#!/usr/bin/env bash
set -Eeuo pipefail

PROGRAM_NAME="mihomo-gateway-installer"
CONFIG_SOURCE=""
UI_BIND="127.0.0.1:9090"
ASSUME_YES="false"
RESTORE_DIR=""
MIHOMO_VERSION=""
UI_VERSION=""

MIHOMO_BIN="/usr/local/bin/mihomo"
CONFIG_DIR="/etc/mihomo"
CONFIG_FILE="${CONFIG_DIR}/config.yaml"
UI_DIR="${CONFIG_DIR}/ui"
SECRET_FILE="${CONFIG_DIR}/ui-secret"
SERVICE_FILE="/etc/systemd/system/mihomo.service"
SERVICE_OVERRIDE_DIR="/etc/systemd/system/mihomo.service.d"
SYSCTL_FILE="/etc/sysctl.d/99-mihomo-gateway.conf"
RESOLVED_DROPIN="/etc/systemd/resolved.conf.d/90-mihomo-gateway.conf"
RESOLV_CONF="/etc/resolv.conf"
BACKUP_ROOT="/var/backups/mihomo-gateway"
INSTALLER_COPY="/usr/local/sbin/mihomo-gateway-installer"

WORK_DIR=""
BACKUP_DIR=""
CHANGES_STARTED="false"
INSTALL_COMMITTED="false"

MANAGED_PATHS=(
  "$MIHOMO_BIN"
  "$CONFIG_DIR"
  "$SERVICE_FILE"
  "$SERVICE_OVERRIDE_DIR"
  "$SYSCTL_FILE"
  "$RESOLVED_DROPIN"
  "$RESOLV_CONF"
  "$INSTALLER_COPY"
)

info() {
  printf '\033[1;32m[信息]\033[0m %s\n' "$*"
}

warn() {
  printf '\033[1;33m[注意]\033[0m %s\n' "$*" >&2
}

die() {
  printf '\033[1;31m[错误]\033[0m %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
用法：
  sudo bash install-linux-gateway.sh --config /tmp/mihomo_client.yaml [--ui-lan] [--yes]
  sudo mihomo-gateway-installer --restore /var/backups/mihomo-gateway/时间戳

参数：
  --config FILE          服务端生成的 mihomo_client.yaml
  --ui-lan               让 9090 Web UI 监听局域网；默认只监听 127.0.0.1
  --yes                  确认安装并自动启动 TUN 网关
  --mihomo-version TAG   安装指定的 Mihomo 正式版，例如 v1.19.30
  --ui-version TAG       安装指定的 MetaCubeXD 正式版，例如 v1.273.0
  --restore DIR          从脚本创建的备份目录恢复
  -h, --help             显示帮助

脚本只支持使用 systemd 的 Ubuntu/Debian amd64 或 arm64。
HTTP_PROXY、HTTPS_PROXY 及其小写形式会自动被下载命令使用。
EOF
}

while (($# > 0)); do
  case "$1" in
    --config)
      (($# >= 2)) || die "--config 缺少文件路径"
      CONFIG_SOURCE="$2"
      shift 2
      ;;
    --ui-lan)
      UI_BIND="0.0.0.0:9090"
      shift
      ;;
    --yes)
      ASSUME_YES="true"
      shift
      ;;
    --mihomo-version)
      (($# >= 2)) || die "--mihomo-version 缺少版本号"
      MIHOMO_VERSION="$2"
      shift 2
      ;;
    --ui-version)
      (($# >= 2)) || die "--ui-version 缺少版本号"
      UI_VERSION="$2"
      shift 2
      ;;
    --restore)
      (($# >= 2)) || die "--restore 缺少备份目录"
      RESTORE_DIR="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$CONFIG_SOURCE" && -z "$RESTORE_DIR" ]]; then
        CONFIG_SOURCE="$1"
        shift
      else
        die "未知参数: $1"
      fi
      ;;
  esac
done

require_root() {
  [[ ${EUID:-$(id -u)} -eq 0 ]] || die "请使用 root 或 sudo 运行。"
}

check_platform() {
  [[ -d /run/systemd/system ]] || die "没有检测到正在运行的 systemd。"
  command -v systemctl >/dev/null 2>&1 || die "没有找到 systemctl。"
  [[ -r /etc/os-release ]] || die "无法读取 /etc/os-release。"

  # shellcheck disable=SC1091
  . /etc/os-release
  case "${ID:-}:${ID_LIKE:-}" in
    ubuntu:*|debian:*|*:debian*) ;;
    *) die "当前只支持 Ubuntu/Debian，检测到: ${PRETTY_NAME:-未知系统}" ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64) TARGET_ARCH="amd64" ;;
    aarch64|arm64) TARGET_ARCH="arm64" ;;
    *) die "当前只支持 amd64/arm64，检测到: $(uname -m)" ;;
  esac

  [[ -c /dev/net/tun ]] || die "/dev/net/tun 不可用，无法启用透明代理网关。"
  [[ ! -f /root/sbox/sbconfig_server.json ]] || \
    die "检测到 sing-box 服务端配置；不要把客户端网关安装到代理服务端本机。"
}

install_dependencies() {
  info "安装基础依赖（来自系统软件源）……"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y ca-certificates coreutils curl gzip iproute2 jq nftables openssl procps tar
}

github_release_json() {
  local repository="$1"
  local requested_tag="$2"
  local output_file="$3"
  local api_url
  local curl_args=(
    --fail --silent --show-error --location
    --retry 3 --retry-delay 2 --connect-timeout 15
    --proto '=https' --tlsv1.2
    --header 'Accept: application/vnd.github+json'
    --header 'X-GitHub-Api-Version: 2022-11-28'
  )

  if [[ -n "$requested_tag" ]]; then
    api_url="https://api.github.com/repos/${repository}/releases/tags/${requested_tag}"
  else
    api_url="https://api.github.com/repos/${repository}/releases/latest"
  fi

  if [[ -n ${GITHUB_TOKEN:-} ]]; then
    curl_args+=(--header "Authorization: Bearer ${GITHUB_TOKEN}")
  fi
  curl "${curl_args[@]}" --output "$output_file" "$api_url"

  jq -e '.draft == false and .prerelease == false and (.tag_name | type == "string")' \
    "$output_file" >/dev/null || die "${repository} 返回的不是正式版发布信息。"
}

download_verified_asset() {
  local release_file="$1"
  local asset_name="$2"
  local output_file="$3"
  local asset_url asset_digest expected_sha actual_sha

  asset_url="$(jq -er --arg name "$asset_name" '.assets[] | select(.name == $name) | .browser_download_url' "$release_file")" || \
    die "正式版中没有找到资源: $asset_name"
  asset_digest="$(jq -er --arg name "$asset_name" '.assets[] | select(.name == $name) | .digest' "$release_file")" || \
    die "GitHub 没有提供 $asset_name 的摘要，已停止安装。"
  [[ "$asset_digest" == sha256:* ]] || die "$asset_name 的摘要格式不是 SHA-256。"
  expected_sha="${asset_digest#sha256:}"

  info "下载官方资源: $asset_name"
  curl --fail --silent --show-error --location \
    --retry 3 --retry-delay 2 --connect-timeout 15 \
    --proto '=https' --tlsv1.2 \
    --output "$output_file" "$asset_url"

  actual_sha="$(sha256sum "$output_file" | awk '{print $1}')"
  [[ "$actual_sha" == "$expected_sha" ]] || die "$asset_name 的 SHA-256 校验失败。"
  info "$asset_name 完整性校验通过。"
}

listener_lines() {
  local port="$1"
  ss -H -lntup 2>/dev/null | awk -v suffix=":${port}" \
    'length($5) >= length(suffix) && substr($5, length($5) - length(suffix) + 1) == suffix'
}

preflight_processes_and_ports() {
  local service_pid="" pid listener port allowed

  if systemctl is-active --quiet mihomo.service 2>/dev/null; then
    service_pid="$(systemctl show mihomo.service -p MainPID --value 2>/dev/null || true)"
  fi

  while IFS= read -r pid; do
    [[ -z "$pid" ]] && continue
    if [[ -z "$service_pid" || "$pid" != "$service_pid" ]]; then
      die "检测到不属于 mihomo.service 的 Mihomo 进程 PID=$pid，请先人工确认并停止，避免双实例。"
    fi
  done < <(pgrep -x mihomo 2>/dev/null || true)

  for port in 7897 9090 53; do
    while IFS= read -r listener; do
      [[ -z "$listener" ]] && continue
      allowed="false"
      if [[ -n "$service_pid" && "$listener" == *"pid=${service_pid},"* ]]; then
        allowed="true"
      elif [[ "$port" == "53" ]] && systemctl is-active --quiet systemd-resolved.service 2>/dev/null && \
           { [[ "$listener" == *"systemd-resolve"* ]] || [[ "$listener" == *"127.0.0.53"* ]]; }; then
        allowed="true"
      fi
      [[ "$allowed" == "true" ]] || die "端口 $port 已被其他程序占用: $listener"
    done < <(listener_lines "$port")
  done
}

create_backup() {
  local timestamp path destination index state
  timestamp="$(date +%Y%m%d-%H%M%S)"
  install -d -m 0700 "$BACKUP_ROOT"
  BACKUP_DIR="$(mktemp -d "${BACKUP_ROOT}/${timestamp}.XXXXXX")"
  chmod 0700 "$BACKUP_DIR"
  install -d -m 0700 "$BACKUP_DIR/rootfs" "$BACKUP_DIR/manifest"

  for index in "${!MANAGED_PATHS[@]}"; do
    path="${MANAGED_PATHS[$index]}"
    destination="${BACKUP_DIR}/rootfs${path}"
    if [[ -e "$path" || -L "$path" ]]; then
      install -d -m 0700 "$(dirname "$destination")"
      cp -a -- "$path" "$destination"
      state="present"
    else
      state="absent"
    fi
    printf '%s\n' "$state" > "${BACKUP_DIR}/manifest/${index}"
  done

  {
    printf 'service_active=%s\n' "$(systemctl is-active mihomo.service 2>/dev/null || true)"
    printf 'service_enabled=%s\n' "$(systemctl is-enabled mihomo.service 2>/dev/null || true)"
    printf 'resolved_active=%s\n' "$(systemctl is-active systemd-resolved.service 2>/dev/null || true)"
    printf 'created_at=%s\n' "$(date --iso-8601=seconds)"
  } > "${BACKUP_DIR}/state"
  info "备份完成: $BACKUP_DIR"
}

remove_managed_path() {
  local path="$1"
  case "$path" in
    "$CONFIG_DIR"|"$SERVICE_OVERRIDE_DIR") rm -rf -- "$path" ;;
    "$MIHOMO_BIN"|"$SERVICE_FILE"|"$SYSCTL_FILE"|"$RESOLVED_DROPIN"|"$RESOLV_CONF"|"$INSTALLER_COPY") rm -f -- "$path" ;;
    *) die "拒绝删除非白名单路径: $path" ;;
  esac
}

state_value() {
  local backup="$1"
  local key="$2"
  awk -F= -v wanted="$key" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' "$backup/state"
}

restore_backup() {
  local backup="$1"
  local index path marker source service_active service_enabled resolved_active

  [[ -d "$backup/manifest" && -d "$backup/rootfs" && -f "$backup/state" ]] || \
    die "不是有效的 Mihomo 网关备份目录: $backup"

  warn "正在从备份恢复: $backup"
  systemctl stop mihomo.service 2>/dev/null || true

  for index in "${!MANAGED_PATHS[@]}"; do
    marker="$(<"${backup}/manifest/${index}")"
    path="${MANAGED_PATHS[$index]}"
    source="${backup}/rootfs${path}"
    remove_managed_path "$path"
    if [[ "$marker" == "present" ]]; then
      [[ -e "$source" || -L "$source" ]] || die "备份内容缺失: $source"
      install -d -m 0755 "$(dirname "$path")"
      cp -a -- "$source" "$path"
    elif [[ "$marker" != "absent" ]]; then
      die "备份清单损坏: ${backup}/manifest/${index}"
    fi
  done

  systemctl daemon-reload
  resolved_active="$(state_value "$backup" resolved_active)"
  if [[ "$resolved_active" == "active" ]]; then
    systemctl restart systemd-resolved.service
  fi
  sysctl --system >/dev/null 2>&1 || true

  service_enabled="$(state_value "$backup" service_enabled)"
  if [[ "$service_enabled" == "enabled" ]]; then
    systemctl enable mihomo.service >/dev/null 2>&1 || true
  else
    systemctl disable mihomo.service >/dev/null 2>&1 || true
  fi
  service_active="$(state_value "$backup" service_active)"
  if [[ "$service_active" == "active" ]]; then
    systemctl start mihomo.service
  fi
  info "恢复完成。"
}

cleanup_and_rollback() {
  local status=$?
  trap - EXIT INT TERM

  if ((status != 0)) && [[ "$CHANGES_STARTED" == "true" && "$INSTALL_COMMITTED" != "true" && -n "$BACKUP_DIR" ]]; then
    set +e
    ( set -e; restore_backup "$BACKUP_DIR" )
    local restore_status=$?
    if ((restore_status == 0)); then
      warn "安装失败，已自动恢复原状态。"
    else
      warn "自动恢复没有完整成功，请保留当前终端并人工执行: $PROGRAM_NAME --restore $BACKUP_DIR"
    fi
    set -e
  fi

  if [[ -n "$WORK_DIR" && "$WORK_DIR" == /tmp/mihomo-gateway.* && -d "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR" || true
  fi
  exit "$status"
}

confirm_install() {
  warn "安装会接管本机默认路由和 DNS；远程服务器请保留第二个 SSH/控制台会话。"
  if [[ "$UI_BIND" == "0.0.0.0:9090" ]]; then
    warn "9090 将监听局域网。请只对可信内网放行，不要暴露到公网。"
  fi
  if [[ "$ASSUME_YES" == "true" ]]; then
    return
  fi
  [[ -t 0 ]] || die "非交互运行必须显式添加 --yes。"
  read -r -p "确认继续安装并启动 Mihomo TUN 网关？[y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || die "用户取消安装。"
}

prepare_release_files() {
  local mihomo_release="$WORK_DIR/mihomo-release.json"
  local ui_release="$WORK_DIR/ui-release.json"
  local geoip_release="$WORK_DIR/geoip-release.json"
  local mihomo_tag ui_tag geoip_tag mihomo_asset

  github_release_json "MetaCubeX/mihomo" "$MIHOMO_VERSION" "$mihomo_release"
  mihomo_tag="$(jq -er '.tag_name' "$mihomo_release")"
  mihomo_asset="mihomo-linux-${TARGET_ARCH}-${mihomo_tag}.gz"
  download_verified_asset "$mihomo_release" "$mihomo_asset" "$WORK_DIR/mihomo.gz"
  gzip -dc "$WORK_DIR/mihomo.gz" > "$WORK_DIR/mihomo"
  chmod 0755 "$WORK_DIR/mihomo"
  "$WORK_DIR/mihomo" -v

  github_release_json "MetaCubeX/metacubexd" "$UI_VERSION" "$ui_release"
  ui_tag="$(jq -er '.tag_name' "$ui_release")"
  download_verified_asset "$ui_release" "compressed-dist.tgz" "$WORK_DIR/metacubexd.tgz"
  install -d -m 0755 "$WORK_DIR/ui"
  tar -xzf "$WORK_DIR/metacubexd.tgz" -C "$WORK_DIR/ui"
  [[ -f "$WORK_DIR/ui/index.html" ]] || die "MetaCubeXD 压缩包结构不符合预期。"

  github_release_json "MetaCubeX/meta-rules-dat" "" "$geoip_release"
  geoip_tag="$(jq -er '.tag_name' "$geoip_release")"
  download_verified_asset "$geoip_release" "geoip.metadb" "$WORK_DIR/geoip.metadb"

  printf '%s\n' "$mihomo_tag" > "$WORK_DIR/mihomo-version"
  printf '%s\n' "$ui_tag" > "$WORK_DIR/ui-version"
  printf '%s\n' "$geoip_tag" > "$WORK_DIR/geoip-version"
}

prepare_config_and_units() {
  local secret stripped_config check_dir

  [[ -f "$CONFIG_SOURCE" ]] || die "客户端配置不存在: $CONFIG_SOURCE"
  [[ -s "$CONFIG_SOURCE" ]] || die "客户端配置是空文件: $CONFIG_SOURCE"
  grep -Eq '^mixed-port:[[:space:]]*7897[[:space:]]*$' "$CONFIG_SOURCE" || \
    die "配置不是本仓库生成的新 Mihomo 配置：缺少 mixed-port: 7897。"
  grep -Eq '^[[:space:]]*- name:[[:space:]]*Reality[[:space:]]*$' "$CONFIG_SOURCE" || \
    die "配置中没有找到 Reality 节点。"
  grep -Eq '^tun:[[:space:]]*$' "$CONFIG_SOURCE" || die "配置中没有找到 TUN 设置。"

  if [[ -s "$SECRET_FILE" ]]; then
    secret="$(head -n 1 "$SECRET_FILE")"
    [[ "$secret" =~ ^[A-Za-z0-9_-]{32,128}$ ]] || secret="$(openssl rand -hex 32)"
  else
    secret="$(openssl rand -hex 32)"
  fi
  printf '%s\n' "$secret" > "$WORK_DIR/ui-secret"
  chmod 0600 "$WORK_DIR/ui-secret"

  stripped_config="$WORK_DIR/config-stripped.yaml"
  awk '!/^(external-controller|external-ui|external-ui-url|secret):[[:space:]]*/' \
    "$CONFIG_SOURCE" > "$stripped_config"
  {
    printf 'external-controller: "%s"\n' "$UI_BIND"
    printf 'external-ui: "%s"\n' "$UI_DIR"
    printf 'secret: "%s"\n' "$secret"
    cat "$stripped_config"
  } > "$WORK_DIR/config.yaml"
  chmod 0600 "$WORK_DIR/config.yaml"

  check_dir="$WORK_DIR/config-check"
  install -d -m 0700 "$check_dir"
  cp "$CONFIG_SOURCE" "$check_dir/config.yaml"
  cp "$WORK_DIR/geoip.metadb" "$check_dir/geoip.metadb"
  "$WORK_DIR/mihomo" -t -d "$check_dir"

  cat > "$WORK_DIR/mihomo.service" <<'EOF'
[Unit]
Description=Mihomo Transparent Proxy Gateway
Documentation=https://wiki.metacubex.one/
Wants=network-online.target
After=network-online.target systemd-resolved.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=1048576
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

  cat > "$WORK_DIR/sysctl.conf" <<'EOF'
# Managed by mihomo-gateway-installer
net.ipv4.ip_forward = 1
net.ipv4.conf.all.src_valid_mark = 1
net.ipv4.conf.all.rp_filter = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv6.conf.all.forwarding = 1
EOF

  cat > "$WORK_DIR/resolved.conf" <<'EOF'
# Managed by mihomo-gateway-installer
[Resolve]
DNSStubListener=no
EOF

  cat > "$WORK_DIR/resolv.conf" <<'EOF'
# Managed by mihomo-gateway-installer
nameserver 127.0.0.1
options edns0 trust-ad
EOF
}

install_transaction() {
  local resolved_was_active="false"
  systemctl is-active --quiet systemd-resolved.service 2>/dev/null && resolved_was_active="true"

  create_backup
  CHANGES_STARTED="true"

  systemctl stop mihomo.service 2>/dev/null || true
  if pgrep -x mihomo >/dev/null 2>&1; then
    die "停止 mihomo.service 后仍有 Mihomo 进程，拒绝继续覆盖。"
  fi

  remove_managed_path "$CONFIG_DIR"
  remove_managed_path "$SERVICE_OVERRIDE_DIR"
  install -d -m 0755 "$CONFIG_DIR" "$UI_DIR" /etc/systemd/resolved.conf.d /usr/local/sbin
  install -m 0755 "$WORK_DIR/mihomo" "$MIHOMO_BIN"
  install -m 0600 "$WORK_DIR/config.yaml" "$CONFIG_FILE"
  install -m 0600 "$WORK_DIR/ui-secret" "$SECRET_FILE"
  install -m 0644 "$WORK_DIR/geoip.metadb" "$CONFIG_DIR/geoip.metadb"
  cp -a "$WORK_DIR/ui/." "$UI_DIR/"
  chmod -R a+rX,u+w,go-w "$UI_DIR"
  install -m 0644 "$WORK_DIR/mihomo.service" "$SERVICE_FILE"
  install -m 0644 "$WORK_DIR/sysctl.conf" "$SYSCTL_FILE"
  install -m 0644 "$WORK_DIR/resolved.conf" "$RESOLVED_DROPIN"

  if [[ -r "${BASH_SOURCE[0]}" ]]; then
    if [[ ! -e "$INSTALLER_COPY" || ! "${BASH_SOURCE[0]}" -ef "$INSTALLER_COPY" ]]; then
      install -m 0755 "${BASH_SOURCE[0]}" "$INSTALLER_COPY"
    fi
  else
    warn "无法保存安装器副本；恢复时需要重新下载本脚本。"
  fi

  systemctl daemon-reload
  sysctl -p "$SYSCTL_FILE" >/dev/null
  "$MIHOMO_BIN" -t -d "$CONFIG_DIR"

  if [[ -L "$RESOLV_CONF" ]]; then
    rm -f -- "$RESOLV_CONF"
  fi
  install -m 0644 "$WORK_DIR/resolv.conf" "$RESOLV_CONF"
  if [[ "$resolved_was_active" == "true" ]]; then
    systemctl restart systemd-resolved.service
  fi
  systemctl enable --now mihomo.service

  for _ in {1..15}; do
    if systemctl is-active --quiet mihomo.service && \
       curl --fail --silent --show-error --max-time 2 \
         --header "Authorization: Bearer $(<"$SECRET_FILE")" \
         "http://127.0.0.1:9090/version" >/dev/null; then
      break
    fi
    sleep 1
  done
  systemctl is-active --quiet mihomo.service || die "mihomo.service 启动失败。"
  curl --fail --silent --show-error --max-time 3 \
    --header "Authorization: Bearer $(<"$SECRET_FILE")" \
    "http://127.0.0.1:9090/version" >/dev/null || die "9090 控制接口检查失败。"
  curl --fail --silent --show-error --max-time 3 \
    "http://127.0.0.1:9090/ui/" >/dev/null || die "MetaCubeXD 页面检查失败。"

  INSTALL_COMMITTED="true"
}

print_result() {
  local gateway_addresses
  gateway_addresses="$(hostname -I 2>/dev/null | xargs || true)"
  cat <<EOF

安装完成
--------
Mihomo: $(<"$WORK_DIR/mihomo-version")
MetaCubeXD: $(<"$WORK_DIR/ui-version")
GeoIP 数据: $(<"$WORK_DIR/geoip-version")
配置: $CONFIG_FILE
Web UI 密钥: $SECRET_FILE
备份: $BACKUP_DIR
网关地址: ${gateway_addresses:-请使用 ip address 查看}

Web UI:
  本机/SSH 隧道: http://127.0.0.1:9090/ui/
EOF
  if [[ "$UI_BIND" == "0.0.0.0:9090" ]]; then
    printf '  局域网: http://<这台网关的局域网IP>:9090/ui/\n'
  fi
  cat <<EOF

查看密钥:
  sudo cat $SECRET_FILE

状态与日志:
  systemctl status mihomo --no-pager
  journalctl -u mihomo -n 100 --no-pager

恢复本次安装前状态:
  sudo $PROGRAM_NAME --restore $BACKUP_DIR

客户端若把这台机器作为局域网网关，请把默认网关和 DNS 都设置为这台机器的局域网 IP。
9090 和 7897 只应对可信内网开放，不要直接暴露到公网。
EOF
}

main() {
  require_root

  if [[ -n "$RESTORE_DIR" ]]; then
    command -v systemctl >/dev/null 2>&1 || die "没有找到 systemctl，无法恢复服务状态。"
    restore_backup "$RESTORE_DIR"
    exit 0
  fi

  check_platform
  [[ -n "$CONFIG_SOURCE" ]] || { usage; die "必须通过 --config 指定 mihomo_client.yaml。"; }
  confirm_install
  install_dependencies

  WORK_DIR="$(mktemp -d /tmp/mihomo-gateway.XXXXXX)"
  trap cleanup_and_rollback EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  prepare_release_files
  prepare_config_and_units
  preflight_processes_and_ports
  install_transaction
  print_result
}

main "$@"
