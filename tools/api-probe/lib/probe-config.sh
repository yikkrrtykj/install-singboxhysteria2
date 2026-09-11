#!/usr/bin/env bash
# Generation of all probe-side material: keys, users, certificates, the probe
# config and the throwaway client configs.
#
# Everything lands in PROBE_ROOT. Production keys, certificates, ports, users and
# bandwidth parameters are never read for reuse and never written.

probe_listen_addr() {
  if [ "${EXPOSE:-0}" = "1" ]; then printf '::'; else printf '127.0.0.1'; fi
}

# A free-port check cannot catch a collision with a production port while the
# production service is stopped, and the generated production ports can randomly
# land on 18443/18444, so compare against the real config instead.
require_no_production_port_collision() {
  local prod_ports p
  prod_ports="$(python3 "$LIB_DIR/analyze.py" prod-ports "$PROD_CONFIG" 2>/dev/null || true)"
  if [ -z "$prod_ports" ]; then
    warn "无法读取生产 inbound 端口（$PROD_CONFIG），请自行确认 probe 端口不与生产冲突"
  else
    for p in "$REALITY_PORT" "$HY2_PORT" "$CLASH_PORT" "$SINK_PORT" \
             "$SOCKS_AR" "$SOCKS_AH" "$SOCKS_BR" "$SOCKS_BH"; do
      case " $prod_ports " in
        *" $p "*) die "端口 $p 与生产 inbound 端口冲突（生产: $prod_ports），请用参数换端口" ;;
      esac
    done
    log "已确认 probe 端口与生产 inbound 端口不冲突（生产: $prod_ports）"
  fi

  local hop hop_s hop_e
  hop="$(sed -n 's/^HY_HOPPING=//p' "$PROD_STATE" 2>/dev/null | tail -n1 | tr -d "'\"")"
  hop_s="$(sed -n 's/^HY_HOPPING_START=//p' "$PROD_STATE" 2>/dev/null | tail -n1 | tr -d "'\"")"
  hop_e="$(sed -n 's/^HY_HOPPING_END=//p' "$PROD_STATE" 2>/dev/null | tail -n1 | tr -d "'\"")"
  if [ "$hop" = "TRUE" ] && is_num "$hop_s" && is_num "$hop_e"; then
    if [ "$HY2_PORT" -ge "$hop_s" ] && [ "$HY2_PORT" -le "$hop_e" ]; then
      die "probe HY2 端口 $HY2_PORT 落在生产端口跳跃区间 $hop_s-$hop_e 内，会收到非本探针流量，请换端口"
    fi
    log "生产端口跳跃为开启状态（$hop_s-$hop_e），probe HY2 端口 $HY2_PORT 不在该区间"
  fi
}

gen_material() {
  mkdir -p "$CERTS_DIR"
  chmod 0700 "$PROBE_ROOT" "$CERTS_DIR"

  if [ ! -s "$SECRET_FILE" ]; then
    rand_hex 16 > "$SECRET_FILE"
    chmod 0600 "$SECRET_FILE"
  fi

  if [ ! -s "$KEYS_FILE" ]; then
    local kp priv pub uuid sid pw_a pw_b cn KEYS_TMP
    kp="$("$PROD_BIN" generate reality-keypair)"
    priv="$(printf '%s\n' "$kp" | awk -F': *' '/PrivateKey/{print $2}')"
    pub="$(printf '%s\n' "$kp" | awk -F': *' '/PublicKey/{print $2}')"
    uuid="$("$PROD_BIN" generate uuid)"
    sid="$("$PROD_BIN" generate rand --hex 8)"
    pw_a="$(rand_hex 16)"
    pw_b="$(rand_hex 16)"
    cn="probe-${RANDOM}.invalid"
    KEYS_TMP=$(mktemp)
    printf '{\n  "reality_private_key": "%s",\n  "reality_public_key": "%s",\n  "reality_uuid": "%s",\n  "reality_short_id": "%s",\n  "hy2_password_a": "%s",\n  "hy2_password_b": "%s",\n  "cert_cn": "%s"\n}\n' \
      "$priv" "$pub" "$uuid" "$sid" "$pw_a" "$pw_b" "$cn" > "$KEYS_TMP"
    [ -s "$KEYS_TMP" ] || die "生成 probe 密钥材料失败"
    install -m 0600 "$KEYS_TMP" "$KEYS_FILE"
    rm -f "$KEYS_TMP"
    ok "已生成独立 probe 密钥材料 ($KEYS_FILE)"
  else
    log "复用已有 probe 密钥材料 ($KEYS_FILE)"
  fi

  if [ ! -s "$CERTS_DIR/private.key" ] || [ ! -s "$CERTS_DIR/cert.pem" ]; then
    openssl ecparam -genkey -name prime256v1 -out "$CERTS_DIR/private.key" >/dev/null 2>&1 \
      || die "生成 probe 私钥失败"
    openssl req -new -x509 -days 30 -key "$CERTS_DIR/private.key" \
      -out "$CERTS_DIR/cert.pem" -subj "/CN=$(getkey cert_cn)" >/dev/null 2>&1 \
      || die "生成 probe 自签证书失败（独立证书，不读取生产证书）"
    chmod 0600 "$CERTS_DIR/private.key"
    ok "已生成独立 probe 自签证书（30 天，仅用于本探针）"
  else
    log "复用已有 probe 证书"
  fi
}

write_probe_config() {
  local listen priv uuid sid pw_a pw_b
  listen="$(probe_listen_addr)"
  priv="$(getkey reality_private_key)"
  uuid="$(getkey reality_uuid)"
  sid="$(getkey reality_short_id)"
  pw_a="$(getkey hy2_password_a)"
  pw_b="$(getkey hy2_password_b)"
  [ -n "$priv" ] && [ -n "$pw_a" ] || die "probe 密钥材料不完整，请先删除 $KEYS_FILE 重新生成"

  cat > "$PROBE_CONFIG" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "route": {
    "rules": [
      { "action": "sniff" },
      { "network": "udp", "port": 443, "action": "reject" }
    ]
  },
  "inbounds": [
    {
      "type": "vless",
      "tag": "$REALITY_TAG",
      "listen": "$listen",
      "listen_port": $REALITY_PORT,
      "users": [
        { "name": "$USER_A", "uuid": "$uuid", "flow": "xtls-rprx-vision" },
        { "name": "$USER_B", "uuid": "$uuid", "flow": "xtls-rprx-vision" }
      ],
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "reality": {
          "enabled": true,
          "handshake": { "server": "itunes.apple.com", "server_port": 443 },
          "private_key": "$priv",
          "short_id": ["$sid"]
        }
      }
    },
    {
      "type": "hysteria2",
      "tag": "$HY2_TAG",
      "listen": "$listen",
      "listen_port": $HY2_PORT,
      "up_mbps": 1000,
      "down_mbps": 1000,
      "users": [
        { "name": "$USER_A", "password": "$pw_a" },
        { "name": "$USER_B", "password": "$pw_b" }
      ],
      "tls": {
        "enabled": true,
        "alpn": ["h3"],
        "certificate_path": "$CERTS_DIR/cert.pem",
        "key_path": "$CERTS_DIR/private.key"
      }
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:$CLASH_PORT",
      "secret": "$(api_secret)",
      "default_mode": "rule"
    }
  }
}
EOF
  chmod 0600 "$PROBE_CONFIG"
  [ "$(python3 -c 'import json,sys;json.load(open(sys.argv[1]))' "$PROBE_CONFIG" >/dev/null 2>&1; echo $?)" = "0" ] \
    || die "生成的 $PROBE_CONFIG 不是合法 JSON"
  ok "已生成 $PROBE_CONFIG (listen=$listen, reality=$REALITY_PORT, hy2=$HY2_PORT, clash=127.0.0.1:$CLASH_PORT)"
}

# One client config per (probe user x protocol) so each curl run maps to exactly
# one credential with no routing ambiguity.
write_one_client() {
  local name=$1 socks=$2 proto=$3 user=$4 server=$5 outfile="$PROBE_ROOT/$1.json"
  local pub uuid sid pw
  pub="$(getkey reality_public_key)"; uuid="$(getkey reality_uuid)"; sid="$(getkey reality_short_id)"
  if [ "$proto" = "reality" ]; then
    cat > "$outfile" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": $socks }
  ],
  "outbounds": [
    {
      "type": "vless",
      "tag": "reality-out",
      "server": "$server",
      "server_port": $REALITY_PORT,
      "uuid": "$uuid",
      "flow": "xtls-rprx-vision",
      "tls": {
        "enabled": true,
        "server_name": "itunes.apple.com",
        "utls": { "enabled": true, "fingerprint": "chrome" },
        "reality": { "enabled": true, "public_key": "$pub", "short_id": "$sid" }
      }
    }
  ]
}
EOF
  else
    if [ "$user" = "$USER_A" ]; then pw="$(getkey hy2_password_a)"; else pw="$(getkey hy2_password_b)"; fi
    cat > "$outfile" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": $socks }
  ],
  "outbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-out",
      "server": "$server",
      "server_port": $HY2_PORT,
      "password": "$pw",
      "up_mbps": 300,
      "down_mbps": 300,
      "tls": { "enabled": true, "insecure": true, "alpn": ["h3"] }
    }
  ]
}
EOF
  fi
  chmod 0600 "$outfile"
}

write_client_configs() {
  write_one_client client-a-reality "$SOCKS_AR" reality "$USER_A" 127.0.0.1
  write_one_client client-a-hy2    "$SOCKS_AH" hy2     "$USER_A" 127.0.0.1
  write_one_client client-b-reality "$SOCKS_BR" reality "$USER_B" 127.0.0.1
  write_one_client client-b-hy2    "$SOCKS_BH" hy2     "$USER_B" 127.0.0.1
  ok "已生成 4 个本机探针客户端配置 (socks $SOCKS_AR/$SOCKS_AH/$SOCKS_BR/$SOCKS_BH)"
}

write_external_client_configs() {
  local ip="${PUBLIC_IP:-}"
  if [ -z "$ip" ]; then
    ip="$(python3 "$LIB_DIR/analyze.py" prod-server-ip "$PROD_STATE" 2>/dev/null || true)"
  fi
  if [ -z "$ip" ]; then
    warn "无法确定公网 IP：未提供 --public-ip，且从 $PROD_STATE 读取 SERVER_IP 失败；跳过外部客户端配置"
    return 0
  fi
  write_one_client client-a-reality-external "$SOCKS_AR" reality "$USER_A" "$ip"
  write_one_client client-a-hy2-external    "$SOCKS_AH" hy2     "$USER_A" "$ip"
  write_one_client client-b-reality-external "$SOCKS_BR" reality "$USER_B" "$ip"
  write_one_client client-b-hy2-external    "$SOCKS_BH" hy2     "$USER_B" "$ip"
  ok "已生成外部客户端配置（server=$ip，供另一台设备手动执行）"
  printf '%s\n' "$ip" > "$PROBE_ROOT/external-ip.txt"
}

check_config() {
  local f=$1 out rc
  out="$("$PROD_BIN" check -c "$f" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then
    err "sing-box check 失败: $f"
    printf '%s\n' "$out" >&2
    return 1
  fi
  if [ -n "$out" ]; then
    warn "check 通过但输出了以下内容（请人工确认是否有 deprecated 提示）: $f"
    printf '%s\n' "$out" >&2
  fi
  return 0
}

check_all_configs() {
  mkdir -p "$EVID_DIR"
  "$PROD_BIN" check -c "$PROBE_CONFIG" > "$EVID_DIR/05-probe-check.txt" 2>&1 \
    || { err "probe 配置检查失败，禁止启动（详见 $EVID_DIR/05-probe-check.txt）"; cat "$EVID_DIR/05-probe-check.txt" >&2; return 1; }
  if [ -s "$EVID_DIR/05-probe-check.txt" ]; then
    warn "probe check 有输出，已保存到 $EVID_DIR/05-probe-check.txt"
  fi
  local c
  for c in "$PROBE_ROOT"/client-*.json; do
    [ -e "$c" ] || continue
    check_config "$c" || { err "客户端配置检查失败: $c"; return 1; }
  done
  ok "全部 probe 配置通过 sing-box check"
}

prepare_all() {
  log "== prepare: 只写入 $PROBE_ROOT，不触碰生产 =="
  require_root
  require_probe_root_sane
  require_prereqs
  require_prod_bin
  local v; v="$(prod_version)"
  log "生产 sing-box 版本（基线，不假设固定版本）: $v"
  if [ "$v" != "" ] && printf '%s' "$v" | grep -qiE 'unknown command|error'; then
    warn "读取版本输出异常，请人工确认: $v"
  fi

  require_free_port "$REALITY_PORT" "Reality"
  require_free_port "$HY2_PORT" "HY2"
  require_free_port "$CLASH_PORT" "Clash API"
  require_free_port "$SINK_PORT" "本机 sink"
  require_free_port "$SOCKS_AR" "socks a/reality"
  require_free_port "$SOCKS_AH" "socks a/hy2"
  require_free_port "$SOCKS_BR" "socks b/reality"
  require_free_port "$SOCKS_BH" "socks b/hy2"

  require_no_production_port_collision

  mkdir -p "$PROBE_ROOT" "$RUN_DIR" "$EVID_DIR"
  chmod 0700 "$PROBE_ROOT"

  gen_material
  write_probe_config
  write_client_configs
  if [ "${EXPOSE:-0}" = "1" ]; then
    write_external_client_configs
  fi
  check_all_configs || die "配置检查未通过，未启动任何进程"
  ok "prepare 完成（未启动任何进程）"
}
