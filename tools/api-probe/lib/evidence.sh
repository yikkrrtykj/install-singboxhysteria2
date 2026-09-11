#!/usr/bin/env bash
# Runtime orchestration and evidence collection for the Phase A probe.
#
# Rules: the probe runs as an ordinary detached process (no systemd unit, so
# nothing survives a reboot and nothing can be enabled by accident). Only pids
# whose cmdline references PROBE_ROOT are ever signalled; curl children are
# tracked as shell children, never through pidfiles.

PROBE_PIDS=()

ev_meta() {
  mkdir -p "$EVID_DIR"
  python3 "$LIB_DIR/analyze.py" write-meta --out "$EVID_DIR/meta.json" \
    --probe-root "$PROBE_ROOT" --production-version "$(prod_version)" \
    --expose "$EXPOSE" --reality-port "$REALITY_PORT" --hy2-port "$HY2_PORT" \
    --clash-api "127.0.0.1:$CLASH_PORT" --reality-tag "$REALITY_TAG" --hy2-tag "$HY2_TAG" \
    --user-a "$USER_A" --user-b "$USER_B" \
    --payload-bytes "$PAYLOAD_BYTES" --transfer-rate "$TRANSFER_RATE" \
    || warn "写入 $EVID_DIR/meta.json 失败，分析器将使用默认期望值"
}

record_production_baseline() {
  mkdir -p "$EVID_DIR"
  {
    printf 'version: %s\n' "$(prod_version)"
    printf 'service_state: %s\n' "$(prod_service_state)"
    printf 'main_pid: %s\n' "$(prod_main_pid)"
    printf 'sha256 %s: %s\n' "$PROD_CONFIG" "$(prod_file_hash "$PROD_CONFIG")"
    printf 'sha256 %s: %s\n' "$PROD_STATE" "$(prod_file_hash "$PROD_STATE")"
    printf 'sha256 %s: %s\n' "$PROD_BIN" "$(prod_file_hash "$PROD_BIN")"
    printf 'hy_hopping(sed): %s\n' "$(sed -n 's/^HY_HOPPING=//p' "$PROD_STATE" 2>/dev/null | tail -n1)"
    printf 'listening_ports:\n'
    ss -H -lntu 2>/dev/null | awk '{print "  " $4}' | sort -u
  } > "$EVID_DIR/00-production-before.txt" 2>&1
  ok "已记录生产基线 ($EVID_DIR/00-production-before.txt)"
}

assert_production_unchanged() {
  local before="$EVID_DIR/00-production-before.txt" after="$EVID_DIR/90-production-after.txt"
  {
    printf 'version: %s\n' "$(prod_version)"
    printf 'service_state: %s\n' "$(prod_service_state)"
    printf 'main_pid: %s\n' "$(prod_main_pid)"
    printf 'sha256 %s: %s\n' "$PROD_CONFIG" "$(prod_file_hash "$PROD_CONFIG")"
    printf 'sha256 %s: %s\n' "$PROD_STATE" "$(prod_file_hash "$PROD_STATE")"
    printf 'sha256 %s: %s\n' "$PROD_BIN" "$(prod_file_hash "$PROD_BIN")"
    printf 'hy_hopping(sed): %s\n' "$(sed -n 's/^HY_HOPPING=//p' "$PROD_STATE" 2>/dev/null | tail -n1)"
    printf 'listening_ports:\n'
    ss -H -lntu 2>/dev/null | awk '{print "  " $4}' | sort -u
  } > "$after" 2>&1
  local changed=0 line
  while IFS= read -r line; do
    case "$line" in
      listening_ports:*|"  "*) continue ;;
    esac
    grep -qxF "$line" "$after" || { warn "生产状态发生变化: $line"; changed=1; }
  done < "$before"
  if [ "$changed" -eq 0 ]; then
    ok "生产配置/版本未发生变化（config、sbconfig_server.json、二进制 sha256 一致）"
  else
    err "检测到生产状态变化，请人工检查 $before 与 $after"
  fi
}

# ------------------------------------------------------------------- process ---

stop_all_probe_procs() {
  local i
  for i in ${PROBE_PIDS[@]+"${PROBE_PIDS[@]}"}; do stop_probe_proc "$i"; done
}

stop_extra_procs() {
  stop_probe_proc client-a-reality
  stop_probe_proc client-a-hy2
  stop_probe_proc client-b-reality
  stop_probe_proc client-b-hy2
  stop_probe_proc sink
  stop_probe_proc probe
}

start_probe() {
  log "启动独立 probe 实例（不影响 $PROD_SERVICE）"
  : > "$PROBE_LOG"
  start_detached probe "$PROBE_LOG" "$PROD_BIN" run -c "$PROBE_CONFIG" >/dev/null
  PROBE_PIDS+=(probe)
  ensure_detached_pid probe "$PROBE_CONFIG" || warn "无法确认 probe 的存活 pid，cleanup 可能找不到它"
  if ! wait_for "clash api" 40 api_ready; then
    err "probe 的 Clash API (127.0.0.1:$CLASH_PORT) 未在 20 秒内就绪"
    tail -n 40 "$PROBE_LOG" >&2 2>/dev/null || true
    die "probe 启动失败（生产实例未被触碰）"
  fi
  ok "probe 已就绪（pid $(read_pid probe), clash api 127.0.0.1:$CLASH_PORT, log $PROBE_LOG）"
}

start_sink() {
  if [ ! -s "$PROBE_ROOT/sink.py" ]; then
    [ -s "$LIB_DIR/sink.py" ] || die "缺少 lib/sink.py"
    install -m 0700 "$LIB_DIR/sink.py" "$PROBE_ROOT/sink.py"
  fi
  truncate -s "$PAYLOAD_BYTES" "$PAYLOAD_FILE" 2>/dev/null \
    || head -c "$PAYLOAD_BYTES" /dev/zero > "$PAYLOAD_FILE"
  truncate -s "$(( PAYLOAD_BYTES / 2 ))" "$PAYLOAD_HALF_FILE" 2>/dev/null \
    || head -c "$(( PAYLOAD_BYTES / 2 ))" /dev/zero > "$PAYLOAD_HALF_FILE"
  start_detached sink "$PROBE_ROOT/sink.log" python3 "$PROBE_ROOT/sink.py" --port "$SINK_PORT" --bytes "$PAYLOAD_BYTES" >/dev/null
  PROBE_PIDS+=(sink)
  ensure_detached_pid sink "$PROBE_ROOT/sink.py" || warn "无法确认 sink 的存活 pid"
  wait_for "sink" 20 port_in_use_after_start "$SINK_PORT" || die "本机 sink 未启动"
  ok "本机 sink 已就绪 (127.0.0.1:$SINK_PORT, pid $(read_pid sink), 负载 ${PAYLOAD_BYTES}B 只在本机流转)"
}

port_in_use_after_start() { port_in_use "$1"; }

start_client() {
  local name=$1 expect_port=$2
  start_detached "$name" "$PROBE_ROOT/$name.log" "$PROD_BIN" run -c "$PROBE_ROOT/$name.json" >/dev/null
  PROBE_PIDS+=("$name")
  ensure_detached_pid "$name" "$PROBE_ROOT/$name.json" || warn "$name: 无法确认存活 pid"
  wait_for "$name" 20 port_in_use_after_start "$expect_port" || die "$name 未启动（socks $expect_port）"
}

start_clients() {
  start_client client-a-reality "$SOCKS_AR"
  start_client client-a-hy2    "$SOCKS_AH"
  start_client client-b-reality "$SOCKS_BR"
  start_client client-b-hy2    "$SOCKS_BH"
  ok "4 个探针客户端已就绪"
}

# ------------------------------------------------------------------ evidence ---

api_capture_version() {
  mkdir -p "$EVID_DIR"
  if ! api_curl /version > "$EVID_DIR/00-api-version.json" 2>/dev/null; then
    printf '{"_probe_api_error": "request to /version failed"}\n' > "$EVID_DIR/00-api-version.json"
  fi
}

api_snapshot() {
  local label=$1 out
  mkdir -p "$EVID_DIR"
  api_capture_version
  api_snapshot_conn "$label"
  for out in traffic memory; do
    if ! api_curl "/$out" > "$EVID_DIR/$label.$out.json" 2>"$EVID_DIR/$label.$out.err"; then
      printf '{"_probe_api_error": "request to /%s failed"}\n' "$out" > "$EVID_DIR/$label.$out.json"
    fi
    rm -f "$EVID_DIR/$label.$out.err"
  done
  if ! python3 "$LIB_DIR/analyze.py" keys "$EVID_DIR/$label.connections.json" \
        > "$EVID_DIR/$label.keys.txt" 2>/dev/null; then
    : > "$EVID_DIR/$label.keys.txt"
  fi
}

# Cheap variant used by the in-transfer sampling loop: /connections only.
api_snapshot_conn() {
  local label=$1
  mkdir -p "$EVID_DIR"
  if ! api_curl /connections > "$EVID_DIR/$label.connections.json" 2>/dev/null; then
    printf '{"_probe_api_error": "request to /connections failed"}\n' > "$EVID_DIR/$label.connections.json"
  fi
  log "sample $label: $(python3 "$LIB_DIR/analyze.py" count "$EVID_DIR/$label.connections.json" 2>/dev/null || echo '?') 条连接"
}

XFER_PIDS=()
XFER_LAST=""

kill_transfers() {
  # Only iterates PIDs still belonging to active transfers: every pid removed by
  # remove_xfer_pid (already waited/reaped) can never be signalled again, so a
  # recycled PID cannot be mistaken for ours by the EXIT trap.
  local p
  for p in ${XFER_PIDS[@]+"${XFER_PIDS[@]}"}; do
    [ -n "$p" ] && kill -TERM "$p" 2>/dev/null || true
  done
  XFER_PIDS=()
}

remove_xfer_pid() { # remove_xfer_pid <pid> -- drop a waited/reaped pid from the active set
  local pid=$1 i
  local remaining=()
  for i in ${XFER_PIDS[@]+"${XFER_PIDS[@]}"}; do
    [ "$i" = "$pid" ] || remaining+=("$i")
  done
  XFER_PIDS=("${remaining[@]}")
}

proto_tag() {
  case "$1" in
    reality) printf '%s' "$REALITY_TAG" ;;
    hy2) printf '%s' "$HY2_TAG" ;;
    *) printf '' ;;
  esac
}

sink_url() {
  local bytes="${1:-$PAYLOAD_BYTES}"
  printf 'http://127.0.0.1:%s/blob?bytes=%s' "$SINK_PORT" "$bytes"
}

payload_file_for() {
  local bytes=$1
  if [ "$bytes" = "$PAYLOAD_BYTES" ]; then printf '%s' "$PAYLOAD_FILE"; return 0; fi
  if [ "$bytes" = "$(( PAYLOAD_BYTES / 2 ))" ] && [ -s "$PAYLOAD_HALF_FILE" ]; then
    printf '%s' "$PAYLOAD_HALF_FILE"; return 0
  fi
  local tmp="$PROBE_ROOT/payload-$bytes.bin"
  if [ ! -s "$tmp" ]; then
    truncate -s "$bytes" "$tmp" 2>/dev/null || head -c "$bytes" /dev/zero > "$tmp" \
      || { warn "无法生成 $bytes 字节负载"; return 1; }
  fi
  printf '%s' "$tmp"
}

# The pid is published through XFER_LAST rather than stdout: a command substitution
# would run in a subshell, so XFER_PIDS would not be updated and the EXIT trap could
# leave curl processes behind.
#
# Every transfer persists THREE separate evidence files under $stem:
#   $stem.json  machine-readable curl -w result (bytes actually moved, http_code)
#   $stem.err   curl stderr (kept apart so it can never corrupt the JSON)
#   $stem.rc    curl exit code, written by await_xfer once the process is reaped
start_download() {
  local socks=$1 bytes=$2 rate=$3 stem=$4
  curl -sS -o /dev/null -w '{"mode":"download","requested_bytes":'"$bytes"',"bytes_downloaded":%{size_download},"speed_bps":%{speed_download},"http_code":%{http_code}}\n' \
    --limit-rate "$rate" --max-time "$TRANSFER_MAX_TIME" \
    -x "socks5h://127.0.0.1:$socks" "$(sink_url "$bytes")" > "$stem.json" 2> "$stem.err" &
  XFER_LAST=$!
  XFER_PIDS+=("$XFER_LAST")
}

start_upload() {
  local socks=$1 bytes=$2 rate=$3 stem=$4
  local payload
  payload="$(payload_file_for "$bytes")" || { XFER_LAST=""; return 1; }
  curl -sS -o /dev/null -w '{"mode":"upload","requested_bytes":'"$bytes"',"bytes_uploaded":%{size_upload},"speed_bps":%{speed_download},"http_code":%{http_code}}\n' \
    --limit-rate "$rate" --max-time "$TRANSFER_MAX_TIME" \
    -H 'Content-Type: application/octet-stream' \
    --data-binary "@$payload" \
    -x "socks5h://127.0.0.1:$socks" "$(sink_url "$bytes")" > "$stem.json" 2> "$stem.err" &
  XFER_LAST=$!
  XFER_PIDS+=("$XFER_LAST")
}

# Sample the API while the transfer runs, then keep sampling only while this
# inbound's connections are still visible. The last sample taken while the
# connection is alive carries its final counters, so direction math never depends
# on a post-transfer snapshot.
sample_transfer() {
  local prefix=$1 pid=$2 tag=$3 i=0 label tail=0
  while kill -0 "$pid" 2>/dev/null; do
    i=$((i + 1))
    api_snapshot_conn "$(printf '%s-s%02d' "$prefix" "$i")"
    sleep "$SAMPLE_INTERVAL"
  done
  while [ "$tail" -lt "$SAMPLE_TAIL_MAX" ]; do
    i=$((i + 1))
    label="$(printf '%s-s%02d' "$prefix" "$i")"
    api_snapshot_conn "$label"
    grep -qF -- "$tag" "$EVID_DIR/$label.connections.json" 2>/dev/null || break
    tail=$((tail + 1))
    sleep "$SAMPLE_TAIL_INTERVAL"
  done
  printf '%s\n' "$i"
}

run_direction_test() {
  local proto=$1 kind=$2 socks=$3 bytes=$4 rate=$5
  local prefix="$proto-$kind" stem="$EVID_DIR/$prefix-curl" pid
  log "== $proto $kind: 已知 ${bytes}B 单向传输（连接存活期间周期采样）=="
  api_snapshot "$prefix-pre"
  case "$kind" in
    dl) start_download "$socks" "$bytes" "$rate" "$stem" ;;
    ul) start_upload   "$socks" "$bytes" "$rate" "$stem" ;;
    *)  die "未知传输类型: $kind" ;;
  esac
  pid=$XFER_LAST
  if [ -z "$pid" ]; then warn "$proto $kind 未能启动传输"; return 1; fi
  local samples
  samples="$(sample_transfer "$prefix" "$pid" "$(proto_tag "$proto")")"
  await_xfer "$pid" "$proto $kind" "$stem"
  # Only for the connection-close behaviour check, never for byte math.
  api_snapshot "$prefix-closed"
  log "$proto $kind 采样数: $samples"
}

run_attribution_test() {
  local proto=$1 socks_a=$2 socks_b=$3
  local half=$(( PAYLOAD_BYTES / 2 ))
  local half_rate=$(( TRANSFER_RATE / 2 ))
  local prefix="$proto-ab" pid pid2 samples
  local stem_a="$EVID_DIR/$proto-ab-a-curl" stem_b="$EVID_DIR/$proto-ab-b-curl"
  log "== $proto: 归因测试（$USER_A / $USER_B 并发，各 ${half}B）=="
  api_snapshot "$prefix-pre"
  start_download "$socks_a" "$half" "$half_rate" "$stem_a"
  pid=$XFER_LAST
  start_download "$socks_b" "$half" "$half_rate" "$stem_b"
  pid2=$XFER_LAST
  if [ -z "$pid" ] || [ -z "$pid2" ]; then warn "$proto 归因传输未能启动"; return 1; fi
  samples="$(sample_transfer "$prefix" "$pid" "$(proto_tag "$proto")")"
  await_xfer "$pid"  "$proto 归因 $USER_A" "$stem_a"
  await_xfer "$pid2" "$proto 归因 $USER_B" "$stem_b"
  api_snapshot "$prefix-closed"
  log "$proto 归因采样数: $samples"
}

run_protocol_tests() {
  local proto=$1 socks_a=$2 socks_b=$3
  run_direction_test "$proto" dl "$socks_a" "$PAYLOAD_BYTES" "$TRANSFER_RATE"
  run_direction_test "$proto" ul "$socks_a" "$PAYLOAD_BYTES" "$TRANSFER_RATE"
  run_attribution_test "$proto" "$socks_a" "$socks_b"
}

await_xfer() { # await_xfer <pid> <what> <stem>
  # Reaps the curl process, persists its exit code as the third evidence file and
  # immediately drops the pid from XFER_PIDS, so the EXIT trap can never signal a
  # pid that has already been reaped (possibly recycled by the OS in the meantime).
  # If the script dies before this runs, the .rc file is simply absent and the
  # analyzer treats the transfer as unevidenced (never as a success).
  local pid=$1 what=$2 stem=$3 rc=0
  if wait "$pid"; then
    ok "$what 完成"
  else
    rc=$?
    warn "$what 未正常结束（curl exit $rc，证据: $stem.err / $stem.rc）"
  fi
  printf '%s\n' "$rc" > "$stem.rc"
  remove_xfer_pid "$pid"
  return 0
}

# --------------------------------------------------------------- test matrix ---

run_local_matrix() {
  mkdir -p "$EVID_DIR"
  ev_meta
  record_production_baseline
  start_sink
  start_clients
  api_snapshot version-prep
  run_protocol_tests reality "$SOCKS_AR" "$SOCKS_BR"
  run_protocol_tests hy2 "$SOCKS_AH" "$SOCKS_BH"
  api_snapshot final-idle
  ok "本机测试矩阵完成"
}

# ----------------------------------------------------------------- analysis ---

run_analysis() {
  local json="$EVID_DIR/analysis.json" md="$EVID_DIR/report.md"
  if [ ! -s "$EVID_DIR/meta.json" ]; then
    warn "缺少 $EVID_DIR/meta.json，使用默认期望值进行分析"
  fi
  python3 "$LIB_DIR/analyze.py" analyze --evidence-dir "$EVID_DIR" \
    --json-out "$json" --md-out "$md" || die "分析失败"
  ok "分析完成: $md"
}
