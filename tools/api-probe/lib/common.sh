#!/usr/bin/env bash
# Shared helpers for the Phase A sing-box API probe.
#
# Invariants enforced in this file (the tool exists to observe production, never
# to change it):
#   * the tool only ever writes inside PROBE_ROOT;
#   * a process is killable only if its /proc cmdline references PROBE_ROOT and
#     it is not the MainPID of the production sing-box unit.
#
# Several values below are read by lib/probe-config.sh and lib/evidence.sh, which
# are always sourced next to this file; shellcheck only sees one file at a time.
# shellcheck disable=SC2034

PROBE_ROOT="${PROBE_ROOT:-/root/sbox-probe}"
PROD_DIR="${PROD_DIR:-/root/sbox}"
PROD_BIN="${PROD_BIN:-$PROD_DIR/sing-box}"
PROD_SERVICE="${PROD_SERVICE:-sing-box}"
PROD_CONFIG="${PROD_CONFIG:-$PROD_DIR/sbconfig_server.json}"
PROD_STATE="${PROD_STATE:-$PROD_DIR/config}"

# shellcheck disable=SC2034
RUN_DIR="$PROBE_ROOT/run"
EVID_DIR="$PROBE_ROOT/evidence"
CERTS_DIR="$PROBE_ROOT/certs"
SECRET_FILE="$PROBE_ROOT/secret"
KEYS_FILE="$PROBE_ROOT/keys.json"
PROBE_CONFIG="$PROBE_ROOT/probe.json"
PROBE_LOG="$PROBE_ROOT/probe.log"
PAYLOAD_FILE="$PROBE_ROOT/payload.bin"
PAYLOAD_HALF_FILE="$PROBE_ROOT/payload-half.bin"

REALITY_PORT="${REALITY_PORT:-18443}"
HY2_PORT="${HY2_PORT:-18444}"
CLASH_PORT="${CLASH_PORT:-19090}"
SINK_PORT="${SINK_PORT:-18080}"
SOCKS_AR="${SOCKS_AR:-18081}"
SOCKS_AH="${SOCKS_AH:-18082}"
SOCKS_BR="${SOCKS_BR:-18083}"
SOCKS_BH="${SOCKS_BH:-18084}"

REALITY_TAG="probe-reality-in"
HY2_TAG="probe-hy2-in"
USER_A="probe-a"
USER_B="probe-b"

EXPOSE="${EXPOSE:-0}"
PUBLIC_IP="${PUBLIC_IP:-}"
PAYLOAD_BYTES="${PAYLOAD_BYTES:-67108864}"
TRANSFER_RATE="${TRANSFER_RATE:-4194304}"
TRANSFER_MAX_TIME="${TRANSFER_MAX_TIME:-300}"
# A connection may disappear the moment the last byte is proxied, so the counters
# are sampled while the transfer runs (and briefly while its connections are still
# visible) instead of relying on a post-transfer snapshot.
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-1}"
SAMPLE_TAIL_INTERVAL="${SAMPLE_TAIL_INTERVAL:-0.25}"
SAMPLE_TAIL_MAX="${SAMPLE_TAIL_MAX:-8}"

if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_CYN=$'\033[36m'; C_RST=$'\033[0m'
else
  C_RED=''; C_YEL=''; C_GRN=''; C_CYN=''; C_RST=''
fi

log()  { printf '%s[%s]%s %s\n' "$C_CYN" "$(date +%H:%M:%S)" "$C_RST" "$*"; }
ok()   { printf '%s[ OK ]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

is_num() { case "${1:-}" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "请以 root 运行（探针需要执行 /root/sbox/sing-box 并绑定端口）"
}

require_prod_bin() {
  [ -x "$PROD_BIN" ] || die "未找到可执行文件 $PROD_BIN —— 本工具假定该机器已用本仓库安装器装好 sing-box"
}

# Guard against a misconfigured PROBE_ROOT turning cleanup into a destructive
# operation on production paths.
require_probe_root_sane() {
  [ -n "${PROBE_ROOT:-}" ] || die "PROBE_ROOT 为空，拒绝继续"
  [ "$PROBE_ROOT" != "/" ] || die "PROBE_ROOT 不允许是 /"
  [ "$PROBE_ROOT" != "/root" ] || die "PROBE_ROOT 不允许是 /root"
  [ "$PROBE_ROOT" != "$PROD_DIR" ] || die "PROBE_ROOT 不允许等于生产目录 $PROD_DIR"
  case "$PROBE_ROOT" in
    /root/*) : ;;
    *) die "PROBE_ROOT 必须位于 /root/ 下（当前: $PROBE_ROOT）" ;;
  esac
  [ "${#PROBE_ROOT}" -ge 12 ] || die "PROBE_ROOT 过短，拒绝继续: $PROBE_ROOT"
  [ ! -L "$PROBE_ROOT" ] || die "PROBE_ROOT 是符号链接，拒绝继续"
}

require_prereqs() {
  local missing=()
  have curl    || missing+=("curl (apt install curl | dnf install curl)")
  have ss      || missing+=("ss / iproute2 (apt install iproute2 | dnf install iproute)")
  have python3 || missing+=("python3 (apt install python3 | dnf install python3)")
  have openssl || missing+=("openssl (apt install openssl | dnf install openssl)")
  have od      || missing+=("od / coreutils (apt install coreutils | dnf install coreutils)")
  if [ "${#missing[@]}" -gt 0 ]; then
    err "缺少依赖:"
    local m
    for m in "${missing[@]}"; do err "  - $m"; done
    die "请先安装上述依赖再运行"
  fi
}

# ---------------------------------------------------------------- production ---

prod_version() {
  if [ -x "$PROD_BIN" ]; then
    "$PROD_BIN" version 2>&1 | head -n 1
  else
    printf 'binary missing: %s' "$PROD_BIN"
  fi
}

prod_service_state() { systemctl is-active "$PROD_SERVICE" 2>/dev/null || true; }

prod_main_pid() { systemctl show -p MainPID --value "$PROD_SERVICE" 2>/dev/null || true; }

prod_file_hash() {
  local f=$1
  if [ -f "$f" ]; then sha256sum "$f" 2>/dev/null | awk '{print $1}'; else printf 'absent'; fi
}

# ---------------------------------------------------------------------- pids ---

write_pid() { mkdir -p "$RUN_DIR"; printf '%s\n' "$2" > "$RUN_DIR/$1.pid"; }
read_pid()  { local f="$RUN_DIR/$1.pid"; [ -s "$f" ] && cat "$f" || true; }
pid_alive() { [ -n "${1:-}" ] && [ -d "/proc/$1" ]; }
pid_cmdline() { [ -r "/proc/$1/cmdline" ] && tr '\0' ' ' < "/proc/$1/cmdline" || true; }

# A pid qualifies as ours only when its cmdline references PROBE_ROOT. The
# production process cmdline references PROD_DIR instead, so it can never match,
# even if a stale pidfile happens to contain its pid.
pid_is_probe() {
  local pid="${1:-}" cmd prod
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  [ "$pid" -gt 1 ] || return 1
  pid_alive "$pid" || return 1
  prod="$(prod_main_pid)"
  [ -n "$prod" ] && [ "$pid" = "$prod" ] && return 1
  cmd="$(pid_cmdline "$pid")"
  case "$cmd" in *"$PROBE_ROOT"*) return 0 ;; *) return 1 ;; esac
}

stop_probe_proc() {
  local name=$1 pid i
  pid="$(read_pid "$name")"
  if [ -z "$pid" ]; then
    log "$name: 无 pid 记录"
    return 0
  fi
  if ! pid_is_probe "$pid"; then
    warn "$name (pid $pid): 无法证明它是本工具的进程，拒绝终止（pid 可能已被复用）"
    rm -f "$RUN_DIR/$name.pid"
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 40); do pid_alive "$pid" || break; sleep 0.25; done
  if pid_alive "$pid"; then
    if pid_is_probe "$pid"; then
      kill -KILL "$pid" 2>/dev/null || true
      warn "$name (pid $pid): SIGTERM 超时，已发送 SIGKILL"
    else
      warn "$name (pid $pid): 终止前复查失败，未发送 SIGKILL"
    fi
  fi
  rm -f "$RUN_DIR/$name.pid"
  ok "$name 已停止 (pid $pid)"
}

start_detached() {
  local name=$1 logfile=$2
  shift 2
  mkdir -p "$RUN_DIR"
  local pid
  if have setsid; then
    setsid "$@" >>"$logfile" 2>&1 &
  else
    nohup "$@" >>"$logfile" 2>&1 &
  fi
  pid=$!
  write_pid "$name" "$pid"
  printf '%s' "$pid"
}

# setsid() forks when the caller already is a process group leader, in which case
# the recorded pid belongs to a short-lived parent. Re-resolve by cmdline so cleanup
# can still find the real process; the result is only ever used after pid_is_probe()
# approves it.
find_probe_pid_by_cmdline() {
  local needle=$1 entry pid
  for entry in /proc/[0-9]*; do
    [ -d "$entry" ] || continue
    pid="${entry#/proc/}"
    if pid_is_probe "$pid" && pid_cmdline "$pid" | grep -qF -- "$needle"; then
      printf '%s' "$pid"
      return 0
    fi
  done
  return 1
}

ensure_detached_pid() {
  local name=$1 needle=$2 pid
  for _ in 1 2 3 4 5 6; do
    pid="$(read_pid "$name")"
    if pid_is_probe "$pid"; then return 0; fi
    sleep 0.5
  done
  if pid="$(find_probe_pid_by_cmdline "$needle")"; then
    write_pid "$name" "$pid"
    warn "$name: 记录的 pid 未存活，已按 cmdline 重新解析为 pid $pid"
    return 0
  fi
  return 1
}

wait_for() {
  local what=$1 tries=$2
  shift 2
  local i
  for i in $(seq 1 "$tries"); do
    if "$@"; then return 0; fi
    sleep 0.5
  done
  return 1
}

# --------------------------------------------------------------------- ports ---

port_in_use() { ss -H -lntu 2>/dev/null | grep -qE "[:.]$1[[:space:]]"; }

require_free_port() {
  local port=$1 what=$2
  case "$port" in ''|*[!0-9]*) die "$what 端口非法: $port" ;; esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "$what 端口越界: $port"
  if port_in_use "$port"; then
    die "$what 端口 $port 已被占用，请用环境变量指定其它端口后重试"
  fi
}

port_listening() { port_in_use "$1"; }

# ----------------------------------------------------------------------- api ---

api_secret() { [ -s "$SECRET_FILE" ] && cat "$SECRET_FILE" || printf ''; }

api_curl() {
  local path=$1
  curl -sS -m 8 -H "Authorization: Bearer $(api_secret)" "http://127.0.0.1:${CLASH_PORT}${path}"
}

api_ready() { api_curl /version >/dev/null 2>&1; }

rand_hex() { od -An -tx1 -N"${1:-16}" /dev/urandom | tr -d ' \n'; }

getkey() { python3 "$LIB_DIR/analyze.py" getkey "$KEYS_FILE" "$1"; }
