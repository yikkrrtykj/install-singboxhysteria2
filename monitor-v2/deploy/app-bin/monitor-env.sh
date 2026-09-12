# monitor-env.sh -- shared helpers for the deployed monitor shims.
# Sourced by monitor-service and monitor-health inside the release tree.
# Kept dependency-free and journal-safe: never prints conf values or secrets.

# Strict KEY=VALUE reader: sets SBMON_ENV_<KEY> globals from a conf file.
# No eval, no source of the conf, values with '=' survive (first '=' splits).
monitor_env_load() { # monitor_env_load <conf-file>
    local conf="$1"
    [ -r "$conf" ] || return 1
    local line key value
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in ''|\#*) continue ;; esac
        key="${line%%=*}"
        value="${line#*=}"
        [ "$key" != "$line" ] || continue
        case "$key" in
            SBMON_WEB_BIND) SBMON_ENV_WEB_BIND="$value" ;;
            SBMON_API_URL) SBMON_ENV_API_URL="$value" ;;
            SBMON_API_SECRET_FILE) SBMON_ENV_API_SECRET_FILE="$value" ;;
            SBMON_MODE) SBMON_ENV_MODE="$value" ;;
            SBMON_CYCLE_SECONDS) SBMON_ENV_CYCLE_SECONDS="$value" ;;
        esac
    done < "$conf"
}

# Split http://host:port into REPLY_HOST / REPLY_PORT (loopback-only guard).
monitor_env_split_url() { # monitor_env_split_url <url>
    local url="$1" rest
    rest="${url#*://}"
    [ "$rest" != "$url" ] || return 1
    REPLY_HOST="${rest%%[:/]*}"
    REPLY_PORT="${rest#*:}"
    REPLY_PORT="${REPLY_PORT%%[/]*}"
    case "$REPLY_HOST" in
        127.0.0.1|localhost|::1) return 0 ;;
        *) return 1 ;;   # fail-closed: service.api must stay loopback (E1 contract)
    esac
}

# TCP connect probe (no curl dependency, no output).
monitor_env_tcp_probe() { # monitor_env_tcp_probe <host> <port> [timeout]
    local host="$1" port="$2" timeout="${3:-2}"
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || return 1
    "$pybin" - "$host" "$port" "$timeout" <<'PY' >/dev/null 2>&1
import socket, sys
host, port, timeout = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
try:
    with socket.create_connection((host, port), timeout=timeout):
        sys.exit(0)
except OSError:
    sys.exit(1)
PY
}

monitor_env_now() { date +%s; }
monitor_env_mtime() { stat -c '%Y' "$1" 2>/dev/null || echo 0; }
