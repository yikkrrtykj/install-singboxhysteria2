# monitor-env.sh -- shared helpers for the deployed monitor shims.
# shellcheck shell=bash
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
        # shellcheck disable=SC2034  # SBMON_ENV_* are consumed by sourcing shims
        case "$key" in
            SBMON_WEB_BIND) SBMON_ENV_WEB_BIND="$value" ;;
            SBMON_API_URL) SBMON_ENV_API_URL="$value" ;;
            SBMON_API_SECRET_FILE) SBMON_ENV_API_SECRET_FILE="$value" ;;
            SBMON_MODE) SBMON_ENV_MODE="$value" ;;
            SBMON_CYCLE_SECONDS) SBMON_ENV_CYCLE_SECONDS="$value" ;;
        esac
    done < "$conf"
}

# P7: production API URL contract, validated via the Python runtime
# (urllib.parse) -- the shell never hand-parses URLs.
#   scheme  = http exactly (service.api is h2c http on loopback)
#   host    = 127.0.0.1 | localhost | ::1  (loopback-only, E1 fail-closed)
#   port    = numeric, valid range
#   no userinfo, no query, no fragment, no path beyond "/"
monitor_env_validate_api_url() { # monitor_env_validate_api_url <url> -> rc 0 valid
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || return 1
    "$pybin" - "$1" <<'PY'
import sys
from urllib.parse import urlsplit
try:
    u = urlsplit(sys.argv[1])
    port = u.port  # may raise ValueError on invalid/overflowing port
    ok = (
        u.scheme == "http"
        and u.hostname in ("127.0.0.1", "localhost", "::1")
        and isinstance(port, int) and 0 < port < 65536
        and u.username is None and u.password is None
        and u.path in ("", "/")
        and u.query == "" and u.fragment == ""
    )
except ValueError:
    ok = False
sys.exit(0 if ok else 1)
PY
}

# Split a VALIDATED loopback URL into REPLY_HOST / REPLY_PORT for the TCP
# probe. Invalid URLs and non-loopback hosts fail closed (E1 contract).
monitor_env_split_url() { # monitor_env_split_url <url>
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || return 1
    local out
    out="$("$pybin" - "$1" <<'PY'
import sys
from urllib.parse import urlsplit
try:
    u = urlsplit(sys.argv[1])
    port = u.port
    ok = (
        u.scheme == "http"
        and u.hostname in ("127.0.0.1", "localhost", "::1")
        and isinstance(port, int) and 0 < port < 65536
        and u.username is None and u.password is None
        and u.path in ("", "/")
        and u.query == "" and u.fragment == ""
    )
    if not ok:
        sys.exit(1)
    print(u.hostname, port)
except ValueError:
    sys.exit(1)
PY
)" || return 1
    REPLY_HOST="${out%% *}"
    REPLY_PORT="${out##* }"
    [ -n "$REPLY_HOST" ] && [ -n "$REPLY_PORT" ]
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
