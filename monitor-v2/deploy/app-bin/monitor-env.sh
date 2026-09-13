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
            SBMON_WEB_POLL_SECONDS) SBMON_ENV_WEB_POLL_SECONDS="$value" ;;
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

# R1: production WEB BIND contract, validated via the Python runtime
# (ipaddress) -- the shell never hand-splits host:port (IPv6 brackets and
# "::1:9191"-style ambiguity are unparseable in Bash).
#   accepted   127.0.0.1:9191 | localhost:9191 | [::1]:9191 | [::1]:port
#   rejected   0.0.0.0, private LAN / public addresses, malformed or
#              overflowing port, userinfo, path/query/fragment, wildcard
# On success prints "<host> <port>" (host normalized: brackets stripped).
monitor_env_split_web_bind() { # monitor_env_split_web_bind <bind> -> "host port"
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || return 1
    local out
    out="$("$pybin" - "$1" <<'PY'
import ipaddress, sys
raw = sys.argv[1]
try:
    if any(ch in raw for ch in "/?#@") or any(ch.isspace() for ch in raw):
        raise ValueError("userinfo/path/query/fragment/space")
    if raw.startswith("["):
        inner, sep, rest = raw[1:].partition("]")
        if not sep or not rest.startswith(":"):
            raise ValueError("bracketed IPv6 without :port")
        host, port_s = inner, rest[1:]
    else:
        host, sep, port_s = raw.rpartition(":")
        if not sep or not host:
            raise ValueError("missing host or :port")
    if not port_s.isdigit():
        raise ValueError("port must be decimal digits")
    port = int(port_s)
    if not 0 < port < 65536:
        raise ValueError("port out of range")
    if host != "localhost":
        addr = ipaddress.ip_address(host)  # rejects hostnames/brackets
        if addr.is_unspecified or not addr.is_loopback:
            raise ValueError("not loopback")
except ValueError:
    sys.exit(1)
print(host, port)
PY
)" || return 1
    REPLY_BIND_HOST="${out%% *}"
    REPLY_BIND_PORT="${out##* }"
    [ -n "$REPLY_BIND_HOST" ] && [ -n "$REPLY_BIND_PORT" ]
}

monitor_env_validate_web_bind() { # rc 0 = valid loopback bind
    monitor_env_split_web_bind "$1" >/dev/null
}

# R1.1-D: strict SBMON_WEB_POLL_SECONDS contract -- the value must be a NUMERIC,
# FINITE float strictly greater than 0. Bash character checks accept "0"/"0.0"
# (which would make the SnapshotBroker publisher wait(0) spin in a tight loop),
# so the parse/reject decision is delegated to the Python float parser.
# Accepted: 1, 1.0, 0.5, 2.25   Rejected: 0, 0.0, -1, NaN, nan, inf, Infinity,
# ".", 1..2, abc, empty. monitor-service AND monitor-health call THIS function
# so the service and the probe can never disagree on what is legal.
monitor_env_validate_poll_seconds() { # monitor_env_validate_poll_seconds <value> -> rc 0 valid
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || return 1
    "$pybin" - "$1" <<'PY'
import math, sys
try:
    value = float(sys.argv[1])
except (TypeError, ValueError):
    sys.exit(1)
sys.exit(0 if math.isfinite(value) and value > 0 else 1)
PY
}

# R1.1-D: derive the broker health freshness window from a VALIDATED poll
# value using ceil(5 * poll_seconds + 15). The old ${WEB_POLL%%.*} integer
# truncation silently mis-handled fractional values (0.5 -> 0). Prints the
# integer threshold on stdout; rc 1 for any invalid value so the caller can
# fail closed instead of silently substituting a different rule.
monitor_env_poll_max_age() { # monitor_env_poll_max_age <value> -> prints ceil(5*v+15)
    local pybin="${SBMON_PYTHON3:-python3}"
    command -v "$pybin" >/dev/null 2>&1 || return 1
    local out
    out="$("$pybin" - "$1" <<'PY'
import math, sys
try:
    value = float(sys.argv[1])
except (TypeError, ValueError):
    sys.exit(1)
if not (math.isfinite(value) and value > 0):
    sys.exit(1)
print(math.ceil(5.0 * value + 15.0))
PY
)" || return 1
    [ -n "$out" ] || return 1
    printf '%s\n' "$out"
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
