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

# ---------------------------------------------------------------------------
# Runtime dependency preflight (capability detection -- never distro-version
# branching; supported baselines: Ubuntu 22.04 / 24.04 / 26.04 LTS).
# The runtime entrypoints FAIL CLOSED on any missing required command with a
# single clear diagnostic -- no degraded mode, no silent downgrade.
#
# Dependency sets are SPLIT by consumer (documented per command):
#   service : python3 -- executes webapp.py / collector.py; the whole E1/E2
#             runtime is stdlib Python. (mkdir/mv/sleep are coreutils and
#             always present; they are not named dependencies.)
#   health  : python3 -- JSON verdict helpers + the loopback identity probe;
#             systemctl -- the service_active signal;
#             stat -- mtime-based freshness windows (monitor_env_mtime).
# journalctl / jq / ss / flock / sha256sum / mktemp are DEPLOYMENT/canary-side
# tooling: they are required by the full compatibility preflight in
# monitor-deploy-lib.sh, never by the runtime shims.
#
# SBMON_REQUIRED_COMMANDS may override a set ONLY behind the explicit
# test-only gate SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE=1 (production
# invocations refuse the bypass: fail-closed).
# ---------------------------------------------------------------------------
monitor_env_required_command_set() { # monitor_env_required_command_set <service|health>
    case "$1" in
        service) printf '%s\n' python3 ;;
        health)  printf '%s\n' python3 systemctl stat ;;
        *) return 1 ;;
    esac
}

monitor_env_require_commands() { # monitor_env_require_commands <service|health> -> rc 0 all present
    local set_name="${1:-service}"
    local list
    list="$(monitor_env_required_command_set "$set_name")" || {
        printf 'monitor: unknown preflight dependency set: %s\n' "$set_name" >&2
        return 1
    }
    if [ "${SBMON_REQUIRED_COMMANDS+x}" = x ]; then
        if [ "${SBMON_TEST_ALLOW_REQUIRED_COMMANDS_OVERRIDE:-0}" != "1" ]; then
            printf 'monitor: SBMON_REQUIRED_COMMANDS override refused outside fixture/test mode (production preflight uses the required %s set)\n' "$set_name" >&2
            return 1
        fi
        # shellcheck disable=SC2086  # intentional word split of the gated override list
        list="${SBMON_REQUIRED_COMMANDS}"
    fi
    local missing="" cmd
    local pybin="${SBMON_PYTHON3:-python3}"
    for cmd in $list; do
        case "$cmd" in
            python3)
                # the wrapper actually used by the shims is checked as itself
                case "$pybin" in
                    */*) [ -x "$pybin" ] || missing=" $pybin" ;;
                    *)   command -v "$pybin" >/dev/null 2>&1 || missing=" $pybin" ;;
                esac
                ;;
            *) command -v "$cmd" >/dev/null 2>&1 || missing="$missing $cmd" ;;
        esac
    done
    if [ -n "$missing" ]; then
        printf 'monitor: missing required runtime command(s):%s -- fail-closed, refusing to continue (install the packages providing them)\n' "$missing" >&2
        return 1
    fi
    return 0
}

# Environment diagnostics for deploy/canary records -- NO secrets, stderr
# only (stdout stays a single JSON line for monitor-health). os-release
# ID+VERSION_ID, python/systemd versions, kernel release; ssh version only
# when an ssh binary exists ("when relevant").
monitor_env_record_environment() {
    if [ -r /etc/os-release ]; then
        local os_id os_ver
        os_id="$(sed -n 's/^ID=//p' /etc/os-release | head -n1 | tr -d '"')"
        os_ver="$(sed -n 's/^VERSION_ID=//p' /etc/os-release | head -n1 | tr -d '"')"
        printf 'monitor: environment os=%s %s\n' "${os_id:-unknown}" "${os_ver:-unknown}"
    else
        printf 'monitor: environment os-release unreadable\n'
    fi
    local pybin="${SBMON_PYTHON3:-python3}"
    "$pybin" --version 2>&1 | sed 's/^/monitor: environment /' || true
    "${SBMON_SYSTEMCTL:-systemctl}" --version 2>/dev/null | head -n1 | sed 's/^/monitor: environment /' || true
    if command -v ssh >/dev/null 2>&1; then
        ssh -V 2>&1 | sed 's/^/monitor: environment /' || true
    fi
    printf 'monitor: environment kernel=%s\n' "$(uname -r)"
}

# ---------------------------------------------------------------------------
# PR-2B: the journal_reader INGEST CONTRACT import path.
#
# The contract modules are bundled INTO the same immutable release tree as
# the Monitor runtime, at <release>/libexec/sbox-journal-reader/journal_reader/.
# The import path is therefore derived from the caller's OWN release location:
# no env var steers it, no repository checkout can satisfy it, and a test can
# only change the answer by changing the installed release itself.
#
# RC is always 0 -- an absent payload is the documented INERT case (a
# pre-PR-2B release ships no libexec), not a startup failure:
#   <app-dir> -> prints the release reader tree path, or nothing when this
#                release carries no complete contract payload.
# ---------------------------------------------------------------------------
monitor_env_contract_pythonpath() {
    local jr="$1/libexec/sbox-journal-reader"
    local f
    [ -d "$jr/journal_reader" ] || return 0
    for f in __init__.py ingest_contract.py schema.py; do
        [ -f "$jr/journal_reader/$f" ] || return 0
    done
    printf '%s\n' "$jr"
}

# Apply the derivation to the environment of the runtime about to be exec'd:
# PYTHONPATH becomes EXACTLY the release contract path (or disappears with it).
# An inherited/operator-supplied PYTHONPATH therefore can never answer for the
# installed release -- in either direction.
monitor_env_apply_contract_pythonpath() { # <app-dir> -> rc always 0
    SBMON_JR_CONTRACT_PATH="$(monitor_env_contract_pythonpath "$1")"
    export SBMON_JR_CONTRACT_PATH
    if [ -n "$SBMON_JR_CONTRACT_PATH" ]; then
        PYTHONPATH="$SBMON_JR_CONTRACT_PATH"
        export PYTHONPATH
    else
        unset PYTHONPATH
    fi
    return 0
}
