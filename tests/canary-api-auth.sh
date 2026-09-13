#!/usr/bin/env bash
# service.api authentication canary (S0 transport-auth boundary).
#
# Validates the monitor-api auth boundary against a REAL running sing-box.
# Automated/local part (no traffic required):
#   1. no credentials        -> must be REJECTED (Unauthenticated)
#   2. wrong Bearer secret   -> must be REJECTED (Unauthenticated)
#   3. correct Bearer secret -> sing-box api connection list must SUCCEED
#                               and return valid JSON
# Optional collector smoke (--with-collector, needs python3):
#   4. monitor-v2 collector must connect to SubscribeConnections with the
#      derived secret file; only an AUTH error fails the canary (a stream
#      ending on an idle server is informational, not a failure).
#
# Truth source for the secret (in order): --secret value, --secret-file
# (default /root/sbox/monitor-api.secret), then the sbconfig_server.json
# services entry. The secret is never printed by this script.
#
# Usage (on the VPS, as root):
#   bash tests/canary-api-auth.sh
#   bash tests/canary-api-auth.sh --with-collector
#   bash tests/canary-api-auth.sh --url http://127.0.0.1:9091 \
#        --secret-file /root/sbox/monitor-api.secret --with-collector
#
# Exit codes: 0 every check green; 1 the auth boundary is BROKEN;
#             2 environment/usage error (canary NOT RUN).
set -uo pipefail

url="http://127.0.0.1:9091"
secret_file="/root/sbox/monitor-api.secret"
config_file="/root/sbox/sbconfig_server.json"
sing_box_bin="/root/sbox/sing-box"
secret_arg=""
with_collector=0
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

while [ $# -gt 0 ]; do
    case "$1" in
        --url) url="${2:?}"; shift 2 ;;
        --secret) secret_arg="${2:?}"; shift 2 ;;
        --secret-file) secret_file="${2:?}"; shift 2 ;;
        --config) config_file="${2:?}"; shift 2 ;;
        --sing-box) sing_box_bin="${2:?}"; shift 2 ;;
        --with-collector) with_collector=1; shift ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

env_error() { printf 'ENVIRONMENT ERROR: %s; canary NOT RUN\n' "$1" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || env_error "jq is missing"
[ -x "$sing_box_bin" ] || env_error "sing-box binary not executable: $sing_box_bin"

secret="$secret_arg"
if [ -z "$secret" ] && [ -n "$secret_file" ] && [ -r "$secret_file" ]; then
    secret="$(tr -d '\r\n' < "$secret_file")"
fi
if [ -z "$secret" ] && [ -n "$config_file" ] && [ -r "$config_file" ]; then
    secret="$(jq -r --arg tag "monitor-api" \
        '([(.services // [])[] | select(.tag == $tag)][0].secret // "")' \
        "$config_file" 2>/dev/null | tr -d '\r\n')"
fi
[ -n "$secret" ] || env_error "no API secret available (checked --secret, $secret_file, $config_file)"
case "$url" in
    http://127.0.0.1:*|http://localhost:*|http://\[::1\]:*) ;;
    *) env_error "canary only runs against a loopback URL (got: $url)" ;;
esac

rc_all=0

printf '[1/3] no credentials must be REJECTED\n'
if err="$("$sing_box_bin" api --url "$url" connection list 2>&1 >/dev/null)"; then
    printf '  FAIL: unauthenticated call SUCCEEDED - service.api auth is NOT enforced\n'
    rc_all=1
else
    if printf '%s' "$err" | grep -qiE 'unauthenticated|permission|auth'; then
        printf '  OK: rejected (Unauthenticated)\n'
    else
        printf '  OK: rejected (rc!=0; first error line: %s)\n' "$(printf '%s' "$err" | head -n1)"
    fi
fi

printf '[2/3] wrong Bearer secret must be REJECTED\n'
wrong="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
if [ "$wrong" = "$secret" ]; then
    printf '  FAIL: the configured secret equals the canary wrong-secret fixture\n'
    rc_all=1
elif err="$("$sing_box_bin" api --url "$url" --secret "$wrong" connection list 2>&1 >/dev/null)"; then
    printf '  FAIL: wrong-secret call SUCCEEDED - service.api auth is NOT enforced\n'
    rc_all=1
else
    if printf '%s' "$err" | grep -qiE 'unauthenticated|permission|auth'; then
        printf '  OK: rejected (Unauthenticated)\n'
    else
        printf '  OK: rejected (rc!=0; first error line: %s)\n' "$(printf '%s' "$err" | head -n1)"
    fi
fi

printf '[3/3] correct Bearer secret must SUCCEED\n'
if out="$("$sing_box_bin" api --url "$url" --secret "$secret" connection list 2>/dev/null)" &&
   printf '%s' "$out" | jq empty >/dev/null 2>&1; then
    printf '  OK: authenticated connection list returned valid JSON\n'
else
    printf '  FAIL: authenticated call failed or returned invalid JSON\n'
    rc_all=1
fi

if [ "$with_collector" = "1" ]; then
    printf '[4] SubscribeConnections collector smoke (--once)\n'
    if ! command -v python3 >/dev/null 2>&1; then
        printf '  SKIP: python3 missing\n'
    else
        if [ -r "$secret_file" ]; then
            snap="$(python3 "$repo_root/monitor-v2/collector.py" \
                        --url "$url" --secret-file "$secret_file" \
                        --once 2>/dev/null || true)"
        else
            snap="$(BOX_API_SECRET="$secret" python3 "$repo_root/monitor-v2/collector.py" \
                        --url "$url" --once 2>/dev/null || true)"
        fi
        if [ -z "$snap" ] || ! printf '%s' "$snap" | jq empty >/dev/null 2>&1; then
            printf '  FAIL: collector produced no parsable snapshot\n'
            rc_all=1
        else
            last_error="$(printf '%s' "$snap" | jq -r '.last_error // ""')"
            if printf '%s' "$last_error" | grep -qiE 'unauthenticated|permissiondenied|permission denied'; then
                printf '  FAIL: SubscribeConnections rejected with the correct secret: %s\n' "$last_error"
                rc_all=1
            elif [ -n "$last_error" ]; then
                # e.g. "event stream ended by the server" on an idle box:
                # a transport observation, not an auth-boundary failure.
                printf '  INFO: snapshot received; non-auth last_error: %s\n' "$last_error"
            else
                printf '  OK: SubscribeConnections connected without an auth error\n'
            fi
        fi
    fi
fi

if [ "$rc_all" -eq 0 ]; then
    printf 'CANARY PASS: service.api auth boundary enforced (loopback only by config)\n'
else
    printf 'CANARY FAIL: do NOT proceed with production monitor migration\n' >&2
fi
exit "$rc_all"
