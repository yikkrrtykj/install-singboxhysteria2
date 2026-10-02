#!/usr/bin/env bash
# PR-6B server ingest / remote store suite (issue #67 PR-6B, Monitor 0.7.0).
#
# Deterministic, offline, no Internet / real proxy / real VPS / wall clock.
# The count is hard-gated:
#
# 187 = S0 static + red-line gates 33 (py_compile of the server modules
#      + harness; the release identity 0.7.0 in both places; History still
#      schema v5 with its six frozen prune sources and no remote words;
#      classifier/runtime/presenter carry no remote reference; the ingest
#      dispatch appears once and sits before the browser cross-origin gate
#      with a single whitelist evaluation; the PR-6C incident read route
#      does not exist and the server remote surface is exactly the frozen
#      PR-6B web file set; the proxy template exposes ONLY the exact
#      ingest path on a loopback upstream with no forwarded headers, a
#      16 KiB body bound and TLS termination; the deploy tooling never
#      references the remote store and the History prestate stays an
#      exact path; the previous release tree has no remote-plane code)
#      + S1 harness 153 verdicts across TWELVE groups (route/auth/epochs/
#      store/retention/continuity/capacity/concurrency/status/limits/isolation/deploy)
#      + the harness rc gate
#      (a crashing harness is itself a gate).
#
# Real owner/group/mode/no-follow/rename-race gates are separate mandatory
# Linux CI checks, as is nginx -t. Common tests do not count skipped host
# assertions as PASS. Linux fixtures require root and the real sboxweb group.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

PY3="${SBMON_TEST_PYTHON:-python3}"
pass=0
fail=0
ok() { pass=$((pass + 1)); printf '  PASS %s\n' "$1"; }
no() { fail=$((fail + 1)); printf '  FAIL %s\n' "$1"; }
assert_eq() { [ "$1" = "$2" ] && ok "$3" || no "$3 (want '$1' got '$2')"; }
assert_contains() { case "$2" in *"$1"*) ok "$3" ;; *) no "$3 (missing '$1')" ;; esac; }
assert_not_contains() { case "$2" in *"$1"*) no "$3 (found '$1')" ;; *) ok "$3" ;; esac; }

echo "== S0: compile, identity, isolation and packaging static gates =="

SERVER_DIR="$ROOT/monitor-v2/web"
SERVER_PY="$SERVER_DIR/server.py"
HIST_PY="$SERVER_DIR/incident_history.py"
WEBAPP="$ROOT/monitor-v2/webapp.py"
PROXY_CONF="$ROOT/monitor-v2/deploy/remote-probes-proxy.conf.example"
DEPLOY_LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"

for module in remote_registry remote_store remote_ingest; do
    if "$PY3" -m py_compile "$SERVER_DIR/$module.py" 2>/dev/null; then
        ok "$module.py compiles"
    else
        no "$module.py compiles"
    fi
done
if "$PY3" -m py_compile tests/remote-server/server_groups.py 2>/dev/null; then
    ok "server_groups.py compiles"
else
    no "server_groups.py compiles"
fi
for harness in store_groups linux_groups; do
    if "$PY3" -m py_compile "tests/remote-server/$harness.py" 2>/dev/null; then
        ok "$harness.py compiles"
    else
        no "$harness.py compiles"
    fi
done

assert_eq '0.7.0' "$(cat "$ROOT/monitor-v2/VERSION")" "VERSION is 0.7.0 (PR-6B owns the release bump)"
assert_contains 'MONITOR_WEB_VERSION = "0.7.0"' "$(cat "$SERVER_PY")" "MONITOR_WEB_VERSION is 0.7.0"

HIST_TXT="$(cat "$HIST_PY")"
assert_contains 'SCHEMA_VERSION = 5' "$HIST_TXT" "History schema stays v5"
PRUNE_BLOCK="$(printf '%s\n' "$HIST_TXT" | sed -n '/^_PRUNE_SOURCES = (/,/^)/p')"
assert_eq '6' "$(printf '%s' "$PRUNE_BLOCK" | grep -c '(\"')" "History _PRUNE_SOURCES keeps exactly six entries"
case "$HIST_TXT" in *remote_probe*|*remote-probes*) no "History store carries no remote reference" ;; *) ok "History store carries no remote reference" ;; esac
for module in incident_classifier incident_runtime incident_presenter; do
    if grep -qiE 'remote_probe|remote-probes' "$SERVER_DIR/$module.py"; then
        no "$module.py carries no remote reference (P4/P5 isolation)"
    else
        ok "$module.py carries no remote reference (P4/P5 isolation)"
    fi
done

# The exact ingest route exists ONCE, inside _route_post, BEFORE the
# browser _cross_origin spine.
assert_eq '1' "$(grep -c 'if path == REMOTE_INGEST_PATH:' "$SERVER_PY")" "the exact ingest dispatch appears exactly once"
DISPATCH_LINE="$(grep -n 'if path == REMOTE_INGEST_PATH:' "$SERVER_PY" | head -1 | cut -d: -f1)"
CROSS_LINE="$(grep -n 'if self._cross_origin():' "$SERVER_PY" | head -1 | cut -d: -f1)"
if [ -n "$DISPATCH_LINE" ] && [ -n "$CROSS_LINE" ] && [ "$DISPATCH_LINE" -lt "$CROSS_LINE" ]; then
    ok "ingest dispatch sits before the browser cross-origin gate"
else
    no "ingest dispatch sits before the browser cross-origin gate"
fi
assert_contains 'def _handle_remote_ingest' "$(cat "$SERVER_PY")" "the ingest handler exists on the shipped handler"
assert_eq '1' "$(grep -c '\.is_allowed(' "$SERVER_PY")" "the whitelist keeps exactly one evaluation (no new exemption)"

# The PR-6C incident read route must not exist anywhere in web/.
if grep -rq 'incidents/<incident_id>/remote-probes' "$SERVER_DIR" 2>/dev/null; then
    no "no PR-6C incident remote-probes read route exists"
else
    ok "no PR-6C incident remote-probes read route exists"
fi
ROUTE_FILES="$(grep -rl 'remote-probes' "$SERVER_DIR" "$WEBAPP" 2>/dev/null | grep -v '__pycache__' | xargs -n1 basename 2>/dev/null | sort | tr '\n' ' ')"
assert_eq 'remote_registry.py remote_store.py server.py ' "$ROUTE_FILES" \
    "server remote surface is exactly the frozen PR-6B web file set"

# Reverse-proxy template contract.
PROXY_TXT="$(cat "$PROXY_CONF")"
assert_contains 'location = /api/v1/remote-probes/ingest' "$PROXY_TXT" "proxy exposes the exact ingest path"
assert_eq '1' "$(printf '%s' "$PROXY_TXT" | grep -c 'proxy_pass')" "proxy forwards to exactly one upstream"
assert_contains 'proxy_pass http://127.0.0.1' "$PROXY_TXT" "proxy upstream is loopback only"
assert_contains 'return 404' "$PROXY_TXT" "proxy answers 404 for every other path"
assert_contains 'client_max_body_size 16k' "$PROXY_TXT" "proxy enforces the 16 KiB body bound"
assert_contains 'ssl_certificate' "$PROXY_TXT" "proxy terminates TLS on the external side"
assert_contains 'proxy_redirect off' "$PROXY_TXT" "proxy never redirects the ingest call"
if printf '%s' "$PROXY_TXT" | grep -v '^[[:space:]]*#' | grep -qE 'X-Forwarded-For|X-Real-IP'; then
    no "proxy sets no forwarded headers (Monitor trusts the socket peer)"
else
    ok "proxy sets no forwarded headers (Monitor trusts the socket peer)"
fi

# Deploy / rollback tooling isolation.
DEPLOY_TXT="$(cat "$DEPLOY_LIB")"
case "$DEPLOY_TXT" in *remote-probes*) no "deploy tooling never references the remote store" ;; *) ok "deploy tooling never references the remote store" ;; esac
assert_contains 'SBMON_HISTORY_DB_REL="diagnostics/history.sqlite3"' "$DEPLOY_TXT" "deploy keeps the exact History DB path"
assert_contains 'history-prestate-$1.sqlite3' "$DEPLOY_TXT" "History prestate backup stays an exact path"

# 0.6.1 (the previous release) shipped no remote plane at all: a rollback
# to it ignores the independent remote path by construction.
PREV_TREE="7bb925be9496605d7e130c8970f9a0a6b4eedcf6"
PREV_HITS=0
for module in remote_ingest.py remote_registry.py remote_store.py; do
    if git -C "$ROOT" cat-file -e "$PREV_TREE:monitor-v2/web/$module" 2>/dev/null; then
        PREV_HITS=$((PREV_HITS + 1))
    fi
done
assert_eq '0' "$PREV_HITS" "the previous release tree carries no remote-plane code"

if bash -n "$0"; then ok "lane is POSIX-parseable"; else no "lane is POSIX-parseable"; fi

echo "== S1: deterministic behaviour harness =="

HARNESS_OUT="$("$PY3" tests/remote-server/server_groups.py 2>&1)"
HARNESS_RC=$?
printf '%s\n' "$HARNESS_OUT" | grep -E '^(PASS|FAIL) ' | while read -r line; do
    printf '  %s\n' "$line"
done
H_PASS="$(printf '%s\n' "$HARNESS_OUT" | grep -cE '^PASS ')"
H_FAIL="$(printf '%s\n' "$HARNESS_OUT" | grep -cE '^FAIL ')"
pass=$((pass + H_PASS))
fail=$((fail + H_FAIL))
if [ "$HARNESS_RC" -eq 0 ]; then
    ok "server_groups.py exited rc=0"
else
    no "server_groups.py exited rc=$HARNESS_RC (a crashing harness is itself a gate)"
fi

TOTAL=$((pass + fail))
printf '== RESULT ==\n'
printf 'checks: %d passed, %d failed (expected %d)\n' "$pass" "$fail" "187"
if [ "$fail" -eq 0 ] && [ "$TOTAL" -eq 187 ]; then
    printf '== PR-6B server ingest suite: GREEN ==\n'
    exit 0
fi
printf '== PR-6B server ingest suite: FAILED ==\n'
exit 1
