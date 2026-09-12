#!/usr/bin/env bash
# Monitor v2 Phase E4 regression tests -- OPTIONAL Mihomo local API enrichment.
#
# E4 is optional CLIENT-side enrichment, never an identity source. Every test
# drives monitor-v2/mihomo/{client,model}.py either with fixture payloads
# shaped exactly like the real Mihomo REST contract (verified against
# MetaCubeX/mihomo hub/route/ + tunnel/statistic/ + adapter/ source) or over a
# real loopback HTTP server (wire sections). The server Monitor (E1) is
# exercised in the same process as a failing Mihomo API to prove separation.
#
# Identity boundary, loopback-only rule, Authorization-header-only secret
# handling, 1-3s timeout clamp and read-only GET-only enforcement are all
# regression-guarded here.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
MIHOMO="$ROOT/monitor-v2/mihomo"
CLIENT="$MIHOMO/client.py"
MODEL="$MIHOMO/model.py"
PY="${PYTHON:-python3}"
export MIHOMO_FIX="$MIHOMO/fixtures"
export MIHOMO_DIR="$MIHOMO"

PASS=0
FAIL=0
# The gate at the bottom of this file fails unless exactly this many
# assertions ran AND passed, so unreachable sections can never fake success.
EXPECTED_PASS=101
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if printf '%s' "$2" | grep -qF "$1"; then pass "$3"; else fail "$3 (missing: $1)"; fi; }
assert_not_contains() { if printf '%s' "$2" | grep -qF "$1"; then fail "$3 (forbidden: $1)"; else pass "$3"; fi; }

mihomo_py() {
    PYTHONPATH="$MIHOMO" "$PY" -c "$1"
}

field() {
    printf '%s' "$1" | PYTHONPATH="$MIHOMO" "$PY" -c \
        'import json,sys; obj=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2"
}

# Shared fixture-transport preamble: routes map path -> (status, body bytes);
# fail map path -> exception to raise instead.
PY_PREAMBLE='
import json, os, sys
FIX = os.environ["MIHOMO_FIX"]
def load(name): return open(os.path.join(FIX, name), "rb").read()
class FakeTransport:
    def __init__(self, routes, fail=None):
        self.routes = routes; self.fail = fail or {}
    def request(self, method, path):
        if path in self.fail: raise self.fail[path]
        status, body = self.routes[path]
        return status, body
    def read_stream_sample(self, path, deadline):
        if path in self.fail: raise self.fail[path]
        return self.routes[path][1]
'

section "static checks"
if "$PY" -m py_compile "$CLIENT" 2>"$TMP/py.err"; then pass "py_compile client.py"; else fail "py_compile client.py: $(cat "$TMP/py.err")"; fi
if "$PY" -m py_compile "$MODEL" 2>>"$TMP/py.err"; then pass "py_compile model.py"; else fail "py_compile model.py: $(cat "$TMP/py.err")"; fi
[ -f "$MIHOMO/README.md" ] && pass "E4 architecture README present" || fail "E4 architecture README missing"
FIX_OK=1
for f in version-ok.json configs-rule.json proxies-ok.json proxies-switched.json \
         proxies-no-now.json configs-missing-mode.json connections-active.json \
         connections-idle-null.json connections-missing-key.json \
         traffic-sample.json malformed.json unauthorized.json; do
    [ -f "$MIHOMO_FIX/$f" ] || FIX_OK=0
done
[ "$FIX_OK" = "1" ] && pass "all E4 fixtures present" || fail "E4 fixture files missing"
if grep -qE "'(PUT|POST|DELETE|PATCH)'|\"(PUT|POST|DELETE|PATCH)\"" "$MIHOMO"/*.py 2>/dev/null; then
    fail "control-plane method literal found in mihomo/*.py (read-only mandate)"
else
    pass "mihomo adapter issues GET only (no control-plane method literals)"
fi
if grep -qE 'urlopen|import requests|http\.server' "$MIHOMO"/*.py 2>/dev/null; then
    fail "forbidden HTTP usage in mihomo/*.py"
else
    pass "mihomo adapter uses stdlib http.client only"
fi
if grep -qF '"user"' "$MIHOMO"/*.py 2>/dev/null || grep -qF '"device"' "$MIHOMO"/*.py 2>/dev/null \
    || grep -qF '"inbound"' "$MIHOMO"/*.py 2>/dev/null; then
    fail "identity field literal found in mihomo/*.py"
else
    pass "no identity field literal anywhere in the adapter"
fi
if grep -qE '^[[:space:]]*(import|from)[[:space:]].*(collector|api_bridge|singbox)' "$MIHOMO"/*.py 2>/dev/null; then
    fail "mihomo adapter imports server-side monitor code"
else
    pass "mihomo adapter imports nothing from the server monitor"
fi
if grep -qF 'token=' "$MIHOMO"/*.py 2>/dev/null; then
    fail "query-string credential pattern found in mihomo/*.py"
else
    pass "no query-string credential pattern in mihomo/*.py"
fi

section "E4-01: controller URL is loopback-only, fail-closed"
out="$(mihomo_py '
from client import parse_controller_url
print(repr(parse_controller_url("http://127.0.0.1:9090")))
')"
assert_eq "$out" "('127.0.0.1', 9090, 'http')" "plain loopback URL parses"
out="$(mihomo_py '
from client import parse_controller_url
print(repr(parse_controller_url("http://localhost")))
')"
assert_eq "$out" "('localhost', 9090, 'http')" "default port 9090"
out="$(mihomo_py '
from client import parse_controller_url
print(repr(parse_controller_url("http://[::1]:9097")))
')"
assert_eq "$out" "('::1', 9097, 'http')" "IPv6 loopback accepted"
for bad in "http://192.168.1.5:9090" "http://0.0.0.0:9090" "http://example.com:9090"; do
    out="$(mihomo_py "
from client import parse_controller_url, ConfigurationError
try:
    parse_controller_url('$bad')
    print('ACCEPTED')
except ConfigurationError:
    print('REFUSED')
")"
    assert_eq "$out" "REFUSED" "non-loopback target refused: $bad"
done
out="$(mihomo_py "
from client import parse_controller_url, ConfigurationError
try:
    parse_controller_url('ftp://127.0.0.1:9090')
    print('ACCEPTED')
except ConfigurationError:
    print('REFUSED')
")"
assert_eq "$out" "REFUSED" "non-http scheme refused"
out="$(mihomo_py "
from client import parse_controller_url, ConfigurationError
try:
    parse_controller_url('http://127.0.0.1:9090?x=1')
    print('ACCEPTED')
except ConfigurationError:
    print('REFUSED')
")"
assert_eq "$out" "REFUSED" "query string in URL refused"

section "E4-02: reachable API -- full happy path from fixtures"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/configs\": (200, load(\"configs-rule.json\")),
    \"/proxies\": (200, load(\"proxies-ok.json\")),
    \"/connections\": (200, load(\"connections-active.json\")),
    \"/traffic\": (200, load(\"traffic-sample.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"PROXY\", transport=t,
                 clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "reachable true"
assert_eq "$(field "$out" 'obj["version"]')" "v1.19.13" "version from /version"
assert_eq "$(field "$out" 'obj["mode"]')" "rule" "mode from /configs"
assert_eq "$(field "$out" 'obj["selected_group"]')" "PROXY" "selected group echoed"
assert_eq "$(field "$out" 'obj["selected_proxy"]')" "vmix-01-HY2" "selected node display name from group now"
assert_eq "$(field "$out" 'obj["delay_ms"]')" "82" "delay from the SELECTED NODE history (not the group)"
assert_eq "$(field "$out" 'obj["active_connections"]')" "3" "active local connections"
assert_eq "$(field "$out" 'obj["traffic_up_bps"]')" "1234" "optional traffic up (one /traffic sample)"
assert_eq "$(field "$out" 'obj["traffic_down_bps"]')" "5678" "optional traffic down"
assert_eq "$(field "$out" 'obj["stale"]')" "False" "fresh sample is not stale"
assert_eq "$(field "$out" 'obj["error"]')" "None" "no error on the happy path"
assert_eq "$(field "$out" 'obj["updated_at"]')" "2025-10-09T08:53:20+00:00" "sample carries its own updated_at"
assert_eq "$(field "$out" 'sorted(obj.keys())')" \
    "['active_connections', 'delay_ms', 'error', 'mode', 'reachable', 'selected_group', 'selected_proxy', 'stale', 'traffic_down_bps', 'traffic_up_bps', 'updated_at', 'version']" \
    "output keys are exactly the enrichment whitelist"

section "E4-03: unreachable API -- observation, never an exception"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({}, fail={\"/version\": ConnectionRefusedError(\"connection refused by peer\")})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"PROXY\", transport=t,
                 clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "False" "unreachable -> reachable false"
assert_contains "ConnectionRefusedError" "$out" "error names the transport failure"
assert_eq "$(field "$out" 'obj["version"]')" "None" "version unknown"
assert_eq "$(field "$out" 'obj["mode"]')" "None" "mode unknown"
assert_eq "$(field "$out" 'obj["active_connections"]')" "None" "connections unknown"
assert_eq "$(field "$out" 'obj["stale"]')" "False" "freshly failed sample is not (yet) stale"
assert_contains "updated_at" "$out" "failed sample is still dated"

section "E4-04: timeout semantics + 1-3s clamp"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({}, fail={\"/version\": TimeoutError(\"timed out\")})
c = MihomoClient(url=\"http://127.0.0.1:9090\", transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "False" "timeout -> reachable false"
assert_contains "TimeoutError" "$out" "error names the timeout"
assert_eq "$(field "$out" 'obj["active_connections"]')" "None" "no fields invented after a timeout"
out="$(mihomo_py '
from client import clamp_timeout
print("%s/%s/%s" % (clamp_timeout(0.1), clamp_timeout(10), clamp_timeout(2.5)))
')"
assert_eq "$out" "1.0/3.0/2.5" "request timeout clamped into the 1-3s budget"

section "E4-05: invalid secret (401) -- still just an observation"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({\"/version\": (401, load(\"unauthorized.json\"))})
c = MihomoClient(url=\"http://127.0.0.1:9090\", secret=\"s3cr3t-MIHOMO-TOKEN\",
                 transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "False" "401 -> reachable false"
assert_contains "401" "$out" "error reports the HTTP status"
assert_eq "$(field "$out" 'obj["version"]')" "None" "no version without auth"
assert_eq "$(field "$out" 'obj["active_connections"]')" "None" "no enrichment without auth"

section "E4-06: malformed JSON -- per-endpoint isolation"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({\"/version\": (200, load(\"malformed.json\"))})
c = MihomoClient(url=\"http://127.0.0.1:9090\", transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "False" "malformed /version -> unreachable"
assert_contains "malformed JSON" "$out" "error explains the decode failure"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"configs\": (200, load(\"configs-rule.json\")),
    \"/configs\": (200, load(\"configs-rule.json\")),
    \"/proxies\": (200, load(\"malformed.json\")),
    \"/connections\": (200, load(\"connections-active.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"PROXY\", transport=t,
                 clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "malformed OPTIONAL endpoint keeps the sample reachable"
assert_eq "$(field "$out" 'obj["selected_proxy"]')" "None" "broken /proxies nulls only its own field"
assert_contains "/proxies returned malformed JSON" "$out" "error points at the broken endpoint"
assert_eq "$(field "$out" 'obj["active_connections"]')" "3" "other endpoints still enriched"

section "E4-07: missing optional fields degrade to null/0, never crash"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/configs\": (200, load(\"configs-missing-mode.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "reachable despite missing mode"
assert_eq "$(field "$out" 'obj["mode"]')" "None" "missing mode key -> null"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/proxies\": (200, load(\"proxies-no-now.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"PROXY\", transport=t,
                 clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["selected_proxy"]')" "None" "group without now -> no selected node"
assert_eq "$(field "$out" 'obj["delay_ms"]')" "None" "no selection -> no delay"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/connections\": (200, load(\"connections-missing-key.json\")),
    \"/traffic\": (200, b\"this is not json\\n\"),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["active_connections"]')" "0" "connections key absent -> 0 (empty is data)"
assert_eq "$(field "$out" 'obj["traffic_up_bps"]')" "None" "garbage traffic line -> null rate"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "optional garbage never breaks reachability"

section "E4-08: changing selected node -- display only, never identity"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
from model import is_identity_safe
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/proxies\": (200, load(\"proxies-switched.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"PROXY\", transport=t,
                 clock=lambda: 1760000000.0)
e = c.collect()
print(json.dumps({\"selected\": e[\"selected_proxy\"], \"safe\": is_identity_safe(e)}))
")"
assert_eq "$(field "$out" 'obj["selected"]')" "香港-01" "selection change is followed verbatim (display only)"
assert_eq "$(field "$out" 'obj["safe"]')" "True" "enrichment stays identity-safe"
assert_not_contains '"user"' "$out" "no identity key in the output"
assert_not_contains '"device"' "$out" "no device key in the output"

section "E4-09: delay null cases + group not found"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/proxies\": (200, load(\"proxies-ok.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"BACKUP\", transport=t,
                 clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["selected_proxy"]')" "vmix-01-Reality" "URLTest group selection read the same way"
assert_eq "$(field "$out" 'obj["delay_ms"]')" "None" "delay 0 means FAILED probe -> null, never 0 ms"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/proxies\": (200, load(\"proxies-ok.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", group=\"NOPE\", transport=t,
                 clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "unknown group name does not break reachability"
assert_contains "not found" "$out" "unknown group reported in error"

section "E4-10: local connections edge cases"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/connections\": (200, load(\"connections-idle-null.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["active_connections"]')" "0" "connections null (idle core) -> 0"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/connections\": (200, b\"[]\"),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_eq "$(field "$out" 'obj["active_connections"]')" "None" "non-object connections payload -> unknown, not 0"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "still reachable"

section "E4-11: freshness -- enrichment stale is its OWN domain"
out="$(mihomo_py '
import datetime, json
from model import apply_freshness, is_identity_safe, new_enrichment
base = new_enrichment(); base["reachable"] = True; base["mode"] = "rule"
T0 = datetime.datetime(2026, 9, 12, 12, 0, 0, tzinfo=datetime.timezone.utc)
def at(offset):
    e = dict(base)
    e["updated_at"] = (T0 + datetime.timedelta(seconds=offset)).isoformat()
    return e
f10 = apply_freshness(at(0), T0 + datetime.timedelta(seconds=10))
f30 = apply_freshness(at(0), T0 + datetime.timedelta(seconds=30))
f60 = apply_freshness(at(0), T0 + datetime.timedelta(seconds=60))
no_date = dict(base); del no_date["updated_at"]
apply_freshness(no_date, T0 + datetime.timedelta(seconds=10))
print(json.dumps({
  "fresh": f10["stale"],
  "boundary": f30["stale"],
  "old": f60["stale"],
  "undated": no_date["stale"],
  "mode_kept": f60["mode"],
  "safe": is_identity_safe(f60),
}))
')"
assert_eq "$(field "$out" 'obj["fresh"]')" "False" "10s old sample with 30s max age: not stale"
assert_eq "$(field "$out" 'obj["boundary"]')" "False" "exactly max_age: not stale (age must EXCEED)"
assert_eq "$(field "$out" 'obj["old"]')" "True" "60s old sample: stale"
assert_eq "$(field "$out" 'obj["undated"]')" "True" "unknown updated_at: stale by definition"
assert_eq "$(field "$out" 'obj["mode_kept"]')" "rule" "stale marking changes only the stale flag"
assert_eq "$(field "$out" 'obj["safe"]')" "True" "freshness pass keeps the object identity-safe"

section "E4-12: secret never leaks -- not into logs, output, or URLs"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
class LoudFailure(FakeTransport):
    def request(self, method, path):
        raise ConnectionRefusedError(\"connect failed: secret=s3cr3t-MIHOMO-TOKEN\")
t = LoudFailure({})
c = MihomoClient(url=\"http://127.0.0.1:9090\", secret=\"s3cr3t-MIHOMO-TOKEN\",
                 transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_not_contains "s3cr3t-MIHOMO-TOKEN" "$out" "secret redacted out of the error text"
assert_contains "[redacted]" "$out" "redaction marker present instead"
out="$(mihomo_py "$PY_PREAMBLE
from client import MihomoClient
t = FakeTransport({
    \"/version\": (200, load(\"version-ok.json\")),
    \"/configs\": (200, load(\"configs-rule.json\")),
    \"/connections\": (200, load(\"connections-active.json\")),
})
c = MihomoClient(url=\"http://127.0.0.1:9090\", secret=\"s3cr3t-MIHOMO-TOKEN\",
                 transport=t, clock=lambda: 1760000000.0)
print(json.dumps(c.collect()))
")"
assert_not_contains "s3cr3t-MIHOMO-TOKEN" "$out" "secret never serialized into the success output"
out="$(mihomo_py '
import json, os, sys, tempfile
sys.path.insert(0, os.environ["MIHOMO_DIR"])
from client import resolve_secret
fd, f = tempfile.mkstemp(suffix=".secret"); os.write(fd, b"file-secret"); os.close(fd)
os.environ["MIHOMO_API_SECRET"] = "env-secret-wins"
r_env = resolve_secret(f)
del os.environ["MIHOMO_API_SECRET"]
r_file = resolve_secret(f)
os.unlink(f)
print(json.dumps({"env": r_env, "file": r_file}))
')"
assert_eq "$(field "$out" 'obj["env"]')" "env-secret-wins" "MIHOMO_API_SECRET env wins over file"
assert_eq "$(field "$out" 'obj["file"]')" "file-secret" "secret file read when env unset"

section "E4-W1: real loopback wire path -- auth header, GET-only, no query string"
out="$(mihomo_py '
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.environ["MIHOMO_DIR"])
from client import MihomoClient
FIX = os.environ["MIHOMO_FIX"]
SECRET = "s3cr3t-MIHOMO-TOKEN"
seen = {"auth": [], "paths": [], "methods": []}
def fix(name): return open(os.path.join(FIX, name), "rb").read()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        seen["methods"].append(self.command)
        seen["paths"].append(self.path)
        seen["auth"].append(self.headers.get("Authorization"))
        if self.headers.get("Authorization") != "Bearer " + SECRET:
            self.send_response(401); body = fix("unauthorized.json")
        else:
            routes = {"/version": "version-ok.json", "/configs": "configs-rule.json",
                      "/proxies": "proxies-ok.json", "/connections": "connections-active.json",
                      "/traffic": "traffic-sample.json"}
            name = routes.get(self.path.split("?")[0])
            if name is None:
                self.send_response(404); body = b"{}"
            else:
                self.send_response(200); body = fix(name)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    good = MihomoClient(url="http://127.0.0.1:%d" % port, group="PROXY", secret=SECRET)
    e = good.collect()
    print(json.dumps({
        "reachable": e["reachable"], "version": e["version"], "delay": e["delay_ms"],
        "conns": e["active_connections"], "traffic_up": e["traffic_up_bps"],
        "auth": seen["auth"][0], "methods": sorted(set(seen["methods"])),
        "paths": seen["paths"],
    }))
finally:
    server.shutdown()
')"
assert_eq "$(field "$out" 'obj["reachable"]')" "True" "real HTTP transport reaches the controller"
assert_eq "$(field "$out" 'obj["version"]')" "v1.19.13" "real wire version"
assert_eq "$(field "$out" 'obj["delay"]')" "82" "real wire selected-node delay"
assert_eq "$(field "$out" 'obj["conns"]')" "3" "real wire connection count"
assert_eq "$(field "$out" 'obj["traffic_up"]')" "1234" "real wire traffic sample"
assert_eq "$(field "$out" 'obj["auth"]')" "Bearer s3cr3t-MIHOMO-TOKEN" "secret sent as Authorization Bearer header"
assert_eq "$(field "$out" 'obj["methods"]')" "['GET']" "GET is the only method ever issued"
assert_not_contains "?" "$(field "$out" 'json.dumps(obj["paths"])')" "no query string on any request path"

section "E4-W2: real wire wrong secret -> 401 observation, no leakage"
out="$(mihomo_py '
import json, os, sys, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
sys.path.insert(0, os.environ["MIHOMO_DIR"])
from client import MihomoClient
FIX = os.environ["MIHOMO_FIX"]
SECRET = "s3cr3t-MIHOMO-TOKEN"
def fix(name): return open(os.path.join(FIX, name), "rb").read()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + SECRET:
            self.send_response(401); body = fix("unauthorized.json")
        else:
            self.send_response(200); body = fix("version-ok.json")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
server = HTTPServer(("127.0.0.1", 0), Handler)
port = server.server_address[1]
threading.Thread(target=server.serve_forever, daemon=True).start()
try:
    bad = MihomoClient(url="http://127.0.0.1:%d" % port, secret="WRONG-secret")
    e = bad.collect()
    print(json.dumps({"reachable": e["reachable"], "error": e["error"]}))
finally:
    server.shutdown()
')"
assert_eq "$(field "$out" 'obj["reachable"]')" "False" "wrong secret over real wire -> reachable false"
assert_contains "401" "$out" "error reports the rejected status"
assert_not_contains "WRONG-secret" "$out" "the wrong secret is not echoed either"

section "E4-13: Mihomo down -- the server Monitor keeps working, domains stay disjoint"
out="$(PYTHONPATH="$ROOT/monitor-v2" MIHOMO_DIR="$MIHOMO" ROOTV2="$ROOT/monitor-v2" "$PY" -c '
import json, os, sys
sys.path.insert(0, os.environ["MIHOMO_DIR"])
sys.path.insert(0, os.environ["ROOTV2"])
from collector import Tracker
from client import MihomoClient, TransportError
class DeadTransport:
    def request(self, method, path): raise TransportError("ConnectionRefusedError: mihomo dead")
    def read_stream_sample(self, path, deadline): raise TransportError("ConnectionRefusedError: mihomo dead")
batch = json.load(open(os.path.join(os.environ["ROOTV2"], "fixtures", "events-initial-reset.json")))
t = Tracker()
t.apply_batch(batch, 1000)
server_snap = t.snapshot(1000)
enr = MihomoClient(url="http://127.0.0.1:9090", transport=DeadTransport(),
                   clock=lambda: 1760000000.0).collect()
print(json.dumps({
    "devices": sorted(server_snap["devices"]),
    "vmix_status": server_snap["devices"]["vmix-01"]["status"],
    "vmix_uplink": server_snap["devices"]["vmix-01"]["protocols"]["vless-in"]["uplink_total"],
    "reachable": enr["reachable"],
    "overlap": sorted(set(server_snap) & set(enr)),
    "enr_has_devices": "devices" in enr,
    "enr_identity_safe_keys": set(enr) <= {"reachable", "version", "mode", "selected_group",
        "selected_proxy", "delay_ms", "active_connections", "traffic_up_bps",
        "traffic_down_bps", "updated_at", "stale", "error"},
}))
')"
assert_eq "$(field "$out" 'obj["devices"]')" "['legacy', 'vmix-01']" "server devices unchanged while Mihomo is down"
assert_eq "$(field "$out" 'obj["vmix_status"]')" "ACTIVE" "device status untouched by the dead client API"
assert_eq "$(field "$out" 'obj["vmix_uplink"]')" "1000.0" "server accounting untouched"
assert_eq "$(field "$out" 'obj["reachable"]')" "False" "enrichment reports its own unreachable"
assert_eq "$(field "$out" 'obj["overlap"]')" "['active_connections']" "no identity key shared; only the coincidental active_connections name (server lifecycle count vs client-local API connections)"
assert_eq "$(field "$out" 'obj["enr_has_devices"]')" "False" "enrichment carries no devices collection"
assert_eq "$(field "$out" 'obj["enr_identity_safe_keys"]')" "True" "enrichment keys stay inside the whitelist"

section "E4-14: output sealing -- the whitelist is the boundary"
out="$(mihomo_py '
import json
from model import finish_enrichment, is_identity_safe, new_enrichment
snap = new_enrichment()
snap["reachable"] = True
snap["version"] = "v1.19.13"
snap["evil_device_identity"] = "vmix-01"   # a bug trying to smuggle identity in
sealed = finish_enrichment(snap, "2026-09-12T12:00:00+00:00")
print(json.dumps({"evil": "evil_device_identity" in sealed,
                  "safe": is_identity_safe(sealed)}))
')"
assert_eq "$(field "$out" 'obj["evil"]')" "False" "injected non-whitelisted key is structurally dropped"
assert_eq "$(field "$out" 'obj["safe"]')" "True" "sealed object remains identity-safe"
out="$(mihomo_py '
import json
from model import is_identity_safe
print(json.dumps({"extra": is_identity_safe({"reachable": True, "user": "vmix-01"})}))
')"
assert_eq "$(field "$out" 'obj["extra"]')" "False" "an object carrying an identity key fails the identity-safe check"

printf '\n== summary ==\n'
printf '  pass=%d fail=%d (expected pass=%d)\n' "$PASS" "$FAIL" "$EXPECTED_PASS"
if [ "$FAIL" -ne 0 ] || [ "$PASS" -ne "$EXPECTED_PASS" ]; then
    printf '  RESULT: FAILED (failures, or a section did not run)\n'
    exit 1
fi
printf '  RESULT: ALL GREEN\n'
exit 0
