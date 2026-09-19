#!/usr/bin/env bash
# Monitor v2 Phase M0.5 regression tests -- G3 step-up + G4 monitor boundary.
#
# Scope (rev5 §5 / §4.5 / §9.2 G3+G4): the step-up authorization boundary,
# its five revocation events, the shared login rate limiter, the orthogonal
# monitor_running / management_active status model, and the monitor unit's
# hardened privilege boundary.
#
# Everything HTTP runs against a REAL loopback server with the client socket
# bound to a controlled source address, exactly like the E2 suite. This suite
# deliberately proves ONE negative fact over and over: no request -- with or
# without a session, CSRF token, or step-up -- can make this build mutate
# anything. The privileged backend is M1/M2 work.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/.." && pwd)"
PY="${PYTHON:-python3}"
export MONITOR_V2_ROOT="$ROOT/monitor-v2"
export WEBAPP="$ROOT/monitor-v2/webapp.py"
export STATIC_DIR="$ROOT/monitor-v2/web/static"

PASS=0
FAIL=0
SKIP=0
# Platform-INDEPENDENT size of the suite. Every assertion either passes, fails
# or is explicitly skipped; the gate at the bottom requires
# PASS + FAIL + SKIP == EXPECTED_TOTAL, so a section that silently disappears
# (the classic "fewer assertions but still green") can never fake success.
EXPECTED_TOTAL=136
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
# skip <how-many-assertions> <label> -- explicit, counted, never a silent pass
skip() { SKIP=$((SKIP + ${1:-1})); shift; printf '  SKIP %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }
assert_eq() { if [ "$1" = "$2" ]; then pass "$3"; else fail "$3 (want '$2', got '$1')"; fi; }
assert_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -gt 0 ]; then pass "$3"; else fail "$3 (missing: $1)"; fi; }
assert_not_contains() { if [ "$(printf '%s' "$2" | grep -cF -- "$1")" -eq 0 ]; then pass "$3"; else fail "$3 (forbidden: $1)"; fi; }

section "static checks: step-up boundary + zero filesystem bridge"
WEB_PY="$ROOT/monitor-v2/web/__init__.py $ROOT/monitor-v2/web/access.py $ROOT/monitor-v2/web/auth.py $ROOT/monitor-v2/web/broker.py $ROOT/monitor-v2/web/e3_broker.py $ROOT/monitor-v2/web/e3rpc.py $ROOT/monitor-v2/web/recovery.py $ROOT/monitor-v2/web/server.py $ROOT/monitor-v2/web/storage.py $ROOT/monitor-v2/webapp.py"
if "$PY" -m py_compile $WEB_PY 2>"$TMP/py.err"; then
    pass "py_compile web backend"
else
    fail "py_compile web backend: $(cat "$TMP/py.err")"
fi
if node --check "$ROOT/monitor-v2/web/static/app.js" 2>"$TMP/js.err" 2>&1; then
    pass "node --check app.js"
else
    fail "node --check app.js: $(cat "$TMP/js.err")"
fi
WEB_SRC="$(cat $WEB_PY)"
SERVER_SRC="$(cat "$ROOT/monitor-v2/web/server.py")"
INDEX_SRC="$(cat "$ROOT/monitor-v2/web/static/index.html")"
APP_SRC="$(cat "$ROOT/monitor-v2/web/static/app.js")"
assert_contains 'reauth_required' "$SERVER_SRC" "backend emits the reauth_required signal"
assert_contains 'reauth_required' "$APP_SRC" "frontend keys its password panel on reauth_required"
assert_contains 'error.code === "reauth_required"' "$APP_SRC" "the panel is opened ONLY by that machine code"
assert_contains '/api/v1/step-up' "$SERVER_SRC" "backend exposes the step-up endpoint"
assert_contains 'verify_password' "$SERVER_SRC" "step-up reuses the existing password verification"
assert_not_contains 'verify_secret' "$SERVER_SRC" "step-up never reaches for a second verification path"
assert_contains 'login_limiter' "$WEB_SRC" "step-up shares the existing login rate limiter"
assert_contains 'management.activate' "$WEB_SRC" "the four-op mutation boundary is declared"
assert_contains 'client.delete' "$WEB_SRC" "the four-op mutation boundary is declared (client.delete)"
assert_contains 'e3_unavailable' "$SERVER_SRC" "the mutation boundary fails closed without an E3 backend (M2; the M0.5 501 was replaced by the real adapter)"
assert_contains 'id="stepup-overlay" class="overlay hidden"' "$INDEX_SRC" "the password panel is hidden on load (never asked proactively)"
assert_contains 'Management plane' "$INDEX_SRC" "the dashboard renders the orthogonal status model"
# T12 (static half): no code path in the web process addresses either
# privileged tree. There is no read, no write, no path constant -- the only
# future channel is the sbox-cm RPC.
assert_not_contains '/root/sbox' "$WEB_SRC" "T12: web code never references the proxy tree"
assert_not_contains '/var/lib/sbox-cm' "$WEB_SRC" "T12: web code never references the sbox-cm runtime tree"
assert_not_contains 'sbconfig' "$WEB_SRC" "web code never touches sbconfig_server.json"
# The activation marker filename must not appear anywhere in the web process:
# the ONLY legitimate future source of management_active is the
# management.status RPC from sbox-cm (M1), never a stat/open of the marker.
assert_not_contains 'management.active' "$WEB_SRC" "web code never names (let alone reads) the activation marker"

section "unit hardening: singbox-monitor.service privilege boundary (G4)"
UNIT="$TMP/singbox-monitor.service"
sed -e 's|@SBMON_USER@|sboxweb|g' \
    -e 's|@SBMON_GROUP@|sboxweb|g' \
    -e 's|@SBMON_APP_DIR@|/opt/singbox-monitor|g' \
    -e 's|@SBMON_CONF@|/etc/singbox-monitor/monitor.conf|g' \
    -e 's|@SBMON_STATE_ROOT@|/var/lib/singbox-monitor|g' \
    "$ROOT/monitor-v2/deploy/singbox-monitor.service.in" > "$UNIT"
UNIT_SRC="$(cat "$UNIT")"
assert_eq "User=sboxweb" "$(grep '^User=' "$UNIT")" "unit runs as the non-privileged monitor user"
assert_eq "Group=sboxweb" "$(grep '^Group=' "$UNIT")" "unit runs in the monitor group"
assert_eq "NoNewPrivileges=true" "$(grep '^NoNewPrivileges=' "$UNIT")" "unit can never gain privileges"
assert_eq "PrivateTmp=true" "$(grep '^PrivateTmp=' "$UNIT")" "unit gets a private /tmp"
assert_eq "ProtectSystem=strict" "$(grep '^ProtectSystem=' "$UNIT")" "unit filesystem is read-only except explicit exceptions"
assert_eq "ProtectHome=yes" "$(grep '^ProtectHome=' "$UNIT")" "unit cannot see /root (or /home)"
assert_eq "ProtectKernelTunables=true" "$(grep '^ProtectKernelTunables=' "$UNIT")" "unit cannot tune the kernel"
assert_eq "ProtectKernelModules=true" "$(grep '^ProtectKernelModules=' "$UNIT")" "unit cannot load kernel modules"
assert_eq "ProtectControlGroups=true" "$(grep '^ProtectControlGroups=' "$UNIT")" "unit cannot write cgroup controls"
assert_eq "RestrictSUIDSGID=true" "$(grep '^RestrictSUIDSGID=' "$UNIT")" "unit cannot create setuid/setgid files"
assert_eq "CapabilityBoundingSet=" "$(grep '^CapabilityBoundingSet=' "$UNIT")" "unit drops the whole capability bounding set"
assert_eq "AmbientCapabilities=" "$(grep '^AmbientCapabilities=' "$UNIT")" "unit holds zero ambient capabilities"
assert_eq "1" "$(grep -c '^ReadWritePaths=' "$UNIT")" "unit declares EXACTLY ONE writable exception"
assert_eq "ReadWritePaths=/var/lib/singbox-monitor" "$(grep '^ReadWritePaths=' "$UNIT")" "the only writable path is the monitor's own data root (M2 final review B5: least privilege restored)"
RW_ROOT="$(grep '^ReadWritePaths=' "$UNIT" | grep -F '/root/sbox' || true)"
assert_eq "" "$RW_ROOT" "T12: the unit opens NO write path into /root/sbox"
RW_CM="$(grep '^ReadWritePaths=' "$UNIT" | grep -F '/var/lib/sbox-cm' || true)"
assert_eq "" "$RW_CM" "T12: the unit opens NO write path into the sbox-cm runtime tree"
assert_eq "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX" "$(grep '^RestrictAddressFamilies=' "$UNIT")" \
    "monitor keeps AF_INET/AF_INET6 (it is a loopback client+listener); NOT collapsed to AF_UNIX-only"

# ---------------------------------------------------------------------------
# T12 runtime half: the privileged trees must be unreachable IN PRACTICE, not
# only "not mentioned in source". Two independent, real checks:
#   (a) the authoritative kernel invariant -- the trees are root-owned and
#       owner-only (or absent). This is what actually stops sboxweb; M1 must
#       re-verify it once /var/lib/sbox-cm exists.
#   (b) an ACTIVE probe: actually attempt to read /root, /root/sbox and the
#       sbox-cm runtime tree as a non-root identity and require refusal.
# (b) needs a foreign identity; when the environment cannot provide one we
# print an explicit SKIP (never a silent pass) and lower the expected count
# accordingly, so the gate still proves every assertion that ran, passed.
# ---------------------------------------------------------------------------
BOUNDARY_PY="$TMP/boundary_probe.py"
cat > "$BOUNDARY_PY" <<'PROBE_EOF'
#!/usr/bin/env python3
"""Actual filesystem probe for the privileged trees.

Default mode: attempt real access and report the outcome.
--modes:      report the authoritative ownership/permission invariant.
Verdicts: absent | denied | allowed | owner-only | loose | wrong-owner |
          not-a-dir | unreadable | not-posix.
"""
import json
import os
import sys

PATHS = ("/root", "/root/sbox", "/var/lib/sbox-cm")

def probe(path):
    if os.name != "posix":
        return "not-posix"
    try:
        if os.path.isdir(path):
            os.listdir(path)
        else:
            with open(path, "rb") as handle:
                handle.read(1)
    except FileNotFoundError:
        return "absent"
    except PermissionError:
        return "denied"
    except OSError:
        return "denied"
    return "allowed"

def modes(path):
    if os.name != "posix":
        return "not-posix"
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "absent"
    except PermissionError:
        # The kernel refused even a stat: strictly stronger than "owner-only"
        # (e.g. /root/sbox observed by an unprivileged test identity).
        return "denied-to-stat"
    except OSError:
        return "unreadable"
    if st.st_uid != 0:
        return "wrong-owner"
    if st.st_mode & 0o077:
        return "loose"
    if not os.path.isdir(path):
        return "not-a-dir"
    return "owner-only"

mode = "--modes" in sys.argv[1:]
report = modes if mode else probe
print(json.dumps({p: report(p) for p in PATHS}, sort_keys=True))
PROBE_EOF
# The foreign-identity probe runs as another account, which must be able to
# traverse the temp dir and read the probe itself. Nothing secret lives in
# $TMP (booleans, unit text, test constants only).
chmod 0755 "$TMP" 2>/dev/null || true
chmod 0644 "$BOUNDARY_PY" 2>/dev/null || true
# Compile-checked on EVERY platform so heredoc rot can never hide behind a
# POSIX-only skip.
if "$PY" -m py_compile "$BOUNDARY_PY" 2>"$TMP/probe.err"; then
    pass "boundary probe compiles (checked everywhere, not only where it runs)"
else
    fail "boundary probe does not compile: $(cat "$TMP/probe.err")"
fi

BOUNDARY_POSIX=0
case "$(uname -s 2>/dev/null)" in
    Linux|Darwin|FreeBSD|OpenBSD|NetBSD) BOUNDARY_POSIX=1 ;;
esac

if [ "$BOUNDARY_POSIX" = 1 ]; then
    MODES_JSON="$("$PY" "$BOUNDARY_PY" --modes 2>/dev/null || printf '{}')"
    mode_of() {
        printf '%s' "$MODES_JSON" | "$PY" -c \
            'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' \
            "$1" 2>/dev/null || printf ''
    }
    assert_eq "owner-only" "$(mode_of /root)" \
        "T12 invariant: /root is root-owned and owner-only (kernel-enforced, not a source assertion)"
    case "$(mode_of /root/sbox)" in
        absent|owner-only|denied-to-stat)
            pass "T12 invariant: /root/sbox is absent, root-only, or unstattable (no readable path for sboxweb)" ;;
        *)
            fail "T12 invariant: /root/sbox is reachable by group/other (verdict: $(mode_of /root/sbox))" ;;
    esac
    case "$(mode_of /var/lib/sbox-cm)" in
        absent|owner-only|denied-to-stat)
            pass "T12 invariant: sbox-cm runtime tree is absent, root:root owner-only, or unstattable (M1 must keep this)" ;;
        *)
            fail "T12 invariant: sbox-cm runtime tree is reachable by group/other (verdict: $(mode_of /var/lib/sbox-cm))" ;;
    esac

    # (b) active probe as a foreign, non-root identity.
    RUN_AS=""
    FOREIGN_LABEL=""
    if [ "$(id -u 2>/dev/null)" != "0" ]; then
        RUN_AS="self"
        FOREIGN_LABEL="$(id -un 2>/dev/null || printf 'current user')"
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        if id -u sboxweb >/dev/null 2>&1; then
            RUN_AS="sudo:sboxweb"; FOREIGN_LABEL="sboxweb"
        elif id -u nobody >/dev/null 2>&1; then
            RUN_AS="sudo:nobody"; FOREIGN_LABEL="nobody"
        fi
    fi
    PROBE_OUT=""
    if [ "$RUN_AS" = "self" ]; then
        PROBE_OUT="$("$PY" "$BOUNDARY_PY" 2>/dev/null || true)"
    elif [ -n "$RUN_AS" ]; then
        PROBE_OUT="$(sudo -n -u "${RUN_AS#sudo:}" -- "$(command -v "$PY" || printf '%s' "$PY")" \
            "$BOUNDARY_PY" 2>/dev/null || true)"
    fi
    if [ -n "$RUN_AS" ]; then
        probe_of() {
            printf '%s' "$PROBE_OUT" | "$PY" -c \
                'import json,sys; print(json.load(sys.stdin).get(sys.argv[1], ""))' \
                "$1" 2>/dev/null || printf ''
        }
        for path in /root /root/sbox /var/lib/sbox-cm; do
            verdict="$(probe_of "$path")"
            case "$verdict" in
                denied|absent)
                    pass "T12 runtime: actual access to $path refused/absent as $FOREIGN_LABEL" ;;
                *)
                    fail "T12 runtime: access to $path was NOT refused as $FOREIGN_LABEL (verdict: '${verdict:-probe produced no output}')" ;;
            esac
        done
    else
        skip 3 "T12 runtime active probe (no non-root identity enforceable here: run unprivileged, or provide sboxweb/nobody plus passwordless sudo)"
    fi
else
    skip 6 "T12 runtime permission boundary (POSIX-only kernel invariant + active probe; this host has no /root and no sbox-cm runtime tree)"
fi

# -- shared python harness ---------------------------------------------------
cat > "$TMP/m05_harness.py" <<'HARNESS_EOF'
#!/usr/bin/env python3
"""Phase M0.5 harness: real loopback servers, step-up + status + revocation."""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import http.client

sys.path.insert(0, os.environ["MONITOR_V2_ROOT"])
STATIC_DIR = os.environ["STATIC_DIR"]

from collector import Collector
from web.access import AccessPolicy
from web.auth import DEFAULT_STEP_UP_TTL, AuthStore, SessionStore
from web.broker import SnapshotBroker
from web.server import MUTATION_ROUTES, MonitorWebApp, build_server

PASSWORD = "m05-admin-password-1"
NEW_PASSWORD = "m05-admin-password-2"
RECOVERY_KEY = "m05-recovery-key-0001"
SOURCE = "127.0.0.5"
MUTATION_PATHS = sorted(MUTATION_ROUTES)

def _raiser():
    raise RuntimeError("management_active provider failed")

def make_stack(data_dir, *, password=None, recovery=None,
               whitelist=(SOURCE + "/32",), poll=0.2, url="http://127.0.0.1:1",
               session_ttl=3600.0, step_up_ttl=DEFAULT_STEP_UP_TTL,
               management_active=None):
    policy = AccessPolicy(data_dir)
    for entry in whitelist:
        policy.add(entry)
    auth = None
    if password is not None or recovery is not None:
        auth = AuthStore(data_dir, session_ttl=session_ttl,
                         step_up_ttl=step_up_ttl)
        if password is not None:
            auth.set_password(password)
        if recovery is not None:
            auth.set_recovery_key(recovery)

    def factory():
        raise RuntimeError("stream EOF")

    collector = Collector(url=url, stream_factory=factory)
    broker = SnapshotBroker(collector, poll_seconds=poll)
    broker.start()
    app = MonitorWebApp(broker=broker, access=policy, static_dir=STATIC_DIR,
                        auth=auth, management_active=management_active)
    srv = build_server(app, "127.0.0.1", 0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.35)
    return {"srv": srv, "port": port, "policy": policy, "auth": auth,
            "broker": broker, "data_dir": data_dir, "app": app}

def req(port, method, path, headers=None, body=None, timeout=8.0,
        source=SOURCE):
    try:
        return _req_once(port, source, method, path, headers, body, timeout)
    except (ConnectionError, OSError):
        time.sleep(0.3)
        return _req_once(port, source, method, path, headers, body, timeout)

def _req_once(port, source, method, path, headers=None, body=None,
              timeout=8.0):
    s = socket.socket()
    s.bind((source, 0))
    s.settimeout(timeout)
    s.connect(("127.0.0.1", port))
    conn = http.client.HTTPConnection("127.0.0.1", port)
    conn.sock = s
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return {"status": resp.status,
            "headers": {k.lower(): v for k, v in resp.getheaders()},
            "body": data.decode("utf-8", "replace")}

def json_body(payload):
    return json.dumps(payload).encode("utf-8")

def login(port, password=PASSWORD):
    return req(port, "POST", "/api/v1/login",
               {"Content-Type": "application/json"},
               json_body({"password": password}))

def cookie_of(response):
    return response["headers"].get("set-cookie", "").split(";")[0]

def token_of(response):
    raw = response["headers"].get("set-cookie", "").split(";")[0]
    return raw.split("=", 1)[1] if "=" in raw else ""

def csrf_of(port, cookie):
    data = json.loads(req(port, "GET", "/api/v1/session",
                          {"Cookie": cookie})["body"])
    return data.get("csrf_token") or ""

def session_info(port, cookie=None):
    headers = {"Cookie": cookie} if cookie else {}
    return json.loads(req(port, "GET", "/api/v1/session", headers)["body"])

def authed(cookie, csrf):
    return {"Content-Type": "application/json", "Cookie": cookie,
            "X-CSRF-Token": csrf}

def step_up(port, cookie, csrf, password=PASSWORD):
    return req(port, "POST", "/api/v1/step-up", authed(cookie, csrf),
               json_body({"password": password}))

def mutate(port, path, cookie, csrf):
    return req(port, "POST", path, authed(cookie, csrf), json_body({}))

def no_raise(func):
    try:
        func()
    except Exception:  # noqa: BLE001
        return False
    return True

def group_gate():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    port = stack["port"]

    # T1: an ORDINARY login opens the dashboard; nothing else is demanded.
    good = login(port)
    out["T1_login_ok"] = good["status"] == 200
    cookie = cookie_of(good)
    csrf = csrf_of(port, cookie)
    out["T1_cookie_httponly"] = "HttpOnly" in good["headers"].get(
        "set-cookie", "")
    out["T1_dashboard_snapshot_ok"] = req(
        port, "GET", "/api/v1/snapshot", {"Cookie": cookie})["status"] == 200

    # T2: every read-only API works with NO step-up, and no second password
    # is ever requested just for loading.
    out["T2_step_up_initially_absent"] = \
        session_info(port, cookie).get("step_up_active") is False
    out["T2_snapshot_read_only_ok"] = req(
        port, "GET", "/api/v1/snapshot", {"Cookie": cookie})["status"] == 200
    out["T2_whitelist_read_only_ok"] = req(
        port, "GET", "/api/v1/whitelist", {"Cookie": cookie})["status"] == 200
    out["T2_session_read_only_ok"] = req(
        port, "GET", "/api/v1/session", {"Cookie": cookie})["status"] == 200

    # T3: no step-up -> 401 reauth_required on EVERY mutation route.
    statuses = []
    codes = []
    for path in MUTATION_PATHS:
        r = mutate(port, path, cookie, csrf)
        statuses.append(r["status"])
        codes.append(json.loads(r["body"]).get("error"))
    out["T3_all_mutations_401"] = statuses == [401] * len(MUTATION_PATHS)
    out["T3_all_reauth_required"] = \
        codes == ["reauth_required"] * len(MUTATION_PATHS)

    # T4: the correct password opens the window.
    r = step_up(port, cookie, csrf)
    out["T4_step_up_200"] = r["status"] == 200
    body = json.loads(r["body"])
    out["T4_status_ok"] = body.get("status") == "ok"
    out["T4_expires_in_300"] = body.get("expires_in") == 300
    out["T4_step_up_active_flag"] = \
        session_info(port, cookie).get("step_up_active") is True

    # T5: inside the window the mutation is AUTHORIZED. The privileged
    # backend is not wired in this harness, so the honest terminal
    # answer is a fail-closed 503 e3_unavailable (M2) --
    # never a silent success and never a second reauth demand.
    r = mutate(port, "/api/v1/clients/add", cookie, csrf)
    out["T5_authorized_not_401"] = r["status"] == 503
    out["T5_op_name_reported"] = \
        json.loads(r["body"]).get("code") == "e3_unavailable"
    out["T5_milestone_reported"] = \
        json.loads(r["body"]).get("error") == "the E3 adapter is not wired in this build"
    out["T5_error_code_not_implemented"] = \
        json.loads(r["body"]).get("ok") is False
    out["T5_wrong_password_not_authorized"] = \
        step_up(port, cookie, csrf, "definitely-wrong")["status"] == 401

    # gate order on the mutation route: session -> CSRF -> step-up.
    r = req(port, "POST", "/api/v1/clients/add",
            {"Content-Type": "application/json"}, json_body({}))
    out["gate_no_session_401"] = r["status"] == 401 \
        and json.loads(r["body"]).get("error") == "login required"
    r = req(port, "POST", "/api/v1/clients/add",
            {"Content-Type": "application/json", "Cookie": cookie},
            json_body({}))
    out["gate_no_csrf_403"] = r["status"] == 403
    r = req(port, "POST", "/api/v1/step-up",
            {"Content-Type": "application/json"},
            json_body({"password": PASSWORD}))
    out["gate_stepup_no_session_401"] = r["status"] == 401
    r = req(port, "POST", "/api/v1/step-up",
            {"Content-Type": "application/json", "Cookie": cookie},
            json_body({"password": PASSWORD}))
    out["gate_stepup_no_csrf_403"] = r["status"] == 403
    r = req(port, "POST", "/api/v1/step-up", authed(cookie, csrf),
            json_body({}))
    out["gate_stepup_missing_password_400"] = r["status"] == 400
    r = step_up(port, cookie, csrf, "definitely-wrong")
    out["gate_stepup_wrong_password_401"] = r["status"] == 401 \
        and json.loads(r["body"]).get("error") == "invalid_credentials"
    out["gate_no_password_echo"] = PASSWORD not in r["body"]

    # CSRF is checked BEFORE any password work or counter mutation: a
    # cross-site step-up POST can neither guess the password nor burn the
    # shared lockout budget (CSRF-triggered lockout DoS).
    allowed_before, _ = stack["auth"].login_limiter.check(SOURCE)
    csrf_less = [
        req(port, "POST", "/api/v1/step-up",
            {"Content-Type": "application/json", "Cookie": cookie},
            json_body({"password": "csrf-wrong-%d" % i}))["status"]
        for i in range(6)
    ]
    allowed_after, _ = stack["auth"].login_limiter.check(SOURCE)
    out["gate_csrf_dos_all_403"] = csrf_less == [403] * 6
    out["gate_csrf_dos_no_budget_burn"] = allowed_before and allowed_after
    out["gate_csrf_dos_admin_recovers"] = \
        step_up(port, cookie, csrf)["status"] == 200

    # T6: the window really expires (short store TTL, production is 300s).
    short = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       step_up_ttl=1.2)
    sp = short["port"]
    sc = cookie_of(login(sp))
    ss = csrf_of(sp, sc)
    out["T6_step_up_ok"] = step_up(sp, sc, ss)["status"] == 200
    out["T6_authorized_in_window"] = \
        mutate(sp, "/api/v1/clients/add", sc, ss)["status"] == 503
    time.sleep(1.6)
    r = mutate(sp, "/api/v1/clients/add", sc, ss)
    out["T6_expired_401"] = r["status"] == 401
    out["T6_expired_reauth_required"] = \
        json.loads(r["body"]).get("error") == "reauth_required"
    out["T6_step_up_flag_false"] = \
        session_info(sp, sc).get("step_up_active") is False
    out["T6_session_still_valid"] = req(
        sp, "GET", "/api/v1/snapshot", {"Cookie": sc})["status"] == 200
    return out

def group_revocation():
    out = {}

    # T7: logout kills the session AND its step-up immediately.
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    port = stack["port"]
    good = login(port)
    cookie = cookie_of(good)
    token = token_of(good)
    csrf = csrf_of(port, cookie)
    out["T7_step_up_granted"] = step_up(port, cookie, csrf)["status"] == 200
    out["T7_step_up_live"] = stack["auth"].sessions.step_up_active(token)
    out["T7_logout_200"] = req(
        port, "POST", "/api/v1/logout", authed(cookie, csrf),
        json_body({}))["status"] == 200
    out["T7_session_dropped"] = \
        stack["auth"].sessions.resolve(token) is None
    out["T7_step_up_dropped"] = \
        not stack["auth"].sessions.step_up_active(token)
    out["T7_mutation_after_logout_401"] = \
        mutate(port, "/api/v1/clients/add", cookie, csrf)["status"] == 401

    # T8: a password change revokes EVERY step-up (the caller's too) while
    # keeping the caller's ordinary session -- no abrupt logout, no mutation
    # privilege.
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    port = stack["port"]
    a = login(port)
    ca = cookie_of(a)
    ta = token_of(a)
    sa = csrf_of(port, ca)
    b = login(port)
    cb = cookie_of(b)
    tb = token_of(b)
    sb = csrf_of(port, cb)
    step_up(port, ca, sa)
    step_up(port, cb, sb)
    out["T8_both_live"] = stack["auth"].sessions.step_up_active(ta) \
        and stack["auth"].sessions.step_up_active(tb)
    r = req(port, "POST", "/api/v1/password", authed(ca, sa),
            json_body({"current_password": PASSWORD,
                       "new_password": NEW_PASSWORD}))
    out["T8_password_change_200"] = r["status"] == 200
    out["T8_caller_session_kept"] = \
        stack["auth"].sessions.resolve(ta) is not None
    out["T8_caller_step_up_revoked"] = \
        not stack["auth"].sessions.step_up_active(ta)
    out["T8_other_session_dropped"] = \
        stack["auth"].sessions.resolve(tb) is None
    r = mutate(port, "/api/v1/clients/add", ca, sa)
    out["T8_caller_mutation_401"] = r["status"] == 401 \
        and json.loads(r["body"]).get("error") == "reauth_required"
    out["T8_caller_read_still_ok"] = req(
        port, "GET", "/api/v1/snapshot", {"Cookie": ca})["status"] == 200

    # T9: recovery rotation revokes every step-up; sessions survive.
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       recovery=RECOVERY_KEY)
    port = stack["port"]
    a = login(port)
    ca = cookie_of(a)
    ta = token_of(a)
    sa = csrf_of(port, ca)
    b = login(port)
    cb = cookie_of(b)
    tb = token_of(b)
    sb = csrf_of(port, cb)
    step_up(port, ca, sa)
    step_up(port, cb, sb)
    out["T9_both_live"] = stack["auth"].sessions.step_up_active(ta) \
        and stack["auth"].sessions.step_up_active(tb)
    r = req(port, "POST", "/api/v1/recovery/rotate", authed(ca, sa),
            json_body({"current_password": PASSWORD}))
    out["T9_rotate_200"] = r["status"] == 200
    out["T9_rotate_new_key"] = bool(json.loads(r["body"]).get("recovery_key"))
    out["T9_all_step_ups_revoked"] = \
        not stack["auth"].sessions.step_up_active(ta) \
        and not stack["auth"].sessions.step_up_active(tb)
    out["T9_sessions_kept"] = \
        stack["auth"].sessions.resolve(ta) is not None \
        and stack["auth"].sessions.resolve(tb) is not None
    out["T9_mutation_401"] = \
        mutate(port, "/api/v1/clients/add", ca, sa)["status"] == 401
    store = AuthStore(tempfile.mkdtemp())
    store.set_password(PASSWORD)
    tok = store.sessions.create()
    store.sessions.grant_step_up(tok)
    before = store.sessions.step_up_active(tok)
    store.set_recovery_key("m05-rotated-recovery-key")
    out["T9_set_recovery_key_revokes"] = \
        before and not store.sessions.step_up_active(tok)

    # T10: a web restart (fresh process memory over the same data dir) drops
    # every session and step-up -- there is nothing on disk to restore.
    data_dir = tempfile.mkdtemp()
    first = make_stack(data_dir, password=PASSWORD)
    good = login(first["port"])
    c1 = cookie_of(good)
    t1 = token_of(good)
    s1 = csrf_of(first["port"], c1)
    step_up(first["port"], c1, s1)
    out["T10_first_live"] = first["auth"].sessions.step_up_active(t1)
    second = make_stack(data_dir, password=PASSWORD)
    out["T10_token_gone"] = second["auth"].sessions.resolve(t1) is None
    out["T10_step_up_gone"] = \
        not second["auth"].sessions.step_up_active(t1)
    out["T10_old_cookie_401"] = req(
        second["port"], "GET", "/api/v1/snapshot", {"Cookie": c1})["status"] == 401
    out["T10_old_mutation_401"] = \
        mutate(second["port"], "/api/v1/clients/add", c1, s1)["status"] == 401

    # Session TTL expiry is the fifth revocation event.
    ttl_stack = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                           session_ttl=0.9)
    good = login(ttl_stack["port"])
    ct = cookie_of(good)
    tt = token_of(good)
    st = csrf_of(ttl_stack["port"], ct)
    step_up(ttl_stack["port"], ct, st)
    out["ttl_step_up_live"] = ttl_stack["auth"].sessions.step_up_active(tt)
    time.sleep(1.3)
    out["ttl_step_up_gone"] = \
        not ttl_stack["auth"].sessions.step_up_active(tt)
    out["ttl_mutation_401"] = mutate(
        ttl_stack["port"], "/api/v1/clients/add", ct, st)["status"] == 401

    fresh = SessionStore()
    out["fresh_store_has_no_step_up"] = \
        fresh.step_up_active("anything") is False
    out["revoke_all_on_empty_store_ok"] = \
        no_raise(SessionStore().revoke_all_step_ups)

    # Revocation is evaluated PER REQUEST: a window granted earlier does not
    # survive a revocation, and nothing that already passed the gate is
    # reconsidered. M0.5 dispatches no work, so no transaction can ever be
    # half-finished; M1 inherits the rule (durable intent => uncancellable).
    store2 = SessionStore()
    tok2 = store2.create()
    granted = store2.grant_step_up(tok2) is not None
    active_before = store2.step_up_active(tok2)
    store2.revoke_all_step_ups()
    out["concurrency_approved_window_revoked"] = \
        granted and active_before and not store2.step_up_active(tok2)
    time.sleep(0.05)
    out["concurrency_revoked_window_not_restored"] = \
        not store2.step_up_active(tok2)

    stack_c = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    pc = stack_c["port"]
    gc = login(pc)
    cc = cookie_of(gc)
    sc = csrf_of(pc, cc)
    step_up(pc, cc, sc)
    out["concurrency_first_request_passes_gate"] = \
        mutate(pc, "/api/v1/clients/add", cc, sc)["status"] == 503
    stack_c["auth"].sessions.revoke_all_step_ups()
    out["concurrency_later_request_blocked"] = \
        mutate(pc, "/api/v1/clients/add", cc, sc)["status"] == 401

    # No step-up state is ever persisted: auth.json stays hash-only.
    with open(os.path.join(stack["data_dir"], "auth.json")) as handle:
        auth_raw = handle.read()
    out["revocation_no_step_up_on_disk"] = "step_up" not in auth_raw \
        and PASSWORD not in auth_raw \
        and "stepup" not in auth_raw
    return out

def group_ratelimit():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    port = stack["port"]
    good = login(port)
    cookie = cookie_of(good)
    csrf = csrf_of(port, cookie)
    allowed, _retry = stack["auth"].login_limiter.check(SOURCE)
    out["rl_login_resets_counter"] = allowed

    statuses = [step_up(port, cookie, csrf, "wrong-%d" % i)["status"]
                for i in range(5)]
    out["rl_five_wrong_stepups_401"] = statuses == [401] * 5
    blocked = step_up(port, cookie, csrf, "wrong-6")
    out["rl_sixth_stepup_429"] = blocked["status"] == 429
    out["rl_429_code"] = json.loads(blocked["body"]).get("error") == "rate_limited"
    out["rl_429_retry_after"] = blocked["headers"].get("retry-after") is not None
    # The SAME counter locks the login endpoint: proof the limiter is shared,
    # not a second brute-force surface.
    out["rl_login_shares_lockout"] = login(port, PASSWORD)["status"] == 429
    out["rl_mutation_still_401"] = \
        mutate(port, "/api/v1/clients/add", cookie, csrf)["status"] == 401

    # ...and the reverse direction: login failures consume the step-up budget.
    stack2 = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    p2 = stack2["port"]
    g2 = login(p2, PASSWORD)
    c2 = cookie_of(g2)
    s2 = csrf_of(p2, c2)
    bad = [login(p2, "bad-%d" % i)["status"] for i in range(4)]
    out["rl_four_bad_logins_401"] = bad == [401] * 4
    out["rl_fifth_attempt_401"] = \
        step_up(p2, c2, s2, "bad-5")["status"] == 401
    out["rl_sixth_attempt_429"] = \
        step_up(p2, c2, s2, "bad-6")["status"] == 429
    return out

def group_status():
    out = {}
    stack = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    port = stack["port"]
    info = session_info(port)
    out["status_monitor_running_true"] = info.get("monitor_running") is True
    out["status_management_active_default_false"] = \
        info.get("management_active") is False
    out["status_orthogonal_default"] = \
        info.get("monitor_running") is True \
        and info.get("management_active") is False

    # The two booleans are independent, in BOTH directions.
    armed = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                       management_active=lambda: True)
    info2 = session_info(armed["port"])
    out["status_armed_monitor_running"] = info2.get("monitor_running") is True
    out["status_armed_management_active"] = \
        info2.get("management_active") is True
    broken = make_stack(tempfile.mkdtemp(), password=PASSWORD,
                        management_active=_raiser)
    out["status_provider_error_fails_closed"] = \
        session_info(broken["port"]).get("management_active") is False

    # A wedged publisher degrades monitor_running while the management plane
    # answer stays independent and the read-only surface keeps serving.
    frozen = make_stack(tempfile.mkdtemp(), password=PASSWORD)
    broker = frozen["broker"]
    if not broker.wait_for_snapshot(timeout=15.0):
        raise AssertionError("publisher never produced a first snapshot")
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    broker._publisher_thread = dead
    time.sleep(0.3)
    info4 = session_info(frozen["port"])
    out["status_frozen_monitor_not_running"] = \
        info4.get("monitor_running") is False
    out["status_frozen_management_still_false"] = \
        info4.get("management_active") is False
    cookie = cookie_of(login(frozen["port"]))
    out["status_frozen_snapshot_still_served"] = req(
        frozen["port"], "GET", "/api/v1/snapshot",
        {"Cookie": cookie})["status"] == 200

    # step_up_active is reported per session, false before any grant.
    info5 = session_info(frozen["port"], cookie)
    out["status_step_up_flag_before"] = info5.get("step_up_active") is False
    csrf = info5.get("csrf_token") or ""
    step_up(frozen["port"], cookie, csrf)
    out["status_step_up_flag_after"] = \
        session_info(frozen["port"], cookie).get("step_up_active") is True
    return out

GROUPS = {
    "gate": group_gate,
    "revocation": group_revocation,
    "ratelimit": group_ratelimit,
    "status": group_status,
}

if __name__ == "__main__":
    name = sys.argv[1]
    try:
        results = GROUPS[name]()
    except Exception as exc:  # noqa: BLE001 - surface harness errors as JSON
        results = {"_harness_error": "%s: %s" % (type(exc).__name__, exc)}
    print(json.dumps(results, sort_keys=True))
HARNESS_EOF

run_group() {
    GROUP="$1"
    PYTHONPATH="$ROOT/monitor-v2" "$PY" "$TMP/m05_harness.py" "$GROUP" \
        > "$TMP/out-$GROUP.json" 2> "$TMP/err-$GROUP.log"
    if ! "$PY" -c 'import json,sys; json.load(open(sys.argv[1]))' \
        "$TMP/out-$GROUP.json" 2>/dev/null; then
        printf '{"_harness_error": "harness did not produce JSON"}' \
            > "$TMP/out-$GROUP.json"
        printf 'harness stderr:\n%s\n' "$(tail -5 "$TMP/err-$GROUP.log")" >&2
    fi
}

result() {
    "$PY" -c 'import json,sys; d=json.load(open(sys.argv[1])); print(eval(sys.argv[2]))' \
        "$TMP/out-$GROUP.json" "$1" 2>/dev/null || printf 'EVAL-ERROR'
}

check() { assert_eq "$(result "$1")" "True" "$2"; }

section "M1: step-up gate, endpoint contract and expiry (T1-T6)"
run_group "gate"
check 'd.get("_harness_error") is None' "gate harness ran clean"
check 'd["T1_login_ok"]' "T1: an ordinary login succeeds"
check 'd["T1_cookie_httponly"]' "T1: login yields an HttpOnly session cookie"
check 'd["T1_dashboard_snapshot_ok"]' "T1: the dashboard reads the snapshot right after login"
check 'd["T2_step_up_initially_absent"]' "T2: no step-up exists merely because the page loaded"
check 'd["T2_snapshot_read_only_ok"]' "T2: snapshot is read-only, no step-up needed"
check 'd["T2_whitelist_read_only_ok"]' "T2: whitelist view needs no step-up"
check 'd["T2_session_read_only_ok"]' "T2: session info needs no step-up"
check 'd["T3_all_mutations_401"]' "T3: all four mutations answer 401 without step-up"
check 'd["T3_all_reauth_required"]' "T3: the 401 body is exactly reauth_required"
check 'd["T4_step_up_200"]' "T4: the correct password completes step-up"
check 'd["T4_status_ok"]' "T4: step-up answers {status: ok}"
check 'd["T4_expires_in_300"]' "T4: the window is 300 seconds"
check 'd["T4_step_up_active_flag"]' "T4: the session reports a live step-up"
check 'd["T5_authorized_not_401"]' "T5: inside the window the mutation passes authorization"
check 'd["T5_op_name_reported"]' "T5: the authorized request reaches the op boundary (client.add)"
check 'd["T5_milestone_reported"]' "T5: without an E3 backend the boundary says so honestly (M2)"
check 'd["T5_error_code_not_implemented"]' "T5: the fail-closed body is ok:false (never success-shaped)"
check 'd["T5_wrong_password_not_authorized"]' "T5: a wrong password never authorizes"
check 'd["gate_no_session_401"]' "gate: mutation without a session -> 401 login required"
check 'd["gate_no_csrf_403"]' "gate: mutation without CSRF -> 403"
check 'd["gate_stepup_no_session_401"]' "gate: step-up without a session -> 401"
check 'd["gate_stepup_no_csrf_403"]' "gate: step-up without CSRF -> 403"
check 'd["gate_stepup_missing_password_400"]' "gate: step-up without a password -> 400"
check 'd["gate_stepup_wrong_password_401"]' "gate: wrong password -> 401 invalid_credentials"
check 'd["gate_no_password_echo"]' "gate: no response ever echoes the password"
check 'd["gate_csrf_dos_all_403"]' "gate: step-up without CSRF is refused every time (403)"
check 'd["gate_csrf_dos_no_budget_burn"]' "gate: CSRF-less attempts never consume the shared lockout budget"
check 'd["gate_csrf_dos_admin_recovers"]' "gate: the real admin can still step up after those attempts"
check 'd["T6_step_up_ok"]' "T6: step-up succeeds on a short-lived store"
check 'd["T6_authorized_in_window"]' "T6: mutation authorized while the window is open"
check 'd["T6_expired_401"]' "T6: expiry -> 401"
check 'd["T6_expired_reauth_required"]' "T6: expiry -> reauth_required"
check 'd["T6_step_up_flag_false"]' "T6: the session reports the step-up is gone"
check 'd["T6_session_still_valid"]' "T6: the ordinary session survives step-up expiry"

section "M2: five revocation events (T7-T10 + TTL)"
run_group "revocation"
check 'd.get("_harness_error") is None' "revocation harness ran clean"
check 'd["T7_step_up_granted"]' "T7: step-up granted before logout"
check 'd["T7_step_up_live"]' "T7: the store sees the live window"
check 'd["T7_logout_200"]' "T7: logout succeeds"
check 'd["T7_session_dropped"]' "T7: logout drops the session"
check 'd["T7_step_up_dropped"]' "T7: logout drops the step-up immediately"
check 'd["T7_mutation_after_logout_401"]' "T7: mutations are refused after logout"
check 'd["T8_both_live"]' "T8: two sessions each hold a step-up"
check 'd["T8_password_change_200"]' "T8: the password change succeeds"
check 'd["T8_caller_session_kept"]' "T8: the caller keeps an ordinary session (no abrupt logout)"
check 'd["T8_caller_step_up_revoked"]' "T8: the caller's step-up is revoked by the change"
check 'd["T8_other_session_dropped"]' "T8: other sessions are dropped outright"
check 'd["T8_caller_mutation_401"]' "T8: the caller must re-authenticate to mutate"
check 'd["T8_caller_read_still_ok"]' "T8: read-only access keeps working"
check 'd["T9_both_live"]' "T9: two sessions each hold a step-up"
check 'd["T9_rotate_200"]' "T9: recovery rotation succeeds"
check 'd["T9_rotate_new_key"]' "T9: rotation issues a new key"
check 'd["T9_all_step_ups_revoked"]' "T9: rotation revokes ALL step-ups"
check 'd["T9_sessions_kept"]' "T9: rotation keeps the sessions themselves"
check 'd["T9_mutation_401"]' "T9: mutation refused after rotation"
check 'd["T9_set_recovery_key_revokes"]' "T9: the store revokes on recovery-key change"
check 'd["T10_first_live"]' "T10: session + step-up live before the restart"
check 'd["T10_token_gone"]' "T10: a fresh process does not resolve the old token"
check 'd["T10_step_up_gone"]' "T10: a fresh process has no step-up"
check 'd["T10_old_cookie_401"]' "T10: the old cookie is refused after restart"
check 'd["T10_old_mutation_401"]' "T10: mutations are refused after restart"
check 'd["ttl_step_up_live"]' "TTL: step-up live before session expiry"
check 'd["ttl_step_up_gone"]' "TTL: session expiry removes the step-up"
check 'd["ttl_mutation_401"]' "TTL: mutations refused once the session lapses"
check 'd["fresh_store_has_no_step_up"]' "a fresh store knows no step-up"
check 'd["revoke_all_on_empty_store_ok"]' "revoking with no sessions is a safe no-op"
check 'd["concurrency_approved_window_revoked"]' "concurrency: an approved window is revoked mid-flight"
check 'd["concurrency_revoked_window_not_restored"]' "concurrency: a revoked window never comes back"
check 'd["concurrency_first_request_passes_gate"]' "concurrency: the request that already passed the gate is honored"
check 'd["concurrency_later_request_blocked"]' "concurrency: the next request after revocation is blocked"
check 'd["revocation_no_step_up_on_disk"]' "no step-up state is ever written to auth.json"

section "M3: shared login rate limiter (T11)"
run_group "ratelimit"
check 'd.get("_harness_error") is None' "ratelimit harness ran clean"
check 'd["rl_login_resets_counter"]' "a successful login clears the shared failure counter"
check 'd["rl_five_wrong_stepups_401"]' "five wrong step-ups -> 401"
check 'd["rl_sixth_stepup_429"]' "the sixth step-up -> 429 (IP lockout)"
check 'd["rl_429_code"]' "the 429 carries the rate_limited code"
check 'd["rl_429_retry_after"]' "the 429 carries Retry-After"
check 'd["rl_login_shares_lockout"]' "the SAME counter locks login (shared limiter)"
check 'd["rl_mutation_still_401"]' "no mutation can slip through a locked-out IP"
check 'd["rl_four_bad_logins_401"]' "four bad logins -> 401"
check 'd["rl_fifth_attempt_401"]' "the shared budget counts the fifth attempt"
check 'd["rl_sixth_attempt_429"]' "login failures also lock the step-up endpoint"

section "M4: monitor_running / management_active orthogonal model"
run_group "status"
check 'd.get("_harness_error") is None' "status harness ran clean"
check 'd["status_monitor_running_true"]' "monitor_running=true while the monitor runs"
check 'd["status_management_active_default_false"]' "management_active=false by default (safe production state)"
check 'd["status_orthogonal_default"]' "the default pair is running + inactive"
check 'd["status_armed_monitor_running"]' "monitor_running is unaffected by the management plane"
check 'd["status_armed_management_active"]' "management_active is its own independent state"
check 'd["status_provider_error_fails_closed"]' "an undeterminable management state fails closed to false"
check 'd["status_frozen_monitor_not_running"]' "a wedged publisher degrades monitor_running"
check 'd["status_frozen_management_still_false"]' "management_active stays independent of that failure"
check 'd["status_frozen_snapshot_still_served"]' "the read-only dashboard keeps serving while degraded"
check 'd["status_step_up_flag_before"]' "step_up_active is false before any grant"
check 'd["status_step_up_flag_after"]' "step_up_active is true after a grant"

printf '\n== summary ==\n'
TOTAL=$((PASS + FAIL + SKIP))
M05_RESULT=PASS
if [ "$FAIL" -ne 0 ] || [ "$TOTAL" -ne "$EXPECTED_TOTAL" ]; then
    M05_RESULT=FAIL
fi
# Machine-readable, unambiguous: PASS + FAIL + SKIP always equals the suite
# size. A skipped assertion is counted, never hidden behind a lower expected
# pass count (the exact failure mode this gate exists to prevent).
printf 'PASS=%d\nFAIL=%d\nSKIP=%d\nTOTAL=%d\nM05_RESULT=%s\n' \
    "$PASS" "$FAIL" "$SKIP" "$TOTAL" "$M05_RESULT"
if [ "$SKIP" -gt 0 ]; then
    printf 'note: %d of %d assertion(s) were explicitly SKIPPED in this environment (see SKIP lines above); every other assertion passed and none disappeared.\n' \
        "$SKIP" "$EXPECTED_TOTAL"
fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        printf '### Monitor v2 M0.5 - step-up + privilege boundary\n\n'
        printf '| metric | value |\n| --- | --- |\n'
        printf '| PASS | %d |\n| FAIL | %d |\n| SKIP | %d |\n| TOTAL | %d |\n' \
            "$PASS" "$FAIL" "$SKIP" "$TOTAL"
        printf '\n**M05_RESULT=%s**\n' "$M05_RESULT"
    } >> "$GITHUB_STEP_SUMMARY"
fi
if [ "$M05_RESULT" != "PASS" ]; then
    printf '  RESULT: FAILED (failures, or an assertion silently disappeared)\n'
    exit 1
fi
printf '  RESULT: ALL GREEN\n'
exit 0
