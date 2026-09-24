#!/usr/bin/env bash
# sbox-journal-reader EXCHANGE-ACCESS live gates (issue #33 P2, review B7).
#
# Every assertion here runs against REAL permission bits held by REAL
# disposable identities on a REAL filesystem: no mocked stat/chmod/chown, no
# root stand-in for an unprivileged verdict, and no skip path when
# SBOX_JR_XACCESS_REQUIRE_LIVE=1 (CI). The identities are created on the spot
# and removed on the spot; nothing outside mktemp -d is touched.
#
# B7 requires six real-permission Linux discriminators. They are proven by
# these sections (execution order; one Monitor process spans X1+X2):
#   D1 -> X1  the shipped 0.3.0 shape MUST FAIL the fixed-shape discriminator
#             (ancestor traversal refused), and the real Monitor on that same
#             shape settles NOTHING: terminal frozen at 0 with two durable
#             seqs already on disk, zero gaps, zero rejections, zero journal
#             rows, journal subsystem degraded with the sanitized closed
#             code, while the P1 timeline write of the SAME publication keeps
#             landing. The deployment gate (sbmon_sboxjr_consumer_probe) must
#             refuse the same shape with its exit-11 diagnosis.
#   D1b-> X1b no path, errno text, traceback or journal content on the
#             health()/journal_status()/query_timeline() surfaces.
#   D5 -> X2  the SAME instance that recorded the degradation ingests the
#             durable files after the REAL library converges the tree, catches
#             the terminal up from exactly 0, clears its own degradation, and
#             a duplicate re-pass re-counts and duplicates nothing.
#   D2 -> X3  the converged shape grants ancestor traversal and nothing more:
#             out/ enumerated, the reader-created 0640 file read byte-exactly,
#             <root> still unlistable, state/committed/hmac.key still
#             unreachable, stat still printing 750, nobody's group set
#             changed, and an unrelated identity still locked out of content.
#   D3 -> X4  an EXISTING production-shaped tree converges safely and
#             idempotently: the second run takes the zero-mutation branch and
#             the real getfacl text is byte-identical; a hand-widened tree is
#             repaired down to the single --x entry.
#   D6 -> X5  an empty readable exchange dir is a legitimate clean no-op,
#             provably distinguishable from EACCES (X1) and from ENOENT (the
#             same tree with out/ removed).
#   --  -> X6 a host that never activated the reader stays quiet: B7-B's raise
#             must not turn a dark host into a false alarm.
#
# PR-2B DARK: installs nothing persistent. Creates three disposable
# identities, throwaway trees under mktemp -d and one disposable widening ACL
# on them; everything is removed on exit.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd -- "$HERE/../.." && pwd)"
LIB="$ROOT/monitor-v2/deploy/lib/monitor-deploy-lib.sh"
REQUIRE_LIVE="${SBOX_JR_XACCESS_REQUIRE_LIVE:-0}"
PY="${PYTHON:-$(command -v python3 || command -v python || true)}"

PASS=0; FAIL=0; SKIP=0
pass() { PASS=$((PASS + 1)); printf '  PASS %s\n' "$*"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*"; }
skip() { SKIP=$((SKIP + 1)); printf '  SKIP %s\n' "$*"; }
assert_eq() { [ "$1" = "$2" ] && pass "$3" || fail "$3 (want=[$1] got=[$2])"; }
log_has() { case "$1" in *"$2"*) return 0 ;; *) return 1 ;; esac; }

gate() {
    if [ "$REQUIRE_LIVE" = "1" ]; then
        fail "$1 (required LIVE cannot skip)"
        printf '\nPASS=%d FAIL=%d SKIP=%d\nSBOX_JR_XACCESS=FAIL\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    skip "$1"
    printf '\nPASS=%d FAIL=%d SKIP=%d\nSBOX_JR_XACCESS=SKIP\n' "$PASS" "$FAIL" "$SKIP"
    exit 0
}

printf '===== SBOX-JOURNAL-READER EXCHANGE ACCESS (B7) =====\n'
[ "$(uname -s 2>/dev/null)" = "Linux" ] || gate 'non-Linux host'
[ "$(id -u)" = "0" ] || gate 'root required to own the permission shapes'
[ -n "$PY" ] || gate 'python3 missing'
[ -f "$LIB" ] || gate 'deploy library missing'
for tool in runuser useradd usermod groupadd userdel groupdel getent \
            setfacl getfacl sha256sum cmp; do
    command -v "$tool" >/dev/null 2>&1 || gate "prerequisite missing: $tool"
done
[ -x /bin/sh ] || gate '/bin/sh missing'

TMP="$(mktemp -d /tmp/sbxjr-xacc.XXXXXX)"
chmod 0711 "$TMP"   # traversal for the disposable identities; never listable
CREATED_IDENTS=""
teardown_idents() {
    local entry
    for entry in $CREATED_IDENTS; do
        userdel "$entry" >/dev/null 2>&1 || true
        groupdel "$entry" >/dev/null 2>&1 || true
    done
    CREATED_IDENTS=""
}
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    teardown_idents
    rm -rf -- "$TMP"
    exit "$rc"
}
trap cleanup EXIT; trap 'exit 130' INT; trap 'exit 143' TERM

# The ACL grant IS the B7-A model, so a filesystem without POSIX ACL support
# can prove nothing here: gate instead of passing vacuously.
ACLPROBE="$TMP/.aclprobe"; : > "$ACLPROBE"
if ! setfacl -m 'u:root:rw-' -- "$ACLPROBE" 2>/dev/null; then
    gate 'setfacl refused to write: this filesystem has no POSIX ACL support'
fi
if ! getfacl -- "$ACLPROBE" 2>/dev/null | grep -c '^user:root:' >/dev/null; then
    gate 'getfacl cannot read back what setfacl wrote'
fi
rm -f -- "$ACLPROBE"
pass "POSIX ACL support present and readable back on this filesystem"

# ---------------------------------------------------------------------------
# Disposable identities. The names are unique to this lane: if one already
# exists the runner is not clean and a permission verdict built on it means
# nothing, so that is a hard FAIL -- never a reuse of someone else's account.
JR_USER=sbxjrxt;  JR_GROUP=sbxjrxt    # reader stand-in  (owns state + out)
CW_USER=sbxwebxt; CW_GROUP=sbxwebxt   # consumer stand-in (Monitor identity)
NZ_USER=sbxnzxt;  NZ_GROUP=sbxnzxt    # unrelated third identity
groups_of() { id -nG "$1" | tr ' ' '\n' | LC_ALL=C sort | tr '\n' ' '; }
make_ident() { # <user> -- exact production shape: nologin, /nonexistent,
               # own primary group and NO supplementary groups at all
    local u="$1"
    if getent passwd "$u" >/dev/null 2>&1 || getent group "$u" >/dev/null 2>&1; then
        fail "disposable identity $u already exists on this runner (not clean)"
        return 1
    fi
    groupadd --system "$u" || { fail "groupadd $u failed"; return 1; }
    CREATED_IDENTS="$CREATED_IDENTS $u"
    useradd --system --gid "$u" --home-dir /nonexistent --no-create-home \
        --shell /usr/sbin/nologin "$u" \
        || { fail "useradd $u failed"; return 1; }
    return 0
}
IDENT_OK=1
for ident in "$JR_USER" "$CW_USER" "$NZ_USER"; do
    make_ident "$ident" || IDENT_OK=0
done
[ "$IDENT_OK" = "1" ] || gate 'disposable identities unavailable'
pass "three disposable identities created (reader / consumer / unrelated)"

CW_GROUPS_BEFORE="$(groups_of "$CW_USER")"
JR_GROUPS_BEFORE="$(groups_of "$JR_USER")"
assert_eq "$CW_GROUPS_BEFORE" "$CW_USER " "consumer starts in its own group only"
assert_eq "$JR_GROUPS_BEFORE" "$JR_USER " "reader starts in its own group only"

# ---------------------------------------------------------------------------
# Staged, world-readable copy of both packages: a disposable system user may
# not traverse the runner's checkout tree, and an unreadable PYTHONPATH would
# surface as a silent ImportError instead of a permission verdict.
LIBSTAGE="$TMP/lib"
mkdir -p "$LIBSTAGE"
cp -r "$ROOT/monitor-v2/journal_reader" "$LIBSTAGE/journal_reader"
cp -r "$ROOT/monitor-v2/web" "$LIBSTAGE/web"
rm -rf "$LIBSTAGE/journal_reader/__pycache__" "$LIBSTAGE/web/__pycache__"
chmod -R a+rX "$LIBSTAGE"
export XACC_LIB="$LIBSTAGE"

cat > "$TMP/mkev.py" <<'MKEV'
#!/usr/bin/env python3
"""Author one contract-shaped exchange file body and self-validate it with
the reader's OWN strict schema before it is ever installed."""
import json
import os
import sys

sys.path.insert(0, os.environ["XACC_LIB"])
from journal_reader.schema import (CLASSIFIER_VERSION, FORMAT_VERSION,
                                   parse_exchange_text)

RUN = "0123456789abcdef0123456789abcdef"
seq, count, path = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
header = {"t": "h", "v": FORMAT_VERSION, "cv": CLASSIFIER_VERSION,
          "seq": seq, "run": RUN, "epoch": 1, "boundary": "NONE",
          "lines": 10, "eligible": count, "info_dropped": 2,
          "nomatch_dropped": 5, "priority_unusable": 0, "pfail": 0,
          "limited": 0}
lines = [json.dumps(header, sort_keys=True)]
for i in range(count):
    lines.append(json.dumps({"t": "e", "ts": 1700000000.0 + seq + i,
                             "cls": "dns", "proto": "OTHER", "port": None,
                             "dcls": None, "fp": None, "n": 1},
                            sort_keys=True))
body = "\n".join(lines) + "\n"
if parse_exchange_text(body, seq) is not None:
    sys.exit(1)
with open(path, "w", newline="\n") as handle:
    handle.write(body)
MKEV
chmod 0644 "$TMP/mkev.py"

cat > "$TMP/mondrv.py" <<'DRV'
#!/usr/bin/env python3
"""Monitor-side driver for the B7 gates, run AS the consumer identity.

Every mode prints a flattened key=value verdict and appends the raw
health() / journal_status() / query_timeline() JSON -- the actual
status/log/API surfaces -- to $XACC_SURFACE, which the shell leak-gates for
paths, errno text, tracebacks and journal content.

`chain` is the single-process break -> repair -> recovery proof: it publishes
under the broken shape, waits for the shell to converge the tree with the
real library (root), then publishes and ingests again -- so the degradation
is cleared by the very instance that recorded it. The wait is bounded: an
unrepaired chain FAILS loudly, it never hangs CI.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.environ["XACC_LIB"])
from journal_reader import ingest_contract
from web.incident_history import IncidentHistory

MODE = sys.argv[1]
DIAG = sys.argv[2]
EXCH = sys.argv[3]
RUNID = sys.argv[4]


def snap(active_vless):
    """A realistic broker-shaped snapshot (whitelisted fields only)."""
    return {
        "active_connections": active_vless + 1,
        "skipped_events": 0, "duplicate_events": 0, "identity_conflicts": 0,
        "abandoned_on_reset": 0, "recently_closed": 0, "connections": [],
        "devices": {
            "xaccdev": {
                "name": "xaccdev", "status": "ACTIVE",
                "protocols": {
                    "vless-in": {"device_name": "xaccdev",
                                 "inbound": "vless-in",
                                 "active_connections": active_vless,
                                 "uplink_rate": 1.0, "downlink_rate": 2.0,
                                 "uplink_total": 10.0, "downlink_total": 20.0},
                    "hy2-in": {"device_name": "xaccdev", "inbound": "hy2-in",
                               "active_connections": 1,
                               "uplink_rate": 1.0, "downlink_rate": 1.0,
                               "uplink_total": 1.0, "downlink_total": 1.0}},
                "active_connections": active_vless + 1,
                "uplink_rate": 2.0, "downlink_rate": 3.0,
                "uplink_total": 11.0, "downlink_total": 21.0,
                "recent_sources": [], "recent_connections": [],
                "closed_ids": []}},
        "stale": False, "last_error": None,
        "snapshot_generated_at": "2026-01-01T00:00:01+00:00",
        "api_status": "CONNECTED", "collector_uptime_seconds": 42.0,
    }


def flag(value):
    return "true" if value else "false"


def num(value):
    return "-" if value is None else str(value)


def report(tag, hist):
    status = hist.journal_status()
    health = hist.health()
    timeline = hist.query_timeline(limit=50)
    with open(os.environ["XACC_SURFACE"], "a") as handle:
        handle.write(json.dumps({"health": health, "status": status,
                                 "timeline": timeline}, sort_keys=True,
                                default=str) + "\n")
    last = status.get("last_pass") or {}
    conn = hist._conn
    runs = conn.execute("SELECT COUNT(*) FROM journal_runs").fetchone()[0]
    events = conn.execute("SELECT COUNT(*) FROM journal_events").fetchone()[0]
    for key, value in (
            ("degraded", flag(health["degraded"])),
            ("enabled", flag(health["enabled"])),
            ("failure_count", str(health["failure_count"])),
            ("last_error_code", num(health["last_error_code"])),
            ("terminal_seq", num(status["terminal_seq"])),
            ("last_consumed_seq", num(status["last_consumed_seq"])),
            ("gaps_total", num(status["gaps_total"])),
            ("rejected_total", num(status["rejected_total"])),
            ("blocked_at", num(status["blocked_at"])),
            ("consumed", num(last.get("consumed"))),
            ("pass_gaps", num(last.get("gaps"))),
            ("pass_rejected", num(last.get("rejected"))),
            ("contract", flag(status["contract_available"])),
            ("configured", flag(status["exchange_dir_configured"])),
            ("provisioned", flag(status["exchange_dir_provisioned"])),
            ("reader_hb", num(status["reader"]["status"])),
            ("samples", str(len(timeline["samples"]))),
            ("states", str(len(timeline["device_states"]))),
            ("runs", str(runs)),
            ("events", str(events))):
        print("%s.%s=%s" % (tag, key, value))
    sys.stdout.flush()


def opened():
    inst = IncidentHistory(DIAG, RUNID, journal_exchange_dir=EXCH)
    inst.open()
    return inst


if MODE == "scan":
    try:
        found = ingest_contract.scan_exchange_dir(EXCH)
    except Exception as exc:  # noqa: BLE001 -- the class IS the verdict
        cause = exc.__cause__
        print("scan.class=%s" % type(exc).__name__)
        print("scan.cause=%s" % (type(cause).__name__ if cause else "-"))
        print("scan.errno=%s" % num(getattr(cause, "errno", None)))
        print("scan.files=-")
        sys.exit(0)
    print("scan.class=ok")
    print("scan.cause=-")
    print("scan.errno=-")
    print("scan.files=%d" % len(found))
    sys.exit(0)

if MODE == "publish":
    instance = opened()
    instance.on_publish(snap(2), 1)
    instance.on_publish(snap(2), 2)
    report("P", instance)
    instance.close()
    sys.exit(0)

if MODE == "chain":
    instance = opened()
    instance.on_publish(snap(2), 1)
    instance.on_publish(snap(2), 2)
    report("A", instance)
    with open(os.environ["XACC_READY"], "w") as handle:
        handle.write("ready\n")
        handle.flush()
    deadline = time.monotonic() + float(os.environ.get("XACC_WAIT", "90"))
    while not os.path.exists(os.environ["XACC_GO"]):
        if time.monotonic() > deadline:
            print("CHAIN.timeout=true")
            sys.stdout.flush()
            sys.exit(3)
        time.sleep(0.05)
    print("CHAIN.timeout=false")
    sys.stdout.flush()
    instance.ingest_journal_events()
    report("B", instance)
    instance.on_publish(snap(3), 3)
    report("C", instance)
    instance.ingest_journal_events()
    report("D", instance)
    instance.close()
    sys.exit(0)

sys.exit(4)
DRV
chmod 0644 "$TMP/mondrv.py"

MON="$TMP/mon"; mkdir -p "$MON"
SURFACE="$TMP/surface-none"

as_consumer() { # <mode> <diag> <exchange> <runid> <outfile>
    runuser -u "$CW_USER" -- env HOME=/nonexistent PYTHONPATH="$LIBSTAGE" \
        PYTHONDONTWRITEBYTECODE=1 XACC_LIB="$LIBSTAGE" \
        XACC_SURFACE="$SURFACE" "$PY" "$TMP/mondrv.py" \
        "$1" "$2" "$3" "$4" > "$5" 2>"$5.err"
}
mkmon() { # -> prints a fresh consumer-owned diagnostics dir
    local d="$MON/$1"
    mkdir -p "$d"; chown "$CW_USER:$CW_GROUP" "$d"; chmod 0700 "$d"
    printf '%s' "$d"
}
mval() { sed -n "s/^$1=//p" "$2" | head -n1; }

# ---------------------------------------------------------------------------
# Tree helpers: build the shipped 0.3.0 shape by hand, converge the fixed
# shape by calling the REAL deployment library.
CUR_ROOT=""
LIB_OUT=""
lib_run() { # <lib-function> [args...] -> rc; library output in $LIB_OUT
    LIB_OUT="$(
        SBMON_FIXTURE=0 \
        SBOXJR_DATA_ROOT="$CUR_ROOT" \
        SBOXJR_STATE_DIR="$CUR_ROOT/state" \
        SBOXJR_OUT_DIR="$CUR_ROOT/out" \
        SBOXJR_USER="$JR_USER" SBOXJR_GROUP="$JR_GROUP" \
        SBMON_USER="$CW_USER" SBMON_GROUP="$CW_GROUP" \
        SBMON_REPO_MONITOR_DIR="$ROOT/monitor-v2" \
        bash -c '. "$1" >/dev/null 2>&1; set +e; shift; "$@"' _ "$LIB" "$@" \
            2>&1
    )"
}

build_prod_tree() { # <root> -- the exact on-disk shape of release 0.3.0
    local r="$1"
    mkdir -p "$r/state" "$r/out"
    chown "root:$JR_GROUP" "$r"; chmod 0750 "$r"
    chown "$JR_USER:$JR_GROUP" "$r/state"; chmod 0700 "$r/state"
    chown "$JR_USER:$CW_GROUP" "$r/out"; chmod 2750 "$r/out"
}

seed_reader_state() { # <root> -- reader-private state files, production modes
    local r="$1"
    printf 'cursor-anchor\n' > "$r/state/committed"
    head -c 32 /dev/urandom > "$r/state/hmac.key"
    chown "$JR_USER:$JR_GROUP" "$r/state/committed" "$r/state/hmac.key"
    chmod 0600 "$r/state/committed" "$r/state/hmac.key"
}

STAGE="$TMP/stage"; mkdir -p "$STAGE"
author_ev() { # <root> <seq> -- the READER identity writes it through setgid
    local r="$1" seq="$2"
    # Two statements on purpose: in `local a=1 b=$a` bash expands b against the
    # OUTER a, so under `set -u` the second one aborts instead of seeing seq.
    local src="$STAGE/ev-$seq.jsonl" dst="$r/out/ev-$seq.jsonl"
    if ! "$PY" "$TMP/mkev.py" "$seq" 2 "$src"; then
        fail "ev-$seq could not be authored and schema-validated"
        return 1
    fi
    chmod 0644 -- "$src"
    if ! runuser -u "$JR_USER" -- /bin/sh -c 'cat -- "$1" > "$2"' sh \
            "$src" "$dst"; then
        fail "reader identity could not write into $r/out"
        return 1
    fi
    chmod 0640 -- "$dst"      # exactly what reader.py does after its write
    return 0
}

# The accessibility matrix, evaluated AS the given identity. Every entry is
# behavioural -- it must really do the stat/list/open, never read a mode.
fs_matrix() { # <identity> <root> [evname] -> key=yes|no lines
    local ev="ev-1.jsonl"
    [ "$#" -ge 3 ] && ev="$3"
    runuser -u "$1" -- /bin/sh -c '
        r=$1; ev=$2
        q() { if eval "$2" >/dev/null 2>&1; then echo "$1=yes"; else echo "$1=no"; fi; }
        q stat_root      "test -d \"$r\""
        q traverse_root  "test -d \"$r/state\""
        q xbit_root      "test -x \"$r\""
        q list_root      "ls -A \"$r\""
        q list_out       "ls -A \"$r/out\""
        q read_ev        "cat \"$r/out/$ev\""
        q list_state     "ls -A \"$r/state\""
        q read_committed "cat \"$r/state/committed\""
        q read_key       "cat \"$r/state/hmac.key\""
    ' m "$2" "$ev"
}

# D2's verdict as one boolean: exactly what B7-A promises the Monitor
# identity may and may not do, plus the library's own two shape proofs.
fixed_shape_holds() { # <root> -> rc 0 only if the whole contract holds
    local r="$1" m="$TMP/.shape"
    fs_matrix "$CW_USER" "$r" > "$m"
    [ "$(mval stat_root "$m")" = "yes" ] || return 1
    [ "$(mval traverse_root "$m")" = "yes" ] || return 1
    [ "$(mval list_out "$m")" = "yes" ] || return 1
    [ "$(mval read_ev "$m")" = "yes" ] || return 1
    [ "$(mval list_root "$m")" = "no" ] || return 1
    [ "$(mval list_state "$m")" = "no" ] || return 1
    [ "$(mval read_committed "$m")" = "no" ] || return 1
    [ "$(mval read_key "$m")" = "no" ] || return 1
    CUR_ROOT="$r"
    lib_run sbmon_sboxjr_exchange_traversal_shape "$r" || return 1
    lib_run sbmon_sboxjr_consumer_probe || return 1
    return 0
}

T1="$TMP/t1"; T2="$TMP/t2"; T3="$TMP/t3"; mkdir -p "$T1" "$T2" "$T3"
T1R="$T1/root"; T2R="$T2/root"; T3R="$T3/root"

# ===========================================================================
printf -- '--- X0: the shipped 0.3.0 shape, built by hand, as reported from production\n'
build_prod_tree "$T1R"
seed_reader_state "$T1R"
author_ev "$T1R" 1
author_ev "$T1R" 2
printf '{"seq":2,"ts":%s}\n' "$(date +%s)" > "$T1R/out/hb"
chown "$JR_USER:$CW_GROUP" "$T1R/out/hb"; chmod 0640 "$T1R/out/hb"
assert_eq "root:$JR_GROUP 750" "$(stat -c '%U:%G %a' "$T1R")" \
    "T1 root reproduces the reported production shape (root:reader 0750, no ACL)"
assert_eq "$JR_USER:$CW_GROUP 2750" "$(stat -c '%U:%G %a' "$T1R/out")" \
    "T1 out reproduces production (reader:consumer 2750 setgid)"
assert_eq "$JR_USER:$CW_GROUP 640" "$(stat -c '%U:%G %a' "$T1R/out/ev-1.jsonl")" \
    "T1 exchange file reproduces production (reader:consumer 0640)"
assert_eq "$JR_USER:$JR_GROUP 700" "$(stat -c '%U:%G %a' "$T1R/state")" \
    "T1 state reproduces production (reader-only 0700)"
assert_eq 0 "$(getfacl -- "$T1R" | grep -c '^user:[^:]' || true)" \
    "T1 root starts with NO named ACL entry (the shipped 0.3.0 baseline)"
assert_eq 2 "$(ls -1 "$STAGE" | grep -c '^ev-' || true)" \
    "two durable seqs exist on disk before any ingest pass runs"

fs_matrix "$CW_USER" "$T1R" > "$TMP/x0-consumer"
assert_eq yes "$(mval stat_root "$TMP/x0-consumer")" \
    "X0: consumer CAN stat <root> -- the failure is on listdir, not stat"
assert_eq no "$(mval list_root "$TMP/x0-consumer")" \
    "X0: consumer CANNOT list <root> -- the reported PermissionError reproduced"
assert_eq no "$(mval traverse_root "$TMP/x0-consumer")" \
    "X0: consumer CANNOT traverse <root>, so the correct-looking leaf is unreachable"
assert_eq no "$(mval list_out "$TMP/x0-consumer")" \
    "X0: consumer CANNOT enumerate out/ -- ingest would see 'nothing to do'"
assert_eq no "$(mval read_ev "$TMP/x0-consumer")" \
    "X0: consumer CANNOT read the exchange file -- Monitor ingest is frozen"
CUR_ROOT="$T1R"
lib_run sbmon_sboxjr_exchange_traversal_shape "$T1R"; rc=$?
assert_eq 1 "$rc" "X0: the library's ACL shape prover refuses the shipped shape"

# ===========================================================================
printf -- '--- X1 (D1): the fixed-shape discriminator FAILS, and so does the deployment gate\n'
if fixed_shape_holds "$T1R"; then
    fail "D1: the fixed-shape discriminator PASSED on the shipped 0.3.0 tree -- it discriminates nothing"
else
    pass "D1: the fixed-shape discriminator FAILS on the shipped 0.3.0 tree (required CI FAIL)"
fi
CUR_ROOT="$T1R"
lib_run sbmon_sboxjr_consumer_probe; rc=$?
if [ "$rc" = "0" ]; then
    fail "D1: the deployment gate accepted the broken shape (silently-broken release risk)"
else
    pass "D1: the deployment gate refuses the broken shape (fail-closed / rollback path)"
fi
if log_has "$LIB_OUT" "无法遍历"; then
    pass "D1: the refusal carries the exit-11 ancestor-traversal diagnosis"
else
    fail "D1: the refusal did not identify ancestor traversal: $LIB_OUT"
fi
SURFACE="$TMP/surface-x1"; : > "$SURFACE"; chmod 0666 "$SURFACE"
MON1="$(mkmon mon1)"
as_consumer scan "$MON1" "$T1R/out" xacc-1 "$TMP/x1-scan" \
    || fail "X1: the scan driver failed: $(tail -n 3 "$TMP/x1-scan.err")"
assert_eq ExchangeDirUnreadable "$(mval scan.class "$TMP/x1-scan")" \
    "X1: the real contract raises ExchangeDirUnreadable, never an empty result"
assert_eq PermissionError "$(mval scan.cause "$TMP/x1-scan")" \
    "X1: the underlying errno really is EACCES (not ENOENT, not a fixture artifact)"
assert_eq - "$(mval scan.files "$TMP/x1-scan")" \
    "X1: no file set comes back from unreadable storage"

# The break -> repair -> recovery chain: ONE Monitor process, publish under
# the broken shape, real-library convergence by root in the middle, then
# publish and ingest again.
READY="$MON1/ready"; GO="$MON1/go"
: > "$TMP/x1-chain"
runuser -u "$CW_USER" -- env HOME=/nonexistent PYTHONPATH="$LIBSTAGE" \
    PYTHONDONTWRITEBYTECODE=1 XACC_LIB="$LIBSTAGE" XACC_SURFACE="$SURFACE" \
    XACC_READY="$READY" XACC_GO="$GO" XACC_WAIT=90 \
    "$PY" "$TMP/mondrv.py" chain "$MON1" "$T1R/out" xaccchain \
    > "$TMP/x1-chain" 2>"$TMP/x1-chain.err" &
CHAIN_PID=$!
CHAIN_RC=0
WAITED=0
until [ -s "$READY" ]; do
    if ! kill -0 "$CHAIN_PID" 2>/dev/null; then CHAIN_RC=1; break; fi
    if [ "$WAITED" -ge 1000 ]; then CHAIN_RC=2; kill "$CHAIN_PID" 2>/dev/null; break; fi
    WAITED=$((WAITED + 1)); sleep 0.05
done
if [ "$CHAIN_RC" != "0" ]; then
    fail "X1: the chain died before publishing under the broken shape (rc=$CHAIN_RC)"
    wait "$CHAIN_PID" 2>/dev/null || true
else
    pass "X1: the chain published as the consumer under the broken shape and is waiting"
    CUR_ROOT="$T1R"
    lib_run sbmon_sboxjr_ensure_data_tree; rc=$?
    if [ "$rc" = "0" ]; then
        pass "X1: the REAL library converged the same tree while the consumer waited"
    else
        fail "X1: real convergence failed (rc=$rc): $LIB_OUT"
    fi
    : > "$GO"
    wait "$CHAIN_PID"; CHAIN_RC=$?
    assert_eq 0 "$CHAIN_RC" "X1: the chain completed its post-repair phases"
fi
A() { mval "A.$1" "$TMP/x1-chain"; }
B() { mval "B.$1" "$TMP/x1-chain"; }
C() { mval "C.$1" "$TMP/x1-chain"; }
D() { mval "D.$1" "$TMP/x1-chain"; }

assert_eq true "$(A degraded)" "D1: the journal subsystem reports degraded under the broken shape"
assert_eq history_journal_exchange_unreadable "$(A last_error_code)" \
    "D1: the closed sanitized code is what surfaces, and nothing else"
assert_eq true "$(A enabled)" "D1: a journal break does not disable the history surface"
assert_eq 0 "$(A terminal_seq)" "D1: zero sequences settle -- the terminal stays frozen at 0"
assert_eq - "$(A last_consumed_seq)" "D1: nothing is reported as consumed"
assert_eq 0 "$(A gaps_total)" "D1: no gap is invented out of unreadable storage"
assert_eq 0 "$(A rejected_total)" "D1: no rejection is invented either"
assert_eq 0 "$(A runs)" "D1: zero journal rows written while two seqs are durable"
assert_eq 0 "$(A events)" "D1: zero journal events -- nothing leapfrogged the unseen seqs"
assert_eq - "$(A blocked_at)" "D1: the aborted pass leaves no blocked seq behind"
assert_eq 1 "$(A samples)" "D1: the P1 timeline write of the SAME publication still lands"
assert_eq 2 "$(A states)" "D1: P1 device rows still land while the journal is degraded"
assert_eq unreadable "$(A reader_hb)" \
    "D1: reader availability lies too under the broken shape (lstat EACCES)"
assert_eq true "$(A provisioned)" "D1: correctly classified as provisioned storage, not a dark host"
assert_eq true "$(A contract)" "D1: the release-bound ingest contract really imported"
assert_eq 1 "$(A failure_count)" \
    "D1: the break is counted once (later publishes are cadence-gated, no storm)"

printf -- '--- X1b: nothing but a sanitized verdict reaches status/log/API\n'
LEAK="$(cat "$SURFACE" "$TMP/x1-chain" "$TMP/x1-chain.err" \
    | grep -Fc -e "$TMP" -e Traceback -e PermissionError -e 'Errno' \
        -e errno -e denied -e 'out/ev' -e 'state/' -e 'hmac' -e '1700000000' \
    || true)"
assert_eq 0 "$LEAK" "D1: no raw path, errno text, traceback or journal content leaked"

# ===========================================================================
printf -- '--- X2 (D5): the repair is ingested, the degradation clears, nothing duplicates\n'
assert_eq false "$(B degraded)" \
    "D5: the SAME instance clears its own journal degradation on a clean pass"
assert_eq - "$(B last_error_code)" "D5: no error code survives the recovery pass"
assert_eq 2 "$(B consumed)" "D5: the two files that were invisible are now consumed"
assert_eq 2 "$(B terminal_seq)" "D5: the terminal caught up from exactly 0 to 2"
assert_eq 2 "$(B last_consumed_seq)" "D5: last_consumed_seq tracked the advance"
assert_eq 0 "$(B gaps_total)" "D5: catching up over never-seen seqs is not a gap"
assert_eq 0 "$(B rejected_total)" "D5: recovery rejected nothing"
assert_eq - "$(B blocked_at)" "D5: the recovery pass completed unblocked"
assert_eq 2 "$(B runs)" "D5: exactly two journal_runs rows landed"
assert_eq 4 "$(B events)" "D5: exactly four journal_events rows landed"
assert_eq false "$(C degraded)" "D5: a P1 publish after recovery keeps the clean verdict"
assert_eq 1 "$(C samples)" "D5: P1 sampling stayed independent through the whole outage"
assert_eq 3 "$(C states)" "D5: P1 device rows kept advancing across the outage"
assert_eq fresh "$(C reader_hb)" "D5: reader availability recovered to fresh"
assert_eq 0 "$(D consumed)" "D5: a duplicate re-pass consumes nothing"
assert_eq 2 "$(D terminal_seq)" "D5: the duplicate re-pass moved the terminal nowhere"
assert_eq 2 "$(D runs)" "D5: the duplicate re-pass duplicated no run row"
assert_eq 4 "$(D events)" "D5: the duplicate re-pass duplicated no event row"
assert_eq false "$(D degraded)" "D5: the subsystem is still clean after the extra pass"

# ===========================================================================
printf -- '--- X3 (D2): the converged shape grants traversal and nothing more\n'
assert_eq "root:$JR_GROUP 750" "$(stat -c '%U:%G %a' "$T1R")" \
    "D2: stat still prints 750 after the grant (mask keeps r-x; base mode untouched)"
assert_eq "$JR_USER:$JR_GROUP 700" "$(stat -c '%U:%G %a' "$T1R/state")" \
    "D2: convergence left state/ at 0700 reader-private"
assert_eq "$JR_USER:$CW_GROUP 2750" "$(stat -c '%U:%G %a' "$T1R/out")" \
    "D2: convergence left out/ at 2750 setgid reader:consumer"
T1ACL="$(getfacl -- "$T1R" | grep -v '^#' | grep -v '^[[:space:]]*$')"
assert_eq 1 "$(printf '%s\n' "$T1ACL" | grep -c '^user:[^:]' || true)" \
    "D2: EXACTLY one named ACL entry on the whole grant"
assert_eq 1 "$(printf '%s\n' "$T1ACL" | grep -c "^user:$CW_USER:--x\$" || true)" \
    "D2: and it is exactly user:<consumer>:--x (a search bit only)"
assert_eq 0 "$(printf '%s\n' "$T1ACL" | grep -c '^default:' || true)" \
    "D2: no default ACL -- inherited grants are the widening this model forbids"
assert_eq 1 "$(printf '%s\n' "$T1ACL" | grep -c '^mask::r-x$' || true)" \
    "D2: the mask still carries r-x, so the reader keeps its own access"
assert_eq 1 "$(printf '%s\n' "$T1ACL" | grep -c '^other::---$' || true)" \
    "D2: the other class is still closed (nothing became world-accessible)"
assert_eq "$CW_GROUPS_BEFORE" "$(groups_of "$CW_USER")" \
    "D2: the consumer joined no new group (an ACL, not a membership change)"
assert_eq "$JR_GROUPS_BEFORE" "$(groups_of "$JR_USER")" \
    "D2: the reader joined no new group either"
assert_eq "" "$(getent group "$JR_GROUP" | cut -d: -f4)" \
    "D2: the reader group still has no members"
assert_eq "" "$(getent group "$CW_GROUP" | cut -d: -f4)" \
    "D2: the consumer group still has no members"

fs_matrix "$CW_USER" "$T1R" > "$TMP/x3-consumer"
assert_eq yes "$(mval traverse_root "$TMP/x3-consumer")" \
    "D2: the consumer now traverses the ancestor"
assert_eq yes "$(mval list_out "$TMP/x3-consumer")" \
    "D2: the consumer enumerates out/"
assert_eq yes "$(mval read_ev "$TMP/x3-consumer")" \
    "D2: the consumer read-opens the reader-created 0640 exchange file"
assert_eq no "$(mval list_root "$TMP/x3-consumer")" \
    "D2: --x grants traversal only -- listing <root> is still refused"
assert_eq no "$(mval list_state "$TMP/x3-consumer")" \
    "D2: state/ is still not enumerable by the consumer"
assert_eq no "$(mval read_committed "$TMP/x3-consumer")" \
    "D2: state/committed (cursor continuity) stays unreadable"
assert_eq no "$(mval read_key "$TMP/x3-consumer")" \
    "D2: state/hmac.key (the fingerprint secret) stays unreadable"
for seq in 1 2; do
    runuser -u "$CW_USER" -- cat -- "$T1R/out/ev-$seq.jsonl" \
        > "$TMP/ev-$seq.as-consumer" \
        || fail "D2: the consumer could not re-read ev-$seq.jsonl"
    if cmp -s "$STAGE/ev-$seq.jsonl" "$TMP/ev-$seq.as-consumer"; then
        pass "D2: ev-$seq.jsonl read as the consumer is byte-identical to the reader's write"
    else
        fail "D2: ev-$seq.jsonl came back altered through the consumer path"
    fi
done
assert_eq "$JR_USER:$CW_GROUP 640" "$(stat -c '%U:%G %a' "$T1R/out/ev-2.jsonl")" \
    "D2: the setgid dir handed the reader's file the consumer group with no chown"
author_ev "$T1R" 3
assert_eq "$JR_USER:$CW_GROUP 640" "$(stat -c '%U:%G %a' "$T1R/out/ev-3.jsonl")" \
    "D2: a reader file created AFTER convergence still lands 0640 reader:consumer"

fs_matrix "$NZ_USER" "$T1R" > "$TMP/x3-stranger"
assert_eq no "$(mval traverse_root "$TMP/x3-stranger")" \
    "D2: an unrelated identity cannot even traverse the ancestor"
assert_eq no "$(mval read_ev "$TMP/x3-stranger")" \
    "D2: an unrelated identity cannot read exchange content"
setfacl -m "u:$NZ_USER:--x" -- "$T1R" \
    && setfacl -m "u:$NZ_USER:--x" -- "$T1R/out"
fs_matrix "$NZ_USER" "$T1R" > "$TMP/x3-stranger2"
assert_eq yes "$(mval traverse_root "$TMP/x3-stranger2")" \
    "D2: control -- granted traversal, the stranger does reach the leaf layer"
assert_eq no "$(mval list_out "$TMP/x3-stranger2")" \
    "D2: the stranger still cannot enumerate out/"
assert_eq no "$(mval read_ev "$TMP/x3-stranger2")" \
    "D2: the stranger still cannot open a 0640 exchange file (leaf mode holds alone)"
assert_eq no "$(mval read_key "$TMP/x3-stranger2")" \
    "D2: the stranger cannot read hmac.key even with the ancestor grant"
CUR_ROOT="$T1R"
lib_run sbmon_sboxjr_exchange_traversal_shape "$T1R"; rc=$?
assert_eq 1 "$rc" "D2: the shape prover refuses 'more than one named user'"
if fixed_shape_holds "$T1R"; then
    fail "D2: the fixed-shape discriminator accepted the deliberately widened tree"
else
    pass "D2: the fixed-shape discriminator refuses the deliberately widened tree"
fi
setfacl -b -- "$T1R" && setfacl -b -- "$T1R/out"
CUR_ROOT="$T1R"
lib_run sbmon_sboxjr_ensure_data_tree; rc=$?
assert_eq 0 "$rc" "D2: the widened tree re-converges to the contract shape"

# ===========================================================================
printf -- '--- X4 (D3): an existing production-shaped tree converges idempotently\n'
build_prod_tree "$T2R"
seed_reader_state "$T2R"
CUR_ROOT="$T2R"
lib_run sbmon_sboxjr_ensure_data_tree; rc=$?
assert_eq 0 "$rc" "D3: convergence of an existing 0750 tree returned clean"
if log_has "$LIB_OUT" "已是目标形状"; then
    fail "D3: the first run claimed the zero-mutation branch (it had real work)"
else
    pass "D3: the first run did the real work instead of claiming a no-op"
fi
getfacl -- "$T2R" > "$TMP/x4-acl-1"
CUR_ROOT="$T2R"
lib_run sbmon_sboxjr_ensure_data_tree; rc=$?
assert_eq 0 "$rc" "D3: re-running convergence is clean"
if log_has "$LIB_OUT" "已是目标形状"; then
    pass "D3: the second run took the zero-mutation branch (idempotent)"
else
    fail "D3: the second run did not recognize the converged shape: $LIB_OUT"
fi
getfacl -- "$T2R" > "$TMP/x4-acl-2"
if cmp -s "$TMP/x4-acl-1" "$TMP/x4-acl-2"; then
    pass "D3: the real getfacl text is byte-identical across re-runs"
else
    fail "D3: convergence is not a fixed point -- getfacl changed between runs"
fi
assert_eq "root:$JR_GROUP 750" "$(stat -c '%U:%G %a' "$T2R")" \
    "D3: base mode, owner and group survived both runs unchanged"
setfacl -m "u:$NZ_USER:rw-" -- "$T2R"
setfacl -m "default:group::$NZ_GROUP:rwx" -- "$T2R"
CUR_ROOT="$T2R"
lib_run sbmon_sboxjr_exchange_traversal_shape "$T2R"; rc=$?
assert_eq 1 "$rc" "D3: the shape prover refuses a hand-widened tree (extra entry + default ACL)"
CUR_ROOT="$T2R"
lib_run sbmon_sboxjr_ensure_data_tree; rc=$?
assert_eq 0 "$rc" "D3: convergence repaired the widened tree"
T2ACL="$(getfacl -- "$T2R" | grep -v '^#' | grep -v '^[[:space:]]*$')"
assert_eq 1 "$(printf '%s\n' "$T2ACL" | grep -c '^user:[^:]' || true)" \
    "D3: the repair left exactly one named entry"
assert_eq 1 "$(printf '%s\n' "$T2ACL" | grep -c "^user:$CW_USER:--x\$" || true)" \
    "D3: and it is the consumer's --x grant"
assert_eq 0 "$(printf '%s\n' "$T2ACL" | grep -c "^user:$NZ_USER:" || true)" \
    "D3: the stranger's rw- grant is gone"
assert_eq 0 "$(printf '%s\n' "$T2ACL" | grep -c '^default:' || true)" \
    "D3: the inherited default ACL is gone"
assert_eq "root:$JR_GROUP 750" "$(stat -c '%U:%G %a' "$T2R")" \
    "D3: the repair never had to widen the base mode to converge"
getfacl -- "$T2R" > "$TMP/x4-acl-3"
if cmp -s "$TMP/x4-acl-1" "$TMP/x4-acl-3"; then
    pass "D3: the repaired tree is byte-identical to the freshly converged tree"
else
    fail "D3: repair converged to a different shape than a fresh install"
fi
fs_matrix "$CW_USER" "$T2R" > "$TMP/x4-consumer"
assert_eq yes "$(mval list_out "$TMP/x4-consumer")" \
    "D3: the consumer enumerates the repaired tree's exchange dir"
assert_eq no "$(mval list_state "$TMP/x4-consumer")" \
    "D3: state/ privacy survived the repair"
CUR_ROOT="$T2R"
if lib_run sbmon_sboxjr_consumer_probe; then
    pass "D3: the deployment gate accepts the repaired tree -- an empty out/ is valid"
else
    fail "D3: the deployment gate refused the repaired tree: $LIB_OUT"
fi

# ===========================================================================
printf -- '--- X5 (D6): an empty readable exchange dir is a clean no-op, not a failure\n'
build_prod_tree "$T3R"
CUR_ROOT="$T3R"
lib_run sbmon_sboxjr_ensure_data_tree; rc=$?
assert_eq 0 "$rc" "D6: T3 converged: $LIB_OUT"
MON3="$(mkmon mon3)"
SURFACE="$TMP/surface-x5"; : > "$SURFACE"; chmod 0666 "$SURFACE"
as_consumer publish "$MON3" "$T3R/out" xaccempty "$TMP/x5-empty" \
    || fail "D6: the publish driver failed: $(tail -n 3 "$TMP/x5-empty.err")"
E() { mval "P.$1" "$TMP/x5-empty"; }
assert_eq false "$(E degraded)" \
    "D6: an empty, readable out/ is a legitimate clean no-op, not degradation"
assert_eq - "$(E last_error_code)" "D6: a clean no-op reports no code at all"
assert_eq 0 "$(E terminal_seq)" "D6: the terminal stays at 0 because there is genuinely nothing"
assert_eq 0 "$(E consumed)" "D6: the pass really ran and consumed zero"
assert_eq - "$(E blocked_at)" "D6: nothing blocked the pass"
assert_eq 0 "$(E runs)" "D6: no rows were invented"
assert_eq true "$(E provisioned)" "D6: the host is provisioned (the data root exists)"
assert_eq absent "$(E reader_hb)" "D6: a missing hb reads as absent, not as unreadable"
LEAK5="$(cat "$SURFACE" "$TMP/x5-empty" "$TMP/x5-empty.err" \
    | grep -Fc -e "$TMP" -e Traceback -e PermissionError -e Errno -e denied \
    || true)"
assert_eq 0 "$LEAK5" "D6: the clean verdict leaks no path or exception text either"

rmdir "$T3R/out"
as_consumer scan "$MON3" "$T3R/out" xaccgone "$TMP/x5-gone" \
    || fail "D6: the scan driver failed after out/ was removed"
assert_eq ExchangeDirUnreadable "$(mval scan.class "$TMP/x5-gone")" \
    "D6: a vanished out/ raises too -- 'empty' has exactly one shape"
assert_eq 2 "$(mval scan.errno "$TMP/x5-gone")" \
    "D6: and its errno is ENOENT, distinguishable from X1's EACCES"
as_consumer publish "$MON3" "$T3R/out" xaccgone2 "$TMP/x5-gone2" \
    || fail "D6: the publish driver failed after the removal"
G() { mval "P.$1" "$TMP/x5-gone2"; }
assert_eq true "$(G degraded)" "D6: the same tree now degrades instead of looking empty"
assert_eq history_journal_exchange_unreadable "$(G last_error_code)" \
    "D6: with the same closed code and zero settlement"
assert_eq 0 "$(G terminal_seq)" "D6: a missing out/ advances nothing either"
assert_eq true "$(G provisioned)" "D6: still provisioned -- the root is there, the storage is not"

# ===========================================================================
printf -- '--- X6: a host that never activated the reader stays quiet\n'
MON5="$(mkmon mon5)"
SURFACE="$TMP/surface-x6"; : > "$SURFACE"; chmod 0666 "$SURFACE"
as_consumer publish "$MON5" "$TMP/t9/out" xaccdark "$TMP/x6-dark" \
    || fail "X6: the publish driver failed on a dark host"
K() { mval "P.$1" "$TMP/x6-dark"; }
assert_eq false "$(K provisioned)" "X6: the absence of any reader data root is detected"
assert_eq false "$(K degraded)" \
    "X6: B7-B's raise does NOT turn a reader-less host into a false alarm"
assert_eq - "$(K last_error_code)" "X6: a dark host surfaces no code"
assert_eq - "$(K consumed)" "X6: no ingest pass is claimed on a dark host"
assert_eq true "$(K configured)" \
    "X6: the exchange dir IS configured -- the root it sits in was never created"
assert_eq 1 "$(K samples)" "X6: P1 history still works on a reader-less host"

# ===========================================================================
teardown_idents
assert_eq "" "$(getent passwd "$JR_USER" "$CW_USER" "$NZ_USER" | tr '\n' ' ')" \
    "teardown: the disposable identities left no residue on the runner"
printf '\nPASS=%d FAIL=%d SKIP=%d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -gt 0 ]; then
    printf 'SBOX_JR_XACCESS=FAIL\n'; exit 1
fi
printf 'SBOX_JR_XACCESS=PASS\n'; exit 0
